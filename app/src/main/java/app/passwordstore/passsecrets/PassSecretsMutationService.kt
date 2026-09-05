/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passsecrets

import app.passwordstore.passsecrets.PassSecretsMapWriter.Update
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.extensions.wipe
import dagger.Reusable
import java.io.File
import java.io.IOException
import java.util.UUID
import javax.inject.Inject
import kotlinx.coroutines.withContext

/** Coordinates physical password mutations with their encrypted Pass-Secrets metadata. */
@Reusable
class PassSecretsMutationService
@Inject
constructor(
  private val writer: PassSecretsMapWriter,
  private val dispatcherProvider: DispatcherProvider,
) {

  class MetadataLockedException(val metadataFile: File) :
    IllegalStateException("Pass-Secrets metadata must be unlocked first: $metadataFile")

  class ReencryptionRequiredException(source: File, destination: File) :
    IllegalStateException(
      "Moving $source to $destination crosses a .gpg-id boundary and requires re-encryption"
    )

  class ProtectedIdentityMarkerException(file: File) :
    IllegalStateException("Cannot mutate $file independently from its Pass-Secrets identity")

  data class PasswordWritePlan(
    val sourceFile: File?,
    val destinationFile: File,
    val logicalName: String,
    val mappedDestination: Boolean,
    val updates: List<Update>,
    val rollbackUpdates: List<Update>,
  )

  data class FileMovePlan(
    val moves: List<Pair<File, File>>,
    val updates: List<Update>,
    val rollbackUpdates: List<Update>,
  )

  data class DeletePlan(
    val targets: List<File>,
    val updates: List<Update>,
    val rollbackUpdates: List<Update>,
  )

  private data class StagedMove(val source: File, val destination: File, val backup: File?)

  fun requiredMetadataForPasswordWrite(
    sourceFile: File?,
    destinationDirectory: File,
    repositoryRoot: File,
  ): List<File> {
    val sourceMap =
      sourceFile?.parentFile?.let { PassSecretsMapStore.mapFileForDirectory(it, repositoryRoot) }
    val targetMap = PassSecretsMapStore.mapFileForDirectory(destinationDirectory, repositoryRoot)
    return listOfNotNull(sourceMap, targetMap)
      .distinctBy { it.canonicalPath }
      .filterNot(PassSecretsMapStore::isLoaded)
  }

  fun planPasswordWrite(
    sourceFile: File?,
    destinationDirectory: File,
    requestedName: String,
    repositoryRoot: File,
  ): PasswordWritePlan {
    require(destinationDirectory.isDirectory) { "Password destination is not a directory" }
    require(requestedName.isNotBlank()) { "Password name must not be blank" }

    val sourceMapFile =
      sourceFile?.parentFile?.let { PassSecretsMapStore.mapFileForDirectory(it, repositoryRoot) }
    val destinationMapFile =
      PassSecretsMapStore.mapFileForDirectory(destinationDirectory, repositoryRoot)

    sourceMapFile?.requireLoaded()
    destinationMapFile?.requireLoaded()

    val sameMap =
      sourceMapFile != null &&
        destinationMapFile != null &&
        sourceMapFile.canonicalPath == destinationMapFile.canonicalPath

    val physicalName =
      if (destinationMapFile != null) {
        if (sourceFile != null && sameMap) sourceFile.nameWithoutExtension
        else PassSecretsMapStore.generateCodename(destinationDirectory)
      } else {
        require('/' !in requestedName && '\\' !in requestedName) {
          "A normal pass filename cannot contain path separators"
        }
        requestedName
      }

    val destinationFile = File(destinationDirectory, "$physicalName.gpg")
    if (
      destinationFile.exists() &&
        (sourceFile == null || destinationFile.canonicalPath != sourceFile.canonicalPath)
    ) {
      throw IOException("Password destination already exists: $destinationFile")
    }

    val oldMaps = linkedMapOf<String, Pair<File, Map<String, String>>>()
    listOfNotNull(sourceMapFile, destinationMapFile).forEach { mapFile ->
      oldMaps[mapFile.canonicalPath] = mapFile to mapFile.requireMapSnapshot()
    }
    val newMaps = oldMaps.mapValuesTo(linkedMapOf()) { (_, pair) -> pair.second }

    if (sourceFile != null && sourceMapFile != null) {
      val sourceIdentity = requireNotNull(sourceMapFile.parentFile)
      val sourceKey =
        requireNotNull(PassSecretsMapStore.passwordRelativePath(sourceFile, sourceIdentity))
      newMaps[sourceMapFile.canonicalPath] =
        PassSecretsMapStore.mapAfterDelete(
          newMaps.getValue(sourceMapFile.canonicalPath),
          sourceKey,
          isDirectory = false,
        )
    }

    if (destinationMapFile != null) {
      val destinationIdentity = requireNotNull(destinationMapFile.parentFile)
      val destinationKey = passwordRelativePath(destinationFile, destinationIdentity)
      newMaps[destinationMapFile.canonicalPath] =
        newMaps.getValue(destinationMapFile.canonicalPath) + (destinationKey to requestedName)
    }

    val updates = mutableListOf<Update>()
    val rollback = mutableListOf<Update>()
    oldMaps.forEach { (key, pair) ->
      val (file, oldValues) = pair
      val newValues = newMaps.getValue(key)
      if (oldValues != newValues) {
        updates += Update.Secrets(file, newValues)
        rollback += Update.Secrets(file, oldValues)
      }
    }

    return PasswordWritePlan(
      sourceFile = sourceFile,
      destinationFile = destinationFile,
      logicalName = requestedName,
      mappedDestination = destinationMapFile != null,
      updates = updates,
      rollbackUpdates = rollback,
    )
  }

  suspend fun commitPasswordWrite(plan: PasswordWritePlan, encryptedBytes: ByteArray) {
    withContext(dispatcherProvider.io()) {
      val source = plan.sourceFile
      val destination = plan.destinationFile
      val sameFile = source?.canonicalPath == destination.canonicalPath
      val originalDestination =
        if (sameFile && destination.isFile) destination.readBytes() else null

      try {
        destination.parentFile?.mkdirs()
        destination.writeBytes(encryptedBytes)
        writer.persist(plan.updates)

        if (!sameFile && source != null && source.exists() && !source.delete()) {
          try {
            writer.persist(plan.rollbackUpdates)
          } finally {
            destination.delete()
          }
          throw IOException("Could not remove the old password after a mapped move: $source")
        }
      } catch (error: Throwable) {
        if (sameFile && originalDestination != null) {
          destination.writeBytes(originalDestination)
        } else if (!sameFile) {
          destination.delete()
        }
        throw error
      } finally {
        originalDestination?.wipe()
      }
    }
  }

  fun requiredMetadataForMoves(
    moves: List<Pair<File, File>>,
    repositoryRoot: File,
  ): List<File> {
    val metadata = linkedMapOf<String, File>()
    moves.forEach { (source, destination) ->
      if (PassSecretsMapStore.isProtectedIdentityMarker(source)) {
        throw ProtectedIdentityMarkerException(source)
      }
      if (PassSecretsMapStore.moveRequiresReencryption(source, destination, repositoryRoot)) {
        throw ReencryptionRequiredException(source, destination)
      }
      val sourceParent = source.parentFile ?: return@forEach
      val sourceIdentity =
        PassSecretsMapStore.identityForDirectory(sourceParent, repositoryRoot) ?: return@forEach
      val destinationIdentity =
        PassSecretsMapStore.identityForDirectory(
          destination.parentFile ?: return@forEach,
          repositoryRoot,
        )
      if (sourceIdentity.canonicalPath != destinationIdentity?.canonicalPath) {
        // Moving an entire nested identity is safe cryptographically because its .gpg-id moves
        // with it, but parent Pass-Secrets metadata could reference that directory. Refuse when
        // such parent metadata exists rather than silently leaving stale associations.
        val parentMetadata =
          PassSecretsMapStore.metadataFilesForDirectory(sourceParent, repositoryRoot).existingFiles
        if (parentMetadata.isNotEmpty()) throw ReencryptionRequiredException(source, destination)
        return@forEach
      }
      PassSecretsMapStore.metadataFilesForDirectory(sourceParent, repositoryRoot)
        .existingFiles
        .forEach { file -> metadata[file.canonicalPath] = file }
    }
    return metadata.values.filterNot(PassSecretsMapStore::isLoaded)
  }

  fun requiredMetadataForMove(source: File, destination: File, repositoryRoot: File): List<File> =
    requiredMetadataForMoves(listOf(source to destination), repositoryRoot)

  fun planMoves(moves: List<Pair<File, File>>, repositoryRoot: File): FileMovePlan {
    requiredMetadataForMoves(moves, repositoryRoot).firstOrNull()?.let {
      throw MetadataLockedException(it)
    }
    val normalizedMoves = moves.distinctBy { (source, _) -> source.canonicalPath }
    val original = linkedMapOf<String, Update>()
    val current = linkedMapOf<String, Update>()

    normalizedMoves.forEach { (source, destination) ->
      val sourceParent = source.parentFile ?: return@forEach
      val sourceIdentity =
        PassSecretsMapStore.identityForDirectory(sourceParent, repositoryRoot) ?: return@forEach
      val destinationIdentity =
        PassSecretsMapStore.identityForDirectory(
          destination.parentFile ?: sourceParent,
          repositoryRoot,
        )
      if (sourceIdentity.canonicalPath != destinationIdentity?.canonicalPath) return@forEach

      val sourceRelative = relativeEntryPath(source, sourceIdentity)
      val destinationRelative = relativeEntryPath(destination, sourceIdentity)
      val metadata = PassSecretsMapStore.metadataFilesForDirectory(sourceParent, repositoryRoot)

      metadata.mapFile?.let { mapFile ->
        val key = mapFile.canonicalPath
        val old =
          (original[key] as? Update.Secrets)?.values
            ?: mapFile.requireMapSnapshot().also {
              original[key] = Update.Secrets(mapFile, it)
            }
        val values = (current[key] as? Update.Secrets)?.values ?: old
        current[key] =
          Update.Secrets(
            mapFile,
            PassSecretsMapStore.mapAfterMove(
              values,
              sourceRelative,
              destinationRelative,
              source.isDirectory,
            ),
          )
      }
      metadata.maskFile?.let { maskFile ->
        val key = maskFile.canonicalPath
        val old =
          (original[key] as? Update.Mask)?.associations
            ?: maskFile.requireMaskSnapshot().also {
              original[key] = Update.Mask(maskFile, it)
            }
        val values = (current[key] as? Update.Mask)?.associations ?: old
        current[key] =
          Update.Mask(
            maskFile,
            if (source.isDirectory)
              PassSecretsMapStore.maskAfterMove(values, sourceRelative, destinationRelative)
            else values,
          )
      }
    }

    return FileMovePlan(
      moves = normalizedMoves,
      updates = current.filter { (key, value) -> value != original[key] }.values.toList(),
      rollbackUpdates = original.filter { (key, value) -> value != current[key] }.values.toList(),
    )
  }

  fun planMove(source: File, destination: File, repositoryRoot: File): FileMovePlan =
    planMoves(listOf(source to destination), repositoryRoot)

  suspend fun commitMoves(plan: FileMovePlan) {
    withContext(dispatcherProvider.io()) {
      val staged = mutableListOf<StagedMove>()
      try {
        plan.moves.forEach { (source, destination) ->
          destination.parentFile?.mkdirs()
          val backup =
            if (destination.exists()) {
              File(
                  destination.parentFile,
                  ".aps-move-backup-${UUID.randomUUID()}-${destination.name}",
                )
                .also { backupFile ->
                  if (!destination.renameTo(backupFile)) {
                    throw IOException("Could not stage existing destination $destination")
                  }
                }
            } else null
          if (!source.renameTo(destination)) {
            backup?.renameTo(destination)
            throw IOException("Could not move $source to $destination")
          }
          staged += StagedMove(source, destination, backup)
        }

        writer.persist(plan.updates)
        staged.forEach { it.backup?.deleteRecursively() }
      } catch (error: Throwable) {
        staged.asReversed().forEach { move ->
          if (move.destination.exists()) move.destination.renameTo(move.source)
          move.backup?.takeIf { it.exists() }?.renameTo(move.destination)
        }
        throw error
      }
    }
  }

  suspend fun commitMove(plan: FileMovePlan) = commitMoves(plan)

  fun requiredMetadataForDelete(targets: List<File>, repositoryRoot: File): List<File> {
    val metadata = linkedMapOf<String, File>()
    normalizeDeleteTargets(targets).forEach { target ->
      if (PassSecretsMapStore.isProtectedIdentityMarker(target)) {
        throw ProtectedIdentityMarkerException(target)
      }
      val parent = target.parentFile ?: return@forEach
      PassSecretsMapStore.metadataFilesForDirectory(parent, repositoryRoot).existingFiles.forEach {
        file ->
        metadata[file.canonicalPath] = file
      }
    }
    return metadata.values.filterNot(PassSecretsMapStore::isLoaded)
  }

  fun planDelete(targets: List<File>, repositoryRoot: File): DeletePlan {
    val normalizedTargets = normalizeDeleteTargets(targets)
    requiredMetadataForDelete(normalizedTargets, repositoryRoot).firstOrNull()?.let {
      throw MetadataLockedException(it)
    }
    val original = linkedMapOf<String, Update>()
    val current = linkedMapOf<String, Update>()

    normalizedTargets.forEach { target ->
      val parent = target.parentFile ?: return@forEach
      val identity =
        PassSecretsMapStore.identityForDirectory(parent, repositoryRoot) ?: return@forEach
      val relativePath = relativeEntryPath(target, identity)
      val metadata = PassSecretsMapStore.metadataFilesForDirectory(parent, repositoryRoot)

      metadata.mapFile?.let { mapFile ->
        val key = mapFile.canonicalPath
        val old =
          (original[key] as? Update.Secrets)?.values
            ?: mapFile.requireMapSnapshot().also {
              original[key] = Update.Secrets(mapFile, it)
            }
        val values = (current[key] as? Update.Secrets)?.values ?: old
        current[key] =
          Update.Secrets(
            mapFile,
            PassSecretsMapStore.mapAfterDelete(values, relativePath, target.isDirectory),
          )
      }
      metadata.maskFile?.let { maskFile ->
        val key = maskFile.canonicalPath
        val old =
          (original[key] as? Update.Mask)?.associations
            ?: maskFile.requireMaskSnapshot().also {
              original[key] = Update.Mask(maskFile, it)
            }
        val values = (current[key] as? Update.Mask)?.associations ?: old
        current[key] =
          Update.Mask(
            maskFile,
            PassSecretsMapStore.maskAfterDelete(values, relativePath, target.isDirectory),
          )
      }
    }

    return DeletePlan(
      targets = normalizedTargets,
      updates = current.filter { (key, value) -> value != original[key] }.values.toList(),
      rollbackUpdates = original.filter { (key, value) -> value != current[key] }.values.toList(),
    )
  }

  suspend fun commitDelete(plan: DeletePlan) {
    withContext(dispatcherProvider.io()) {
      val staged = mutableListOf<Pair<File, File>>()
      try {
        plan.targets.forEach { target ->
          if (!target.exists()) return@forEach
          val parent = requireNotNull(target.parentFile)
          val temporary = File(parent, ".aps-delete-${UUID.randomUUID()}-${target.name}")
          if (!target.renameTo(temporary)) {
            throw IOException("Could not stage $target for deletion")
          }
          staged += target to temporary
        }
        writer.persist(plan.updates)
      } catch (error: Throwable) {
        staged.asReversed().forEach { (original, temporary) ->
          if (temporary.exists()) temporary.renameTo(original)
        }
        throw error
      }

      // At this point the original paths are gone and encrypted metadata has committed. Cleanup is
      // best effort: a failed unlink leaves only a hidden, unreferenced ciphertext tombstone rather
      // than making the logical deletion inconsistent.
      staged.forEach { (_, temporary) -> temporary.deleteRecursively() }
    }
  }

  private fun normalizeDeleteTargets(targets: List<File>): List<File> {
    val unique = targets.distinctBy { it.canonicalPath }
    return unique.filter { candidate ->
      unique.none { other ->
        other != candidate &&
          other.isDirectory &&
          candidate.canonicalPath.startsWith(
            other.canonicalPath.trimEnd(File.separatorChar) + File.separator
          )
      }
    }
  }

  private fun File.requireLoaded() {
    if (!PassSecretsMapStore.isLoaded(this)) throw MetadataLockedException(this)
  }

  private fun File.requireMapSnapshot(): Map<String, String> {
    return PassSecretsMapStore.mapSnapshot(this) ?: throw MetadataLockedException(this)
  }

  private fun File.requireMaskSnapshot(): List<PassSecretsMapStore.MaskAssociation> {
    return PassSecretsMapStore.maskSnapshot(this) ?: throw MetadataLockedException(this)
  }

  private fun relativeEntryPath(file: File, identity: File): String {
    val relative = file.relativeTo(identity).invariantSeparatorsPath
    return if (file.isFile || file.name.endsWith(".gpg")) relative.removeSuffix(".gpg")
    else relative
  }

  private fun passwordRelativePath(file: File, identity: File): String {
    return file.relativeTo(identity).invariantSeparatorsPath.removeSuffix(".gpg")
  }
}
