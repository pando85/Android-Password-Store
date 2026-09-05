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
    val source: File,
    val destination: File,
    val updates: List<Update>,
    val rollbackUpdates: List<Update>,
  )

  data class DeletePlan(
    val targets: List<File>,
    val updates: List<Update>,
    val rollbackUpdates: List<Update>,
  )

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
      val sourceKey = requireNotNull(PassSecretsMapStore.passwordRelativePath(sourceFile, sourceIdentity))
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
      val originalDestination = if (sameFile && destination.isFile) destination.readBytes() else null

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

  fun requiredMetadataForMove(source: File, destination: File, repositoryRoot: File): List<File> {
    if (PassSecretsMapStore.isProtectedIdentityMarker(source)) {
      throw ProtectedIdentityMarkerException(source)
    }
    if (PassSecretsMapStore.moveRequiresReencryption(source, destination, repositoryRoot)) {
      throw ReencryptionRequiredException(source, destination)
    }
    val sourceParent = source.parentFile ?: return emptyList()
    val sourceIdentity = PassSecretsMapStore.identityForDirectory(sourceParent, repositoryRoot)
      ?: return emptyList()
    val destinationIdentity =
      PassSecretsMapStore.identityForDirectory(destination.parentFile ?: return emptyList(), repositoryRoot)
    if (sourceIdentity.canonicalPath != destinationIdentity?.canonicalPath) return emptyList()

    return PassSecretsMapStore.metadataFilesForDirectory(sourceParent, repositoryRoot)
      .existingFiles
      .filterNot(PassSecretsMapStore::isLoaded)
  }

  fun planMove(source: File, destination: File, repositoryRoot: File): FileMovePlan {
    requiredMetadataForMove(source, destination, repositoryRoot).firstOrNull()?.let {
      throw MetadataLockedException(it)
    }
    val sourceParent = source.parentFile
      ?: return FileMovePlan(source, destination, emptyList(), emptyList())
    val sourceIdentity = PassSecretsMapStore.identityForDirectory(sourceParent, repositoryRoot)
      ?: return FileMovePlan(source, destination, emptyList(), emptyList())
    val destinationIdentity =
      PassSecretsMapStore.identityForDirectory(destination.parentFile ?: sourceParent, repositoryRoot)
    if (sourceIdentity.canonicalPath != destinationIdentity?.canonicalPath) {
      // A self-contained nested identity can move without re-encrypting its contents. Its own maps
      // are relative to its root and therefore remain unchanged. Parent aliases are intentionally
      // not guessed across trust boundaries.
      return FileMovePlan(source, destination, emptyList(), emptyList())
    }

    val metadata = PassSecretsMapStore.metadataFilesForDirectory(sourceParent, repositoryRoot)
    val sourceRelative = relativeEntryPath(source, sourceIdentity)
    val destinationRelative = relativeEntryPath(destination, sourceIdentity)
    val updates = mutableListOf<Update>()
    val rollback = mutableListOf<Update>()

    metadata.mapFile?.let { mapFile ->
      val old = mapFile.requireMapSnapshot()
      val new =
        PassSecretsMapStore.mapAfterMove(old, sourceRelative, destinationRelative, source.isDirectory)
      if (new != old) {
        updates += Update.Secrets(mapFile, new)
        rollback += Update.Secrets(mapFile, old)
      }
    }
    metadata.maskFile?.let { maskFile ->
      val old = maskFile.requireMaskSnapshot()
      val new =
        if (source.isDirectory)
          PassSecretsMapStore.maskAfterMove(old, sourceRelative, destinationRelative)
        else old
      if (new != old) {
        updates += Update.Mask(maskFile, new)
        rollback += Update.Mask(maskFile, old)
      }
    }
    return FileMovePlan(source, destination, updates, rollback)
  }

  suspend fun commitMove(plan: FileMovePlan) {
    withContext(dispatcherProvider.io()) {
      if (!plan.source.renameTo(plan.destination)) {
        throw IOException("Could not move ${plan.source} to ${plan.destination}")
      }
      try {
        writer.persist(plan.updates)
      } catch (error: Throwable) {
        if (!plan.destination.renameTo(plan.source)) {
          throw IOException(
            "Pass-Secrets metadata update failed and filesystem move could not be rolled back",
            error,
          )
        }
        throw error
      }
    }
  }

  fun requiredMetadataForDelete(targets: List<File>, repositoryRoot: File): List<File> {
    val metadata = linkedMapOf<String, File>()
    targets.forEach { target ->
      if (PassSecretsMapStore.isProtectedIdentityMarker(target)) {
        throw ProtectedIdentityMarkerException(target)
      }
      val parent = target.parentFile ?: return@forEach
      PassSecretsMapStore.metadataFilesForDirectory(parent, repositoryRoot)
        .existingFiles
        .forEach { file -> metadata[file.canonicalPath] = file }
    }
    return metadata.values.filterNot(PassSecretsMapStore::isLoaded)
  }

  fun planDelete(targets: List<File>, repositoryRoot: File): DeletePlan {
    requiredMetadataForDelete(targets, repositoryRoot).firstOrNull()?.let {
      throw MetadataLockedException(it)
    }
    val oldUpdates = linkedMapOf<String, Update>()
    val newUpdates = linkedMapOf<String, Update>()

    targets.forEach { target ->
      val parent = target.parentFile ?: return@forEach
      val identity = PassSecretsMapStore.identityForDirectory(parent, repositoryRoot) ?: return@forEach
      val relativePath = relativeEntryPath(target, identity)
      val metadata = PassSecretsMapStore.metadataFilesForDirectory(parent, repositoryRoot)

      metadata.mapFile?.let { mapFile ->
        val key = mapFile.canonicalPath
        val old =
          (oldUpdates[key] as? Update.Secrets)?.values ?: mapFile.requireMapSnapshot().also {
            oldUpdates[key] = Update.Secrets(mapFile, it)
          }
        val current = (newUpdates[key] as? Update.Secrets)?.values ?: old
        newUpdates[key] =
          Update.Secrets(
            mapFile,
            PassSecretsMapStore.mapAfterDelete(current, relativePath, target.isDirectory),
          )
      }
      metadata.maskFile?.let { maskFile ->
        val key = maskFile.canonicalPath
        val old =
          (oldUpdates[key] as? Update.Mask)?.associations ?: maskFile.requireMaskSnapshot().also {
            oldUpdates[key] = Update.Mask(maskFile, it)
          }
        val current = (newUpdates[key] as? Update.Mask)?.associations ?: old
        newUpdates[key] =
          Update.Mask(
            maskFile,
            PassSecretsMapStore.maskAfterDelete(current, relativePath, target.isDirectory),
          )
      }
    }

    val updates =
      newUpdates.filter { (key, value) -> value != oldUpdates[key] }.values.toList()
    val rollback =
      oldUpdates.filter { (key, value) -> value != newUpdates[key] }.values.toList()
    return DeletePlan(targets.distinctBy { it.canonicalPath }, updates, rollback)
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
        staged.forEach { (_, temporary) ->
          if (!temporary.deleteRecursively()) {
            throw IOException("Could not remove staged deleted entry: $temporary")
          }
        }
      } catch (error: Throwable) {
        val metadataCommitted = staged.any { (_, temporary) -> !temporary.exists() }
        if (metadataCommitted) runCatching { writer.persist(plan.rollbackUpdates) }
        staged.asReversed().forEach { (original, temporary) ->
          if (temporary.exists()) temporary.renameTo(original)
        }
        throw error
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
    return if (file.isFile || file.name.endsWith(".gpg")) relative.removeSuffix(".gpg") else relative
  }

  private fun passwordRelativePath(file: File, identity: File): String {
    return file.relativeTo(identity).invariantSeparatorsPath.removeSuffix(".gpg")
  }
}
