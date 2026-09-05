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
      val snapshot = mapFile.requireMapSnapshot()
      oldMaps[mapFile.canonicalPath] = mapFile to snapshot
    }
    val newMaps = oldMaps.mapValuesTo(linkedMapOf()) { (_, fileAndValues) -> fileAndValues.second }

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
      val destinationKey =
        requireNotNull(
          PassSecretsMapStore.passwordRelativePath(destinationFileForLookup(destinationFile), destinationIdentity)
        )
      newMaps[destinationMapFile.canonicalPath] =
        newMaps.getValue(destinationMapFile.canonicalPath) + (destinationKey to requestedName)
    }

    val updates =
      oldMaps.mapNotNull { (key, fileAndValues) ->
        val (file, oldValues) = fileAndValues
        val newValues = newMaps.getValue(key)
        if (oldValues == newValues) null else Update.Secrets(file, newValues)
      }
    val rollbackUpdates =
      oldMaps.mapNotNull { (key, fileAndValues) ->
        val (file, oldValues) = fileAndValues
        if (oldValues == newMaps.getValue(key)) null else Update.Secrets(file, oldValues)
      }

    return PasswordWritePlan(
      sourceFile = sourceFile,
      destinationFile = destinationFile,
      logicalName = requestedName,
      mappedDestination = destinationMapFile != null,
      updates = updates,
      rollbackUpdates = rollbackUpdates,
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
    if (PassSecretsMapStore.moveRequiresReencryption(source, destination, repositoryRoot)) {
      throw ReencryptionRequiredException(source, destination)
    }
    val ownerDirectory = source.parentFile ?: return emptyList()
    val identity = PassSecretsMapStore.identityForDirectory(ownerDirectory, repositoryRoot)
      ?: return emptyList()
    val destinationIdentity =
      PassSecretsMapStore.identityForDirectory(destination.parentFile ?: return emptyList(), repositoryRoot)
    if (identity.canonicalPath != destinationIdentity?.canonicalPath) return emptyList()

    return PassSecretsMapStore.metadataFilesForDirectory(ownerDirectory, repositoryRoot)
      .existingFiles
      .filterNot(PassSecretsMapStore::isLoaded)
  }

  fun planMove(source: File, destination: File, repositoryRoot: File): FileMovePlan {
    if (PassSecretsMapStore.moveRequiresReencryption(source, destination, repositoryRoot)) {
      throw ReencryptionRequiredException(source, destination)
    }
    val sourceParent = source.parentFile ?: return FileMovePlan(source, destination, emptyList(), emptyList())
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
    metadata.existingFiles.forEach(File::requireLoaded)

    val sourceRelative = relativeEntryPath(source, sourceIdentity)
    val destinationRelative = relativeEntryPath(destination, sourceIdentity)
    val updates = mutableListOf<Update>()
    val rollback = mutableListOf<Update>()

    metadata.mapFile?.let { mapFile ->
      val old = mapFile.requireMapSnapshot()
      val new = PassSecretsMapStore.mapAfterMove(old, sourceRelative, destinationRelative, source.isDirectory)
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

  // `passwordRelativePath` deliberately requires an existing file. During planning the destination
  // does not exist yet, so create a lightweight File view whose path is used by the same rules.
  private fun destinationFileForLookup(destination: File): File =
    object : File(destination.absolutePath) {
      override fun isFile(): Boolean = true
    }
}
