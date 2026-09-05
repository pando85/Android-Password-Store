/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passsecrets

import java.io.File
import java.io.IOException

/** In-memory resolver for Pass-Secrets' per-identity `.secrets.gpg` mapping files. */
object PassSecretsMapStore {

  const val MAP_FILE_NAME = ".secrets.gpg"
  const val MASK_FILE_NAME = ".mask.gpg"
  private const val PENDING_VALUE = "(pendente)"
  private val validMapKey = Regex("[A-Za-z0-9_./-]+")

  private data class FileVersion(val lastModified: Long, val length: Long)

  private data class LoadedMap(val version: FileVersion, val values: Map<String, String>)

  private val lock = Any()
  private val loadedMaps = mutableMapOf<String, LoadedMap>()
  private val gatedVersions = mutableMapOf<String, FileVersion>()

  /** Parse the plaintext map format `<relative codename path> = <real description>`. */
  fun parse(plaintext: String): Map<String, String> {
    val values = linkedMapOf<String, String>()
    plaintext.lineSequence().forEach { rawLine ->
      val separator = rawLine.indexOf('=')
      if (separator <= 0) return@forEach

      val key = rawLine.substring(0, separator).trim()
      val value = rawLine.substring(separator + 1).trim()
      if (!isValidMapKey(key) || value.isBlank() || value == PENDING_VALUE) return@forEach

      // Deliberately let the last mapping win for malformed files with duplicate keys.
      values[key] = value
    }
    return values
  }

  /** Resolve the mapped display name for a physical password file, if its map is unlocked. */
  fun mappedName(file: File, repositoryRoot: File): String? {
    if (!file.isFile || file.extension != "gpg" || isMetadataFile(file)) return null
    val identity =
      findNearestIdentity(file.parentFile ?: return null, repositoryRoot) ?: return null
    val mapFile = File(identity, MAP_FILE_NAME)
    if (!mapFile.isFile) return null

    val relativePath =
      try {
        file.relativeTo(identity).invariantSeparatorsPath.removeSuffix(".gpg")
      } catch (_: IllegalArgumentException) {
        return null
      }

    synchronized(lock) {
      val identityKey = identity.absolutePath
      val loaded = loadedMaps[identityKey] ?: return null
      if (loaded.version != mapFile.version()) {
        loadedMaps.remove(identityKey)
        gatedVersions.remove(identityKey)
        return null
      }
      return loaded.values[relativePath]
    }
  }

  /**
   * Claim the map belonging to [directory]'s nearest identity for lazy unlock.
   *
   * A nested `.gpg-id` is always a hard boundary: if that identity has no map, the parent map is
   * never inherited. A map is only returned once until it is either loaded, skipped, changed, or
   * the in-memory state is cleared.
   */
  fun claimForDirectory(directory: File, repositoryRoot: File): File? {
    val identity = findNearestIdentity(directory, repositoryRoot) ?: return null
    val mapFile = File(identity, MAP_FILE_NAME)
    if (!mapFile.isFile) return null

    synchronized(lock) {
      val identityKey = identity.absolutePath
      val version = mapFile.version()
      val loaded = loadedMaps[identityKey]
      if (loaded != null) {
        if (loaded.version == version) return null
        loadedMaps.remove(identityKey)
      }

      val gatedVersion = gatedVersions[identityKey]
      if (gatedVersion != null) {
        if (gatedVersion == version) return null
        gatedVersions.remove(identityKey)
      }

      gatedVersions[identityKey] = version
      return mapFile
    }
  }

  /** Store a successfully decrypted map. Plaintext mappings never leave process memory. */
  fun put(mapFile: File, values: Map<String, String>) {
    val identity = mapFile.parentFile ?: return
    synchronized(lock) {
      val identityKey = identity.absolutePath
      loadedMaps[identityKey] = LoadedMap(mapFile.version(), values.toMap())
      gatedVersions.remove(identityKey)
    }
  }

  /** Suppress repeated automatic prompts after cancellation or a non-recoverable unlock failure. */
  fun skip(mapFile: File) {
    val identity = mapFile.parentFile ?: return
    synchronized(lock) {
      val identityKey = identity.absolutePath
      if (!loadedMaps.containsKey(identityKey)) {
        gatedVersions[identityKey] = mapFile.version()
      }
    }
  }

  /** Forget all decrypted labels and prompt gates, e.g. when the screen locks. */
  fun clear() {
    synchronized(lock) {
      loadedMaps.clear()
      gatedVersions.clear()
    }
  }

  fun isMetadataFile(file: File): Boolean {
    return file.isFile && (file.name == MAP_FILE_NAME || file.name == MASK_FILE_NAME)
  }

  private fun findNearestIdentity(start: File, repositoryRoot: File): File? {
    val root: File
    var current: File
    try {
      root = repositoryRoot.canonicalFile
      current = start.canonicalFile
    } catch (_: IOException) {
      return null
    }
    if (!isInsideRoot(current, root)) return null

    while (true) {
      if (File(current, ".gpg-id").isFile) return current
      if (current == root) return null
      current = current.parentFile ?: return null
      if (!isInsideRoot(current, root)) return null
    }
  }

  private fun isInsideRoot(file: File, root: File): Boolean {
    val rootPath = root.absolutePath.trimEnd(File.separatorChar)
    val path = file.absolutePath
    return path == rootPath || path.startsWith("$rootPath${File.separator}")
  }

  private fun isValidMapKey(key: String): Boolean {
    if (!validMapKey.matches(key) || key.startsWith('/') || ".." in key) return false
    return key.split('/').none { component -> component.isBlank() || component == "." }
  }

  private fun File.version() = FileVersion(lastModified = lastModified(), length = length())
}
