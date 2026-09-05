/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passsecrets

import java.io.File
import java.io.IOException
import java.security.SecureRandom

/** In-memory resolver and mutation model for Pass-Secrets identity metadata. */
object PassSecretsMapStore {

  const val MAP_FILE_NAME = ".secrets.gpg"
  const val MASK_FILE_NAME = ".mask.gpg"
  private const val GPG_ID_FILE_NAME = ".gpg-id"
  private const val PENDING_VALUE = "(pendente)"
  private const val DEFAULT_CODENAME_LENGTH = 5
  private const val CODENAME_ATTEMPTS = 50
  private const val CONSONANTS = "bcdfglmnprstvz"
  private const val VOWELS = "aeiou"
  private val validMapKey = Regex("[A-Za-z0-9_./-]+")
  private val random = SecureRandom()

  data class MaskAssociation(val alias: String, val directory: String)

  data class MetadataFiles(val mapFile: File?, val maskFile: File?) {

    val existingFiles: List<File>
      get() = listOfNotNull(mapFile, maskFile)
  }

  private data class FileVersion(val lastModified: Long, val length: Long)

  private data class IdentityVersion(val map: FileVersion?, val mask: FileVersion?)

  private data class LoadedMap(val version: FileVersion, val values: Map<String, String>)

  private data class LoadedMask(
    val version: FileVersion,
    val associations: List<MaskAssociation>,
  )

  private val lock = Any()
  private val loadedMaps = mutableMapOf<String, LoadedMap>()
  private val loadedMasks = mutableMapOf<String, LoadedMask>()
  private val gatedVersions = mutableMapOf<String, IdentityVersion>()

  /** Parse the plaintext map format `<relative codename path> = <real description>`. */
  fun parse(plaintext: String): Map<String, String> {
    val values = linkedMapOf<String, String>()
    plaintext.lineSequence().forEach { rawLine ->
      val separator = rawLine.indexOf('=')
      if (separator <= 0) return@forEach

      val key = rawLine.substring(0, separator).trim()
      val value = rawLine.substring(separator + 1).trim()
      if (!isValidMapKey(key) || value.isBlank() || value == PENDING_VALUE) return@forEach

      // Pass-Secrets treats a path as a unique key. Last value wins for a malformed duplicate.
      values[key] = value
    }
    return values
  }

  /** Parse `.mask.gpg`'s many-to-many `<email alias> = <relative directory>` format. */
  fun parseMask(plaintext: String): List<MaskAssociation> {
    return plaintext
      .lineSequence()
      .mapNotNull { rawLine ->
        val separator = rawLine.indexOf('=')
        if (separator <= 0) return@mapNotNull null
        val alias = rawLine.substring(0, separator).trim()
        val directory = rawLine.substring(separator + 1).trim()
        if (alias.isBlank() || !isValidMapKey(directory)) return@mapNotNull null
        MaskAssociation(alias, directory)
      }
      .distinct()
      .sortedWith(compareBy<MaskAssociation> { it.alias }.thenBy { it.directory })
      .toList()
  }

  fun serializeMap(values: Map<String, String>): String {
    return values
      .toSortedMap()
      .entries
      .joinToString(separator = "\n", postfix = if (values.isEmpty()) "" else "\n") {
        (key, value) ->
        "$key = $value"
      }
  }

  fun serializeMask(associations: List<MaskAssociation>): String {
    val values = associations.distinct().sortedWith(compareBy<MaskAssociation> { it.alias }.thenBy { it.directory })
    return values.joinToString(separator = "\n", postfix = if (values.isEmpty()) "" else "\n") {
      association ->
      "${association.alias} = ${association.directory}"
    }
  }

  /** Resolve the mapped display name for a physical password file, if its map is unlocked. */
  fun mappedName(file: File, repositoryRoot: File): String? {
    if (!isPasswordFile(file)) return null
    val identity = findNearestIdentity(file.parentFile ?: return null, repositoryRoot) ?: return null
    val mapFile = File(identity, MAP_FILE_NAME)
    if (!mapFile.isFile) return null
    val relativePath = passwordRelativePath(file, identity) ?: return null

    synchronized(lock) {
      val identityKey = identity.key()
      val loaded = loadedMaps[identityKey] ?: return null
      if (loaded.version != mapFile.version()) {
        loadedMaps.remove(identityKey)
        gatedVersions.remove(identityKey)
        return null
      }
      return loaded.values[relativePath]
    }
  }

  /** Resolve any `.mask.gpg` aliases applying to this password's physical directory. */
  fun aliases(file: File, repositoryRoot: File): List<String> {
    if (!isPasswordFile(file)) return emptyList()
    val identity = findNearestIdentity(file.parentFile ?: return emptyList(), repositoryRoot)
      ?: return emptyList()
    val maskFile = File(identity, MASK_FILE_NAME)
    if (!maskFile.isFile) return emptyList()
    val relativeDirectory =
      try {
        file.parentFile
          ?.relativeTo(identity)
          ?.invariantSeparatorsPath
          ?.ifBlank { "." }
          ?: return emptyList()
      } catch (_: IllegalArgumentException) {
        return emptyList()
      }

    synchronized(lock) {
      val identityKey = identity.key()
      val loaded = loadedMasks[identityKey] ?: return emptyList()
      if (loaded.version != maskFile.version()) {
        loadedMasks.remove(identityKey)
        gatedVersions.remove(identityKey)
        return emptyList()
      }
      return loaded.associations
        .asSequence()
        .filter { association -> directoryContains(association.directory, relativeDirectory) }
        .map { it.alias }
        .distinct()
        .toList()
    }
  }

  /**
   * Claim this directory's nearest identity metadata for lazy unlock.
   *
   * A nested `.gpg-id` is always a hard boundary. Both `.secrets.gpg` and `.mask.gpg` are loaded
   * in one authentication session when present. The returned path is merely the primary file used
   * to launch the unlock activity.
   */
  fun claimForDirectory(directory: File, repositoryRoot: File): File? {
    val identity = findNearestIdentity(directory, repositoryRoot) ?: return null
    val metadata = identity.metadataFiles()
    val primaryFile = metadata.mapFile ?: metadata.maskFile ?: return null

    synchronized(lock) {
      val identityKey = identity.key()
      val version = identity.version()
      if (isCurrent(identityKey, metadata)) return null

      val gatedVersion = gatedVersions[identityKey]
      if (gatedVersion == version) return null
      gatedVersions[identityKey] = version
      return primaryFile
    }
  }

  fun metadataFilesForDirectory(directory: File, repositoryRoot: File): MetadataFiles {
    val identity = findNearestIdentity(directory, repositoryRoot) ?: return MetadataFiles(null, null)
    return identity.metadataFiles()
  }

  fun mapFileForDirectory(directory: File, repositoryRoot: File): File? {
    return metadataFilesForDirectory(directory, repositoryRoot).mapFile
  }

  fun maskFileForDirectory(directory: File, repositoryRoot: File): File? {
    return metadataFilesForDirectory(directory, repositoryRoot).maskFile
  }

  fun identityForDirectory(directory: File, repositoryRoot: File): File? {
    return findNearestIdentity(directory, repositoryRoot)
  }

  fun isLoaded(metadataFile: File): Boolean {
    val identity = metadataFile.parentFile ?: return false
    synchronized(lock) {
      return when (metadataFile.name) {
        MAP_FILE_NAME -> loadedMaps[identity.key()]?.version == metadataFile.version()
        MASK_FILE_NAME -> loadedMasks[identity.key()]?.version == metadataFile.version()
        else -> false
      }
    }
  }

  /** Store a successfully decrypted `.secrets.gpg`. Plaintext remains process-local. */
  fun putMap(mapFile: File, values: Map<String, String>) {
    val identity = mapFile.parentFile ?: return
    synchronized(lock) {
      loadedMaps[identity.key()] = LoadedMap(mapFile.version(), values.toMap())
      gatedVersions.remove(identity.key())
    }
  }

  /** Store a successfully decrypted `.mask.gpg`. Plaintext remains process-local. */
  fun putMask(maskFile: File, associations: List<MaskAssociation>) {
    val identity = maskFile.parentFile ?: return
    synchronized(lock) {
      loadedMasks[identity.key()] = LoadedMask(maskFile.version(), associations.toList())
      gatedVersions.remove(identity.key())
    }
  }

  /** Backwards-compatible shorthand used by older tests/callers for `.secrets.gpg`. */
  fun put(mapFile: File, values: Map<String, String>) = putMap(mapFile, values)

  fun mapSnapshot(mapFile: File): Map<String, String>? {
    if (mapFile.name != MAP_FILE_NAME || !mapFile.isFile) return null
    val identity = mapFile.parentFile ?: return null
    synchronized(lock) {
      val loaded = loadedMaps[identity.key()] ?: return null
      if (loaded.version != mapFile.version()) return null
      return loaded.values.toMap()
    }
  }

  fun maskSnapshot(maskFile: File): List<MaskAssociation>? {
    if (maskFile.name != MASK_FILE_NAME || !maskFile.isFile) return null
    val identity = maskFile.parentFile ?: return null
    synchronized(lock) {
      val loaded = loadedMasks[identity.key()] ?: return null
      if (loaded.version != maskFile.version()) return null
      return loaded.associations.toList()
    }
  }

  /** Suppress repeated automatic prompts after cancellation/failure for this metadata version. */
  fun skip(metadataFile: File) {
    val identity = metadataFile.parentFile ?: return
    synchronized(lock) { gatedVersions[identity.key()] = identity.version() }
  }

  /** Forget all decrypted labels, aliases and prompt gates, e.g. when the screen locks. */
  fun clear() {
    synchronized(lock) {
      loadedMaps.clear()
      loadedMasks.clear()
      gatedVersions.clear()
    }
  }

  fun isMetadataFile(file: File): Boolean {
    return file.isFile && (file.name == MAP_FILE_NAME || file.name == MASK_FILE_NAME)
  }

  fun isProtectedIdentityMarker(file: File): Boolean {
    if (file.name != GPG_ID_FILE_NAME || !file.isFile) return false
    val parent = file.parentFile ?: return false
    return File(parent, MAP_FILE_NAME).isFile || File(parent, MASK_FILE_NAME).isFile
  }

  fun passwordRelativePath(file: File, identity: File): String? {
    if (!isPasswordFile(file)) return null
    return try {
      file.relativeTo(identity).invariantSeparatorsPath.removeSuffix(".gpg")
    } catch (_: IllegalArgumentException) {
      null
    }
  }

  /** Generate a free codename exactly like Pass-Secrets 2.5.x `namegen`. */
  fun generateCodename(directory: File, length: Int = DEFAULT_CODENAME_LENGTH): String {
    require(length > 0) { "Codename length must be positive" }
    repeat(CODENAME_ATTEMPTS) {
      val startsWithConsonant = random.nextBoolean()
      val generated =
        buildString(length) {
          repeat(length) { index ->
            val useConsonant = (index % 2 == 0) == startsWithConsonant
            val alphabet = if (useConsonant) CONSONANTS else VOWELS
            append(alphabet[random.nextInt(alphabet.length)])
          }
        }
      val codename = generated.replaceFirstChar { it.uppercaseChar() }
      if (!File(directory, codename).exists() && !File(directory, "$codename.gpg").exists()) {
        return codename
      }
    }
    error("Unable to generate a free Pass-Secrets codename after $CODENAME_ATTEMPTS attempts")
  }

  fun mapAfterMove(
    values: Map<String, String>,
    sourceRelativePath: String,
    destinationRelativePath: String,
    sourceIsDirectory: Boolean,
  ): Map<String, String> {
    val result = linkedMapOf<String, String>()
    values.forEach { (key, value) ->
      val movedKey =
        when {
          !sourceIsDirectory && key == sourceRelativePath -> destinationRelativePath
          sourceIsDirectory && key.startsWith("$sourceRelativePath/") ->
            destinationRelativePath + key.removePrefix(sourceRelativePath)
          else -> key
        }
      result[movedKey] = value
    }
    return result
  }

  fun mapAfterDelete(
    values: Map<String, String>,
    relativePath: String,
    isDirectory: Boolean,
  ): Map<String, String> {
    return values.filterKeys { key ->
      if (isDirectory) key != relativePath && !key.startsWith("$relativePath/")
      else key != relativePath
    }
  }

  fun maskAfterMove(
    associations: List<MaskAssociation>,
    sourceRelativePath: String,
    destinationRelativePath: String,
  ): List<MaskAssociation> {
    return associations
      .map { association ->
        val movedDirectory =
          when {
            association.directory == sourceRelativePath -> destinationRelativePath
            association.directory.startsWith("$sourceRelativePath/") ->
              destinationRelativePath + association.directory.removePrefix(sourceRelativePath)
            else -> association.directory
          }
        association.copy(directory = movedDirectory)
      }
      .distinct()
  }

  fun maskAfterDelete(
    associations: List<MaskAssociation>,
    relativePath: String,
    isDirectory: Boolean,
  ): List<MaskAssociation> {
    if (!isDirectory) return associations
    return associations.filterNot { association ->
      association.directory == relativePath || association.directory.startsWith("$relativePath/")
    }
  }

  /**
   * Return true when a generic filesystem move would change the `.gpg-id` owning encrypted files.
   * Such a move requires decrypt/re-encrypt and must not be performed by the bulk move path.
   */
  fun moveRequiresReencryption(source: File, destination: File, repositoryRoot: File): Boolean {
    if (isProtectedIdentityMarker(source)) return true
    if (source.isFile) {
      if (!isPasswordFile(source)) return false
      val sourceIdentity = findNearestIdentity(source.parentFile ?: return false, repositoryRoot)
      val targetIdentity =
        findNearestIdentity(destination.parentFile ?: return false, repositoryRoot)
      return !sameIdentity(sourceIdentity, targetIdentity)
    }

    if (!source.isDirectory || File(source, GPG_ID_FILE_NAME).isFile) return false
    val sourceIdentity = findNearestIdentity(source, repositoryRoot)
    val targetIdentity =
      findNearestIdentity(destination.parentFile ?: return false, repositoryRoot)
    if (sameIdentity(sourceIdentity, targetIdentity)) return false

    return source
      .walkTopDown()
      .onEnter { directory ->
        directory == source || !File(directory, GPG_ID_FILE_NAME).isFile
      }
      .any(::isPasswordFile)
  }

  private fun isCurrent(identityKey: String, metadata: MetadataFiles): Boolean {
    val mapCurrent =
      metadata.mapFile == null || loadedMaps[identityKey]?.version == metadata.mapFile.version()
    val maskCurrent =
      metadata.maskFile == null || loadedMasks[identityKey]?.version == metadata.maskFile.version()
    return mapCurrent && maskCurrent
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
      if (File(current, GPG_ID_FILE_NAME).isFile) return current
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
    return key.isNotBlank() && validMapKey.matches(key) && !key.startsWith('/') && ".." !in key
  }

  private fun directoryContains(mappedDirectory: String, actualDirectory: String): Boolean {
    return mappedDirectory == "." ||
      actualDirectory == mappedDirectory ||
      actualDirectory.startsWith("$mappedDirectory/")
  }

  private fun isPasswordFile(file: File): Boolean {
    return file.isFile && file.extension.equals("gpg", ignoreCase = true) && !isMetadataFile(file)
  }

  private fun sameIdentity(first: File?, second: File?): Boolean {
    if (first == null || second == null) return first == null && second == null
    return first.key() == second.key()
  }

  private fun File.metadataFiles(): MetadataFiles {
    val map = File(this, MAP_FILE_NAME).takeIf { it.isFile }
    val mask = File(this, MASK_FILE_NAME).takeIf { it.isFile }
    return MetadataFiles(map, mask)
  }

  private fun File.version() = FileVersion(lastModified = lastModified(), length = length())

  private fun File.version(): IdentityVersion =
    IdentityVersion(
      map = File(this, MAP_FILE_NAME).takeIf { it.isFile }?.version(),
      mask = File(this, MASK_FILE_NAME).takeIf { it.isFile }?.version(),
    )

  private fun File.key(): String =
    try {
      canonicalPath
    } catch (_: IOException) {
      absolutePath
    }
}
