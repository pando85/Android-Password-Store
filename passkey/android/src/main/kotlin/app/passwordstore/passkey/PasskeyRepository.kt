/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey

import app.passwordstore.util.coroutines.DispatcherProvider
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Repository for storing and retrieving passkey credentials.
 *
 * Credentials are stored in a Passless-compatible directory structure:
 * ```
 * {password-store}/{passkeysDir}/{rp_id}/{credential_id_hex}.gpg
 * ```
 *
 * Each `.gpg` file contains a CBOR-encoded credential (including the private key)
 * encrypted with PGP using the password store's GPG key.
 *
 * This format is compatible with Passless (https://github.com/pando85/passless)
 * allowing passkeys to sync via git between Android Password Store and Passless.
 *
 * The [passkeysDir] parameter defaults to [DEFAULT_PASSKEYS_DIR] ("fido2") to match
 * Passless's default configuration, but can be customized via settings.
 */
@Singleton
public class PasskeyRepository @Inject constructor(
  private val dispatcherProvider: DispatcherProvider,
) {

  public companion object {
    /** Default directory name for passkeys (matches Passless default: fido2) */
    public const val DEFAULT_PASSKEYS_DIR: String = "fido2"

    /** File extension for GPG-encrypted credentials */
    private const val GPG_EXTENSION = ".gpg"
  }

  private val mutex = Mutex()

  /**
   * Store an encrypted credential.
   *
   * @param baseDir The password store base directory
   * @param rpId The relying party ID (used for directory structure)
   * @param credentialId The credential ID (used for filename)
   * @param encryptedData The GPG-encrypted CBOR data
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   */
  public suspend fun storeCredential(
    baseDir: File,
    rpId: String,
    credentialId: ByteArray,
    encryptedData: ByteArray,
    passkeysDir: String = DEFAULT_PASSKEYS_DIR,
  ): Unit =
    withContext(dispatcherProvider.io()) {
      mutex.withLock {
        val credFile = getCredentialFile(baseDir, rpId, credentialId, passkeysDir)
        credFile.parentFile?.mkdirs()
        credFile.writeBytes(encryptedData)
      }
    }

  /**
   * Load an encrypted credential by ID.
   *
   * @param baseDir The password store base directory
   * @param credentialId The credential ID
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return The encrypted GPG data, or null if not found
   */
  public suspend fun loadCredential(
    baseDir: File,
    credentialId: ByteArray,
    passkeysDir: String = DEFAULT_PASSKEYS_DIR,
  ): ByteArray? =
    withContext(dispatcherProvider.io()) {
      mutex.withLock {
        val credIdHex = credentialId.toHexString()
        val passkeysDirectory = File(baseDir, passkeysDir)

        if (!passkeysDirectory.exists()) return@withContext null

        // Search through all RP directories
        for (rpDir in passkeysDirectory.listFiles().orEmpty()) {
          if (!rpDir.isDirectory) continue

          val credFile = File(rpDir, "$credIdHex$GPG_EXTENSION")
          if (credFile.exists()) {
            return@withContext credFile.readBytes()
          }
        }

        null
      }
    }

  /**
   * Load an encrypted credential by RP ID and credential ID.
   *
   * @param baseDir The password store base directory
   * @param rpId The relying party ID
   * @param credentialId The credential ID
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return The encrypted GPG data, or null if not found
   */
  public suspend fun loadCredential(
    baseDir: File,
    rpId: String,
    credentialId: ByteArray,
    passkeysDir: String = DEFAULT_PASSKEYS_DIR,
  ): ByteArray? =
    withContext(dispatcherProvider.io()) {
      mutex.withLock {
        val credFile = getCredentialFile(baseDir, rpId, credentialId, passkeysDir)
        if (credFile.exists()) credFile.readBytes() else null
      }
    }

  /**
   * Delete a credential.
   *
   * @param baseDir The password store base directory
   * @param credentialId The credential ID
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return true if deleted, false if not found
   */
  public suspend fun deleteCredential(
    baseDir: File,
    credentialId: ByteArray,
    passkeysDir: String = DEFAULT_PASSKEYS_DIR,
  ): Boolean =
    withContext(dispatcherProvider.io()) {
      mutex.withLock {
        val credIdHex = credentialId.toHexString()
        val passkeysDirectory = File(baseDir, passkeysDir)

        if (!passkeysDirectory.exists()) return@withContext false

        for (rpDir in passkeysDirectory.listFiles().orEmpty()) {
          if (!rpDir.isDirectory) continue

          val credFile = File(rpDir, "$credIdHex$GPG_EXTENSION")
          if (credFile.exists()) {
            credFile.delete()

            // Remove empty RP directory
            if (rpDir.listFiles().isNullOrEmpty()) {
              rpDir.delete()
            }

            return@withContext true
          }
        }

        false
      }
    }

  /**
   * List all credential files for a relying party.
   *
   * @param baseDir The password store base directory
   * @param rpId The relying party ID
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return List of encrypted credential data
   */
  public suspend fun listCredentialsForRp(
    baseDir: File,
    rpId: String,
    passkeysDir: String = DEFAULT_PASSKEYS_DIR,
  ): List<ByteArray> =
    withContext(dispatcherProvider.io()) {
      mutex.withLock {
        val rpDir = getRpDir(baseDir, rpId, passkeysDir)
        if (!rpDir.exists()) return@withContext emptyList()

        rpDir.listFiles().orEmpty()
          .filter { it.name.endsWith(GPG_EXTENSION) && it.isFile }
          .map { it.readBytes() }
      }
    }

  /**
   * List all credential files.
   *
   * @param baseDir The password store base directory
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return List of encrypted credential data
   */
  public suspend fun listAllCredentials(
    baseDir: File,
    passkeysDir: String = DEFAULT_PASSKEYS_DIR,
  ): List<ByteArray> =
    withContext(dispatcherProvider.io()) {
      mutex.withLock {
        val passkeysDirectory = File(baseDir, passkeysDir)
        if (!passkeysDirectory.exists()) return@withContext emptyList()

        val credentials = mutableListOf<ByteArray>()

        for (rpDir in passkeysDirectory.listFiles().orEmpty()) {
          if (!rpDir.isDirectory) continue

          for (file in rpDir.listFiles().orEmpty()) {
            if (file.name.endsWith(GPG_EXTENSION) && file.isFile) {
              credentials.add(file.readBytes())
            }
          }
        }

        credentials
      }
    }

  /**
   * Update a credential (replace the encrypted data).
   *
   * @param baseDir The password store base directory
   * @param rpId The relying party ID
   * @param credentialId The credential ID
   * @param encryptedData The new encrypted data
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   */
  public suspend fun updateCredential(
    baseDir: File,
    rpId: String,
    credentialId: ByteArray,
    encryptedData: ByteArray,
    passkeysDir: String = DEFAULT_PASSKEYS_DIR,
  ): Unit =
    withContext(dispatcherProvider.io()) {
      mutex.withLock {
        val credFile = getCredentialFile(baseDir, rpId, credentialId, passkeysDir)
        if (credFile.exists()) {
          credFile.writeBytes(encryptedData)
        }
      }
    }

  /**
   * Check if a credential exists.
   *
   * @param baseDir The password store base directory
   * @param credentialId The credential ID
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return true if the credential exists
   */
  public suspend fun credentialExists(
    baseDir: File,
    credentialId: ByteArray,
    passkeysDir: String = DEFAULT_PASSKEYS_DIR,
  ): Boolean =
    withContext(dispatcherProvider.io()) {
      mutex.withLock {
        val credIdHex = credentialId.toHexString()
        val passkeysDirectory = File(baseDir, passkeysDir)

        if (!passkeysDirectory.exists()) return@withContext false

        for (rpDir in passkeysDirectory.listFiles().orEmpty()) {
          if (!rpDir.isDirectory) continue

          val credFile = File(rpDir, "$credIdHex$GPG_EXTENSION")
          if (credFile.exists()) {
            return@withContext true
          }
        }

        false
      }
    }

  /**
   * Get the file path for a credential.
   *
   * @param baseDir The password store base directory
   * @param rpId The relying party ID
   * @param credentialId The credential ID
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return The credential file path: {baseDir}/{passkeysDir}/{rpId}/{credentialIdHex}.gpg
   */
  public fun getCredentialFile(
    baseDir: File,
    rpId: String,
    credentialId: ByteArray,
    passkeysDir: String = DEFAULT_PASSKEYS_DIR,
  ): File {
    val sanitizedRpId = sanitizeRpId(rpId)
    val credIdHex = credentialId.toHexString()
    return File(File(File(baseDir, passkeysDir), sanitizedRpId), "$credIdHex$GPG_EXTENSION")
  }

  /**
   * Get the directory for a relying party.
   */
  private fun getRpDir(baseDir: File, rpId: String, passkeysDir: String): File {
    val sanitizedRpId = sanitizeRpId(rpId)
    return File(File(baseDir, passkeysDir), sanitizedRpId)
  }

  /**
   * Sanitize RP ID for filesystem use.
   * 
   * Passless uses the RP ID directly as the directory name, which works for
   * domain-like IDs. We do minimal sanitization to be compatible.
   */
  private fun sanitizeRpId(rpId: String): String {
    // Replace characters that are problematic on most filesystems
    // Keep alphanumeric, dots, and hyphens (typical domain characters)
    return rpId.replace(Regex("[^a-zA-Z0-9.-]"), "_")
  }

  /**
   * List credential index entries for a relying party (without reading file contents).
   * This only uses the directory structure: {passkeysDir}/{rpId}/{credentialId}.gpg
   *
   * @param baseDir The password store base directory
   * @param rpId The relying party ID
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return List of CredentialIndex entries
   */
  public suspend fun listCredentialIndexForRp(
    baseDir: File,
    rpId: String,
    passkeysDir: String = DEFAULT_PASSKEYS_DIR,
  ): List<CredentialIndex> =
    withContext(dispatcherProvider.io()) {
      mutex.withLock {
        val rpDir = getRpDir(baseDir, rpId, passkeysDir)
        if (!rpDir.exists()) return@withContext emptyList()

        rpDir.listFiles().orEmpty()
          .filter { it.name.endsWith(GPG_EXTENSION) && it.isFile }
          .mapNotNull { file ->
            val credIdHex = file.name.removeSuffix(GPG_EXTENSION)
            val credId = credIdHex.hexToByteArray() ?: return@mapNotNull null
            CredentialIndex(
              credentialId = credId,
              rpId = rpId,
            )
          }
      }
    }

  /**
   * List all credential index entries (without reading file contents).
   * This only uses the directory structure: {passkeysDir}/{rpId}/{credentialId}.gpg
   *
   * @param baseDir The password store base directory
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return List of CredentialIndex entries
   */
  public suspend fun listAllCredentialIndex(
    baseDir: File,
    passkeysDir: String = DEFAULT_PASSKEYS_DIR,
  ): List<CredentialIndex> =
    withContext(dispatcherProvider.io()) {
      mutex.withLock {
        val passkeysDirectory = File(baseDir, passkeysDir)
        if (!passkeysDirectory.exists()) return@withContext emptyList()

        val indices = mutableListOf<CredentialIndex>()

        for (rpDir in passkeysDirectory.listFiles().orEmpty()) {
          if (!rpDir.isDirectory) continue
          val rpId = rpDir.name

          for (file in rpDir.listFiles().orEmpty()) {
            if (file.name.endsWith(GPG_EXTENSION) && file.isFile) {
              val credIdHex = file.name.removeSuffix(GPG_EXTENSION)
              val credId = credIdHex.hexToByteArray() ?: continue
              indices.add(CredentialIndex(credentialId = credId, rpId = rpId))
            }
          }
        }

        indices
      }
    }

  /**
   * List all relying party IDs that have stored credentials.
   *
   * @param baseDir The password store base directory
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return List of RP IDs
   */
  public suspend fun listRpIds(
    baseDir: File,
    passkeysDir: String = DEFAULT_PASSKEYS_DIR,
  ): List<String> =
    withContext(dispatcherProvider.io()) {
      mutex.withLock {
        val passkeysDirectory = File(baseDir, passkeysDir)
        if (!passkeysDirectory.exists()) return@withContext emptyList()

        passkeysDirectory.listFiles().orEmpty()
          .filter { it.isDirectory && it.listFiles()?.any { f -> f.name.endsWith(GPG_EXTENSION) } == true }
          .map { it.name }
      }
    }

  private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

  private fun String.hexToByteArray(): ByteArray? {
    if (length % 2 != 0) return null
    return try {
      chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    } catch (e: Exception) {
      null
    }
  }
}

/**
 * Index entry for a credential (from directory structure only, no decryption needed).
 */
public data class CredentialIndex(
  /** The credential ID (from filename) */
  val credentialId: ByteArray,
  /** The relying party ID (from directory name) */
  val rpId: String,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false
    other as CredentialIndex
    return credentialId.contentEquals(other.credentialId) && rpId == other.rpId
  }

  override fun hashCode(): Int {
    var result = credentialId.contentHashCode()
    result = 31 * result + rpId.hashCode()
    return result
  }
}
