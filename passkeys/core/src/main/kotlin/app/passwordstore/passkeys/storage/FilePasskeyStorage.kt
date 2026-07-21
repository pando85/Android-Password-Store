/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.crypto.CryptoHandler
import app.passwordstore.crypto.CryptoOptions
import app.passwordstore.passkeys.crypto.PasskeyDecryptionError
import app.passwordstore.passkeys.crypto.PasskeyPgpDecryptor
import app.passwordstore.passkeys.crypto.PgpUnlockContext
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import app.passwordstore.passkeys.model.StoredCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import kotlin.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.logcat

public class FilePasskeyStorage<
  Key,
  Identifier,
  KeyPair,
  EncOpts : CryptoOptions,
  DecryptOpts : CryptoOptions,
>(
  private val repositoryRoot: File,
  private val cryptoHandler: CryptoHandler<Key, Identifier, KeyPair, EncOpts, DecryptOpts>,
  private val passkeyPgpDecryptor: PasskeyPgpDecryptor,
  private val pgpUnlockContext: PgpUnlockContext,
  private val encryptionKeys: () -> List<Key>,
  private val encryptionOptions: EncOpts,
  private val config: PasskeyStorageConfig = PasskeyStorageConfig(),
  private val atomicWriter: DefaultAtomicCredentialWriter =
    DefaultAtomicCredentialWriter(repositoryRoot),
) : PasskeyStorage {

  private val passkeyDir: File
    get() = File(repositoryRoot, config.passkeyDirectory)

  override suspend fun listMetadata(rpId: String?): Result<List<PasskeyMetadata>, Throwable> =
    withContext(Dispatchers.IO) {
      try {
        val dir = passkeyDir
        if (!dir.exists() || !dir.isDirectory) {
          return@withContext Ok(emptyList())
        }

        val targetDir = if (rpId != null) File(dir, sanitizeRpId(rpId)) else dir
        if (!targetDir.exists() || !targetDir.isDirectory) {
          return@withContext Ok(emptyList())
        }

        val metadata = mutableListOf<PasskeyMetadata>()
        targetDir
          .walkTopDown()
          .filter { file ->
            file.isFile &&
              file.extension == config.fileExtension.removePrefix(".") &&
              !atomicWriter.isInternalArtifact(file.name)
          }
          .forEach { file ->
            if (java.nio.file.Files.isSymbolicLink(file.toPath())) return@forEach
            val credentialId = hexToBytes(file.nameWithoutExtension) ?: return@forEach
            val fileRpId =
              if (rpId != null) rpId else unsanitizeRpId(file.parentFile?.name ?: return@forEach)
            metadata.add(
              PasskeyMetadata(
                credentialId = credentialId,
                rpId = fileRpId,
                userName = "",
                userDisplayName = "",
                createdAt = Instant.fromEpochMilliseconds(file.lastModified()),
                signCount = 0u,
                fileLastModified = file.lastModified(),
              )
            )
          }

        Ok(metadata)
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Failed to list metadata: ${e.message}" }
        Err(e)
      }
    }

  override suspend fun loadForSigning(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable> =
    withContext(Dispatchers.IO) {
      try {
        val hexId = credentialId.joinToString("") { byte -> "%02x".format(byte) }

        val dir = passkeyDir
        if (!dir.exists() || !dir.isDirectory) {
          return@withContext Err(IllegalArgumentException("Credential not found"))
        }

        dir
          .walkTopDown()
          .filter { it.isFile && it.nameWithoutExtension == hexId }
          .forEach { file ->
            if (java.nio.file.Files.isSymbolicLink(file.toPath())) {
              return@withContext Err(IllegalStateException("Symlink rejected for credential file"))
            }
            val stored = decryptCredential(file)
            if (stored != null) {
              return@withContext Ok(
                SensitivePasskeyCredential.fromStoredCredential(stored, file.lastModified())
              )
            }
          }

        Err(IllegalArgumentException("Credential not found"))
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Failed to load credential for signing: ${e.message}" }
        Err(e)
      }
    }

  override suspend fun saveCredential(credential: PasskeyCredential): Result<Unit, Throwable> =
    withContext(Dispatchers.IO) {
      try {
        val dir = passkeyDir
        if (!dir.exists()) {
          if (!dir.mkdirs()) {
            return@withContext Err(IllegalStateException("Failed to create passkey directory"))
          }
        }

        val storedCred = StoredCredential.fromPasskeyCredential(credential)
        val rpDir = File(dir, sanitizeRpId(credential.rpId))
        if (!rpDir.exists()) {
          if (!rpDir.mkdirs()) {
            return@withContext Err(IllegalStateException("Failed to create RP directory"))
          }
        }

        val fileName = storedCred.credentialIdHex() + config.fileExtension
        val file = File(rpDir, fileName)

        val plaintext = storedCred.toCbor()

        try {
          atomicWriter
            .replace(file) { outputStream ->
              val plaintextStream = ByteArrayInputStream(plaintext)
              cryptoHandler
                .encrypt(
                  keys = encryptionKeys(),
                  passphrase = null,
                  plaintextStream = plaintextStream,
                  outputStream = outputStream,
                  options = encryptionOptions,
                )
                .fold(
                  success = {},
                  failure = { throw it },
                )
            }
            .fold(
              success = {
                logcat { "Saved passkey for ${credential.rpId}/${storedCred.credentialIdHex()}" }
                Ok(Unit)
              },
              failure = { error ->
                logcat(LogPriority.ERROR) { "Atomic write failed: ${error.message}" }
                Err(storageErrorToException(error))
              },
            )
        } finally {
          plaintext.fill(0)
        }
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Failed to save credential: ${e.message}" }
        Err(e)
      }
    }

  override suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable> =
    withContext(Dispatchers.IO) {
      try {
        val hexId = credentialId.joinToString("") { byte -> "%02x".format(byte) }

        passkeyDir
          .walkTopDown()
          .filter { it.isFile && it.nameWithoutExtension == hexId }
          .forEach { file ->
            return@withContext atomicWriter
              .deleteAtomic(file)
              .fold(
                success = { deleted ->
                  if (deleted) {
                    logcat { "Deleted passkey ${hexId}" }
                    cleanupEmptyDirectories(file.parentFile)
                  }
                  Ok(deleted)
                },
                failure = { error ->
                  logcat(LogPriority.ERROR) { "Atomic delete failed: ${error.message}" }
                  Err(storageErrorToException(error))
                },
              )
          }

        Ok(false)
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Failed to delete credential: ${e.message}" }
        Err(e)
      }
    }

  override suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable> =
    withContext(Dispatchers.IO) {
      try {
        val hexId = credentialId.joinToString("") { byte -> "%02x".format(byte) }

        passkeyDir
          .walkTopDown()
          .filter { it.isFile && it.nameWithoutExtension == hexId }
          .forEach { file ->
            val credential = decryptCredential(file)
            if (credential != null) {
              val updated = credential.copy(signCount = newSignCount.toUInt())
              val plaintext = updated.toCbor()

              try {
                return@withContext atomicWriter
                  .replace(file) { outputStream ->
                    val plaintextStream = ByteArrayInputStream(plaintext)
                    cryptoHandler
                      .encrypt(
                        keys = encryptionKeys(),
                        passphrase = null,
                        plaintextStream = plaintextStream,
                        outputStream = outputStream,
                        options = encryptionOptions,
                      )
                      .fold(
                        success = {},
                        failure = { throw it },
                      )
                  }
                  .fold(
                    success = {
                      logcat { "Updated sign count for ${hexId}" }
                      Ok(Unit)
                    },
                    failure = { error ->
                      logcat(LogPriority.ERROR) {
                        "Atomic write for counter update failed: ${error.message}"
                      }
                      Err(storageErrorToException(error))
                    },
                  )
              } finally {
                plaintext.fill(0)
              }
            }
          }

        Err(IllegalArgumentException("Credential not found"))
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Failed to update sign count: ${e.message}" }
        Err(e)
      }
    }

  override suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): Result<CredentialSourceVersion?, Throwable> =
    withContext(Dispatchers.IO) {
      try {
        val hexId = credentialId.joinToString("") { byte -> "%02x".format(byte) }
        val dir = passkeyDir
        if (!dir.exists() || !dir.isDirectory) {
          return@withContext Ok(null)
        }

        var found: CredentialSourceVersion? = null
        dir
          .walkTopDown()
          .filter { file ->
            file.isFile &&
              file.nameWithoutExtension == hexId &&
              !atomicWriter.isInternalArtifact(file.name)
          }
          .forEach { file ->
            if (found != null) return@forEach
            if (java.nio.file.Files.isSymbolicLink(file.toPath())) return@forEach
            val canonicalPath = file.canonicalPath
            val fileSize = file.length()
            val modifiedAtMillis = file.lastModified()
            val digest = MessageDigest.getInstance("SHA-256").digest(file.readBytes())
            found =
              CredentialSourceVersion(
                repositoryGeneration =
                  RepositoryGeneration(
                    repositoryIdentity = repositoryRoot.canonicalPath,
                    gitHead = null,
                    worktreeGeneration = modifiedAtMillis,
                  ),
                canonicalPath = canonicalPath,
                fileSize = fileSize,
                modifiedAtMillis = modifiedAtMillis,
                ciphertextDigest = digest,
              )
          }
        Ok(found)
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Failed to resolve source version: ${e.message}" }
        Err(e)
      }
    }

  public suspend fun recoverStaleArtifacts(): List<File> {
    val dir = passkeyDir
    if (!dir.exists() || !dir.isDirectory) return emptyList()
    return atomicWriter.cleanupStaleTempFiles(dir)
  }

  private suspend fun decryptCredential(file: File): StoredCredential? {
    return try {
      passkeyPgpDecryptor
        .decrypt(file, pgpUnlockContext)
        .fold(
          success = { plaintext ->
            try {
              StoredCredential.fromCbor(plaintext)
            } finally {
              plaintext.fill(0)
            }
          },
          failure = { error ->
            logcat(LogPriority.WARN) {
              "Failed to decrypt ${file.name}: ${formatDecryptionError(error)}"
            }
            null
          },
        )
    } catch (e: Exception) {
      logcat(LogPriority.WARN) { "Error decrypting ${file.name}: ${e.message}" }
      null
    }
  }

  private fun formatDecryptionError(error: PasskeyDecryptionError): String {
    return when (error) {
      is PasskeyDecryptionError.NoRecipientPackets -> "No recipient packets found"
      is PasskeyDecryptionError.MissingSecretKey ->
        "No matching secret key for recipients: ${error.recipientIds.joinToString()}"
      is PasskeyDecryptionError.KeyLocked -> "Key ${error.keyId} is locked"
      is PasskeyDecryptionError.IncorrectPassphrase -> "Incorrect passphrase for key ${error.keyId}"
      is PasskeyDecryptionError.IntegrityCheckFailed -> "Integrity check failed"
      is PasskeyDecryptionError.MalformedCiphertext -> "Malformed ciphertext"
      is PasskeyDecryptionError.UnsupportedFormat -> "Unsupported format: ${error.reason}"
    }
  }

  private fun cleanupEmptyDirectories(dir: File?) {
    var current = dir
    while (current != null && current != passkeyDir) {
      if (current.isDirectory && current.listFiles()?.isEmpty() == true) {
        current.delete()
        current = current.parentFile
      } else {
        break
      }
    }
  }

  private fun sanitizeRpId(rpId: String): String {
    return rpId.replace("/", "_").replace("\\", "_").replace("..", "_")
  }

  private fun unsanitizeRpId(sanitized: String): String {
    return sanitized
  }

  private fun hexToBytes(hex: String): ByteArray? {
    if (hex.length % 2 != 0) return null
    return try {
      ByteArray(hex.length / 2) { i ->
        hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
      }
    } catch (e: NumberFormatException) {
      null
    }
  }

  private fun storageErrorToException(error: AtomicWriteError): Exception {
    return when (error) {
      is AtomicWriteError.TargetOutsideRepository -> SecurityException(error.message)
      is AtomicWriteError.SymlinkRejected -> SecurityException(error.message)
      is AtomicWriteError.AtomicMoveUnsupported -> UnsupportedOperationException(error.message)
      is AtomicWriteError.ConcurrentModification -> IllegalStateException(error.message)
      is AtomicWriteError.DirectorySyncFailed -> java.io.IOException(error.message)
      is AtomicWriteError.EncryptionFailed -> java.io.IOException(error.message)
      is AtomicWriteError.FileSyncFailed -> java.io.IOException(error.message)
      is AtomicWriteError.IoError -> java.io.IOException(error.message)
      is AtomicWriteError.RenameFailed -> java.io.IOException(error.message)
      is AtomicWriteError.TempCreateFailed -> java.io.IOException(error.message)
      is AtomicWriteError.VerificationFailed -> java.io.IOException(error.message)
    }
  }
}
