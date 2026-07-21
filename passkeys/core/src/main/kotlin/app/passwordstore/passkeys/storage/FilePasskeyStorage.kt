/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

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
import java.io.ByteArrayOutputStream
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Instant
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
          .filter { it.isFile && it.extension == config.fileExtension.removePrefix(".") }
          .forEach { file ->
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
        val plaintextStream = ByteArrayInputStream(plaintext)
        val outputStream = ByteArrayOutputStream()

        cryptoHandler
          .encrypt(
            keys = encryptionKeys(),
            passphrase = null,
            plaintextStream = plaintextStream,
            outputStream = outputStream,
            options = encryptionOptions,
          )
          .fold(
            success = {
              file.writeBytes(outputStream.toByteArray())
              plaintext.fill(0)
              logcat { "Saved passkey for ${credential.rpId}/${storedCred.credentialIdHex()}" }
              Ok(Unit)
            },
            failure = {
              plaintext.fill(0)
              Err(it)
            },
          )
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
            val deleted = file.delete()
            if (deleted) {
              logcat { "Deleted passkey ${hexId}" }
              cleanupEmptyDirectories(file.parentFile)
            }
            return@withContext Ok(deleted)
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
              val plaintextStream = ByteArrayInputStream(plaintext)
              val outputStream = ByteArrayOutputStream()

              cryptoHandler
                .encrypt(
                  keys = encryptionKeys(),
                  passphrase = null,
                  plaintextStream = plaintextStream,
                  outputStream = outputStream,
                  options = encryptionOptions,
                )
                .fold(
                  success = {
                    file.writeBytes(outputStream.toByteArray())
                    plaintext.fill(0)
                    logcat { "Updated sign count for ${hexId}" }
                  },
                  failure = {
                    plaintext.fill(0)
                    return@withContext Err(it)
                  },
                )
              return@withContext Ok(Unit)
            }
          }

        Err(IllegalArgumentException("Credential not found"))
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Failed to update sign count: ${e.message}" }
        Err(e)
      }
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
      is PasskeyDecryptionError.IncorrectPassphrase ->
        "Incorrect passphrase for key ${error.keyId}"
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
}
