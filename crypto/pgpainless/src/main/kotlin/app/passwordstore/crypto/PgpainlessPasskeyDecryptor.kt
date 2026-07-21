/*
 * Copyright (C) 2014-2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.passkeys.crypto.PasskeyDecryptionError
import app.passwordstore.passkeys.crypto.PasskeyPgpDecryptor
import app.passwordstore.passkeys.crypto.PgpUnlockContext
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import com.github.michaelbull.result.getOrNull
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.logcat
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.PGPainless
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.decryption_verification.MessageMetadata
import org.pgpainless.exception.WrongPassphraseException

public class PgpainlessPasskeyDecryptor(
  private val cryptoHandler: PGPainlessCryptoHandler,
  private val keyManager: PGPKeyManager,
) : PasskeyPgpDecryptor {

  private val pgpApi = PGPainless.getInstance()

  override suspend fun decrypt(
    file: File,
    unlockContext: PgpUnlockContext,
  ): Result<ByteArray, PasskeyDecryptionError> =
    withContext(Dispatchers.IO) {
      try {
        val ciphertext = file.readBytes()

        val recipientKeyIds = extractRecipientKeyIds(ciphertext)
        if (recipientKeyIds.isEmpty()) {
          return@withContext Err(PasskeyDecryptionError.NoRecipientPackets)
        }

        val allKeys = keyManager.getAllKeys().getOrNull() ?: emptyList()
        val matchingKeys = findMatchingSecretKeys(allKeys, recipientKeyIds)

        if (matchingKeys.isEmpty()) {
          return@withContext Err(
            PasskeyDecryptionError.MissingSecretKey(recipientKeyIds.map { it.toString() }.toSet())
          )
        }

        var lastError: PasskeyDecryptionError? = null

        for ((key, keyId) in matchingKeys) {
          val passphrase = unlockContext.unlockKey(keyId.toString())

          try {
            val plaintext = attemptDecryption(key, passphrase, ciphertext)
            passphrase?.fill(0)
            return@withContext Ok(plaintext)
          } catch (e: WrongPassphraseException) {
            passphrase?.fill(0)
            lastError = PasskeyDecryptionError.IncorrectPassphrase(keyId.toString())
            logcat(LogPriority.DEBUG) {
              "Wrong passphrase for key ${keyId}, trying next matching key"
            }
            continue
          } catch (e: IncorrectPassphraseException) {
            passphrase?.fill(0)
            lastError = PasskeyDecryptionError.IncorrectPassphrase(keyId.toString())
            logcat(LogPriority.DEBUG) {
              "Incorrect passphrase for key ${keyId}, trying next matching key"
            }
            continue
          } catch (e: Exception) {
            passphrase?.fill(0)
            lastError = mapExceptionToError(e)
            logcat(LogPriority.DEBUG) {
              "Decryption failed with key ${keyId}: ${e.message}, trying next"
            }
            continue
          }
        }

        Err(lastError ?: PasskeyDecryptionError.MalformedCiphertext)
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Unexpected error decrypting ${file.name}: ${e.message}" }
        Err(mapExceptionToError(e))
      }
    }

  private fun extractRecipientKeyIds(ciphertext: ByteArray): Set<Long> {
    return try {
      val metadata = inspectMessageMetadata(ciphertext)
      metadata.recipientKeyIds.toSet()
    } catch (e: Exception) {
      logcat(LogPriority.WARN) { "Failed to extract recipient key IDs: ${e.message}" }
      emptySet()
    }
  }

  private fun inspectMessageMetadata(ciphertext: ByteArray): MessageMetadata {
    val inputStream = ByteArrayInputStream(ciphertext)
    val consumerOptions = ConsumerOptions.get(pgpApi)
    val decryptionStream =
      pgpApi.processMessage().onInputStream(inputStream).withOptions(consumerOptions)

    decryptionStream.use { stream ->
      try {
        val buffer = ByteArray(8192)
        while (stream.read(buffer) != -1) {
          // Read through to populate metadata
        }
      } catch (e: Exception) {
        // Expected to fail without keys, but metadata should be populated
      }
      return stream.result
    }
  }

  private fun findMatchingSecretKeys(
    allKeys: List<PGPKey>,
    recipientKeyIds: Set<Long>,
  ): List<Pair<PGPKey, Long>> {
    val matchingKeys = mutableListOf<Pair<PGPKey, Long>>()

    for (key in allKeys) {
      val certOrKey = KeyUtils.tryParseCertificateOrKey(key) ?: continue
      if (certOrKey !is OpenPGPKey) continue
      if (!KeyUtils.isSecretKey(certOrKey)) continue
      if (!KeyUtils.hasDecKey(certOrKey)) continue

      val secretKeyIds = certOrKey.getSecretKeys().keys.map { it.getKeyId() }.toSet()

      for (recipientId in recipientKeyIds) {
        if (secretKeyIds.contains(recipientId)) {
          matchingKeys.add(key to recipientId)
          break
        }
      }
    }

    return matchingKeys
  }

  private fun attemptDecryption(
    key: PGPKey,
    passphrase: CharArray?,
    ciphertext: ByteArray,
  ): ByteArray {
    val inputStream = ByteArrayInputStream(ciphertext)
    val outputStream = ByteArrayOutputStream()

    cryptoHandler
      .decrypt(
        key = key,
        passphrase = passphrase,
        ciphertextStream = inputStream,
        outputStream = outputStream,
        options = PGPDecryptOptions.Builder().build(),
      )
      .fold(
        success = {
          return outputStream.toByteArray()
        },
        failure = { throw it },
      )

    throw IllegalStateException("Decryption failed without exception")
  }

  private fun mapExceptionToError(e: Exception): PasskeyDecryptionError {
    return when (e) {
      is WrongPassphraseException,
      is IncorrectPassphraseException -> PasskeyDecryptionError.IncorrectPassphrase("unknown")
      is org.pgpainless.exception.MessageNotIntegrityProtectedException ->
        PasskeyDecryptionError.IntegrityCheckFailed
      is org.bouncycastle.openpgp.PGPException -> {
        if (e.message?.contains("modification detection code") == true) {
          PasskeyDecryptionError.IntegrityCheckFailed
        } else {
          PasskeyDecryptionError.MalformedCiphertext
        }
      }
      else -> PasskeyDecryptionError.MalformedCiphertext
    }
  }
}
