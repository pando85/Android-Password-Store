/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.SharedPreferences
import app.passwordstore.data.crypto.OpenPgpApiBackend
import app.passwordstore.data.crypto.OpenPgpInteractionCoordinator
import app.passwordstore.data.crypto.OpenPgpOutputLimitExceededException
import app.passwordstore.data.crypto.OpenPgpProviderRepository
import app.passwordstore.injection.prefs.SettingsPreferences
import app.passwordstore.passkeys.crypto.PasskeyDecryptionError
import app.passwordstore.passkeys.crypto.PasskeyPgpDecryptor
import app.passwordstore.passkeys.crypto.PgpUnlockContext
import app.passwordstore.passkeys.security.BoundedInputStream
import app.passwordstore.passkeys.security.PasskeyInputLimits
import app.passwordstore.passkeys.security.SensitiveBytes
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import java.io.File
import java.io.InputStream
import javax.inject.Inject

/** Selects PGPainless or the configured OpenPGP provider for passkey decryption. */
class OpenPgpPasskeyDecryptor
@Inject
constructor(
  private val localDecryptor: PasskeyPgpDecryptor,
  private val providerRepository: OpenPgpProviderRepository,
  private val interactionCoordinator: OpenPgpInteractionCoordinator,
  @SettingsPreferences private val settings: SharedPreferences,
) : PasskeyPgpDecryptor {

  override suspend fun decrypt(
    file: File,
    unlockContext: PgpUnlockContext,
    limits: PasskeyInputLimits,
  ): Result<SensitiveBytes, PasskeyDecryptionError> {
    if (!usesExternalProvider()) return localDecryptor.decrypt(file, unlockContext, limits)

    val length = file.length()
    if (length == 0L) return Err(PasskeyDecryptionError.MalformedCiphertext)
    if (length > limits.maxCiphertextBytes) {
      return Err(PasskeyDecryptionError.CiphertextTooLarge(length, limits.maxCiphertextBytes))
    }

    val ciphertext =
      file.inputStream().use { stream ->
        BoundedInputStream(stream, limits.maxCiphertextBytes).readBoundedBytes(length.toInt())
      }
    return try {
      decryptExternal(ciphertext, limits)
    } finally {
      ciphertext.fill(0)
    }
  }

  override suspend fun decryptFromBytes(
    ciphertext: ByteArray,
    unlockContext: PgpUnlockContext,
    limits: PasskeyInputLimits,
  ): Result<SensitiveBytes, PasskeyDecryptionError> {
    if (!usesExternalProvider()) {
      return localDecryptor.decryptFromBytes(ciphertext, unlockContext, limits)
    }
    if (ciphertext.isEmpty()) return Err(PasskeyDecryptionError.MalformedCiphertext)
    if (ciphertext.size.toLong() > limits.maxCiphertextBytes) {
      return Err(
        PasskeyDecryptionError.CiphertextTooLarge(
          ciphertext.size.toLong(),
          limits.maxCiphertextBytes,
        )
      )
    }
    return decryptExternal(ciphertext, limits)
  }

  override suspend fun decryptFromStream(
    ciphertextStream: InputStream,
    ciphertextLength: Long,
    unlockContext: PgpUnlockContext,
    limits: PasskeyInputLimits,
  ): Result<SensitiveBytes, PasskeyDecryptionError> {
    if (!usesExternalProvider()) {
      return localDecryptor.decryptFromStream(
        ciphertextStream,
        ciphertextLength,
        unlockContext,
        limits,
      )
    }
    if (ciphertextLength == 0L) return Err(PasskeyDecryptionError.MalformedCiphertext)
    if (ciphertextLength > limits.maxCiphertextBytes) {
      return Err(
        PasskeyDecryptionError.CiphertextTooLarge(ciphertextLength, limits.maxCiphertextBytes)
      )
    }

    val ciphertext =
      BoundedInputStream(ciphertextStream, limits.maxCiphertextBytes)
        .readBoundedBytes(ciphertextLength.toInt())
    return try {
      decryptExternal(ciphertext, limits)
    } finally {
      ciphertext.fill(0)
    }
  }

  private suspend fun decryptExternal(
    ciphertext: ByteArray,
    limits: PasskeyInputLimits,
  ): Result<SensitiveBytes, PasskeyDecryptionError> {
    val provider =
      settings.getString(PreferenceKeys.OPENPGP_PROVIDER_PACKAGE, null)
        ?: return Err(PasskeyDecryptionError.MissingSecretKey(emptySet()))

    return when (
      val result =
        providerRepository.decrypt(
          ciphertext,
          OpenPgpApiBackend.InteractionHandler { pendingIntent ->
            interactionCoordinator.interact(pendingIntent)
          },
          maxOutputBytes = limits.maxPlaintextBytes,
        )
    ) {
      is OpenPgpApiBackend.OperationResult.Success -> Ok(SensitiveBytes(result.value))
      is OpenPgpApiBackend.OperationResult.UserInteractionRequired ->
        Err(PasskeyDecryptionError.KeyLocked(provider))
      OpenPgpApiBackend.OperationResult.Cancelled -> Err(PasskeyDecryptionError.KeyLocked(provider))
      is OpenPgpApiBackend.OperationResult.Failure ->
        if (result.error is OpenPgpOutputLimitExceededException) {
          Err(PasskeyDecryptionError.PlaintextTooLarge(limits.maxPlaintextBytes))
        } else {
          Err(
            PasskeyDecryptionError.UnsupportedFormat(
              result.error.message ?: "External OpenPGP provider decryption failed"
            )
          )
        }
    }
  }

  private fun usesExternalProvider(): Boolean =
    !settings.getString(PreferenceKeys.OPENPGP_PROVIDER_PACKAGE, null).isNullOrBlank()
}
