/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.content.SharedPreferences
import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.injection.prefs.SettingsPreferences
import app.passwordstore.util.settings.PreferenceKeys
import javax.inject.Inject
import javax.inject.Singleton

/** Coordinates APS-local provider selection with local public-certificate storage. */
@Singleton
class OpenPgpProviderRepository @Inject constructor(
  private val backend: OpenPgpApiBackend,
  private val keyManager: PGPKeyManager,
  @SettingsPreferences private val settings: SharedPreferences,
) {

  fun providers(): List<OpenPgpApiBackend.Provider> = backend.providers()

  fun selectedProviderPackage(): String? =
    settings.getString(PreferenceKeys.OPENPGP_PROVIDER_PACKAGE, null)?.takeIf { it.isNotBlank() }

  fun hasSelectedProvider(): Boolean = selectedProviderPackage() != null

  fun isSelectedProviderInstalled(): Boolean =
    selectedProviderPackage()?.let(backend::isProviderInstalled) == true

  suspend fun checkPermission(
    interactionHandler: OpenPgpApiBackend.InteractionHandler? = null,
  ): OpenPgpApiBackend.OperationResult<Unit> {
    val provider =
      selectedProviderPackage()
        ?: return OpenPgpApiBackend.OperationResult.Failure(
          IllegalStateException("No external OpenPGP provider is selected")
        )
    return backend.checkPermission(provider, interactionHandler)
  }

  suspend fun decrypt(
    ciphertext: ByteArray,
    interactionHandler: OpenPgpApiBackend.InteractionHandler? = null,
  ): OpenPgpApiBackend.OperationResult<ByteArray> {
    val provider =
      selectedProviderPackage()
        ?: return OpenPgpApiBackend.OperationResult.Failure(
          IllegalStateException("No external OpenPGP provider is selected")
        )
    return backend.decrypt(provider, ciphertext, interactionHandler)
  }

  /**
   * Makes the public certificates required by [identifiers] available to PGPainless.
   *
   * The provider remains the sole owner of private key material. Retrieved certificates are
   * checked against the provider-returned key ID before they are accepted by the local key manager.
   */
  suspend fun ensurePublicKeys(
    identifiers: List<PGPIdentifier>,
    interactionHandler: OpenPgpApiBackend.InteractionHandler? = null,
  ): OpenPgpApiBackend.OperationResult<Unit> {
    val provider =
      selectedProviderPackage()
        ?: return OpenPgpApiBackend.OperationResult.Failure(
          IllegalStateException("No external OpenPGP provider is selected")
        )

    for (identifier in identifiers) {
      if (hasLocalKey(identifier)) continue

      val keyIds =
        when (identifier) {
          is PGPIdentifier.KeyId -> longArrayOf(identifier.id)
          is PGPIdentifier.UserId -> {
            when (
              val resolved =
                backend.resolveKeyIds(
                  providerPackage = provider,
                  userIds = arrayOf(identifier.email),
                  interactionHandler = interactionHandler,
                )
            ) {
              is OpenPgpApiBackend.OperationResult.Success -> resolved.value
              is OpenPgpApiBackend.OperationResult.UserInteractionRequired -> return resolved
              OpenPgpApiBackend.OperationResult.Cancelled -> return resolved
              is OpenPgpApiBackend.OperationResult.Failure -> return resolved
            }
          }
        }

      if (keyIds.isEmpty()) {
        return OpenPgpApiBackend.OperationResult.Failure(
          IllegalStateException("OpenPGP provider could not resolve $identifier")
        )
      }

      for (keyId in keyIds.distinct()) {
        when (
          val fetched =
            backend.getPublicKey(
              providerPackage = provider,
              keyId = keyId,
              interactionHandler = interactionHandler,
            )
        ) {
          is OpenPgpApiBackend.OperationResult.Success -> {
            val candidate = PGPKey(fetched.value)
            val certificate =
              KeyUtils.tryParseCertificateOrKey(candidate)
                ?: return OpenPgpApiBackend.OperationResult.Failure(
                  IllegalArgumentException("Provider returned an invalid OpenPGP certificate")
                )
            if (KeyUtils.isSecretKey(certificate)) {
              return OpenPgpApiBackend.OperationResult.Failure(
                SecurityException("OpenPGP provider unexpectedly returned secret key material")
              )
            }
            if (certificate.getAllKeyIdentifiers().none { it.getKeyId() == keyId }) {
              return OpenPgpApiBackend.OperationResult.Failure(
                SecurityException("Provider certificate does not match requested key ID")
              )
            }

            var importFailure: Throwable? = null
            keyManager.addKey(candidate, replace = false).fold(
              success = {},
              failure = { error ->
                // A concurrent import or an existing public certificate is harmless if the
                // requested identity can now be resolved locally.
                if (!hasLocalKey(identifier)) importFailure = error
              },
            )
            if (importFailure != null) {
              return OpenPgpApiBackend.OperationResult.Failure(importFailure!!)
            }
          }
          is OpenPgpApiBackend.OperationResult.UserInteractionRequired -> return fetched
          OpenPgpApiBackend.OperationResult.Cancelled -> return fetched
          is OpenPgpApiBackend.OperationResult.Failure -> return fetched
        }
      }

      if (!hasLocalKey(identifier)) {
        return OpenPgpApiBackend.OperationResult.Failure(
          IllegalStateException("Retrieved certificates do not satisfy $identifier")
        )
      }
    }

    return OpenPgpApiBackend.OperationResult.Success(Unit)
  }

  private fun hasLocalKey(identifier: PGPIdentifier): Boolean =
    keyManager.getKeyById(identifier).fold(success = { true }, failure = { false })
}
