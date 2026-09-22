/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.content.SharedPreferences
import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKey
import app.passwordstore.injection.prefs.SettingsPreferences
import app.passwordstore.util.settings.PreferenceKeys
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/** Coordinates APS-local provider selection with provider-owned OpenPGP key material. */
@Singleton
class OpenPgpProviderRepository
@Inject
constructor(
  private val backend: OpenPgpApiBackend,
  @SettingsPreferences private val settings: SharedPreferences,
) {

  private data class PublicKeyCacheKey(
    val providerPackage: String,
    val identifier: PGPIdentifier,
  )

  private val resolvedPublicKeys = ConcurrentHashMap<PublicKeyCacheKey, List<PGPKey>>()

  fun providers(): List<OpenPgpApiBackend.Provider> = backend.providers()

  fun selectedProviderPackage(): String? =
    settings.getString(PreferenceKeys.OPENPGP_PROVIDER_PACKAGE, null)?.takeIf { it.isNotBlank() }

  fun hasSelectedProvider(): Boolean = selectedProviderPackage() != null

  fun isSelectedProviderInstalled(): Boolean =
    selectedProviderPackage()?.let(backend::isProviderInstalled) == true

  suspend fun checkPermission(
    interactionHandler: OpenPgpApiBackend.InteractionHandler? = null
  ): OpenPgpApiBackend.OperationResult<Unit> {
    val provider =
      selectedProviderPackage()
        ?: return OpenPgpApiBackend.OperationResult.Failure(
          IllegalStateException("No external OpenPGP provider is selected")
        )
    if (!backend.isProviderInstalled(provider)) return providerUnavailable(provider)
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
    if (!backend.isProviderInstalled(provider)) return providerUnavailable(provider)
    return backend.decrypt(provider, ciphertext, interactionHandler)
  }

  /**
   * Resolves [identifiers] against the selected provider and returns fresh public certificates.
   *
   * The provider is authoritative for recipient resolution whenever it is selected. The local APS
   * key manager is deliberately not consulted here: otherwise a previously imported certificate or
   * an older key carrying the same user ID could silently override provider-side rotation or
   * revocation state.
   */
  suspend fun resolvePublicKeys(
    identifiers: List<PGPIdentifier>,
    interactionHandler: OpenPgpApiBackend.InteractionHandler? = null,
  ): OpenPgpApiBackend.OperationResult<List<PGPKey>> {
    return when (val resolved = resolvePublicKeysByIdentifier(identifiers, interactionHandler)) {
      is OpenPgpApiBackend.OperationResult.Success ->
        OpenPgpApiBackend.OperationResult.Success(deduplicate(resolved.value.values.flatten()))
      is OpenPgpApiBackend.OperationResult.UserInteractionRequired -> resolved
      OpenPgpApiBackend.OperationResult.Cancelled -> resolved
      is OpenPgpApiBackend.OperationResult.Failure -> resolved
    }
  }

  /**
   * Resolves fresh provider certificates and makes that exact resolution available to the immediate
   * APS password-encryption path.
   *
   * This cache is only a hand-off between recipient validation and encryption; it is never used to
   * avoid a provider lookup. Every call refreshes the provider state first.
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
    if (!backend.isProviderInstalled(provider)) return providerUnavailable(provider)

    return when (val resolved = resolvePublicKeysByIdentifier(identifiers, interactionHandler)) {
      is OpenPgpApiBackend.OperationResult.Success -> {
        for ((identifier, keys) in resolved.value) {
          resolvedPublicKeys[PublicKeyCacheKey(provider, identifier)] = keys
        }
        OpenPgpApiBackend.OperationResult.Success(Unit)
      }
      is OpenPgpApiBackend.OperationResult.UserInteractionRequired -> resolved
      OpenPgpApiBackend.OperationResult.Cancelled -> resolved
      is OpenPgpApiBackend.OperationResult.Failure -> resolved
    }
  }

  /** Returns only a complete provider resolution previously produced by [ensurePublicKeys]. */
  fun resolvedPublicKeysFor(identifiers: List<PGPIdentifier>): List<PGPKey>? {
    val provider = selectedProviderPackage() ?: return null
    val keys = mutableListOf<PGPKey>()
    for (identifier in identifiers) {
      val resolved = resolvedPublicKeys[PublicKeyCacheKey(provider, identifier)] ?: return null
      keys += resolved
    }
    return deduplicate(keys)
  }

  private suspend fun resolvePublicKeysByIdentifier(
    identifiers: List<PGPIdentifier>,
    interactionHandler: OpenPgpApiBackend.InteractionHandler?,
  ): OpenPgpApiBackend.OperationResult<Map<PGPIdentifier, List<PGPKey>>> {
    val provider =
      selectedProviderPackage()
        ?: return OpenPgpApiBackend.OperationResult.Failure(
          IllegalStateException("No external OpenPGP provider is selected")
        )
    if (!backend.isProviderInstalled(provider)) return providerUnavailable(provider)

    val result = linkedMapOf<PGPIdentifier, List<PGPKey>>()
    for (identifier in identifiers.distinct()) {
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
              is OpenPgpApiBackend.OperationResult.Success -> resolved.value.distinct().toLongArray()
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
      if (identifier is PGPIdentifier.UserId && keyIds.size > 1) {
        return OpenPgpApiBackend.OperationResult.Failure(
          OpenPgpAmbiguousRecipientException(identifier.email, keyIds.toList())
        )
      }

      val keys = mutableListOf<PGPKey>()
      for (keyId in keyIds) {
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
            if (!KeyUtils.isKeyUsable(certificate)) {
              return OpenPgpApiBackend.OperationResult.Failure(
                IllegalArgumentException("Provider returned an unusable OpenPGP certificate")
              )
            }
            if (
              identifier is PGPIdentifier.UserId &&
                certificate.getAllUserIds().none {
                  identifier.email == it.getUserId() ||
                    identifier.email == PGPIdentifier.splitUserId(it.getUserId())
                }
            ) {
              return OpenPgpApiBackend.OperationResult.Failure(
                SecurityException("Provider certificate does not match requested user ID")
              )
            }
            keys += PGPKey(certificate.getEncoded())
          }
          is OpenPgpApiBackend.OperationResult.UserInteractionRequired -> return fetched
          OpenPgpApiBackend.OperationResult.Cancelled -> return fetched
          is OpenPgpApiBackend.OperationResult.Failure -> return fetched
        }
      }
      result[identifier] = keys
    }

    return OpenPgpApiBackend.OperationResult.Success(result)
  }

  private fun deduplicate(keys: List<PGPKey>): List<PGPKey> {
    val seenPrimaryKeyIds = mutableSetOf<Long>()
    return keys.filter { key ->
      val certificate = KeyUtils.tryParseCertificateOrKey(key) ?: return@filter false
      seenPrimaryKeyIds.add(KeyUtils.tryGetKeyId(certificate).id)
    }
  }

  private fun <T> providerUnavailable(
    provider: String
  ): OpenPgpApiBackend.OperationResult<T> =
    OpenPgpApiBackend.OperationResult.Failure(
      OpenPgpProviderException("Selected OpenPGP provider $provider is not installed")
    )
}

class OpenPgpAmbiguousRecipientException(
  val identifier: String,
  val keyIds: List<Long>,
) : Exception("OpenPGP provider resolved $identifier to multiple keys")
