/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey.provider

import android.os.Build
import androidx.annotation.RequiresApi
import androidx.fragment.app.FragmentActivity
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.passkey.CreateCredentialOutput
import app.passwordstore.passkey.GetAssertionOutput
import app.passwordstore.passkey.PasskeyCredential
import app.passwordstore.passkey.PasskeyManager
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.mapError
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * High-level operations for passkey creation and authentication.
 *
 * This class bridges between the Android Credential Provider API and
 * the underlying passkey storage and cryptographic operations.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@Singleton
public class PasskeyOperations
@Inject
constructor(
  private val passkeyManager: PasskeyManager,
) {

  /**
   * Create a new passkey credential.
   *
   * @param activity The activity for showing biometric prompt
   * @param baseDir The password store base directory
   * @param rpId Relying party ID (e.g., "example.com")
   * @param rpName Relying party display name
   * @param userId User ID (opaque bytes from the RP)
   * @param userName User name (e.g., email)
   * @param userDisplayName User display name
   * @param challenge The challenge from the relying party
   * @param algorithms List of acceptable COSE algorithm IDs in preference order
   * @param pgpKeyIds PGP key identifiers for encryption
   * @param excludeCredentials Credentials to exclude
   * @return Result containing the attestation object and credential ID
   */
  public suspend fun createCredential(
    activity: FragmentActivity,
    baseDir: File,
    rpId: String,
    rpName: String,
    userId: ByteArray,
    userName: String,
    userDisplayName: String,
    challenge: ByteArray,
    algorithms: List<Int>,
    pgpKeyIds: List<PGPIdentifier>,
    excludeCredentials: List<ByteArray> = emptyList(),
  ): Result<CreateCredentialOutput, Throwable> {
    return passkeyManager.createCredential(
      activity = activity,
      baseDir = baseDir,
      rpId = rpId,
      rpName = rpName,
      userId = userId,
      userName = userName,
      userDisplayName = userDisplayName,
      challenge = challenge,
      algorithms = algorithms,
      pgpKeyIds = pgpKeyIds,
      excludeCredentials = excludeCredentials,
      requireResidentKey = true,
    ).mapError { it }
  }

  /**
   * Get an assertion for authentication.
   *
   * @param activity The activity for showing biometric prompt
   * @param baseDir The password store base directory
   * @param rpId Relying party ID
   * @param challenge The challenge from the relying party
   * @param pgpKeyId PGP key identifier for decryption
   * @param passphrase Passphrase for PGP key
   * @param pgpKeyIdsForReencrypt PGP key identifiers for re-encryption after sign count update
   * @param allowCredentials Optional list of allowed credential IDs
   * @return Result containing the authenticator data and signature
   */
  public suspend fun getAssertion(
    activity: FragmentActivity,
    baseDir: File,
    rpId: String,
    challenge: ByteArray,
    pgpKeyId: PGPIdentifier,
    passphrase: CharArray,
    pgpKeyIdsForReencrypt: List<PGPIdentifier>,
    allowCredentials: List<ByteArray> = emptyList(),
  ): Result<GetAssertionOutput, Throwable> {
    return passkeyManager.getAssertion(
      activity = activity,
      baseDir = baseDir,
      rpId = rpId,
      challenge = challenge,
      pgpKeyId = pgpKeyId,
      passphrase = passphrase,
      pgpKeyIdsForReencrypt = pgpKeyIdsForReencrypt,
      allowCredentials = allowCredentials,
    ).mapError { it }
  }

  /**
   * List all credentials for a relying party.
   */
  public suspend fun listCredentialsForRp(
    baseDir: File,
    rpId: String,
    pgpKeyId: PGPIdentifier,
    passphrase: CharArray,
  ): List<PasskeyCredential> {
    return passkeyManager.listCredentialsForRp(baseDir, rpId, pgpKeyId, passphrase)
  }

  /**
   * List all stored credentials.
   */
  public suspend fun listAllCredentials(
    baseDir: File,
    pgpKeyId: PGPIdentifier,
    passphrase: CharArray,
  ): List<PasskeyCredential> {
    return passkeyManager.listCredentials(baseDir, pgpKeyId, passphrase)
  }

  /**
   * Delete a credential.
   */
  public suspend fun deleteCredential(
    baseDir: File,
    credentialId: ByteArray,
  ): Result<Unit, Throwable> {
    return passkeyManager.deleteCredential(baseDir, credentialId).mapError { it }
  }
}
