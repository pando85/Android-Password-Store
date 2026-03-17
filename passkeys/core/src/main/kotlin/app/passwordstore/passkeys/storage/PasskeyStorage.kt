/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.Result

/**
 * Interface for storing and retrieving passkey credentials.
 *
 * Implementations should handle encryption of sensitive data (private keys) and provide thread-safe
 * access to stored credentials.
 */
public interface PasskeyStorage {

  /**
   * Lists all stored credentials, optionally filtered by Relying Party ID.
   *
   * @param rpId Optional RP ID to filter credentials. If null, returns all credentials.
   * @return A list of credentials or an error
   */
  public suspend fun listCredentials(
    rpId: String? = null
  ): Result<List<PasskeyCredential>, Throwable>

  /**
   * Retrieves a specific credential by its ID.
   *
   * @param credentialId The unique identifier for the credential
   * @return The credential if found, null if not found, or an error
   */
  public suspend fun getCredential(credentialId: ByteArray): Result<PasskeyCredential?, Throwable>

  /**
   * Stores a new credential or updates an existing one.
   *
   * @param credential The credential to store
   * @return Success or an error
   */
  public suspend fun saveCredential(credential: PasskeyCredential): Result<Unit, Throwable>

  /**
   * Deletes a credential by its ID.
   *
   * @param credentialId The unique identifier for the credential
   * @return True if the credential was deleted, false if it didn't exist, or an error
   */
  public suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable>

  /**
   * Updates the sign count for a credential.
   *
   * The sign count should be incremented after each successful authentication to help detect cloned
   * authenticators.
   *
   * @param credentialId The unique identifier for the credential
   * @param newSignCount The new sign count value
   * @return Success or an error
   */
  public suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable>
}

/**
 * Configuration for passkey storage.
 *
 * @property passkeyDirectory Directory name within the repository root for storing credentials
 * @property fileExtension File extension for credential files (e.g., ".gpg")
 */
public data class PasskeyStorageConfig(
  public val passkeyDirectory: String = "fido2",
  public val fileExtension: String = ".gpg",
)
