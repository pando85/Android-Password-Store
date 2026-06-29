/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.Result

/**
 * Interface for cryptographic operations required by the WebAuthn/FIDO2 passkey implementation.
 *
 * Implementations must support ES256 (P-256 with SHA-256) for signature operations.
 */
public interface PasskeyCryptoHandler {

  /**
   * Generates a new P-256 ECDSA key pair.
   *
   * @return A pair of (privateKey, publicKey) where:
   *     - privateKey is a PKCS#8 encoded private key
   *     - publicKey is a raw 65-byte uncompressed EC point (0x04 || x || y)
   */
  public fun generateKeyPair(): Pair<ByteArray, ByteArray>

  /**
   * Signs authenticator data and client data hash using ES256.
   *
   * @param privateKey PKCS#8 encoded private key
   * @param authenticatorData 37-byte authenticator data structure
   * @param clientDataHash 32-byte SHA-256 hash of client data JSON
   * @return DER-encoded ECDSA signature (typically 70-72 bytes) or an error
   */
  public fun sign(
    privateKey: ByteArray,
    authenticatorData: ByteArray,
    clientDataHash: ByteArray,
  ): Result<ByteArray, Throwable>

  /**
   * Verifies an ES256 signature.
   *
   * @param publicKey Raw 65-byte uncompressed P-256 public key
   * @param signature DER-encoded ECDSA signature (typically 70-72 bytes)
   * @param authenticatorData 37-byte authenticator data structure
   * @param clientDataHash 32-byte SHA-256 hash of client data JSON
   * @return True if signature is valid, false otherwise, or an error
   */
  public fun verify(
    publicKey: ByteArray,
    signature: ByteArray,
    authenticatorData: ByteArray,
    clientDataHash: ByteArray,
  ): Result<Boolean, Throwable>

  /**
   * Creates a new passkey credential.
   *
   * @param rpId Relying Party identifier (e.g., "example.com")
   * @param userId User identifier from the relying party
   * @param userName Username for display purposes
   * @param userDisplayName Display name for the user
   * @param challenge Challenge from the WebAuthn ceremony
   * @return A new PasskeyCredential or an error
   */
  public fun createCredential(
    rpId: String,
    userId: ByteArray,
    userName: String,
    userDisplayName: String,
    challenge: ByteArray,
  ): Result<PasskeyCredential, Throwable>

  /**
   * Generates a WebAuthn assertion for authentication.
   *
   * @param credential The stored passkey credential
   * @param rpId Relying Party identifier
   * @param challenge Challenge from the WebAuthn ceremony
   * @param origin Origin of the WebAuthn request (e.g., "https://example.com")
   * @return An AssertionResult containing the signature or an error
   */
  public fun getAssertion(
    credential: PasskeyCredential,
    rpId: String,
    challenge: ByteArray,
    origin: String,
  ): Result<AssertionResult, Throwable>
}

/**
 * Result of a WebAuthn assertion (authentication) operation.
 *
 * @property credentialId The credential identifier
 * @property authenticatorData 37-byte authenticator data structure
 * @property signature DER-encoded ECDSA signature (typically 70-72 bytes)
 * @property userHandle Optional user handle returned to the relying party
 * @property clientDataJSON The client data JSON string used for signing
 */
public data class AssertionResult(
  public val credentialId: ByteArray,
  public val authenticatorData: ByteArray,
  public val signature: ByteArray,
  public val userHandle: ByteArray?,
  public val clientDataJSON: String,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is AssertionResult) return false
    if (!credentialId.contentEquals(other.credentialId)) return false
    if (!authenticatorData.contentEquals(other.authenticatorData)) return false
    if (!signature.contentEquals(other.signature)) return false
    if (userHandle != null) {
      if (other.userHandle == null) return false
      if (!userHandle.contentEquals(other.userHandle)) return false
    } else if (other.userHandle != null) return false
    if (clientDataJSON != other.clientDataJSON) return false
    return true
  }

  override fun hashCode(): Int {
    var result = credentialId.contentHashCode()
    result = 31 * result + authenticatorData.contentHashCode()
    result = 31 * result + signature.contentHashCode()
    result = 31 * result + (userHandle?.contentHashCode() ?: 0)
    result = 31 * result + clientDataJSON.hashCode()
    return result
  }
}
