/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey

/**
 * Passkey credential data structure compatible with Passless.
 *
 * This format matches the storage format used by Passless (https://github.com/pando85/passless)
 * to allow syncing passkeys between Android Password Store and Passless via git.
 *
 * Storage format:
 * - Serialized as CBOR
 * - Encrypted with PGP using the password store's GPG key
 * - Stored at: {store}/passless/{rp_id}/{credential_id_hex}.gpg
 */
public data class PasskeyCredential(
  /** Credential ID (random bytes, typically 32 bytes) */
  val id: ByteArray,

  /** Relying Party information */
  val rp: RelyingParty,

  /** User information */
  val user: User,

  /** Signature counter (incremented on each authentication) */
  val signCount: Int,

  /** COSE algorithm identifier (e.g., -7 for ES256) */
  val alg: Int,

  /** EC private key in raw format (32 bytes for P-256) */
  val privateKey: ByteArray,

  /** Unix timestamp (seconds) when credential was created */
  val created: Long,

  /** Whether this is a discoverable/resident credential */
  val discoverable: Boolean,

  /** Optional extensions */
  val extensions: Extensions = Extensions(),
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as PasskeyCredential

    if (!id.contentEquals(other.id)) return false
    if (rp != other.rp) return false

    return true
  }

  override fun hashCode(): Int {
    var result = id.contentHashCode()
    result = 31 * result + rp.hashCode()
    return result
  }
}

/**
 * Relying Party information.
 */
public data class RelyingParty(
  /** Relying party identifier (e.g., "example.com") */
  val id: String,

  /** Human-readable name (optional) */
  val name: String? = null,
)

/**
 * User information.
 */
public data class User(
  /** User ID (opaque bytes from the relying party) */
  val id: ByteArray,

  /** User name (e.g., email address) */
  val name: String? = null,

  /** User display name (human-readable) */
  val displayName: String? = null,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as User

    if (!id.contentEquals(other.id)) return false

    return true
  }

  override fun hashCode(): Int {
    return id.contentHashCode()
  }
}

/**
 * Credential extensions.
 */
public data class Extensions(
  /** Credential protection level */
  val credProtect: Int? = null,

  /** HMAC secret extension */
  val hmacSecret: Boolean? = null,
)
