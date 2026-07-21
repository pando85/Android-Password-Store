/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.model

import kotlin.time.Instant

public class SensitivePasskeyCredential(
  public val credentialId: ByteArray,
  public val publicKey: ByteArray,
  public val rpId: String,
  public val user: FidoUser,
  public val signCount: ULong,
  public val createdAt: Instant,
  public val transports: List<String>,
  public val uvInitialized: Boolean,
  public val backupEligible: Boolean,
  public val backupState: Boolean,
  public val fileLastModified: Long,
  privateKey: ByteArray,
) : AutoCloseable {

  @Volatile private var privateKey: ByteArray? = privateKey

  public fun <T> usePrivateKey(block: (ByteArray) -> T): T {
    val key = privateKey ?: throw IllegalStateException("Credential has been closed")
    return block(key)
  }

  public fun toPasskeyCredential(): PasskeyCredential {
    val key = privateKey ?: throw IllegalStateException("Credential has been closed")
    return PasskeyCredential(
      credentialId = credentialId.copyOf(),
      privateKey = key,
      publicKey = publicKey.copyOf(),
      rpId = rpId,
      user = user,
      signCount = signCount,
      createdAt = createdAt,
      transports = transports,
      uvInitialized = uvInitialized,
      backupEligible = backupEligible,
      backupState = backupState,
    )
  }

  override fun close() {
    privateKey?.fill(0)
    privateKey = null
  }

  public companion object {
    public fun fromStoredCredential(
      stored: StoredCredential,
      fileLastModified: Long = 0L,
    ): SensitivePasskeyCredential {
      return SensitivePasskeyCredential(
        credentialId = stored.id.copyOf(),
        publicKey =
          stored.publicKey?.copyOf() ?: StoredCredential.deriveP256PublicKey(stored.privateKey),
        rpId = stored.rp.id,
        user =
          FidoUser(
            id = stored.user.id.copyOf(),
            name = stored.user.name ?: "",
            displayName = stored.user.displayName ?: "",
          ),
        signCount = stored.signCount.toULong(),
        createdAt = Instant.fromEpochSeconds(stored.created),
        transports = listOf("internal"),
        uvInitialized = true,
        backupEligible = stored.backupEligible,
        backupState = stored.backupState,
        fileLastModified = fileLastModified,
        privateKey = stored.privateKey.copyOf(),
      )
    }
  }
}
