/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.model

import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable

@Serializable
public data class PasskeyCredential(
  public val credentialId: ByteArray,
  public val privateKey: ByteArray,
  public val publicKey: ByteArray,
  public val rpId: String,
  public val user: FidoUser,
  public val signCount: ULong = 0u,
  public val createdAt: Instant,
  public val transports: List<String> = listOf("internal"),
  public val uvInitialized: Boolean = true,
) {
  
  override fun toString(): String =
    "PasskeyCredential(credentialId=${'$'}{credentialId.contentToString()}, rpId=$'$'{rpId}, privateKey=<REDACTED>, publicKey=${'$'}{publicKey.contentToString()})"
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is PasskeyCredential) return false
    if (!credentialId.contentEquals(other.credentialId)) return false
    if (!privateKey.contentEquals(other.privateKey)) return false
    if (!publicKey.contentEquals(other.publicKey)) return false
    if (rpId != other.rpId) return false
    if (user != other.user) return false
    if (signCount != other.signCount) return false
    if (createdAt != other.createdAt) return false
    if (transports != other.transports) return false
    if (uvInitialized != other.uvInitialized) return false
    return true
  }

  override fun hashCode(): Int {
    var result = credentialId.contentHashCode()
    result = 31 * result + privateKey.contentHashCode()
    result = 31 * result + publicKey.contentHashCode()
    result = 31 * result + rpId.hashCode()
    result = 31 * result + user.hashCode()
    result = 31 * result + signCount.hashCode()
    result = 31 * result + createdAt.hashCode()
    result = 31 * result + transports.hashCode()
    result = 31 * result + uvInitialized.hashCode()
    return result
  }

  public fun incrementSignCount(): PasskeyCredential {
    return copy(signCount = signCount + 1u)
  }

  public fun credentialIdBase64(): String {
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId)
  }

  public fun displayNameOrName(): String {
    return user.displayName.takeIf { it.isNotBlank() } ?: user.name
  }
}
