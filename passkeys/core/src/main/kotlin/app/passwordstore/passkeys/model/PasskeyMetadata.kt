/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.model

import kotlinx.datetime.Instant

public data class PasskeyMetadata(
  val credentialId: ByteArray,
  val rpId: String,
  val userName: String,
  val userDisplayName: String,
  val createdAt: Instant,
  val signCount: ULong = 0u,
  val fileLastModified: Long = 0L,
) {

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is PasskeyMetadata) return false
    if (!credentialId.contentEquals(other.credentialId)) return false
    if (rpId != other.rpId) return false
    if (userName != other.userName) return false
    if (userDisplayName != other.userDisplayName) return false
    if (createdAt != other.createdAt) return false
    if (signCount != other.signCount) return false
    if (fileLastModified != other.fileLastModified) return false
    return true
  }

  override fun hashCode(): Int {
    var result = credentialId.contentHashCode()
    result = 31 * result + rpId.hashCode()
    result = 31 * result + userName.hashCode()
    result = 31 * result + userDisplayName.hashCode()
    result = 31 * result + createdAt.hashCode()
    result = 31 * result + signCount.hashCode()
    result = 31 * result + fileLastModified.hashCode()
    return result
  }

  public fun credentialIdBase64(): String {
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId)
  }

  public fun displayNameOrName(): String {
    return userDisplayName.takeIf { it.isNotBlank() } ?: userName
  }

  public companion object {
    public fun fromPasskeyCredential(credential: PasskeyCredential): PasskeyMetadata {
      return PasskeyMetadata(
        credentialId = credential.credentialId,
        rpId = credential.rpId,
        userName = credential.user.name,
        userDisplayName = credential.user.displayName,
        createdAt = credential.createdAt,
        signCount = credential.signCount,
      )
    }
  }
}
