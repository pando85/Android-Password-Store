/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.model

import kotlinx.serialization.Serializable

@Serializable
public data class FidoUser(
  public val id: ByteArray,
  public val name: String,
  public val displayName: String,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is FidoUser) return false
    return id.contentEquals(other.id) && name == other.name && displayName == other.displayName
  }

  override fun hashCode(): Int {
    var result = id.contentHashCode()
    result = 31 * result + name.hashCode()
    result = 31 * result + displayName.hashCode()
    return result
  }
}