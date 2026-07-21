/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

import java.net.URI

public object RpIdValidator {

  public fun validateRpIdSyntax(rpId: String): Boolean {
    if (rpId.isBlank()) return false
    if (rpId.contains('/')) return false
    if (rpId.contains(':')) return false
    if (rpId.contains('?')) return false
    if (rpId.contains('#')) return false
    if (rpId.contains('@')) return false
    if (rpId.startsWith('.') || rpId.endsWith('.')) return false
    if (rpId.contains("..")) return false
    if (rpId.length > 253) return false
    val labels = rpId.split('.')
    if (labels.size < 1) return false
    for (label in labels) {
      if (label.isEmpty() || label.length > 63) return false
      if (label.startsWith('-') || label.endsWith('-')) return false
      for (ch in label) {
        if (!ch.isLetterOrDigit() && ch != '-') return false
      }
    }
    return true
  }

  public fun isValidOriginForRpId(origin: String, rpId: String): Boolean {
    if (!validateRpIdSyntax(rpId)) return false
    val canonicalOrigin = canonicalizeWebOrigin(origin) ?: return false
    val host = URI(canonicalOrigin).host
    if (host == rpId) return true
    if (host.endsWith(".$rpId")) return true
    return false
  }

  public fun canonicalizeWebOrigin(origin: String): String? {
    return try {
      val uri = URI(origin)
      if (uri.scheme.lowercase() != "https") return null
      if (uri.userInfo != null) return null
      if (uri.port != -1 && uri.port != 443) return null
      if (uri.path.isNotEmpty() && uri.path != "/") return null
      if (uri.query != null || uri.fragment != null) return null
      val host = uri.host?.lowercase() ?: return null
      "https://$host"
    } catch (_: Exception) {
      null
    }
  }

  public fun isRegistrableSuffix(parent: String, child: String): Boolean {
    if (!validateRpIdSyntax(parent)) return false
    if (!validateRpIdSyntax(child)) return false
    if (parent == child) return true
    return child.endsWith(".$parent")
  }

  public fun isAndroidAppOrigin(origin: String): Boolean {
    return origin.startsWith("android:apk-key-hash:")
  }
}
