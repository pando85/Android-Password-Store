/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkeys

import app.passwordstore.crypto.PGPIdentifier
import java.util.concurrent.TimeUnit

/** Pure policy shared by passkey unlock selection and its regression tests. */
internal data class PersistentPassphraseEntry(
  val persistedId: String,
  val primaryKeyId: String,
  val encrypted: CharArray,
)

internal object PasskeyFastUnlockPolicy {
  fun isExpired(nowMillis: Long, lastUseMillis: Long, timeoutDays: Long): Boolean {
    if (timeoutDays <= 0L) return false
    if (lastUseMillis <= 0L || nowMillis < lastUseMillis) return true
    return nowMillis - lastUseMillis >= TimeUnit.DAYS.toMillis(timeoutDays)
  }

  /** Do not guess: a persisted key must actually match an encrypted recipient. */
  fun findMatchingPassphrase(
    persisted: Map<String, *>,
    recipientPrimaryKeyIds: Set<String>,
    resolvePrimaryKeyId: (PGPIdentifier) -> String?,
  ): PersistentPassphraseEntry? {
    if (recipientPrimaryKeyIds.isEmpty()) return null
    for ((id, value) in persisted) {
      val encrypted = value as? String ?: continue
      if (id == "unlock_pin") continue
      val identifier = PGPIdentifier.fromString(id) ?: continue
      val primaryKeyId = resolvePrimaryKeyId(identifier) ?: continue
      if (primaryKeyId in recipientPrimaryKeyIds) {
        return PersistentPassphraseEntry(id, primaryKeyId, encrypted.toCharArray())
      }
    }
    return null
  }
}
