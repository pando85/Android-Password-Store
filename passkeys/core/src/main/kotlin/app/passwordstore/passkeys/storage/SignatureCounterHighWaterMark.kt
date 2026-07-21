/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

public class SignatureCounterHighWaterMark {

  private val marks = ConcurrentHashMap<String, ULong>()

  private fun keyFor(credentialId: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId)
  }

  public fun getHighWaterMark(credentialId: ByteArray): ULong {
    return marks[keyFor(credentialId)] ?: 0u
  }

  public fun updateHighWaterMark(credentialId: ByteArray, value: ULong) {
    val key = keyFor(credentialId)
    marks[key] = value
  }

  public fun detectRollback(credentialId: ByteArray, diskCounter: ULong): Boolean {
    val highWaterMark = getHighWaterMark(credentialId)
    return diskCounter < highWaterMark
  }

  public fun reset(credentialId: ByteArray) {
    marks.remove(keyFor(credentialId))
  }

  public fun resetAll() {
    marks.clear()
  }
}
