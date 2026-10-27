/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkeys

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PasskeyFastUnlockPolicyTest {
  private val keyA = "0123456789abcdef"
  private val keyB = "fedcba9876543210"

  @Test
  fun `only selects passphrase for the encrypted recipient with multiple keys`() {
    val entries = linkedMapOf("alice@example.org" to "first", "bob@example.org" to "second")
    val lookup: (app.passwordstore.crypto.PGPIdentifier) -> String? = {
      when (it.toString()) {
        "alice@example.org" -> keyA
        "bob@example.org" -> keyB
        else -> null
      }
    }

    val selected = PasskeyFastUnlockPolicy.findMatchingPassphrase(entries, setOf(keyB), lookup)

    assertEquals(keyB, selected?.primaryKeyId)
    assertEquals("second", selected?.encrypted?.concatToString())
    assertNull(PasskeyFastUnlockPolicy.findMatchingPassphrase(entries, setOf("unknown"), lookup))
  }

  @Test
  fun `skips non-key entries and accepts primary key IDs`() {
    val entries =
      linkedMapOf(
        "unlock_pin" to "hidden",
        "biometrics_and_pin_last_use" to 42L,
        keyA to "encrypted",
      )
    val result =
      PasskeyFastUnlockPolicy.findMatchingPassphrase(entries, setOf(keyA)) { it.toString() }

    assertEquals(keyA, result?.primaryKeyId)
    assertEquals(keyA, result?.persistedId)
  }

  @Test
  fun `expires missing stale and future timestamps but not disabled timeouts`() {
    val day = java.util.concurrent.TimeUnit.DAYS.toMillis(1)
    assertTrue(PasskeyFastUnlockPolicy.isExpired(5 * day, 0, 3))
    assertTrue(PasskeyFastUnlockPolicy.isExpired(5 * day, day, 3))
    assertTrue(PasskeyFastUnlockPolicy.isExpired(5 * day, 6 * day, 3))
    assertFalse(PasskeyFastUnlockPolicy.isExpired(5 * day - 1, 2 * day, 3))
    assertFalse(PasskeyFastUnlockPolicy.isExpired(5 * day, 0, 0))
  }
}
