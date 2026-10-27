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

class PasskeyPinPolicyTest {
  @Test
  fun `parses valid saved PIN record and counter`() {
    val record = PasskeyPinPolicy.parse("2:9876".toCharArray())
    assertEquals(2, record?.attempts)
    assertEquals("9876", record?.pin?.concatToString())
    record?.pin?.fill('\u0000')
  }

  @Test
  fun `rejects malformed or forged PIN counters`() {
    for (invalid in listOf("", "1234", ":1234", "bad:1234", "-1:1234", "4:1234", "0:")) {
      assertNull(PasskeyPinPolicy.parse(invalid.toCharArray()))
    }
  }

  @Test
  fun `compares PINs without early exit on a differing character`() {
    assertTrue(PasskeyPinPolicy.constantTimeEquals("0000".toCharArray(), "0000".toCharArray()))
    assertFalse(PasskeyPinPolicy.constantTimeEquals("0000".toCharArray(), "0001".toCharArray()))
    assertFalse(PasskeyPinPolicy.constantTimeEquals("0000".toCharArray(), "000".toCharArray()))
  }
}
