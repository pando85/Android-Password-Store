/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.model

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class FidoUserTest {

  @Test
  fun `FidoUser equals works correctly`() {
    val user1 = FidoUser(id = "user123".toByteArray(), name = "testuser", displayName = "Test User")

    val user2 = FidoUser(id = "user123".toByteArray(), name = "testuser", displayName = "Test User")

    val user3 = FidoUser(id = "user456".toByteArray(), name = "testuser", displayName = "Test User")

    assertEquals(user1, user2, "Users with same values should be equal")
    assertNotEquals(user1, user3, "Users with different IDs should not be equal")
  }

  @Test
  fun `FidoUser hashCode is consistent`() {
    val user1 = FidoUser(id = "user123".toByteArray(), name = "testuser", displayName = "Test User")

    val user2 = FidoUser(id = "user123".toByteArray(), name = "testuser", displayName = "Test User")

    assertEquals(user1.hashCode(), user2.hashCode(), "Equal users should have same hash code")
  }
}
