/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.Context
import app.passwordstore.R
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
class PasskeyPlatformCompatibilityTest {

  @Test
  @Config(sdk = [31])
  fun `credential provider compatibility flag is disabled on Android 12`() {
    val context = RuntimeEnvironment.getApplication() as Context
    assertFalse(context.resources.getBoolean(R.bool.isAtLeastU))
  }

  @Test
  @Config(sdk = [34])
  fun `credential provider compatibility flag is enabled on Android 14`() {
    val context = RuntimeEnvironment.getApplication() as Context
    assertTrue(context.resources.getBoolean(R.bool.isAtLeastU))
  }
}
