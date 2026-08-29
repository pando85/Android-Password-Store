/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
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
  fun `credential provider entry points are disabled on Android 12`() {
    val context = RuntimeEnvironment.getApplication() as Context

    assertFalse(context.resources.getBoolean(R.bool.isAtLeastU))
    assertFalse(providerServiceInfo(context).enabled)
    assertFalse(providerActivityInfo(context).enabled)
  }

  @Test
  @Config(sdk = [34])
  fun `credential provider entry points are enabled on Android 14`() {
    val context = RuntimeEnvironment.getApplication() as Context

    assertTrue(context.resources.getBoolean(R.bool.isAtLeastU))
    assertTrue(providerServiceInfo(context).enabled)
    assertTrue(providerActivityInfo(context).enabled)
  }

  @Suppress("DEPRECATION")
  private fun providerServiceInfo(context: Context) =
    context.packageManager.getServiceInfo(
      ComponentName(
        context.packageName,
        "app.passwordstore.passkeys.AppPasskeyCredentialProviderService",
      ),
      PackageManager.MATCH_DISABLED_COMPONENTS,
    )

  @Suppress("DEPRECATION")
  private fun providerActivityInfo(context: Context) =
    context.packageManager.getActivityInfo(
      ComponentName(context.packageName, "app.passwordstore.passkeys.AppPasskeyProviderActivity"),
      PackageManager.MATCH_DISABLED_COMPONENTS,
    )
}
