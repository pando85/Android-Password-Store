/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.pm.PackageManager
import android.os.Build
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
class PasskeyPlatformCompatibilityTest {

  @Test
  @Config(sdk = [Build.VERSION_CODES.S])
  fun `credential provider entry points are disabled on Android 12`() {
    val context = RuntimeEnvironment.getApplication()
    val packageManager = context.packageManager
    val packageInfo =
      packageManager.getPackageInfo(
        context.packageName,
        PackageManager.GET_SERVICES or PackageManager.GET_ACTIVITIES,
      )

    val serviceInfo =
      packageInfo.services?.firstOrNull { info ->
        info.name == "${context.packageName}.passkeys.AppPasskeyCredentialProviderService"
      }
    val activityInfo =
      packageInfo.activities?.firstOrNull { info ->
        info.name == "${context.packageName}.passkeys.AppPasskeyProviderActivity"
      }

    assertNotNull(serviceInfo)
    assertNotNull(activityInfo)
    assertFalse(serviceInfo.enabled)
    assertFalse(activityInfo.enabled)
  }

  @Test
  @Config(sdk = [Build.VERSION_CODES.UPSIDE_DOWN_CAKE])
  fun `credential provider entry points are enabled on Android 14`() {
    val context = RuntimeEnvironment.getApplication()
    val packageManager = context.packageManager
    val packageInfo =
      packageManager.getPackageInfo(
        context.packageName,
        PackageManager.GET_SERVICES or PackageManager.GET_ACTIVITIES,
      )

    val serviceInfo =
      packageInfo.services?.firstOrNull { info ->
        info.name == "${context.packageName}.passkeys.AppPasskeyCredentialProviderService"
      }
    val activityInfo =
      packageInfo.activities?.firstOrNull { info ->
        info.name == "${context.packageName}.passkeys.AppPasskeyProviderActivity"
      }

    assertNotNull(serviceInfo)
    assertNotNull(activityInfo)
    assertTrue(serviceInfo.enabled)
    assertTrue(activityInfo.enabled)
  }
}
