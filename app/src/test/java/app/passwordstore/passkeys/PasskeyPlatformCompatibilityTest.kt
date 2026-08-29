/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.ComponentName
import android.content.pm.PackageManager
import android.os.Build
import app.passwordstore.R
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
class PasskeyPlatformCompatibilityTest {

  private fun isComponentEnabled(pm: PackageManager, componentName: ComponentName): Boolean? {
    return try {
      val info = pm.getServiceInfo(componentName, 0)
      info.enabled
    } catch (_: PackageManager.NameNotFoundException) {
      try {
        val info = pm.getActivityInfo(componentName, 0)
        info.enabled
      } catch (_: PackageManager.NameNotFoundException) {
        null
      }
    }
  }

  @Test
  @Config(sdk = [Build.VERSION_CODES.S])
  fun `credential provider entry points are disabled on Android 12`() {
    val context = RuntimeEnvironment.getApplication()
    assertFalse(context.resources.getBoolean(R.bool.isAtLeastU))

    val serviceComponent =
      ComponentName(
        context.packageName,
        "${context.packageName}.passkeys.AppPasskeyCredentialProviderService",
      )
    val activityComponent =
      ComponentName(
        context.packageName,
        "${context.packageName}.passkeys.AppPasskeyProviderActivity",
      )

    val serviceEnabled = isComponentEnabled(context.packageManager, serviceComponent)
    val activityEnabled = isComponentEnabled(context.packageManager, activityComponent)

    if (serviceEnabled != null) assertFalse(serviceEnabled)
    if (activityEnabled != null) assertFalse(activityEnabled)
  }

  @Test
  @Config(sdk = [Build.VERSION_CODES.UPSIDE_DOWN_CAKE])
  fun `credential provider entry points are enabled on Android 14`() {
    val context = RuntimeEnvironment.getApplication()
    assertTrue(context.resources.getBoolean(R.bool.isAtLeastU))

    val serviceComponent =
      ComponentName(
        context.packageName,
        "${context.packageName}.passkeys.AppPasskeyCredentialProviderService",
      )
    val activityComponent =
      ComponentName(
        context.packageName,
        "${context.packageName}.passkeys.AppPasskeyProviderActivity",
      )

    val serviceEnabled = isComponentEnabled(context.packageManager, serviceComponent)
    val activityEnabled = isComponentEnabled(context.packageManager, activityComponent)

    if (serviceEnabled != null) assertTrue(serviceEnabled)
    if (activityEnabled != null) assertTrue(activityEnabled)
  }
}
