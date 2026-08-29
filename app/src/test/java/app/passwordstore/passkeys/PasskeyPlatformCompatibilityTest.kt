/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.pm.PackageManager
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import app.passwordstore.Application
import com.google.common.truth.Truth.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
class PasskeyPlatformCompatibilityTest {

  @Test
  @Config(sdk = [Build.VERSION_CODES.S])
  fun `credential provider entry points are disabled on Android 12`() {
    val context = ApplicationProvider.getApplicationContext<Application>()
    val packageManager = context.packageManager
    val packageInfo =
      packageManager.getPackageInfo(
        context.packageName,
        PackageManager.GET_SERVICES or PackageManager.GET_ACTIVITIES,
      )

    val serviceInfo =
      packageInfo.services?.firstOrNull {
        it.name == "app.passwordstore.passkeys.AppPasskeyCredentialProviderService"
      }
    val activityInfo =
      packageInfo.activities?.firstOrNull {
        it.name == "app.passwordstore.passkeys.AppPasskeyProviderActivity"
      }

    assertThat(serviceInfo).isNotNull()
    assertThat(activityInfo).isNotNull()
    assertThat(serviceInfo!!.enabled).isFalse()
    assertThat(activityInfo!!.enabled).isFalse()
  }

  @Test
  @Config(sdk = [Build.VERSION_CODES.UPSIDE_DOWN_CAKE])
  fun `credential provider entry points are enabled on Android 14`() {
    val context = ApplicationProvider.getApplicationContext<Application>()
    val packageManager = context.packageManager
    val packageInfo =
      packageManager.getPackageInfo(
        context.packageName,
        PackageManager.GET_SERVICES or PackageManager.GET_ACTIVITIES,
      )

    val serviceInfo =
      packageInfo.services?.firstOrNull {
        it.name == "app.passwordstore.passkeys.AppPasskeyCredentialProviderService"
      }
    val activityInfo =
      packageInfo.activities?.firstOrNull {
        it.name == "app.passwordstore.passkeys.AppPasskeyProviderActivity"
      }

    assertThat(serviceInfo).isNotNull()
    assertThat(activityInfo).isNotNull()
    assertThat(serviceInfo!!.enabled).isTrue()
    assertThat(activityInfo!!.enabled).isTrue()
  }
}
