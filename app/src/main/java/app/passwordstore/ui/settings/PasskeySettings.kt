/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.settings

import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.fragment.app.FragmentActivity
import app.passwordstore.R
import app.passwordstore.passkey.PasskeyRepository
import app.passwordstore.ui.passkey.PasskeyListActivity
import app.passwordstore.util.extensions.credentialProviderManager
import app.passwordstore.util.settings.PreferenceKeys
import de.Maxr1998.modernpreferences.PreferenceScreen
import de.Maxr1998.modernpreferences.helpers.editText
import de.Maxr1998.modernpreferences.helpers.onClick
import de.Maxr1998.modernpreferences.helpers.pref
import logcat.logcat

class PasskeySettings(private val activity: FragmentActivity) : SettingsProvider {

  private val isPasskeyProviderEnabled: Boolean
    get() {
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        return false
      }
      // Check if our app is registered as a credential provider
      return try {
        val componentName = ComponentName(
          activity.packageName,
          "app.passwordstore.passkey.provider.PasskeyProviderService"
        )
        activity.credentialProviderManager?.isEnabledCredentialProviderService(
          componentName
        ) == true
      } catch (e: Exception) {
        // May fail on some devices/emulators
        false
      }
    }

  override fun provideSettings(builder: PreferenceScreen.Builder) {
    builder.apply {
      // Only show passkey settings on Android 14+
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        pref(PreferenceKeys.PASSKEY_PROVIDER_ENABLE) {
          titleRes = R.string.pref_passkey_enable_title
          summaryRes = R.string.pref_passkey_enable_summary
          onClick {
            openCredentialProviderSettings()
            true
          }
        }

        pref(PreferenceKeys.PASSKEY_MANAGE) {
          titleRes = R.string.pref_passkey_manage_title
          summaryRes = R.string.pref_passkey_manage_summary
          onClick {
            // Launch passkey management activity
            val intent = Intent(activity, PasskeyListActivity::class.java)
            activity.startActivity(intent)
            true
          }
        }

        editText(PreferenceKeys.PASSKEY_DIRECTORY) {
          titleRes = R.string.pref_passkey_directory_title
          summaryRes = R.string.pref_passkey_directory_summary
          defaultValue = PasskeyRepository.DEFAULT_PASSKEYS_DIR
        }
      } else {
        // Show a message that passkeys require Android 14+
        pref("passkey_unsupported") {
          titleRes = R.string.pref_passkey_unsupported_title
          summaryRes = R.string.pref_passkey_unsupported_summary
          enabled = false
        }
      }
    }
  }

  @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
  private fun openCredentialProviderSettings() {
    // On Android 15+ (API 35+), try using CredentialManager.createSettingsPendingIntent()
    if (Build.VERSION.SDK_INT >= 35) {
      try {
        val credentialManager = activity.credentialProviderManager
        if (credentialManager != null) {
          logcat { "Trying CredentialManager.createSettingsPendingIntent() via reflection (API 35+)" }
          // Use reflection since the method may not be in SDK stubs yet
          val method = credentialManager.javaClass.getMethod("createSettingsPendingIntent")
          val pendingIntent = method.invoke(credentialManager) as android.app.PendingIntent
          pendingIntent.send()
          logcat { "Successfully launched credential settings via PendingIntent" }
          return
        }
      } catch (e: Exception) {
        logcat { "CredentialManager.createSettingsPendingIntent() failed: ${e.message}" }
      }
    }

    // Try the CREDENTIAL_PROVIDER intent with package data (required by Settings app)
    try {
      val intent = Intent(Settings.ACTION_CREDENTIAL_PROVIDER).apply {
        data = Uri.parse("package:${activity.packageName}")
        addCategory(Intent.CATEGORY_DEFAULT)
      }
      logcat { "Trying intent ${intent.action} with package data" }
      activity.startActivity(intent)
      logcat { "Successfully started ${intent.action}" }
      return
    } catch (e: Exception) {
      logcat { "Intent ${Settings.ACTION_CREDENTIAL_PROVIDER} with package failed: ${e.message}" }
    }

    // Try without package data
    val intentsToTry = listOf(
      Intent(Settings.ACTION_CREDENTIAL_PROVIDER),
      Intent("android.settings.CREDENTIAL_PROVIDER_SETTINGS"),
      Intent("android.settings.CREDENTIALS_SETTINGS"),
    )

    for (intent in intentsToTry) {
      try {
        logcat { "Trying intent ${intent.action}" }
        activity.startActivity(intent)
        logcat { "Successfully started ${intent.action}" }
        return
      } catch (e: Exception) {
        logcat { "Intent ${intent.action} failed: ${e.message}" }
      }
    }

    // Try security settings as last resort
    try {
      logcat { "Falling back to ACTION_SECURITY_SETTINGS" }
      activity.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
      Toast.makeText(
        activity,
        "Look for 'Passwords, passkeys and autofill' or similar option",
        Toast.LENGTH_LONG
      ).show()
      return
    } catch (e: Exception) {
      logcat { "ACTION_SECURITY_SETTINGS failed: ${e.message}" }
    }

    // If all else fails, show instructions
    Toast.makeText(
      activity,
      "Please go to Settings > Passwords & accounts > Passwords, passkeys and autofill to enable Password Store as a provider",
      Toast.LENGTH_LONG
    ).show()
  }
}
