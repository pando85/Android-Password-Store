/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.settings

import androidx.fragment.app.FragmentActivity
import app.passwordstore.R
import app.passwordstore.util.settings.PreferenceKeys
import de.Maxr1998.modernpreferences.PreferenceScreen
import de.Maxr1998.modernpreferences.helpers.switch

class PasskeySettings(private val activity: FragmentActivity) : SettingsProvider {

  override fun provideSettings(builder: PreferenceScreen.Builder) {
    builder.apply {
      switch(PreferenceKeys.PASSKEY_CONSTANT_SIGNATURE_COUNTER) {
        defaultValue = true
        titleRes = R.string.pref_passkey_constant_signature_counter_title
        summaryRes = R.string.pref_passkey_constant_signature_counter_summary
      }
      switch(PreferenceKeys.PASSKEY_AUTO_GIT_SYNC) {
        defaultValue = true
        titleRes = R.string.pref_passkey_auto_git_sync_title
        summaryRes = R.string.pref_passkey_auto_git_sync_summary
      }
    }
  }
}