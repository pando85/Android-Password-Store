/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.settings

import android.content.Intent
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import app.passwordstore.R
import app.passwordstore.data.crypto.OpenPgpApiBackend
import app.passwordstore.ui.pgp.PGPKeyListActivity
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.settings.PreferenceKeys
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import de.Maxr1998.modernpreferences.PreferenceScreen
import de.Maxr1998.modernpreferences.helpers.onClick
import de.Maxr1998.modernpreferences.helpers.pref
import de.Maxr1998.modernpreferences.helpers.switch

class PGPSettings(private val activity: FragmentActivity) : SettingsProvider {

  override fun provideSettings(builder: PreferenceScreen.Builder) {
    builder.apply {
      pref("_") {
        titleRes = R.string.pref_pgp_key_manager_title
        persistent = false
        onClick {
          (activity as SettingsActivity)
            .repositorySettings
            .sshKeyAction
            .launch(Intent(activity, PGPKeyListActivity::class.java))
          false
        }
      }
      pref("_openpgp_provider") {
        titleRes = R.string.pref_openpgp_provider_title
        summaryRes = R.string.pref_openpgp_provider_summary
        persistent = false
        onClick {
          showOpenPgpProviderDialog()
          false
        }
      }
      switch(PreferenceKeys.ASCII_ARMOR) {
        titleRes = R.string.pref_pgp_ascii_armor_title
        persistent = true
      }
    }
  }

  private fun showOpenPgpProviderDialog() {
    val backend = OpenPgpApiBackend(activity.applicationContext)
    val providers = backend.providers()
    val current = activity.sharedPrefs.getString(PreferenceKeys.OPENPGP_PROVIDER_PACKAGE, null)
    val labels =
      listOf(activity.getString(R.string.pref_openpgp_provider_internal)) +
        providers.map { "${it.label} (${it.packageName})" }
    val checked = providers.indexOfFirst { it.packageName == current }.let { if (it < 0) 0 else it + 1 }

    MaterialAlertDialogBuilder(activity)
      .setTitle(R.string.pref_openpgp_provider_title)
      .setSingleChoiceItems(labels.toTypedArray(), checked) { dialog, which ->
        activity.sharedPrefs.edit {
          if (which == 0) remove(PreferenceKeys.OPENPGP_PROVIDER_PACKAGE)
          else putString(PreferenceKeys.OPENPGP_PROVIDER_PACKAGE, providers[which - 1].packageName)
        }
        dialog.dismiss()
      }
      .setNegativeButton(R.string.dialog_cancel, null)
      .show()
  }
}
