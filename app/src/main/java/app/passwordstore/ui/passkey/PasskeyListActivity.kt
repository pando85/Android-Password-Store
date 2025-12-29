/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.passkey

import android.content.SharedPreferences
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import app.passwordstore.R
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.injection.prefs.SettingsPreferences
import app.passwordstore.passkey.PasskeyRepository
import app.passwordstore.passkey.ui.PasskeyListScreen
import app.passwordstore.passkey.ui.PasskeyListViewModel
import app.passwordstore.ui.APSAppBar
import app.passwordstore.ui.compose.theme.APSTheme
import app.passwordstore.util.settings.PreferenceKeys
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

/**
 * Activity for displaying and managing stored passkeys.
 *
 * Uses index-based listing which doesn't require PGP decryption,
 * showing RP ID and credential ID from the directory structure.
 */
@AndroidEntryPoint
class PasskeyListActivity : AppCompatActivity() {

  private val viewModel: PasskeyListViewModel by viewModels()

  @Inject
  @SettingsPreferences
  lateinit var settings: SharedPreferences

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    // Initialize ViewModel with the password store directory and passkeys directory
    val passwordStoreDir = PasswordRepository.getRepositoryDirectory()
    val passkeysDir = settings.getString(
      PreferenceKeys.PASSKEY_DIRECTORY,
      PasskeyRepository.DEFAULT_PASSKEYS_DIR
    ) ?: PasskeyRepository.DEFAULT_PASSKEYS_DIR
    viewModel.initialize(passwordStoreDir, passkeysDir)

    setContent {
      APSTheme {
        val state by viewModel.state.collectAsState()

        Scaffold(
          topBar = {
            APSAppBar(
              title = stringResource(R.string.pref_passkey_manage_title),
              navigationIcon = painterResource(R.drawable.ic_arrow_back_24dp),
              onNavigationIconClick = { finish() },
              backgroundColor = MaterialTheme.colorScheme.surface,
            )
          },
        ) { paddingValues ->
          PasskeyListScreen(
            state = state,
            onDeleteCredential = { credentialId ->
              viewModel.deleteCredential(credentialId)
            },
            onNavigateBack = { finish() },
            modifier = Modifier.padding(paddingValues),
          )
        }
      }
    }
  }
}
