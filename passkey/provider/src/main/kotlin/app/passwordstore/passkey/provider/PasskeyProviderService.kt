/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey.provider

import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import app.passwordstore.passkey.PasskeyRepository
import dagger.hilt.android.AndroidEntryPoint
import java.io.File
import javax.inject.Inject
import logcat.logcat

/**
 * Credential Provider Service for Android 14+ (API 34+).
 *
 * This service integrates with the Android Credential Manager to provide passkeys
 * to any app that requests them. When an app calls `CredentialManager.getCredential()`,
 * Android will query this service for matching passkeys.
 *
 * The flow is:
 * 1. `onBeginGetCredentialRequest` - Return a list of matching credentials (entries)
 * 2. User selects an entry from the system UI
 * 3. `onGetCredentialRequest` - Actually perform the authentication and return the credential
 *
 * For creating passkeys:
 * 1. `onBeginCreateCredentialRequest` - Return create entries (where to store)
 * 2. User selects where to store
 * 3. `onCreateCredentialRequest` - Actually create and store the credential
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@AndroidEntryPoint
public class PasskeyProviderService : CredentialProviderService() {

  @Inject public lateinit var credentialHandler: PasskeyCredentialHandler

  override fun onCreate() {
    super.onCreate()
    initializeCredentialHandler()
  }

  private fun initializeCredentialHandler() {
    val prefs = getSharedPreferences("${packageName}_preferences", MODE_PRIVATE)

    // Set password store directory
    val repoPath = prefs.getString("git_external_repo", null)
    val passwordStoreDir = if (repoPath != null) {
      File(repoPath)
    } else {
      File(filesDir, "store")
    }
    credentialHandler.setPasswordStoreDir(passwordStoreDir)

    // Set passkeys directory
    val passkeysDir = prefs.getString("passkey_directory", PasskeyRepository.DEFAULT_PASSKEYS_DIR)
      ?: PasskeyRepository.DEFAULT_PASSKEYS_DIR
    credentialHandler.setPasskeysDir(passkeysDir)

    logcat { "Initialized credential handler: passwordStoreDir=$passwordStoreDir, passkeysDir=$passkeysDir" }
  }

  override fun onBeginGetCredentialRequest(
    request: BeginGetCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
  ) {
    logcat { "onBeginGetCredentialRequest called" }

    try {
      val response = credentialHandler.handleBeginGetCredential(this, request)
      callback.onResult(response)
    } catch (e: Exception) {
      logcat { "Error in onBeginGetCredentialRequest: ${e.message}" }
      callback.onError(GetCredentialUnknownException(e.message))
    }
  }

  override fun onBeginCreateCredentialRequest(
    request: BeginCreateCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
  ) {
    logcat { "onBeginCreateCredentialRequest called" }

    try {
      val response = credentialHandler.handleBeginCreateCredential(this, request)
      callback.onResult(response)
    } catch (e: Exception) {
      logcat { "Error in onBeginCreateCredentialRequest: ${e.message}" }
      callback.onError(CreateCredentialUnknownException(e.message))
    }
  }

  override fun onClearCredentialStateRequest(
    request: ProviderClearCredentialStateRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<Void?, ClearCredentialException>,
  ) {
    logcat { "onClearCredentialStateRequest called" }

    // Clear any cached state (e.g., session tokens)
    // For passkeys, we don't typically need to clear anything
    callback.onResult(null)
  }
}
