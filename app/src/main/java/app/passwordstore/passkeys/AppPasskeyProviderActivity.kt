/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import app.passwordstore.passkeys.crypto.PasskeyCryptoHandler
import app.passwordstore.passkeys.provider.PasskeyAuthenticator
import app.passwordstore.passkeys.provider.PasskeyCredentialProviderService
import app.passwordstore.passkeys.provider.PasskeyProviderUtils
import app.passwordstore.passkeys.storage.PasskeyStorage
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.fold
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import logcat.LogPriority
import logcat.logcat

@AndroidEntryPoint
class AppPasskeyProviderActivity : AppCompatActivity() {

  @Inject lateinit var passkeyStorage: PasskeyStorage
  @Inject lateinit var cryptoHandler: PasskeyCryptoHandler
  @Inject lateinit var authenticator: PasskeyAuthenticator
  @Inject lateinit var dispatcherProvider: DispatcherProvider

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    CoroutineScope(dispatcherProvider.mainImmediate()).launch { handleProviderRequest() }
  }

  private suspend fun handleProviderRequest() {
    PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)?.let {
      handleGetCredential(it)
      return
    }

    PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)?.let {
      handleCreateCredential(it)
      return
    }

    finishWithGetError(GetCredentialUnknownException("Missing provider request"))
  }

  private suspend fun handleGetCredential(
    request: androidx.credentials.provider.ProviderGetCredentialRequest
  ) {
    val selectedCredentialId =
      intent.getStringExtra(PasskeyCredentialProviderService.EXTRA_CREDENTIAL_ID)
    if (selectedCredentialId == null) {
      finishWithGetError(GetCredentialCancellationException("No passkey was selected"))
      return
    }

    val option =
      request.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull()
    if (option == null) {
      finishWithGetError(GetCredentialUnknownException("Missing passkey get option"))
      return
    }

    val parsedRequest =
      PasskeyProviderUtils.json.decodeFromString<
        app.passwordstore.passkeys.provider.WebAuthnGetRequest
      >(
        option.requestJson
      )

    val credentialId = PasskeyProviderUtils.decodeBase64Url(selectedCredentialId)
    val credential =
      passkeyStorage
        .getCredential(credentialId)
        .fold(
          success = { it },
          failure = {
            logcat(LogPriority.ERROR) { "Failed reading stored passkey: $it" }
            null
          },
        )
    if (credential == null) {
      finishWithGetError(GetCredentialUnknownException("Selected passkey is unavailable"))
      return
    }

    if (authenticator.canAuthenticate(this)) {
      when (val authResult = authenticator.authenticateForPasskey(this, credential.rpId)) {
        is PasskeyAuthenticator.Result.Success -> {}
        is PasskeyAuthenticator.Result.Canceled -> {
          finishWithGetError(GetCredentialCancellationException("Authentication canceled"))
          return
        }
        is PasskeyAuthenticator.Result.NotAvailable -> {
          logcat(LogPriority.WARN) { "Biometric auth not available, proceeding without it" }
        }
        is PasskeyAuthenticator.Result.Failure -> {
          finishWithGetError(
            GetCredentialUnknownException("Authentication failed: ${authResult.message}")
          )
          return
        }
      }
    }

    val constantSignatureCounter =
      sharedPrefs.getBoolean(PreferenceKeys.PASSKEY_CONSTANT_SIGNATURE_COUNTER, true)
    val newSignCount = if (constantSignatureCounter) 0u else credential.signCount + 1u
    passkeyStorage
      .updateSignCount(credential.credentialId, newSignCount)
      .fold(
        success = {},
        failure = { logcat(LogPriority.WARN) { "Failed to update sign count: $it" } },
      )

    val requestJson = option.requestJson
    val assertion =
      cryptoHandler
        .getAssertion(
          credential = credential.copy(signCount = newSignCount),
          rpId = credential.rpId,
          challenge = PasskeyProviderUtils.decodeBase64Url(parsedRequest.challenge),
          origin = parsedRequest.origin ?: "https://${credential.rpId}",
        )
        .fold(
          success = { it },
          failure = {
            logcat(LogPriority.ERROR) { "Failed building assertion: $it" }
            null
          },
        )
    if (assertion == null) {
      finishWithGetError(GetCredentialUnknownException("Failed generating passkey assertion"))
      return
    }

    passkeyStorage
      .updateSignCount(credential.credentialId, newSignCount)
      .fold(
        success = {},
        failure = { logcat(LogPriority.WARN) { "Failed to update sign count: $it" } },
      )

    val responseJson =
      PasskeyProviderUtils.buildAssertionResponse(assertion, credential, requestJson)
    val resultIntent = Intent()
    PendingIntentHandler.setGetCredentialResponse(
      resultIntent,
      GetCredentialResponse(PublicKeyCredential(responseJson)),
    )
    setResult(Activity.RESULT_OK, resultIntent)
    finish()
  }

  private suspend fun handleCreateCredential(
    request: androidx.credentials.provider.ProviderCreateCredentialRequest
  ) {
    val createRequest = request.callingRequest as? CreatePublicKeyCredentialRequest
    if (createRequest == null) {
      finishWithCreateError(CreateCredentialUnknownException("Missing passkey create request"))
      return
    }

    val parsedRequest =
      PasskeyProviderUtils.json.decodeFromString<
        app.passwordstore.passkeys.provider.WebAuthnCreateRequest
      >(
        createRequest.requestJson
      )

    if (authenticator.canAuthenticate(this)) {
      when (val authResult = authenticator.authenticateForCreation(this, parsedRequest.rp.id)) {
        is PasskeyAuthenticator.Result.Success -> {}
        is PasskeyAuthenticator.Result.Canceled -> {
          finishWithCreateError(CreateCredentialUnknownException("Authentication canceled"))
          return
        }
        is PasskeyAuthenticator.Result.NotAvailable -> {
          logcat(LogPriority.WARN) { "Biometric auth not available, proceeding without it" }
        }
        is PasskeyAuthenticator.Result.Failure -> {
          finishWithCreateError(
            CreateCredentialUnknownException("Authentication failed: ${authResult.message}")
          )
          return
        }
      }
    }

    val createdCredential =
      cryptoHandler
        .createCredential(
          rpId = parsedRequest.rp.id,
          userId = PasskeyProviderUtils.decodeBase64Url(parsedRequest.user.id),
          userName = parsedRequest.user.name ?: "",
          userDisplayName = parsedRequest.user.displayName ?: parsedRequest.user.name ?: "",
          challenge = PasskeyProviderUtils.decodeBase64Url(parsedRequest.challenge),
        )
        .fold(
          success = { it },
          failure = {
            logcat(LogPriority.ERROR) { "Failed creating passkey: $it" }
            null
          },
        )
    if (createdCredential == null) {
      finishWithCreateError(CreateCredentialUnknownException("Failed creating passkey"))
      return
    }

    val saveResult = passkeyStorage.saveCredential(createdCredential)
    if (saveResult.isErr) {
      saveResult.fold(
        success = {},
        failure = { logcat(LogPriority.ERROR) { "Failed storing passkey: $it" } },
      )
      finishWithCreateError(CreateCredentialUnknownException("Failed storing passkey"))
      return
    }

    val responseJson =
      PasskeyProviderUtils.buildAttestationResponse(createdCredential, createRequest.requestJson)
    val resultIntent = Intent()
    PendingIntentHandler.setCreateCredentialResponse(
      resultIntent,
      CreatePublicKeyCredentialResponse(responseJson),
    )
    setResult(Activity.RESULT_OK, resultIntent)
    finish()
  }

  private fun finishWithGetError(
    exception: androidx.credentials.exceptions.GetCredentialException
  ) {
    val resultIntent = Intent()
    PendingIntentHandler.setGetCredentialException(resultIntent, exception)
    setResult(Activity.RESULT_OK, resultIntent)
    finish()
  }

  private fun finishWithCreateError(
    exception: androidx.credentials.exceptions.CreateCredentialException
  ) {
    val resultIntent = Intent()
    PendingIntentHandler.setCreateCredentialException(resultIntent, exception)
    setResult(Activity.RESULT_OK, resultIntent)
    finish()
  }
}
