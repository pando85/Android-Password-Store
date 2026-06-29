/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.annotation.RequiresApi
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
import app.passwordstore.ui.git.base.BaseGitActivity
import app.passwordstore.ui.git.base.BaseGitActivity.GitOp
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
class AppPasskeyProviderActivity : BaseGitActivity() {

  @Inject lateinit var passkeyStorage: PasskeyStorage
  @Inject lateinit var cryptoHandler: PasskeyCryptoHandler
  @Inject lateinit var authenticator: PasskeyAuthenticator

  private fun dbg(msg: () -> String) {
    Log.i("PASSKEY_DEBUG", msg())
  }

  private fun maybeSyncToGit() {
    if (!sharedPrefs.getBoolean(PreferenceKeys.PASSKEY_AUTO_GIT_SYNC, true)) return
    if (gitSettings.url == null) return
    CoroutineScope(dispatcherProvider.io()).launch {
      launchGitOperation(GitOp.SYNC)
        .fold(
          success = { logcat { "Passkey auto-sync completed" } },
          failure = { logcat(LogPriority.WARN) { "Passkey auto-sync failed: $it" } },
        )
    }
  }

  @RequiresApi(34)
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    CoroutineScope(dispatcherProvider.mainImmediate()).launch { handleProviderRequest() }
  }

  @RequiresApi(34)
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

  @RequiresApi(34)
  private suspend fun handleGetCredential(
    request: androidx.credentials.provider.ProviderGetCredentialRequest
  ) {
    try {
      @Suppress("InlinedApi")
      val selectedCredentialId =
        intent.getStringExtra(PasskeyCredentialProviderService.EXTRA_CREDENTIAL_ID)
      if (selectedCredentialId == null) {
        Log.e("PASSKEY_DEBUG", "finishing with get error: No passkey was selected")
        finishWithGetError(GetCredentialCancellationException("No passkey was selected"))
        return
      }

      val option =
        request.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull()
      if (option == null) {
        Log.e("PASSKEY_DEBUG", "finishing with get error: Missing passkey get option")
        finishWithGetError(GetCredentialUnknownException("Missing passkey get option"))
        return
      }

      dbg { "GET request JSON: ${option.requestJson}" }

      val parsedRequest =
        PasskeyProviderUtils.json.decodeFromString<
          app.passwordstore.passkeys.provider.WebAuthnGetRequest
        >(
          option.requestJson
        )
      dbg {
        "GET parsed: rpId=${parsedRequest.rpId}, challenge=${parsedRequest.challenge}, origin=${parsedRequest.origin}, userVerification=${parsedRequest.userVerification}"
      }

      val credentialId = PasskeyProviderUtils.decodeBase64Url(selectedCredentialId)
      val credential =
        passkeyStorage
          .getCredential(credentialId)
          .fold(
            success = { it },
            failure = {
              Log.e("PASSKEY_DEBUG", "getCredential failed", it)
              logcat(LogPriority.ERROR) { "Failed reading stored passkey: $it" }
              null
            },
          )
      if (credential == null) {
        Log.e("PASSKEY_DEBUG", "finishing with get error: Selected passkey is unavailable")
        finishWithGetError(GetCredentialUnknownException("Selected passkey is unavailable"))
        return
      }
      dbg {
        "GET credential loaded: id=${PasskeyProviderUtils.encodeBase64Url(credential.credentialId)}, rpId=${credential.rpId}"
      }

      if (authenticator.canAuthenticate(this)) {
        when (val authResult = authenticator.authenticateForPasskey(this, credential.rpId)) {
          is PasskeyAuthenticator.Result.Success -> {
            Log.i("PASSKEY_DEBUG", "biometric success, proceeding to assertion")
          }
          is PasskeyAuthenticator.Result.Canceled -> {
            Log.e("PASSKEY_DEBUG", "finishing with get error: Authentication canceled")
            finishWithGetError(GetCredentialCancellationException("Authentication canceled"))
            return
          }
          is PasskeyAuthenticator.Result.NotAvailable -> {
            logcat(LogPriority.WARN) { "Biometric auth not available, proceeding without it" }
          }
          is PasskeyAuthenticator.Result.Failure -> {
            Log.e("PASSKEY_DEBUG", "finishing with get error: Authentication failed: ${authResult.message}")
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
          failure = { 
            Log.w("PASSKEY_DEBUG", "updateSignCount failed", it)
            logcat(LogPriority.WARN) { "Failed to update sign count: $it" } 
          },
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
              Log.e("PASSKEY_DEBUG", "getAssertion failed", it)
              logcat(LogPriority.ERROR) { "Failed building assertion: $it" }
              null
            },
          )
      if (assertion == null) {
        Log.e("PASSKEY_DEBUG", "finishing with get error: Failed generating passkey assertion")
        finishWithGetError(GetCredentialUnknownException("Failed generating passkey assertion"))
        return
      }

      dbg {
        "GET assertion: authData=${assertion.authenticatorData.size}B, sig=${assertion.signature.size}B, clientDataJSON=${assertion.clientDataJSON}"
      }
      val clientDataHash =
        java.security.MessageDigest.getInstance("SHA-256")
          .digest(assertion.clientDataJSON.toByteArray())
      cryptoHandler
        .verify(
          credential.publicKey,
          assertion.signature,
          assertion.authenticatorData,
          clientDataHash,
        )
        .fold(
          success = { Log.w("PASSKEY_DEBUG", "self-verify: $it") },
          failure = { Log.e("PASSKEY_DEBUG", "self-verify error", it) },
        )

      val responseJson =
        PasskeyProviderUtils.buildAssertionResponse(assertion, credential, requestJson)
      dbg { "GET response JSON: $responseJson" }
      val resultIntent = Intent()
      PendingIntentHandler.setGetCredentialResponse(
        resultIntent,
        GetCredentialResponse(PublicKeyCredential(responseJson)),
      )
      setResult(Activity.RESULT_OK, resultIntent)
      maybeSyncToGit()
      finish()
    } catch (e: Exception) {
      Log.e("PASSKEY_DEBUG", "handleGetCredential UNCAUGHT EXCEPTION", e)
      finishWithGetError(GetCredentialUnknownException("Unexpected error: ${e.message}"))
    }
  }

  @RequiresApi(34)
  private suspend fun handleCreateCredential(
    request: androidx.credentials.provider.ProviderCreateCredentialRequest
  ) {
    try {
      val createRequest = request.callingRequest as? CreatePublicKeyCredentialRequest
      if (createRequest == null) {
        Log.e("PASSKEY_DEBUG", "finishing with create error: Missing passkey create request")
        finishWithCreateError(CreateCredentialUnknownException("Missing passkey create request"))
        return
      }

      dbg { "CREATE request JSON: ${createRequest.requestJson}" }

      val parsedRequest =
        PasskeyProviderUtils.json.decodeFromString<
          app.passwordstore.passkeys.provider.WebAuthnCreateRequest
        >(
          createRequest.requestJson
        )
      dbg {
        "CREATE parsed: rpId=${parsedRequest.rp.id}, challenge=${parsedRequest.challenge}, attestation=${parsedRequest.attestation}"
      }

      if (authenticator.canAuthenticate(this)) {
        when (val authResult = authenticator.authenticateForCreation(this, parsedRequest.rp.id)) {
          is PasskeyAuthenticator.Result.Success -> {}
          is PasskeyAuthenticator.Result.Canceled -> {
            Log.e("PASSKEY_DEBUG", "finishing with create error: Authentication canceled")
            finishWithCreateError(CreateCredentialUnknownException("Authentication canceled"))
            return
          }
          is PasskeyAuthenticator.Result.NotAvailable -> {
            logcat(LogPriority.WARN) { "Biometric auth not available, proceeding without it" }
          }
          is PasskeyAuthenticator.Result.Failure -> {
            Log.e("PASSKEY_DEBUG", "finishing with create error: Authentication failed: ${authResult.message}")
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
              Log.e("PASSKEY_DEBUG", "Failed creating passkey: $it", it)
              logcat(LogPriority.ERROR) { "Failed creating passkey: $it" }
              null
            },
          )
      if (createdCredential == null) {
        Log.e("PASSKEY_DEBUG", "finishing with create error: Failed creating passkey")
        finishWithCreateError(CreateCredentialUnknownException("Failed creating passkey"))
        return
      }

      val saveResult = passkeyStorage.saveCredential(createdCredential)
      if (saveResult.isErr) {
        saveResult.fold(
          success = {},
          failure = { 
            Log.e("PASSKEY_DEBUG", "Failed storing passkey: $it", it)
            logcat(LogPriority.ERROR) { "Failed storing passkey: $it" } 
          },
        )
        Log.e("PASSKEY_DEBUG", "finishing with create error: Failed storing passkey")
        finishWithCreateError(CreateCredentialUnknownException("Failed storing passkey"))
        return
      }

      val responseJson =
        PasskeyProviderUtils.buildAttestationResponse(createdCredential, createRequest.requestJson)
      dbg { "CREATE response JSON: $responseJson" }
      val resultIntent = Intent()
      PendingIntentHandler.setCreateCredentialResponse(
        resultIntent,
        CreatePublicKeyCredentialResponse(responseJson),
      )
      setResult(Activity.RESULT_OK, resultIntent)
      maybeSyncToGit()
      finish()
    } catch (e: Exception) {
      Log.e("PASSKEY_DEBUG", "handleCreateCredential UNCAUGHT EXCEPTION", e)
      finishWithCreateError(CreateCredentialUnknownException("Unexpected error: ${e.message}"))
    }
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
