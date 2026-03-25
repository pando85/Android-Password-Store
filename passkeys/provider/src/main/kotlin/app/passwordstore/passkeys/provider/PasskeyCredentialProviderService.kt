/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.provider

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialNoCreateOptionException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import app.passwordstore.passkeys.crypto.PasskeyCryptoHandler
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.storage.PasskeyStorage
import com.github.michaelbull.result.fold
import java.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import logcat.LogPriority
import logcat.logcat

@RequiresApi(34)
public abstract class PasskeyCredentialProviderService : CredentialProviderService() {

  protected abstract val passkeyStorage: PasskeyStorage
  protected abstract val cryptoHandler: PasskeyCryptoHandler
  protected abstract val providerActivity: Class<out Activity>

  override fun onCreate() {
    super.onCreate()
    logcat { "PasskeyCredentialProviderService created" }
  }

  final override fun onBeginGetCredentialRequest(
    request: BeginGetCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
  ) {
    try {
      val options =
        request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>()
      if (options.isEmpty()) {
        callback.onError(GetCredentialUnknownException("No passkey options available"))
        return
      }

      val entries =
        mutableListOf<PublicKeyCredentialEntry>().apply {
          for (option in options) {
            val parsedRequest =
              PasskeyProviderUtils.json.decodeFromString<WebAuthnGetRequest>(option.requestJson)
            val rpId =
              parsedRequest.rpId ?: parsedRequest.allowCredentials.firstNotNullOfOrNull { it.rpId }
            if (rpId == null) {
              logcat(LogPriority.WARN) { "Skipping passkey option without RP ID" }
              continue
            }

            @Suppress("RawDispatchersUse")
            val credentials =
              runBlocking(Dispatchers.IO) {
                passkeyStorage
                  .listCredentials(rpId)
                  .fold(
                    success = {
                      PasskeyProviderUtils.selectCredentials(it, parsedRequest.allowCredentials)
                    },
                    failure = {
                      logcat(LogPriority.ERROR) { "Failed loading passkeys for $rpId: $it" }
                      emptyList()
                    },
                  )
              }

            addAll(credentials.map { credential -> buildCredentialEntry(option, credential) })
          }
        }

      if (entries.isEmpty()) {
        callback.onError(GetCredentialUnknownException("No matching passkeys found"))
        return
      }

      callback.onResult(
        BeginGetCredentialResponse(
          credentialEntries = entries,
          actions = emptyList(),
          authenticationActions = emptyList(),
          remoteEntry = null,
        )
      )
    } catch (e: Exception) {
      logcat(LogPriority.ERROR) { "Unable to build get-credential response: $e" }
      callback.onError(GetCredentialUnknownException(e.message ?: "Unknown passkey error"))
    }
  }

  final override fun onBeginCreateCredentialRequest(
    request: BeginCreateCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
  ) {
    try {
      val createRequest = request as? BeginCreatePublicKeyCredentialRequest
      if (createRequest == null) {
        callback.onError(CreateCredentialNoCreateOptionException("Unsupported credential type"))
        return
      }

      val parsedRequest =
        PasskeyProviderUtils.json.decodeFromString<WebAuthnCreateRequest>(createRequest.requestJson)
      val pendingIntent = buildCreatePendingIntent()
      val description = parsedRequest.rp.name ?: parsedRequest.rp.id
      val accountName =
        parsedRequest.user.displayName ?: parsedRequest.user.name ?: parsedRequest.rp.id
      val entry =
        CreateEntry(
          accountName,
          pendingIntent,
          description,
          Instant.now(),
          providerIcon(),
          null,
          1,
          1,
          true,
        )

      callback.onResult(
        BeginCreateCredentialResponse(createEntries = listOf(entry), remoteEntry = null)
      )
    } catch (e: Exception) {
      logcat(LogPriority.ERROR) { "Unable to build create-credential response: $e" }
      callback.onError(CreateCredentialUnknownException(e.message ?: "Unknown passkey error"))
    }
  }

  final override fun onClearCredentialStateRequest(
    request: ProviderClearCredentialStateRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<Void?, ClearCredentialException>,
  ) {
    callback.onResult(null)
  }

  private fun buildCredentialEntry(
    option: BeginGetPublicKeyCredentialOption,
    credential: PasskeyCredential,
  ): PublicKeyCredentialEntry {
    return PublicKeyCredentialEntry(
      this,
      credential.user.name,
      buildGetPendingIntent(credential),
      option,
      credential.user.displayName,
      Instant.ofEpochMilli(credential.createdAt.toEpochMilliseconds()),
      providerIcon(),
      true,
    )
  }

  private fun buildGetPendingIntent(credential: PasskeyCredential): PendingIntent {
    val intent =
      Intent(this, providerActivity)
        .putExtra(EXTRA_OPERATION, OPERATION_GET)
        .putExtra(
          EXTRA_CREDENTIAL_ID,
          PasskeyProviderUtils.encodeBase64Url(credential.credentialId),
        )
    return PendingIntent.getActivity(
      this,
      credential.credentialId.contentHashCode(),
      intent,
      PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
    )
  }

  private fun buildCreatePendingIntent(): PendingIntent {
    val intent = Intent(this, providerActivity).putExtra(EXTRA_OPERATION, OPERATION_CREATE)
    return PendingIntent.getActivity(
      this,
      OPERATION_CREATE.hashCode(),
      intent,
      PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
    )
  }

  private fun providerIcon(): Icon {
    return Icon.createWithResource(this, applicationInfo.icon)
  }

  public companion object {
    public const val EXTRA_OPERATION: String = "passkey_operation"
    public const val EXTRA_CREDENTIAL_ID: String = "passkey_credential_id"
    public const val OPERATION_CREATE: String = "create"
    public const val OPERATION_GET: String = "get"
  }
}
