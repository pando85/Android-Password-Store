/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ResolveInfo
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.openintents.openpgp.IOpenPgpService2
import org.openintents.openpgp.OpenPgpError
import org.openintents.openpgp.util.OpenPgpApi
import org.openintents.openpgp.util.OpenPgpServiceConnection

/**
 * Operation-oriented adapter for providers implementing the OpenPGP API.
 *
 * This deliberately does not implement [app.passwordstore.crypto.KeyManager]: provider-held secret
 * keys are capabilities used through Binder, not key bytes owned by APS. Public certificates can be
 * retrieved with [getPublicKey], while private-key operations remain inside the provider.
 */
class OpenPgpApiBackend(private val context: Context) {

  sealed interface OperationResult<out T> {
    data class Success<T>(val value: T) : OperationResult<T>

    data class UserInteractionRequired(val pendingIntent: PendingIntent) : OperationResult<Nothing>

    data class Failure(val error: Throwable) : OperationResult<Nothing>
  }

  data class Provider(val packageName: String, val label: String)

  /** Installed providers are discovered through the standard IOpenPgpService2 service action. */
  @Suppress("DEPRECATION")
  fun providers(): List<Provider> {
    val intent = Intent(OpenPgpApi.SERVICE_INTENT_2)
    return context.packageManager
      .queryIntentServices(intent, 0)
      .mapNotNull(::providerFromResolveInfo)
      .distinctBy { it.packageName }
      .sortedBy { it.label.lowercase() }
  }

  suspend fun checkPermission(providerPackage: String): OperationResult<Unit> =
    execute(providerPackage, Intent(OpenPgpApi.ACTION_CHECK_PERMISSION), null) { Unit }

  suspend fun decrypt(
    providerPackage: String,
    ciphertext: ByteArray,
  ): OperationResult<ByteArray> =
    execute(
      providerPackage,
      Intent(OpenPgpApi.ACTION_DECRYPT_VERIFY),
      ciphertext,
    ) { output -> output }

  suspend fun getPublicKey(
    providerPackage: String,
    keyId: Long,
    asciiArmor: Boolean = false,
  ): OperationResult<ByteArray> =
    execute(
      providerPackage,
      Intent(OpenPgpApi.ACTION_GET_KEY).apply {
        putExtra(OpenPgpApi.EXTRA_KEY_ID, keyId)
        putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, asciiArmor)
      },
      null,
    ) { output -> output }

  suspend fun resolveKeyIds(
    providerPackage: String,
    userIds: Array<String>,
  ): OperationResult<LongArray> =
    executeWithoutOutput(
      providerPackage,
      Intent(OpenPgpApi.ACTION_GET_KEY_IDS).apply {
        putExtra(OpenPgpApi.EXTRA_USER_IDS, userIds)
      },
    ) { result -> result.getLongArrayExtra(OpenPgpApi.RESULT_KEY_IDS) ?: longArrayOf() }

  private suspend fun <T> execute(
    providerPackage: String,
    request: Intent,
    input: ByteArray?,
    success: (ByteArray) -> T,
  ): OperationResult<T> =
    withService(providerPackage) { service ->
      val output = ByteArrayOutputStream()
      val result =
        OpenPgpApi(context, service)
          .executeApi(request, input?.let(::ByteArrayInputStream), output)
      mapResult(result) { success(output.toByteArray()) }
    }

  private suspend fun <T> executeWithoutOutput(
    providerPackage: String,
    request: Intent,
    success: (Intent) -> T,
  ): OperationResult<T> =
    withService(providerPackage) { service ->
      val result = OpenPgpApi(context, service).executeApi(request, null, null)
      mapResult(result) { success(result) }
    }

  private suspend fun <T> withService(
    providerPackage: String,
    operation: (IOpenPgpService2) -> OperationResult<T>,
  ): OperationResult<T> =
    withContext(Dispatchers.IO) {
      val service = CompletableDeferred<IOpenPgpService2>()
      val connection =
        OpenPgpServiceConnection(
          context,
          providerPackage,
          object : OpenPgpServiceConnection.OnBound {
            override fun onBound(boundService: IOpenPgpService2) {
              service.complete(boundService)
            }

            override fun onError(error: Exception) {
              service.completeExceptionally(error)
            }
          },
        )

      try {
        connection.bindToService()
        operation(service.await())
      } catch (error: Throwable) {
        OperationResult.Failure(error)
      } finally {
        if (connection.isBound) runCatching { connection.unbindFromService() }
      }
    }

  private fun <T> mapResult(result: Intent, success: () -> T): OperationResult<T> =
    when (result.getIntExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR)) {
      OpenPgpApi.RESULT_CODE_SUCCESS -> OperationResult.Success(success())
      OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED -> {
        @Suppress("DEPRECATION")
        val pendingIntent = result.getParcelableExtra<PendingIntent>(OpenPgpApi.RESULT_INTENT)
        if (pendingIntent != null) OperationResult.UserInteractionRequired(pendingIntent)
        else OperationResult.Failure(IllegalStateException("OpenPGP provider requested interaction without a PendingIntent"))
      }
      else -> {
        @Suppress("DEPRECATION")
        val error = result.getParcelableExtra<OpenPgpError>(OpenPgpApi.RESULT_ERROR)
        OperationResult.Failure(
          IllegalStateException(error?.message ?: "OpenPGP provider operation failed")
        )
      }
    }

  private fun providerFromResolveInfo(info: ResolveInfo): Provider? {
    val serviceInfo = info.serviceInfo ?: return null
    val packageName = serviceInfo.packageName ?: return null
    val label = info.loadLabel(context.packageManager)?.toString()?.ifBlank { packageName } ?: packageName
    return Provider(packageName, label)
  }
}
