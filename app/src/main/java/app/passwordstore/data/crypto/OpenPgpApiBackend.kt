/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ResolveInfo
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.concurrent.CancellationException
import javax.inject.Inject
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.openintents.openpgp.IOpenPgpService2
import org.openintents.openpgp.OpenPgpError
import org.openintents.openpgp.util.OpenPgpApi
import org.openintents.openpgp.util.OpenPgpServiceConnection

/**
 * Operation-oriented adapter for apps implementing the OpenPGP API.
 *
 * Secret keys never cross this boundary. Private-key operations are delegated to the selected
 * provider, while public certificates can be retrieved for APS' local PGPainless encryption path.
 */
class OpenPgpApiBackend internal constructor(private val executor: OpenPgpApiExecutor) {

  @Inject
  constructor(@ApplicationContext context: Context) : this(BinderOpenPgpApiExecutor(context))

  data class Provider(val packageName: String, val label: String)

  sealed interface OperationResult<out T> {
    data class Success<T>(val value: T) : OperationResult<T>

    data class UserInteractionRequired(val pendingIntent: PendingIntent) : OperationResult<Nothing>

    data object Cancelled : OperationResult<Nothing>

    data class Failure(val error: Throwable) : OperationResult<Nothing>
  }

  fun interface InteractionHandler {
    suspend fun interact(pendingIntent: PendingIntent): InteractionResult
  }

  sealed interface InteractionResult {
    data class Completed(val data: Intent?) : InteractionResult

    data object Cancelled : InteractionResult
  }

  fun providers(): List<Provider> = executor.providers()

  fun isProviderInstalled(packageName: String): Boolean =
    providers().any { it.packageName == packageName }

  suspend fun checkPermission(
    providerPackage: String,
    interactionHandler: InteractionHandler? = null,
  ): OperationResult<Unit> =
    executeWithInteraction(
      providerPackage = providerPackage,
      initialRequest = Intent(OpenPgpApi.ACTION_CHECK_PERMISSION),
      input = null,
      interactionHandler = interactionHandler,
    ) {
      Unit
    }

  suspend fun decrypt(
    providerPackage: String,
    ciphertext: ByteArray,
    interactionHandler: InteractionHandler? = null,
  ): OperationResult<ByteArray> =
    executeWithInteraction(
      providerPackage = providerPackage,
      initialRequest = Intent(OpenPgpApi.ACTION_DECRYPT_VERIFY),
      input = ciphertext,
      interactionHandler = interactionHandler,
    ) { call ->
      call.output
    }

  suspend fun getPublicKey(
    providerPackage: String,
    keyId: Long,
    asciiArmor: Boolean = false,
    interactionHandler: InteractionHandler? = null,
  ): OperationResult<ByteArray> =
    executeWithInteraction(
      providerPackage = providerPackage,
      initialRequest =
        Intent(OpenPgpApi.ACTION_GET_KEY).apply {
          putExtra(OpenPgpApi.EXTRA_KEY_ID, keyId)
          putExtra(OpenPgpApi.EXTRA_REQUEST_ASCII_ARMOR, asciiArmor)
        },
      input = null,
      interactionHandler = interactionHandler,
    ) { call ->
      call.output
    }

  suspend fun resolveKeyIds(
    providerPackage: String,
    userIds: Array<String>,
    interactionHandler: InteractionHandler? = null,
  ): OperationResult<LongArray> =
    executeWithInteraction(
      providerPackage = providerPackage,
      initialRequest =
        Intent(OpenPgpApi.ACTION_GET_KEY_IDS).apply {
          putExtra(OpenPgpApi.EXTRA_USER_IDS, userIds)
        },
      input = null,
      interactionHandler = interactionHandler,
    ) { call ->
      call.result.getLongArrayExtra(OpenPgpApi.RESULT_KEY_IDS) ?: longArrayOf()
    }

  private suspend fun <T> executeWithInteraction(
    providerPackage: String,
    initialRequest: Intent,
    input: ByteArray?,
    interactionHandler: InteractionHandler?,
    onSuccess: (OpenPgpApiCall) -> T,
  ): OperationResult<T> {
    var request = initialRequest

    repeat(MAX_INTERACTION_ROUNDS) {
      val call =
        try {
          executor.execute(providerPackage, request, input)
        } catch (error: CancellationException) {
          throw error
        } catch (error: Throwable) {
          return OperationResult.Failure(error)
        }

      when (call.result.getIntExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR)) {
        OpenPgpApi.RESULT_CODE_SUCCESS -> {
          return try {
            OperationResult.Success(onSuccess(call))
          } catch (error: CancellationException) {
            call.output.fill(0)
            throw error
          } catch (error: Throwable) {
            call.output.fill(0)
            OperationResult.Failure(error)
          }
        }
        OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED -> {
          @Suppress("DEPRECATION")
          val pendingIntent =
            call.result.getParcelableExtra<PendingIntent>(OpenPgpApi.RESULT_INTENT)
              ?: run {
                call.output.fill(0)
                return OperationResult.Failure(
                  IllegalStateException(
                    "OpenPGP provider requested user interaction without a PendingIntent"
                  )
                )
              }
          call.output.fill(0)
          val handler =
            interactionHandler ?: return OperationResult.UserInteractionRequired(pendingIntent)
          val interaction =
            try {
              handler.interact(pendingIntent)
            } catch (error: CancellationException) {
              throw error
            } catch (error: Throwable) {
              return OperationResult.Failure(error)
            }
          when (interaction) {
            is InteractionResult.Completed -> {
              // The OpenPGP API specifies that the result Intent contains the original operation
              // plus the provider's newly granted state. Some providers return no data after a
              // pure permission grant, in which case retrying the original request is safe.
              request = interaction.data ?: request
            }
            InteractionResult.Cancelled -> return OperationResult.Cancelled
          }
        }
        else -> {
          call.output.fill(0)
          @Suppress("DEPRECATION")
          val error = call.result.getParcelableExtra<OpenPgpError>(OpenPgpApi.RESULT_ERROR)
          return OperationResult.Failure(
            OpenPgpProviderException(error?.message ?: "OpenPGP provider operation failed")
          )
        }
      }
    }

    return OperationResult.Failure(
      IllegalStateException("OpenPGP provider requested too many interaction rounds")
    )
  }

  private companion object {
    const val MAX_INTERACTION_ROUNDS = 4
  }
}

class OpenPgpProviderException(message: String) : Exception(message)

internal data class OpenPgpApiCall(val result: Intent, val output: ByteArray)

internal interface OpenPgpApiExecutor {
  fun providers(): List<OpenPgpApiBackend.Provider>

  suspend fun execute(
    providerPackage: String,
    request: Intent,
    input: ByteArray?,
  ): OpenPgpApiCall
}

internal class BinderOpenPgpApiExecutor(private val context: Context) : OpenPgpApiExecutor {

  @Suppress("DEPRECATION")
  override fun providers(): List<OpenPgpApiBackend.Provider> {
    return context.packageManager
      .queryIntentServices(Intent(OpenPgpApi.SERVICE_INTENT_2), 0)
      .mapNotNull(::providerFromResolveInfo)
      .distinctBy { it.packageName }
      .sortedBy { it.label.lowercase() }
  }

  override suspend fun execute(
    providerPackage: String,
    request: Intent,
    input: ByteArray?,
  ): OpenPgpApiCall =
    withService(providerPackage) { service ->
      val output = ByteArrayOutputStream()
      val result =
        OpenPgpApi(context, service).executeApi(request, input?.let(::ByteArrayInputStream), output)
      OpenPgpApiCall(result, output.toByteArray())
    }

  private suspend fun <T> withService(
    providerPackage: String,
    operation: (IOpenPgpService2) -> T,
  ): T =
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
        operation(withTimeout(SERVICE_BIND_TIMEOUT_MILLIS) { service.await() })
      } finally {
        if (connection.isBound) runCatching { connection.unbindFromService() }
      }
    }

  private fun providerFromResolveInfo(info: ResolveInfo): OpenPgpApiBackend.Provider? {
    val serviceInfo = info.serviceInfo ?: return null
    val packageName = serviceInfo.packageName ?: return null
    val label =
      info.loadLabel(context.packageManager)?.toString()?.ifBlank { packageName } ?: packageName
    return OpenPgpApiBackend.Provider(packageName, label)
  }

  private companion object {
    const val SERVICE_BIND_TIMEOUT_MILLIS = 15_000L
  }
}
