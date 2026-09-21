/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.app.PendingIntent
import android.content.Intent
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.runBlocking
import org.junit.runner.RunWith
import org.openintents.openpgp.util.OpenPgpApi
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class OpenPgpApiBackendTest {

  @Test
  fun `decrypt returns provider output on success`() = runBlocking {
    val executor = FakeExecutor { _, _, _ ->
      OpenPgpApiCall(result(OpenPgpApi.RESULT_CODE_SUCCESS), byteArrayOf(1, 2, 3))
    }
    val backend = OpenPgpApiBackend(executor)

    val result = backend.decrypt("provider", byteArrayOf(9))

    assertContentEquals(
      byteArrayOf(1, 2, 3),
      assertIs<OpenPgpApiBackend.OperationResult.Success<ByteArray>>(result).value,
    )
  }

  @Test
  fun `provider continuation intent is used after user interaction`() = runBlocking {
    val pendingIntent =
      PendingIntent.getActivity(
        RuntimeEnvironment.getApplication(),
        7,
        Intent("interaction"),
        PendingIntent.FLAG_IMMUTABLE,
      )
    val seenActions = mutableListOf<String?>()
    val executor = FakeExecutor { _, request, _ ->
      seenActions += request.action
      if (seenActions.size == 1) {
        OpenPgpApiCall(
          result(OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED).apply {
            putExtra(OpenPgpApi.RESULT_INTENT, pendingIntent)
          },
          byteArrayOf(),
        )
      } else {
        OpenPgpApiCall(result(OpenPgpApi.RESULT_CODE_SUCCESS), byteArrayOf(4))
      }
    }
    val backend = OpenPgpApiBackend(executor)

    val operation =
      backend.decrypt(
        "provider",
        byteArrayOf(9),
        OpenPgpApiBackend.InteractionHandler {
          OpenPgpApiBackend.InteractionResult.Completed(Intent("continued"))
        },
      )

    assertIs<OpenPgpApiBackend.OperationResult.Success<ByteArray>>(operation)
    assertEquals(listOf(OpenPgpApi.ACTION_DECRYPT_VERIFY, "continued"), seenActions)
  }

  @Test
  fun `interaction is surfaced when no foreground handler exists`() = runBlocking {
    val pendingIntent =
      PendingIntent.getActivity(
        RuntimeEnvironment.getApplication(),
        8,
        Intent("interaction"),
        PendingIntent.FLAG_IMMUTABLE,
      )
    val executor = FakeExecutor { _, _, _ ->
      OpenPgpApiCall(
        result(OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED).apply {
          putExtra(OpenPgpApi.RESULT_INTENT, pendingIntent)
        },
        byteArrayOf(),
      )
    }

    val operation = OpenPgpApiBackend(executor).decrypt("provider", byteArrayOf(9))

    assertIs<OpenPgpApiBackend.OperationResult.UserInteractionRequired>(operation)
  }

  private fun result(code: Int): Intent = Intent().apply { putExtra(OpenPgpApi.RESULT_CODE, code) }

  private class FakeExecutor(
    private val executeBlock: suspend (String, Intent, ByteArray?) -> OpenPgpApiCall
  ) : OpenPgpApiExecutor {
    override fun providers(): List<OpenPgpApiBackend.Provider> = emptyList()

    override suspend fun execute(
      providerPackage: String,
      request: Intent,
      input: ByteArray?,
    ): OpenPgpApiCall = executeBlock(providerPackage, request, input)
  }
}
