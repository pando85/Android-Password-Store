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
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlinx.coroutines.runBlocking
import org.junit.runner.RunWith
import org.openintents.openpgp.util.OpenPgpApi
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class OpenPgpApiBackendTest {

  @Test
  fun `decrypt returns provider output on success`(): Unit = runBlocking {
    val executor = FakeExecutor { _, _, _, _ ->
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
  fun `decrypt forwards the caller output limit`(): Unit = runBlocking {
    var seenLimit = 0L
    val executor = FakeExecutor { _, _, _, maxOutputBytes ->
      seenLimit = maxOutputBytes
      OpenPgpApiCall(result(OpenPgpApi.RESULT_CODE_SUCCESS), byteArrayOf(1))
    }
    val backend = OpenPgpApiBackend(executor)

    backend.decrypt("provider", byteArrayOf(9), maxOutputBytes = 1234L)

    assertEquals(1234L, seenLimit)
  }

  @Test
  fun `bounded provider output remembers overflow after the write fails`() {
    val output = BoundedByteArrayOutputStream(3)
    output.write(byteArrayOf(1, 2, 3))

    assertFailsWith<OpenPgpOutputLimitExceededException> { output.write(4) }
    assertFailsWith<OpenPgpOutputLimitExceededException> { output.throwIfLimitExceeded() }
    output.wipe()
  }

  @Test
  fun `provider continuation intent is used after user interaction`(): Unit = runBlocking {
    val pendingIntent =
      PendingIntent.getActivity(
        RuntimeEnvironment.getApplication(),
        7,
        Intent("interaction"),
        PendingIntent.FLAG_IMMUTABLE,
      )
    val seenActions = mutableListOf<String?>()
    val executor = FakeExecutor { _, request, _, _ ->
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
    assertEquals(
      listOf<String?>(OpenPgpApi.ACTION_DECRYPT_VERIFY, "continued"),
      seenActions,
    )
  }

  @Test
  fun `interaction is surfaced when no foreground handler exists`(): Unit = runBlocking {
    val pendingIntent =
      PendingIntent.getActivity(
        RuntimeEnvironment.getApplication(),
        8,
        Intent("interaction"),
        PendingIntent.FLAG_IMMUTABLE,
      )
    val executor = FakeExecutor { _, _, _, _ ->
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
    private val executeBlock: suspend (String, Intent, ByteArray?, Long) -> OpenPgpApiCall
  ) : OpenPgpApiExecutor {
    override fun providers(): List<OpenPgpApiBackend.Provider> = emptyList()

    override suspend fun execute(
      providerPackage: String,
      request: Intent,
      input: ByteArray?,
      maxOutputBytes: Long,
    ): OpenPgpApiCall = executeBlock(providerPackage, request, input, maxOutputBytes)
  }
}
