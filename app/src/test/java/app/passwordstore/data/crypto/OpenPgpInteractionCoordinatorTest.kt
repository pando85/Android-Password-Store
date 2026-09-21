/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.app.PendingIntent
import android.content.Intent
import kotlin.test.Test
import kotlin.test.assertIs
import kotlinx.coroutines.runBlocking
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class OpenPgpInteractionCoordinatorTest {

  @Test
  fun `handler is visible only inside its coroutine scope`(): Unit = runBlocking {
    val coordinator = OpenPgpInteractionCoordinator()
    val pendingIntent =
      PendingIntent.getActivity(
        RuntimeEnvironment.getApplication(),
        9,
        Intent("interaction"),
        PendingIntent.FLAG_IMMUTABLE,
      )

    assertIs<OpenPgpApiBackend.InteractionResult.Cancelled>(coordinator.interact(pendingIntent))

    coordinator.withHandler(
      OpenPgpApiBackend.InteractionHandler {
        OpenPgpApiBackend.InteractionResult.Completed(Intent("completed"))
      }
    ) {
      assertIs<OpenPgpApiBackend.InteractionResult.Completed>(coordinator.interact(pendingIntent))
    }

    assertIs<OpenPgpApiBackend.InteractionResult.Cancelled>(coordinator.interact(pendingIntent))
  }
}
