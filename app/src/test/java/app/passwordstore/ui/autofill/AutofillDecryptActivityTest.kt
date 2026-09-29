/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.autofill

import android.os.Bundle
import app.passwordstore.ui.crypto.BasePGPActivity
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [23])
class AutofillDecryptActivityTest {

  @Test
  fun makeDecryptFileIntentCarriesFilePathExtra() {
    val context = RuntimeEnvironment.getApplication()
    val file = File("/tmp/test-entry.gpg")
    val forwardedExtras = Bundle()

    val intent = AutofillDecryptActivity.makeDecryptFileIntent(file, forwardedExtras, context)

    val filePathExtra = intent.getStringExtra(BasePGPActivity.EXTRA_FILE_PATH)
    assertNotNull(filePathExtra)
    assertEquals(file.absolutePath, filePathExtra)
  }
}
