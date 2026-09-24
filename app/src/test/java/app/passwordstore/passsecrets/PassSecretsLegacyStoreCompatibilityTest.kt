/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passsecrets

import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNull
import org.junit.Rule
import org.junit.rules.TemporaryFolder

/** Regression coverage for password-store layouts that predate Pass-Secrets integration. */
class PassSecretsLegacyStoreCompatibilityTest {

  @get:Rule val tempFolder = TemporaryFolder()

  private lateinit var root: File

  @BeforeTest
  fun setup() {
    PassSecretsMapStore.clear()
    root = tempFolder.newFolder("store")
  }

  @AfterTest
  fun tearDown() {
    PassSecretsMapStore.clear()
  }

  @Test
  fun `independent nested identities without Pass-Secrets metadata remain untouched`() {
    val hg = identity("ID-Pessoal/HG")
    val vupon = identity("ID-Pessoal/Vupon")
    val work = identity("ID-Work/ORGs")

    assertNull(PassSecretsMapStore.claimForDirectory(hg, root))
    assertNull(PassSecretsMapStore.claimForDirectory(vupon, root))
    assertNull(PassSecretsMapStore.claimForDirectory(work, root))
    assertFalse(File(root, ".gpg-id").exists())
  }

  private fun identity(relativePath: String): File {
    val directory = File(root, relativePath).apply { mkdirs() }
    File(directory, ".gpg-id").writeText("0123456789ABCDEF\n")
    return directory
  }
}
