/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.autofill

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class AutofillPasskeyExclusionTest {

  @get:Rule val tempFolder = TemporaryFolder()

  @Test
  fun passkeyCredentialFilesAreExcluded() {
    val root = tempFolder.newFolder("store")
    val passkey = File(root, "fido2/example.org/0123abcd.gpg")
    assertTrue(AutofillPasskeyExclusion.isPasskeyCredentialFile(passkey, root))
    assertTrue(
      AutofillPasskeyExclusion.isPasskeyCredentialFile(passkey, root, resolveLinks = false)
    )
  }

  @Test
  fun classicPasswordFilesAreNotExcluded() {
    val root = tempFolder.newFolder("store")
    listOf("example.org.gpg", "web/example.org/john.gpg", "fido2.gpg", "web/fido2/john.gpg")
      .map { File(root, it) }
      .forEach { assertFalse(AutofillPasskeyExclusion.isPasskeyCredentialFile(it, root)) }
    assertFalse(AutofillPasskeyExclusion.isPasskeyCredentialFile(File(root, "fido2x/a.gpg"), root))
  }

  @Test
  fun pathTraversalIntoPasskeyDirectoryIsExcluded() {
    val root = tempFolder.newFolder("store")
    val file = File(root, "web/../fido2/example.org/0123abcd.gpg")
    assertTrue(AutofillPasskeyExclusion.isPasskeyCredentialFile(file, root, resolveLinks = false))
  }

  @Test
  fun symbolicLinkIntoPasskeyDirectoryIsExcluded() {
    val root = tempFolder.newFolder("store")
    val target = File(root, "fido2/example.org").apply { mkdirs() }
    File(target, "0123abcd.gpg").writeText("x")
    val link = File(root, "web/example.org")
    link.parentFile.mkdirs()
    Files.createSymbolicLink(link.toPath(), target.toPath())
    assertTrue(AutofillPasskeyExclusion.isPasskeyCredentialFile(File(link, "0123abcd.gpg"), root))
  }
}
