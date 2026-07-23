/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.KeyUtils.tryGetKeyId
import app.passwordstore.passkeys.storage.RecipientPolicyError
import com.github.michaelbull.result.unwrap
import com.github.michaelbull.result.unwrapError
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class DefaultPassRecipientResolverTest {

  @get:Rule val temporaryFolder: TemporaryFolder = TemporaryFolder()

  private val rootDir by lazy { temporaryFolder.root }
  private val keyManager by lazy { PGPKeyManager(rootDir.absolutePath) }
  private val secretKey = PGPKey(TestUtils.getArmoredSecretKey())
  private val secretKeyMultipleIdentities =
    PGPKey(TestUtils.getArmoredSecretKeyWithMultipleIdentities())

  private fun resolver(): DefaultPassRecipientResolver =
    DefaultPassRecipientResolver(rootDir, keyManager)

  private fun keyFingerprint(): String {
    val keyId = tryGetKeyId(secretKey)!!
    return keyId.toString()
  }

  @Test
  fun `root gpg-id with one key resolves to that key`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()
    File(rootDir, ".gpg-id").writeText("${keyFingerprint()}\n")

    val target = File(rootDir, "fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    val keys = result.unwrap()
    assertEquals(1, keys.size)
    assertEquals(tryGetKeyId(secretKey), tryGetKeyId(keys.first()))
  }

  @Test
  fun `imported unrelated key never appears in recipients`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()
    keyManager.addKey(secretKeyMultipleIdentities, true).unwrap()

    File(rootDir, ".gpg-id").writeText("${keyFingerprint()}\n")

    val target = File(rootDir, "fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    val keys = result.unwrap()
    assertEquals(1, keys.size)
    assertEquals(tryGetKeyId(secretKey), tryGetKeyId(keys.first()))
  }

  @Test
  fun `nested gpg-id overrides root policy`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()
    keyManager.addKey(secretKeyMultipleIdentities, true).unwrap()

    val rootKeyId = tryGetKeyId(secretKey)!!.toString()
    val nestedKeyId = tryGetKeyId(secretKeyMultipleIdentities)!!.toString()

    File(rootDir, ".gpg-id").writeText("$rootKeyId\n")

    val workDir = File(rootDir, "work")
    workDir.mkdirs()
    File(workDir, ".gpg-id").writeText("$nestedKeyId\n")

    val target = File(rootDir, "work/fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    val keys = result.unwrap()
    assertEquals(1, keys.size)
    assertEquals(tryGetKeyId(secretKeyMultipleIdentities), tryGetKeyId(keys.first()))
  }

  @Test
  fun `multiple recipients in gpg-id resolves exactly those recipients`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()
    keyManager.addKey(secretKeyMultipleIdentities, true).unwrap()

    val rootKeyId = tryGetKeyId(secretKey)!!.toString()
    val nestedKeyId = tryGetKeyId(secretKeyMultipleIdentities)!!.toString()

    File(rootDir, ".gpg-id").writeText("$rootKeyId\n$nestedKeyId\n")

    val target = File(rootDir, "fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    val keys = result.unwrap()
    assertEquals(2, keys.size)
    val resolvedIds = keys.map { tryGetKeyId(it) }.toSet()
    assertTrue(resolvedIds.contains(tryGetKeyId(secretKey)))
    assertTrue(resolvedIds.contains(tryGetKeyId(secretKeyMultipleIdentities)))
  }

  @Test
  fun `duplicate identifiers deduplicated by fingerprint`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()

    val keyId = keyFingerprint()
    File(rootDir, ".gpg-id").writeText("$keyId\n$keyId\n")

    val target = File(rootDir, "fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    val keys = result.unwrap()
    assertEquals(1, keys.size)
  }

  @Test
  fun `missing gpg-id fails with GpgIdNotFound`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()

    val target = File(rootDir, "fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    assertTrue(result.isErr)
    assertIs<RecipientPolicyError.GpgIdNotFound>(result.unwrapError())
  }

  @Test
  fun `empty gpg-id fails with EmptyRecipientSet`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()
    File(rootDir, ".gpg-id").writeText("\n\n")

    val target = File(rootDir, "fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    assertTrue(result.isErr)
    assertIs<RecipientPolicyError.EmptyRecipientSet>(result.unwrapError())
  }

  @Test
  fun `comment-only gpg-id fails with EmptyRecipientSet`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()
    File(rootDir, ".gpg-id").writeText("# this is a comment\n")

    val target = File(rootDir, "fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    assertTrue(result.isErr)
    assertIs<RecipientPolicyError.EmptyRecipientSet>(result.unwrapError())
  }

  @Test
  fun `unknown key fails with RecipientNotFound`() = runTest {
    File(rootDir, ".gpg-id").writeText("DEADBEEFDEADBEEF\n")

    val target = File(rootDir, "fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    assertTrue(result.isErr)
    assertIs<RecipientPolicyError.RecipientNotFound>(result.unwrapError())
  }

  @Test
  fun `ambiguous short key ID fails with AmbiguousRecipient`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()
    File(rootDir, ".gpg-id").writeText("12345678\n")

    val target = File(rootDir, "fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    assertTrue(result.isErr)
    assertIs<RecipientPolicyError.AmbiguousRecipient>(result.unwrapError())
  }

  @Test
  fun `malformed identifier fails with MalformedGpgId`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()
    File(rootDir, ".gpg-id").writeText("   \n\n")

    val target = File(rootDir, "fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    assertTrue(result.isErr)
    assertIs<RecipientPolicyError.EmptyRecipientSet>(result.unwrapError())
  }

  @Test
  fun `target outside repository fails with TargetOutsideRepository`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()
    File(rootDir, ".gpg-id").writeText("${keyFingerprint()}\n")

    val separateFolder = TemporaryFolder()
    separateFolder.create()
    try {
      val outsideTarget = File(separateFolder.root, "cred.gpg")

      val outsideResolver = DefaultPassRecipientResolver(rootDir, keyManager)
      val result = outsideResolver.resolveFor(outsideTarget)
      assertTrue(result.isErr)
      assertIs<RecipientPolicyError.TargetOutsideRepository>(result.unwrapError())
    } finally {
      separateFolder.delete()
    }
  }

  @Test
  fun `gpg-id with inline comments parses correctly`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()
    File(rootDir, ".gpg-id").writeText("${keyFingerprint()} # my key\n")

    val target = File(rootDir, "fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    val keys = result.unwrap()
    assertEquals(1, keys.size)
  }

  @Test
  fun `gpg-id with subkey marker parses correctly`() = runTest {
    keyManager.addKey(secretKey, true).unwrap()
    File(rootDir, ".gpg-id").writeText("${keyFingerprint()}!\n")

    val target = File(rootDir, "fido2/example.com/cred.gpg")
    target.parentFile.mkdirs()

    val result = resolver().resolveFor(target)
    val keys = result.unwrap()
    assertEquals(1, keys.size)
  }
}
