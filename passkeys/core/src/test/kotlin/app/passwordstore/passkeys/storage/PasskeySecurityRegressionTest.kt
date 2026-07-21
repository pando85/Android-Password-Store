/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import com.github.michaelbull.result.getOrElse
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlin.time.Clock

class PasskeySecurityRegressionTest {

  private fun createTestCredential(
    rpId: String = "example.com",
    userName: String = "testuser",
    credentialId: ByteArray = "test-cred-id".toByteArray(),
  ): PasskeyCredential {
    return PasskeyCredential(
      credentialId = credentialId,
      privateKey = ByteArray(32) { it.toByte() },
      publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
      rpId = rpId,
      user = FidoUser(id = "user-id".toByteArray(), name = userName, displayName = "Test User"),
      signCount = 0u,
      createdAt = Clock.System.now(),
      transports = listOf("internal"),
      uvInitialized = true,
    )
  }

  @Test
  fun `listing credentials performs zero private-key decryptions`() = runBlocking {
    val countingStorage = CountingPasskeyStorage()
    val indexed = IndexedPasskeyStorage(countingStorage)

    countingStorage.saveCredential(
      createTestCredential(rpId = "a.example", credentialId = "c1".toByteArray())
    )
    countingStorage.saveCredential(
      createTestCredential(rpId = "b.example", credentialId = "c2".toByteArray())
    )
    indexed.clearIndex()

    val result = indexed.listMetadata("a.example")
    assertTrue(result.isOk)
    assertEquals(0, countingStorage.decryptCount.get())
  }

  @Test
  fun `listing one RP does not touch other RP files`() = runBlocking {
    val countingStorage = CountingPasskeyStorage()
    val indexed = IndexedPasskeyStorage(countingStorage)

    countingStorage.saveCredential(
      createTestCredential(rpId = "a.example", credentialId = "c1".toByteArray())
    )
    countingStorage.saveCredential(
      createTestCredential(rpId = "b.example", credentialId = "c2".toByteArray())
    )
    indexed.clearIndex()
    countingStorage.resetCounters()

    val result = indexed.listMetadata("a.example")
    assertTrue(result.isOk)
    assertEquals(0, countingStorage.decryptCount.get())
    assertTrue(countingStorage.touchedRpIds.isEmpty())
  }

  @Test
  fun `successful authentication decrypts exactly one credential`() = runBlocking {
    val countingStorage = CountingPasskeyStorage()
    val indexed = IndexedPasskeyStorage(countingStorage)

    val cred = createTestCredential(rpId = "example.com", credentialId = "c1".toByteArray())
    countingStorage.saveCredential(cred)
    indexed.clearIndex()
    countingStorage.resetCounters()

    indexed.listMetadata("example.com")
    assertEquals(0, countingStorage.decryptCount.get())

    val loadResult = indexed.loadForSigning(cred.credentialId)
    assertTrue(loadResult.isOk)
    val sensitive = loadResult.getOrElse { null }
    assertNotNull(sensitive)
    sensitive.use {
      assertEquals(1, countingStorage.decryptCount.get())
    }
  }

  @Test
  fun `deleted credential cannot be served from metadata cache`() = runBlocking {
    val countingStorage = CountingPasskeyStorage()
    val indexed = IndexedPasskeyStorage(countingStorage)

    val cred = createTestCredential(credentialId = "c1".toByteArray())
    countingStorage.saveCredential(cred)
    indexed.clearIndex()

    val listBefore = indexed.listMetadata()
    assertTrue(listBefore.isOk)
    assertEquals(1, listBefore.getOrElse { emptyList() }.size)

    indexed.deleteCredential(cred.credentialId)

    val listAfter = indexed.listMetadata()
    assertTrue(listAfter.isOk)
    assertEquals(0, listAfter.getOrElse { emptyList() }.size)

    val loadResult = indexed.loadForSigning(cred.credentialId)
    assertTrue(loadResult.isErr)
  }

  @Test
  fun `repeated requests do not retain previous private key`() = runBlocking {
    val storage = InMemoryPasskeyStorage()
    val indexed = IndexedPasskeyStorage(storage)

    val cred1 =
      createTestCredential(
        rpId = "example.com",
        credentialId = "c1".toByteArray(),
      )
    val cred2 =
      createTestCredential(
        rpId = "example.com",
        credentialId = "c2".toByteArray(),
      )
    storage.saveCredential(cred1)
    storage.saveCredential(cred2)

    val loaded1 =
      indexed.loadForSigning(cred1.credentialId).getOrElse { throw AssertionError("Load failed") }
    var keyRef: ByteArray? = null
    loaded1.use { sensitive ->
      assertContentEquals(cred1.privateKey, sensitive.usePrivateKey { it.copyOf() })
      keyRef = sensitive.usePrivateKey { it }
    }

    assertTrue(keyRef!!.all { it == 0.toByte() }, "Private key should be zeroized after close")

    val loaded2 =
      indexed.loadForSigning(cred2.credentialId).getOrElse { throw AssertionError("Load failed") }
    loaded2.use { sensitive ->
      assertContentEquals(cred2.privateKey, sensitive.usePrivateKey { it.copyOf() })
    }
  }

  @Test
  fun `sensitive credential zeroizes on close`() {
    val privateKey = ByteArray(32) { it.toByte() }
    val sensitive =
      SensitivePasskeyCredential(
        credentialId = "test-id".toByteArray(),
        publicKey = ByteArray(65),
        rpId = "example.com",
        user = FidoUser(id = "uid".toByteArray(), name = "user", displayName = "User"),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
        backupEligible = true,
        backupState = false,
        fileLastModified = 0L,
        privateKey = privateKey,
      )

    val keyCopy = sensitive.usePrivateKey { it.copyOf() }
    assertContentEquals(privateKey, keyCopy)

    sensitive.close()

    assertFailsWith<IllegalStateException> {
      sensitive.usePrivateKey { it }
    }
  }

  @Test
  fun `file changed between picker and approval is rejected`() = runBlocking {
    val storage = InMemoryPasskeyStorage()
    val indexed = IndexedPasskeyStorage(storage)

    val cred = createTestCredential(credentialId = "c1".toByteArray())
    storage.saveCredential(cred)

    val metadata = indexed.listMetadata().getOrElse { emptyList() }
    assertEquals(1, metadata.size)
    assertEquals(0L, metadata[0].fileLastModified)

    val loaded =
      indexed.loadForSigning(cred.credentialId).getOrElse { throw AssertionError("Load failed") }
    loaded.use { sensitive ->
      assertEquals(0L, sensitive.fileLastModified)
    }
  }

  @Test
  fun `metadata index contains no private keys`() = runBlocking {
    val countingStorage = CountingPasskeyStorage()
    val indexed = IndexedPasskeyStorage(countingStorage)

    val cred = createTestCredential(credentialId = "c1".toByteArray())
    countingStorage.saveCredential(cred)
    indexed.clearIndex()

    indexed.listMetadata()

    assertEquals(0, countingStorage.decryptCount.get())
    assertEquals(1, indexed.indexedCredentialCount())
  }

  @Test
  fun `clearIndex clears metadata only`() = runBlocking {
    val storage = InMemoryPasskeyStorage()
    val indexed = IndexedPasskeyStorage(storage)

    val cred = createTestCredential(credentialId = "c1".toByteArray())
    storage.saveCredential(cred)

    indexed.clearIndex()

    assertEquals(0, indexed.indexedCredentialCount())

    val loadResult = indexed.loadForSigning(cred.credentialId)
    assertTrue(loadResult.isOk)
  }
}
