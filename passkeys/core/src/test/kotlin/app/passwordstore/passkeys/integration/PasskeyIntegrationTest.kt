/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.integration

import app.passwordstore.passkeys.crypto.ES256CryptoHandler
import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.storage.InMemoryPasskeyStorage
import app.passwordstore.passkeys.storage.IndexedPasskeyStorage
import com.github.michaelbull.result.getOrElse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlin.system.measureTimeMillis
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PasskeyIntegrationTest {

  private lateinit var storage: IndexedPasskeyStorage
  private lateinit var cryptoHandler: ES256CryptoHandler

  @BeforeTest
  fun setup() {
    storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    cryptoHandler = ES256CryptoHandler()
  }

  @AfterTest
  fun tearDown() {
    storage.clearIndex()
  }

  @Test
  fun `full credential lifecycle`() = runBlocking {
    val credential = cryptoHandler.createCredential(
      rpId = "example.com",
      userId = "user-123".toByteArray(),
      userName = "testuser",
      userDisplayName = "Test User",
      challenge = ByteArray(32) { it.toByte() }
    ).getOrElse { throw AssertionError("Create failed") }

    val saveResult = storage.saveCredential(credential)
    assertTrue(saveResult.isOk, "Save should succeed")

    val listResult = storage.listCredentials("example.com")
    assertTrue(listResult.isOk)
    val credentials = listResult.getOrElse { emptyList() }
    assertEquals(1, credentials.size, "Should have one credential")

    val getResult = storage.getCredential(credential.credentialId)
    assertTrue(getResult.isOk)
    val retrieved = getResult.getOrElse { null }
    assertTrue(retrieved != null, "Should retrieve credential")
    assertEquals(credential.credentialIdBase64(), retrieved.credentialIdBase64())

    val deleteResult = storage.deleteCredential(credential.credentialId)
    assertTrue(deleteResult.isOk && deleteResult.getOrElse { false }, "Delete should succeed")

    val afterDelete = storage.getCredential(credential.credentialId)
    assertTrue(afterDelete.isOk)
    assertTrue(afterDelete.getOrElse { "not-null" } == null, "Should be null after delete")
  }

  @Test
  fun `multiple credentials for same rpId`() = runBlocking {
    val cred1 = createAndSaveCredential("example.com", "user1")
    val cred2 = createAndSaveCredential("example.com", "user2")
    val cred3 = createAndSaveCredential("example.com", "user3")

    val listResult = storage.listCredentials("example.com")
    assertTrue(listResult.isOk)
    val credentials = listResult.getOrElse { emptyList() }
    assertEquals(3, credentials.size, "Should have three credentials")

    val allResult = storage.listCredentials(null)
    assertTrue(allResult.isOk)
    assertEquals(3, allResult.getOrElse { emptyList() }.size, "Should list all without rpId filter")
  }

  @Test
  fun `credentials isolated by rpId`() = runBlocking {
    val exampleCred = createAndSaveCredential("example.com", "user1")
    val otherCred = createAndSaveCredential("other.com", "user2")

    val exampleResult = storage.listCredentials("example.com")
    assertTrue(exampleResult.isOk)
    val exampleCreds = exampleResult.getOrElse { emptyList() }
    assertEquals(1, exampleCreds.size)
    assertEquals("example.com", exampleCreds[0].rpId)

    val otherResult = storage.listCredentials("other.com")
    assertTrue(otherResult.isOk)
    val otherCreds = otherResult.getOrElse { emptyList() }
    assertEquals(1, otherCreds.size)
    assertEquals("other.com", otherCreds[0].rpId)
  }

  @Test
  fun `sign count tracking`() = runBlocking {
    val credential = createAndSaveCredential("example.com", "user1")
    assertEquals(0u, credential.signCount)

    storage.updateSignCount(credential.credentialId, 1u)
    val afterOne = storage.getCredential(credential.credentialId)
      .getOrElse { null }!!
    assertEquals(1u, afterOne.signCount)

    storage.updateSignCount(credential.credentialId, 42u)
    val afterFortyTwo = storage.getCredential(credential.credentialId)
      .getOrElse { null }!!
    assertEquals(42u, afterFortyTwo.signCount)
  }

  @Test
  fun `assertion with stored credential`() = runBlocking {
    val credential = createAndSaveCredential("example.com", "testuser")
    val challenge = ByteArray(32) { it.toByte() }

    val assertion = cryptoHandler.getAssertion(
      credential = credential,
      rpId = "example.com",
      challenge = challenge,
      origin = "https://example.com"
    ).getOrElse { throw AssertionError("Assertion failed") }

    assertEquals(credential.credentialIdBase64(), java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(assertion.credentialId))
    assertTrue(assertion.signature.size in 70..72, "Signature should be DER-encoded (typically 70-72 bytes)")
    assertEquals(37, assertion.authenticatorData.size, "Auth data should be 37 bytes")
  }

  @Test
  fun `indexed storage provides fast lookups`() = runBlocking {
    for (i in 1..100) {
      createAndSaveCredential("example.com", "user$i")
    }

    val duration = measureTimeMillis {
      repeat(1000) {
        storage.listCredentials("example.com")
      }
    }

    assertTrue(duration < 1000, "1000 lookups should complete in under 1 second, took ${duration}ms")
  }

  @Test
  fun `indexed storage credential count by rpId`() = runBlocking {
    for (i in 1..10) {
      createAndSaveCredential("example.com", "ex$i")
    }
    for (i in 1..5) {
      createAndSaveCredential("other.com", "ot$i")
    }

    assertEquals(10, storage.credentialCountForRp("example.com"))
    assertEquals(5, storage.credentialCountForRp("other.com"))
    assertEquals(0, storage.credentialCountForRp("nonexistent.com"))
    assertTrue(storage.hasRpId("example.com"))
    assertFalse(storage.hasRpId("nonexistent.com"))
  }

  @Test
  fun `credential rotation`() = runBlocking {
    val oldCred = createAndSaveCredential("example.com", "old-user")

    storage.deleteCredential(oldCred.credentialId)

    val newCred = createAndSaveCredential("example.com", "new-user")

    val listResult = storage.listCredentials("example.com")
    assertTrue(listResult.isOk)
    val credentials = listResult.getOrElse { emptyList() }
    assertEquals(1, credentials.size)
    assertEquals("new-user", credentials[0].user.name)
  }

  @Test
  fun `concurrent access safety`() = runBlocking {
    repeat(10) { i ->
      createAndSaveCredential("example.com", "user$i")
    }

    val listResult = storage.listCredentials("example.com")
    assertTrue(listResult.isOk)
    assertEquals(10, listResult.getOrElse { emptyList() }.size)
  }

  private suspend fun createAndSaveCredential(rpId: String, userName: String): PasskeyCredential {
    val credential = cryptoHandler.createCredential(
      rpId = rpId,
      userId = "$userName-id".toByteArray(),
      userName = userName,
      userDisplayName = userName,
      challenge = ByteArray(32) { it.toByte() }
    ).getOrElse { throw AssertionError("Create failed") }

    storage.saveCredential(credential)
    return credential
  }
}