/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.getOrElse
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock

class InMemoryPasskeyStorageTest {

  private lateinit var storage: InMemoryPasskeyStorage

  @BeforeTest
  fun setup() {
    storage = InMemoryPasskeyStorage()
  }

  @AfterTest
  fun tearDown() {
    storage.clear()
  }

  @Test
  fun `listCredentials returns empty list when empty`() = runBlocking {
    val result = storage.listCredentials()
    assertTrue(result.isOk)
    val credentials = result.getOrElse { emptyList() }
    assertTrue(credentials.isEmpty())
  }

  @Test
  fun `saveCredential and getCredential work correctly`() = runBlocking {
    val credential = createTestCredential()

    val saveResult = storage.saveCredential(credential)
    assertTrue(saveResult.isOk)

    val getResult = storage.getCredential(credential.credentialId)
    assertTrue(getResult.isOk)
    val retrieved = getResult.getOrElse { null }
    assertNotNull(retrieved)
    assertEquals(credential.rpId, retrieved.rpId)
    assertEquals(credential.user.name, retrieved.user.name)
  }

  @Test
  fun `getCredential returns null for non-existent id`() = runBlocking {
    val result = storage.getCredential("non-existent".toByteArray())
    assertTrue(result.isOk)
    val credential = result.getOrElse { null }
    assertNull(credential)
  }

  @Test
  fun `listCredentials filters by rpId`() = runBlocking {
    val cred1 =
      createTestCredential(
        rpId = "example.com",
        userName = "user1",
        credentialId = "cred1".toByteArray(),
      )
    val cred2 =
      createTestCredential(
        rpId = "example.com",
        userName = "user2",
        credentialId = "cred2".toByteArray(),
      )
    val cred3 =
      createTestCredential(
        rpId = "other.com",
        userName = "user3",
        credentialId = "cred3".toByteArray(),
      )

    storage.saveCredential(cred1)
    storage.saveCredential(cred2)
    storage.saveCredential(cred3)

    val result = storage.listCredentials("example.com")
    assertTrue(result.isOk)
    val credentials = result.getOrElse { emptyList() }
    assertEquals(2, credentials.size)
    assertTrue(credentials.all { it.rpId == "example.com" })
  }

  @Test
  fun `listCredentials returns all when rpId is null`() = runBlocking {
    val cred1 = createTestCredential(rpId = "example.com", credentialId = "cred1".toByteArray())
    val cred2 = createTestCredential(rpId = "other.com", credentialId = "cred2".toByteArray())

    storage.saveCredential(cred1)
    storage.saveCredential(cred2)

    val result = storage.listCredentials(null)
    assertTrue(result.isOk)
    val credentials = result.getOrElse { emptyList() }
    assertEquals(2, credentials.size)
  }

  @Test
  fun `deleteCredential removes credential`() = runBlocking {
    val credential = createTestCredential()
    storage.saveCredential(credential)

    val deleteResult = storage.deleteCredential(credential.credentialId)
    assertTrue(deleteResult.isOk)
    assertTrue(deleteResult.getOrElse { false })

    val getResult = storage.getCredential(credential.credentialId)
    assertTrue(getResult.isOk)
    assertNull(getResult.getOrElse { null })
  }

  @Test
  fun `deleteCredential returns false for non-existent`() = runBlocking {
    val result = storage.deleteCredential("non-existent".toByteArray())
    assertTrue(result.isOk)
    assertFalse(result.getOrElse { true })
  }

  @Test
  fun `updateSignCount updates sign count`() = runBlocking {
    val credential = createTestCredential()
    storage.saveCredential(credential)

    val updateResult = storage.updateSignCount(credential.credentialId, 5u)
    assertTrue(updateResult.isOk)

    val getResult = storage.getCredential(credential.credentialId)
    assertTrue(getResult.isOk)
    val updated = getResult.getOrElse { null }
    assertNotNull(updated)
    assertEquals(5u, updated.signCount)
  }

  @Test
  fun `updateSignCount fails for non-existent credential`() = runBlocking {
    val result = storage.updateSignCount("non-existent".toByteArray(), 1u)
    assertTrue(result.isErr)
  }

  @Test
  fun `count tracks stored credentials`() = runBlocking {
    assertEquals(0, storage.count())

    storage.saveCredential(createTestCredential(credentialId = "cred1".toByteArray()))
    assertEquals(1, storage.count())

    storage.saveCredential(createTestCredential(credentialId = "cred2".toByteArray()))
    assertEquals(2, storage.count())

    storage.clear()
    assertEquals(0, storage.count())
  }

  @Test
  fun `saveCredential overwrites existing with same id`() = runBlocking {
    val credential = createTestCredential()
    storage.saveCredential(credential)

    val updated = credential.copy(signCount = 10u)
    storage.saveCredential(updated)

    val result = storage.getCredential(credential.credentialId)
    assertTrue(result.isOk)
    val retrieved = result.getOrElse { null }
    assertNotNull(retrieved)
    assertEquals(10u, retrieved.signCount)
    assertEquals(1, storage.count())
  }

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
}
