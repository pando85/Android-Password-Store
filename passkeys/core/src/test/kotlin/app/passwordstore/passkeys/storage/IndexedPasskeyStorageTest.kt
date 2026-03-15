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
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock

class IndexedPasskeyStorageTest {

  private lateinit var delegateStorage: InMemoryPasskeyStorage
  private lateinit var indexedStorage: IndexedPasskeyStorage

  @BeforeTest
  fun setup() {
    delegateStorage = InMemoryPasskeyStorage()
    indexedStorage = IndexedPasskeyStorage(delegateStorage)
  }

  @AfterTest
  fun tearDown() {
    indexedStorage.clearIndex()
    delegateStorage.clear()
  }

  @Test
  fun `index starts empty`() {
    assertEquals(0, indexedStorage.indexedCredentialCount())
    assertFalse(indexedStorage.hasRpId("example.com"))
  }

  @Test
  fun `saveCredential indexes credential`() = runBlocking {
    val credential = createTestCredential()

    indexedStorage.saveCredential(credential)

    assertEquals(1, indexedStorage.indexedCredentialCount())
    assertTrue(indexedStorage.hasRpId(credential.rpId))
    assertEquals(1, indexedStorage.credentialCountForRp(credential.rpId))
  }

  @Test
  fun `getCredential returns from index after save`() = runBlocking {
    val credential = createTestCredential()
    indexedStorage.saveCredential(credential)

    val result = indexedStorage.getCredential(credential.credentialId)

    assertTrue(result.isOk)
    val retrieved = result.getOrElse { null }
    assertEquals(credential.credentialIdBase64(), retrieved?.credentialIdBase64())
  }

  @Test
  fun `listCredentials filters by rpId from index`() = runBlocking {
    val cred1 = createTestCredential(rpId = "example.com", credentialId = "cred1".toByteArray())
    val cred2 = createTestCredential(rpId = "example.com", credentialId = "cred2".toByteArray())
    val cred3 = createTestCredential(rpId = "other.com", credentialId = "cred3".toByteArray())

    indexedStorage.saveCredential(cred1)
    indexedStorage.saveCredential(cred2)
    indexedStorage.saveCredential(cred3)

    val result = indexedStorage.listCredentials("example.com")

    assertTrue(result.isOk)
    val credentials = result.getOrElse { emptyList() }
    assertEquals(2, credentials.size)
    assertTrue(credentials.all { it.rpId == "example.com" })
  }

  @Test
  fun `deleteCredential removes from index`() = runBlocking {
    val credential = createTestCredential()
    indexedStorage.saveCredential(credential)

    indexedStorage.deleteCredential(credential.credentialId)

    assertEquals(0, indexedStorage.indexedCredentialCount())
    assertFalse(indexedStorage.hasRpId(credential.rpId))
  }

  @Test
  fun `updateSignCount updates index`() = runBlocking {
    val credential = createTestCredential()
    indexedStorage.saveCredential(credential)

    indexedStorage.updateSignCount(credential.credentialId, 42u)

    val result = indexedStorage.getCredential(credential.credentialId)
    assertTrue(result.isOk)
    val updated = result.getOrElse { null }
    assertEquals(42u, updated?.signCount)
  }

  @Test
  fun `indexedRpIds returns all rp ids`() = runBlocking {
    indexedStorage.saveCredential(createTestCredential(rpId = "example.com"))
    indexedStorage.saveCredential(createTestCredential(rpId = "other.com"))

    val rpIds = indexedStorage.indexedRpIds()

    assertEquals(setOf("example.com", "other.com"), rpIds)
  }

  @Test
  fun `clearIndex resets everything`() = runBlocking {
    indexedStorage.saveCredential(createTestCredential())

    indexedStorage.clearIndex()

    assertEquals(0, indexedStorage.indexedCredentialCount())
    assertTrue(indexedStorage.indexedRpIds().isEmpty())
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
      user = FidoUser(
        id = "user-id".toByteArray(),
        name = userName,
        displayName = "Test User"
      ),
      signCount = 0u,
      createdAt = Clock.System.now(),
      transports = listOf("internal"),
      uvInitialized = true,
    )
  }
}