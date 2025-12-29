/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey

import app.passwordstore.util.coroutines.DispatcherProvider
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest

class PasskeyRepositoryTest {

  private lateinit var tempDir: File
  private lateinit var repository: PasskeyRepository

  private val testDispatcherProvider = object : DispatcherProvider {
    override fun io(): CoroutineDispatcher = Dispatchers.Unconfined
    override fun default(): CoroutineDispatcher = Dispatchers.Unconfined
    override fun main(): CoroutineDispatcher = Dispatchers.Unconfined
    override fun mainImmediate(): CoroutineDispatcher = Dispatchers.Unconfined
    override fun unconfined(): CoroutineDispatcher = Dispatchers.Unconfined
  }

  @BeforeTest
  fun setup() {
    tempDir = createTempDir("passkey_test_")
    repository = PasskeyRepository(testDispatcherProvider)
  }

  @AfterTest
  fun tearDown() {
    tempDir.deleteRecursively()
  }

  @Test
  fun storeAndLoadCredential() = runTest {
    val credentialId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
    val rpId = "example.com"
    val encryptedData = "encrypted_cbor_data".toByteArray()

    repository.storeCredential(tempDir, rpId, credentialId, encryptedData)
    val loaded = repository.loadCredential(tempDir, credentialId)

    assertNotNull(loaded)
    assertTrue(encryptedData.contentEquals(loaded))
  }

  @Test
  fun loadCredentialByRpIdAndCredentialId() = runTest {
    val credentialId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
    val rpId = "example.com"
    val encryptedData = "encrypted_cbor_data".toByteArray()

    repository.storeCredential(tempDir, rpId, credentialId, encryptedData)
    val loaded = repository.loadCredential(tempDir, rpId, credentialId)

    assertNotNull(loaded)
    assertTrue(encryptedData.contentEquals(loaded))
  }

  @Test
  fun loadNonExistentCredentialReturnsNull() = runTest {
    val nonExistentId = byteArrayOf(99, 99, 99, 99)

    val loaded = repository.loadCredential(tempDir, nonExistentId)

    assertNull(loaded)
  }

  @Test
  fun loadFromNonExistentDirectoryReturnsNull() = runTest {
    val nonExistentDir = File(tempDir, "non_existent")
    val credentialId = byteArrayOf(1, 2, 3, 4)

    val loaded = repository.loadCredential(nonExistentDir, credentialId)

    assertNull(loaded)
  }

  @Test
  fun deleteCredential() = runTest {
    val credentialId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
    val rpId = "example.com"
    val encryptedData = "encrypted_cbor_data".toByteArray()

    repository.storeCredential(tempDir, rpId, credentialId, encryptedData)

    // Verify it exists
    assertNotNull(repository.loadCredential(tempDir, credentialId))

    // Delete it
    val deleted = repository.deleteCredential(tempDir, credentialId)

    assertTrue(deleted)
    // Verify it's gone
    assertNull(repository.loadCredential(tempDir, credentialId))
  }

  @Test
  fun deleteCredentialRemovesEmptyRpDirectory() = runTest {
    val credentialId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
    val rpId = "example.com"
    val encryptedData = "encrypted_cbor_data".toByteArray()

    repository.storeCredential(tempDir, rpId, credentialId, encryptedData)

    // Verify RP directory exists
    val rpDir = File(File(tempDir, "passless"), rpId)
    assertTrue(rpDir.exists())

    // Delete credential
    repository.deleteCredential(tempDir, credentialId)

    // RP directory should be deleted since it's empty
    assertTrue(!rpDir.exists() || rpDir.listFiles()?.isEmpty() == true)
  }

  @Test
  fun listCredentialsForRp() = runTest {
    val cred1Id = byteArrayOf(1, 2, 3, 4)
    val cred2Id = byteArrayOf(5, 6, 7, 8)
    val credOtherId = byteArrayOf(9, 10, 11, 12)

    repository.storeCredential(tempDir, "example.com", cred1Id, "data1".toByteArray())
    repository.storeCredential(tempDir, "example.com", cred2Id, "data2".toByteArray())
    repository.storeCredential(tempDir, "other.com", credOtherId, "data3".toByteArray())

    val exampleCredentials = repository.listCredentialsForRp(tempDir, "example.com")
    val otherCredentials = repository.listCredentialsForRp(tempDir, "other.com")

    assertEquals(2, exampleCredentials.size)
    assertEquals(1, otherCredentials.size)
  }

  @Test
  fun listCredentialsForNonExistentRpReturnsEmpty() = runTest {
    val credentials = repository.listCredentialsForRp(tempDir, "nonexistent.com")

    assertTrue(credentials.isEmpty())
  }

  @Test
  fun listAllCredentials() = runTest {
    val cred1Id = byteArrayOf(1, 2, 3, 4)
    val cred2Id = byteArrayOf(5, 6, 7, 8)
    val cred3Id = byteArrayOf(9, 10, 11, 12)

    repository.storeCredential(tempDir, "example.com", cred1Id, "data1".toByteArray())
    repository.storeCredential(tempDir, "example.com", cred2Id, "data2".toByteArray())
    repository.storeCredential(tempDir, "other.com", cred3Id, "data3".toByteArray())

    val allCredentials = repository.listAllCredentials(tempDir)

    assertEquals(3, allCredentials.size)
  }

  @Test
  fun listAllCredentialsEmptyDirectoryReturnsEmpty() = runTest {
    val allCredentials = repository.listAllCredentials(tempDir)

    assertTrue(allCredentials.isEmpty())
  }

  @Test
  fun updateCredential() = runTest {
    val credentialId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
    val rpId = "example.com"
    val originalData = "original_data".toByteArray()
    val updatedData = "updated_data".toByteArray()

    repository.storeCredential(tempDir, rpId, credentialId, originalData)
    repository.updateCredential(tempDir, rpId, credentialId, updatedData)

    val loaded = repository.loadCredential(tempDir, credentialId)

    assertNotNull(loaded)
    assertTrue(updatedData.contentEquals(loaded))
  }

  @Test
  fun storeMultipleCredentialsSameRp() = runTest {
    val credentials = (1..5).map { i ->
      byteArrayOf(i.toByte(), (i * 2).toByte(), (i * 3).toByte(), (i * 4).toByte())
    }

    credentials.forEachIndexed { index, credId ->
      repository.storeCredential(tempDir, "example.com", credId, "data$index".toByteArray())
    }

    val allForRp = repository.listCredentialsForRp(tempDir, "example.com")
    assertEquals(5, allForRp.size)

    // Verify each can be loaded individually
    credentials.forEach { credId ->
      assertNotNull(repository.loadCredential(tempDir, credId))
    }
  }

  @Test
  fun sanitizesRpIdForFilesystem() = runTest {
    val credentialId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
    val rpId = "example.com:8080/path?query=1"
    val encryptedData = "data".toByteArray()

    repository.storeCredential(tempDir, rpId, credentialId, encryptedData)

    val loaded = repository.loadCredential(tempDir, rpId, credentialId)
    assertNotNull(loaded)

    // Verify the directory was created with a sanitized name
    val passkeysDir = File(tempDir, "passless")
    assertTrue(passkeysDir.exists())
    val rpDirs = passkeysDir.listFiles()?.filter { it.isDirectory } ?: emptyList()
    assertEquals(1, rpDirs.size)
    // The sanitized name should not contain special characters
    val rpDirName = rpDirs[0].name
    assertFalse(rpDirName.contains(":"))
    assertFalse(rpDirName.contains("/"))
    assertFalse(rpDirName.contains("?"))
    assertFalse(rpDirName.contains("="))
  }

  @Test
  fun handlesLargeCredentialData() = runTest {
    val credentialId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
    val rpId = "example.com"
    // 1MB of data
    val largeData = ByteArray(1024 * 1024) { it.toByte() }

    repository.storeCredential(tempDir, rpId, credentialId, largeData)

    val loaded = repository.loadCredential(tempDir, credentialId)

    assertNotNull(loaded)
    assertTrue(largeData.contentEquals(loaded))
  }

  @Test
  fun credentialExists() = runTest {
    val credentialId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
    val rpId = "example.com"
    val encryptedData = "data".toByteArray()

    assertFalse(repository.credentialExists(tempDir, credentialId))

    repository.storeCredential(tempDir, rpId, credentialId, encryptedData)

    assertTrue(repository.credentialExists(tempDir, credentialId))
  }

  @Test
  fun listCredentialIndexForRp() = runTest {
    val cred1Id = byteArrayOf(1, 2, 3, 4)
    val cred2Id = byteArrayOf(5, 6, 7, 8)
    val rpId = "example.com"

    repository.storeCredential(tempDir, rpId, cred1Id, "data1".toByteArray())
    repository.storeCredential(tempDir, rpId, cred2Id, "data2".toByteArray())

    val indices = repository.listCredentialIndexForRp(tempDir, rpId)

    assertEquals(2, indices.size)
    assertTrue(indices.any { it.credentialId.contentEquals(cred1Id) && it.rpId == rpId })
    assertTrue(indices.any { it.credentialId.contentEquals(cred2Id) && it.rpId == rpId })
  }

  @Test
  fun listAllCredentialIndex() = runTest {
    val cred1Id = byteArrayOf(1, 2, 3, 4)
    val cred2Id = byteArrayOf(5, 6, 7, 8)
    val cred3Id = byteArrayOf(9, 10, 11, 12)

    repository.storeCredential(tempDir, "example.com", cred1Id, "data1".toByteArray())
    repository.storeCredential(tempDir, "example.com", cred2Id, "data2".toByteArray())
    repository.storeCredential(tempDir, "other.com", cred3Id, "data3".toByteArray())

    val indices = repository.listAllCredentialIndex(tempDir)

    assertEquals(3, indices.size)
    assertTrue(indices.any { it.credentialId.contentEquals(cred1Id) && it.rpId == "example.com" })
    assertTrue(indices.any { it.credentialId.contentEquals(cred2Id) && it.rpId == "example.com" })
    assertTrue(indices.any { it.credentialId.contentEquals(cred3Id) && it.rpId == "other.com" })
  }

  @Test
  fun listRpIds() = runTest {
    repository.storeCredential(tempDir, "example.com", byteArrayOf(1, 2, 3, 4), "data1".toByteArray())
    repository.storeCredential(tempDir, "other.com", byteArrayOf(5, 6, 7, 8), "data2".toByteArray())
    repository.storeCredential(tempDir, "third.com", byteArrayOf(9, 10, 11, 12), "data3".toByteArray())

    val rpIds = repository.listRpIds(tempDir)

    assertEquals(3, rpIds.size)
    assertTrue(rpIds.contains("example.com"))
    assertTrue(rpIds.contains("other.com"))
    assertTrue(rpIds.contains("third.com"))
  }

  @Test
  fun getCredentialFile() {
    val credentialId = byteArrayOf(0x01, 0x02, 0x0A, 0x0F)
    val rpId = "example.com"

    val file = repository.getCredentialFile(tempDir, rpId, credentialId)

    assertEquals("01020a0f.gpg", file.name)
    assertEquals("example.com", file.parentFile?.name)
    assertEquals("passless", file.parentFile?.parentFile?.name)
  }
}
