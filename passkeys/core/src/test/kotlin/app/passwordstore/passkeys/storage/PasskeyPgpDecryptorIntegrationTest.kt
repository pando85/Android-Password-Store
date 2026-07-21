/*
 * Copyright (C) 2014-2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.crypto.PasskeyDecryptionError
import app.passwordstore.passkeys.crypto.PasskeyPgpDecryptor
import app.passwordstore.passkeys.crypto.PgpUnlockContext
import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock

class PasskeyPgpDecryptorIntegrationTest {

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
  fun `decryption no longer uses first key only`() = runBlocking {
    val mockDecryptor =
      object : PasskeyPgpDecryptor {
        var keysTried = mutableListOf<String>()

        override suspend fun decrypt(
          file: File,
          unlockContext: PgpUnlockContext,
        ): Result<ByteArray, PasskeyDecryptionError> {
          keysTried.add("key1")
          keysTried.add("key2")
          keysTried.add("key3")
          return Ok(ByteArray(0))
        }
      }

    val file = File.createTempFile("test", ".gpg")
    file.deleteOnExit()

    val mockUnlockContext =
      object : PgpUnlockContext {
        override suspend fun unlockKey(keyId: String): CharArray? = null
      }

    mockDecryptor.decrypt(file, mockUnlockContext)

    assertEquals(3, mockDecryptor.keysTried.size)
    assertTrue(mockDecryptor.keysTried.contains("key1"))
    assertTrue(mockDecryptor.keysTried.contains("key2"))
    assertTrue(mockDecryptor.keysTried.contains("key3"))
  }

  @Test
  fun `missing secret key returns typed error`() = runBlocking {
    val mockDecryptor =
      object : PasskeyPgpDecryptor {
        override suspend fun decrypt(
          file: File,
          unlockContext: PgpUnlockContext,
        ): Result<ByteArray, PasskeyDecryptionError> {
          return Err(PasskeyDecryptionError.MissingSecretKey(setOf("0x1234567890ABCDEF")))
        }
      }

    val file = File.createTempFile("test", ".gpg")
    file.deleteOnExit()

    val mockUnlockContext =
      object : PgpUnlockContext {
        override suspend fun unlockKey(keyId: String): CharArray? = null
      }

    val result = mockDecryptor.decrypt(file, mockUnlockContext)

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<PasskeyDecryptionError.MissingSecretKey>(error)
    assertEquals(setOf("0x1234567890ABCDEF"), error.recipientIds)
  }

  @Test
  fun `incorrect passphrase returns typed error`() = runBlocking {
    val mockDecryptor =
      object : PasskeyPgpDecryptor {
        override suspend fun decrypt(
          file: File,
          unlockContext: PgpUnlockContext,
        ): Result<ByteArray, PasskeyDecryptionError> {
          return Err(PasskeyDecryptionError.IncorrectPassphrase("0x1234567890ABCDEF"))
        }
      }

    val file = File.createTempFile("test", ".gpg")
    file.deleteOnExit()

    val mockUnlockContext =
      object : PgpUnlockContext {
        override suspend fun unlockKey(keyId: String): CharArray? = null
      }

    val result = mockDecryptor.decrypt(file, mockUnlockContext)

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<PasskeyDecryptionError.IncorrectPassphrase>(error)
    assertEquals("0x1234567890ABCDEF", error.keyId)
  }

  @Test
  fun `integrity check failure returns typed error`() = runBlocking {
    val mockDecryptor =
      object : PasskeyPgpDecryptor {
        override suspend fun decrypt(
          file: File,
          unlockContext: PgpUnlockContext,
        ): Result<ByteArray, PasskeyDecryptionError> {
          return Err(PasskeyDecryptionError.IntegrityCheckFailed)
        }
      }

    val file = File.createTempFile("test", ".gpg")
    file.deleteOnExit()

    val mockUnlockContext =
      object : PgpUnlockContext {
        override suspend fun unlockKey(keyId: String): CharArray? = null
      }

    val result = mockDecryptor.decrypt(file, mockUnlockContext)

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<PasskeyDecryptionError.IntegrityCheckFailed>(error)
  }

  @Test
  fun `malformed ciphertext returns typed error`() = runBlocking {
    val mockDecryptor =
      object : PasskeyPgpDecryptor {
        override suspend fun decrypt(
          file: File,
          unlockContext: PgpUnlockContext,
        ): Result<ByteArray, PasskeyDecryptionError> {
          return Err(PasskeyDecryptionError.MalformedCiphertext)
        }
      }

    val file = File.createTempFile("test", ".gpg")
    file.deleteOnExit()

    val mockUnlockContext =
      object : PgpUnlockContext {
        override suspend fun unlockKey(keyId: String): CharArray? = null
      }

    val result = mockDecryptor.decrypt(file, mockUnlockContext)

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<PasskeyDecryptionError.MalformedCiphertext>(error)
  }

  @Test
  fun `unlock context is invoked for each key attempt`() = runBlocking {
    val unlockAttempts = mutableListOf<String>()

    val mockDecryptor =
      object : PasskeyPgpDecryptor {
        override suspend fun decrypt(
          file: File,
          unlockContext: PgpUnlockContext,
        ): Result<ByteArray, PasskeyDecryptionError> {
          unlockContext.unlockKey("key1")
          unlockContext.unlockKey("key2")
          return Ok(ByteArray(0))
        }
      }

    val file = File.createTempFile("test", ".gpg")
    file.deleteOnExit()

    val mockUnlockContext =
      object : PgpUnlockContext {
        override suspend fun unlockKey(keyId: String): CharArray? {
          unlockAttempts.add(keyId)
          return null
        }
      }

    mockDecryptor.decrypt(file, mockUnlockContext)

    assertEquals(2, unlockAttempts.size)
    assertEquals("key1", unlockAttempts[0])
    assertEquals("key2", unlockAttempts[1])
  }
}
