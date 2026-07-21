/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Clock
import java.security.MessageDigest

public class InMemoryPasskeyStorage : PasskeyStorage {

  private val credentials = mutableMapOf<String, PasskeyCredential>()

  private fun credentialIdKey(id: ByteArray): String {
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(id)
  }

  override suspend fun listMetadata(rpId: String?): Result<List<PasskeyMetadata>, Throwable> =
    withContext(Dispatchers.Default) {
      val filtered =
        if (rpId != null) {
          credentials.values.filter { it.rpId == rpId }
        } else {
          credentials.values.toList()
        }
      Ok(filtered.map { PasskeyMetadata.fromPasskeyCredential(it) })
    }

  override suspend fun loadForSigning(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable> =
    withContext(Dispatchers.Default) {
      val credential = credentials[credentialIdKey(credentialId)]
      if (credential != null) {
        Ok(
          SensitivePasskeyCredential(
            credentialId = credential.credentialId.copyOf(),
            publicKey = credential.publicKey.copyOf(),
            rpId = credential.rpId,
            user = credential.user,
            signCount = credential.signCount,
            createdAt = credential.createdAt,
            transports = credential.transports,
            uvInitialized = credential.uvInitialized,
            fileLastModified = 0L,
            privateKey = credential.privateKey.copyOf(),
          )
        )
      } else {
        Err(IllegalArgumentException("Credential not found"))
      }
    }

  override suspend fun saveCredential(credential: PasskeyCredential): Result<Unit, Throwable> =
    withContext(Dispatchers.Default) {
      credentials[credentialIdKey(credential.credentialId)] = credential
      Ok(Unit)
    }

  override suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable> =
    withContext(Dispatchers.Default) {
      val key = credentialIdKey(credentialId)
      val existed = credentials.containsKey(key)
      credentials.remove(key)
      Ok(existed)
    }

  override suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable> =
    withContext(Dispatchers.Default) {
      val key = credentialIdKey(credentialId)
      val existing = credentials[key]
      if (existing != null) {
        credentials[key] = existing.copy(signCount = newSignCount)
        Ok(Unit)
      } else {
        Err(IllegalArgumentException("Credential not found"))
      }
    }

  override suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): Result<CredentialSourceVersion?, Throwable> =
    withContext(Dispatchers.Default) {
      val key = credentialIdKey(credentialId)
      val credential = credentials[key]
      if (credential != null) {
        val digest = MessageDigest.getInstance("SHA-256").digest(credential.privateKey)
        Ok(
          CredentialSourceVersion(
            repositoryGeneration =
              RepositoryGeneration(
                repositoryIdentity = "in-memory",
                gitHead = null,
                worktreeGeneration = credentials.size.toLong(),
              ),
            canonicalPath = "in-memory://$key",
            fileSize = credential.privateKey.size.toLong(),
            modifiedAtMillis = Clock.System.now().toEpochMilliseconds(),
            ciphertextDigest = digest,
          )
        )
      } else {
        Ok(null)
      }
    }

  public fun clear() {
    credentials.clear()
  }

  public fun count(): Int = credentials.size

  public companion object {
    public fun withTestCredentials(vararg creds: PasskeyCredential): InMemoryPasskeyStorage {
      val storage = InMemoryPasskeyStorage()
      creds.forEach { storage.credentials[storage.credentialIdKey(it.credentialId)] = it }
      return storage
    }

    public fun createTestCredential(
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
}
