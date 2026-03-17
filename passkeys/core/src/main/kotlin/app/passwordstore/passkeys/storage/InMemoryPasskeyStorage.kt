/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Clock
import kotlinx.serialization.encodeToString

public class InMemoryPasskeyStorage : PasskeyStorage {

  private val credentials = mutableMapOf<String, PasskeyCredential>()

  private fun credentialIdKey(id: ByteArray): String {
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(id)
  }

  override suspend fun listCredentials(rpId: String?): Result<List<PasskeyCredential>, Throwable> =
    withContext(Dispatchers.Default) {
      val filtered =
        if (rpId != null) {
          credentials.values.filter { it.rpId == rpId }
        } else {
          credentials.values.toList()
        }
      Ok(filtered)
    }

  override suspend fun getCredential(
    credentialId: ByteArray
  ): Result<PasskeyCredential?, Throwable> =
    withContext(Dispatchers.Default) { Ok(credentials[credentialIdKey(credentialId)]) }

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
