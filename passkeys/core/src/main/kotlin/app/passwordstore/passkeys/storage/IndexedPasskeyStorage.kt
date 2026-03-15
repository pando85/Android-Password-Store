/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

public class IndexedPasskeyStorage(
  private val delegate: PasskeyStorage
) : PasskeyStorage {

  private val credentialIndex = ConcurrentHashMap<String, PasskeyCredential>()
  private val rpIdIndex = ConcurrentHashMap<String, MutableSet<String>>()
  private var indexLoaded = false

  private fun credentialKey(id: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(id)
  }

  private suspend fun ensureIndexLoaded() {
    if (indexLoaded) return
    withContext(Dispatchers.IO) {
      delegate.listCredentials().fold(
        success = { credentials ->
          credentials.forEach { credential ->
            indexCredential(credential)
          }
          indexLoaded = true
        },
        failure = { }
      )
    }
  }

  private fun indexCredential(credential: PasskeyCredential) {
    val key = credentialKey(credential.credentialId)
    credentialIndex[key] = credential
    rpIdIndex.getOrPut(credential.rpId) { ConcurrentHashMap.newKeySet() }.add(key)
  }

  private fun removeFromIndex(credential: PasskeyCredential) {
    val key = credentialKey(credential.credentialId)
    credentialIndex.remove(key)
    val rpSet = rpIdIndex[credential.rpId]
    rpSet?.remove(key)
    if (rpSet?.isEmpty() == true) {
      rpIdIndex.remove(credential.rpId)
    }
  }

  override suspend fun listCredentials(rpId: String?): Result<List<PasskeyCredential>, Throwable> {
    ensureIndexLoaded()

    return withContext(Dispatchers.Default) {
      try {
        val credentials = if (rpId != null) {
          rpIdIndex[rpId]?.mapNotNull { credentialIndex[it] } ?: emptyList()
        } else {
          credentialIndex.values.toList()
        }
        Ok(credentials)
      } catch (e: Exception) {
        Err(e)
      }
    }
  }

  override suspend fun getCredential(credentialId: ByteArray): Result<PasskeyCredential?, Throwable> {
    ensureIndexLoaded()

    return withContext(Dispatchers.Default) {
      try {
        val key = credentialKey(credentialId)
        Ok(credentialIndex[key])
      } catch (e: Exception) {
        Err(e)
      }
    }
  }

  override suspend fun saveCredential(credential: PasskeyCredential): Result<Unit, Throwable> {
    return delegate.saveCredential(credential).also { result ->
      if (result.isOk) {
        indexCredential(credential)
      }
    }
  }

  override suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable> {
    val key = credentialKey(credentialId)
    val credential = credentialIndex[key]

    return delegate.deleteCredential(credentialId).fold(
      success = { deleted ->
        if (deleted && credential != null) {
          removeFromIndex(credential)
        }
        Ok(deleted)
      },
      failure = { Err(it) }
    )
  }

  override suspend fun updateSignCount(credentialId: ByteArray, newSignCount: ULong): Result<Unit, Throwable> {
    val key = credentialKey(credentialId)
    val existing = credentialIndex[key]

    return if (existing != null) {
      val updated = existing.copy(signCount = newSignCount)
      delegate.saveCredential(updated).also { result ->
        if (result.isOk) {
          credentialIndex[key] = updated
        }
      }
    } else {
      delegate.updateSignCount(credentialId, newSignCount)
    }
  }

  public fun clearIndex() {
    credentialIndex.clear()
    rpIdIndex.clear()
    indexLoaded = false
  }

  public fun indexedCredentialCount(): Int = credentialIndex.size

  public fun indexedRpIds(): Set<String> = rpIdIndex.keys.toSet()

  public fun hasRpId(rpId: String): Boolean {
    return rpIdIndex.containsKey(rpId)
  }

  public fun credentialCountForRp(rpId: String): Int {
    return rpIdIndex[rpId]?.size ?: 0
  }
}