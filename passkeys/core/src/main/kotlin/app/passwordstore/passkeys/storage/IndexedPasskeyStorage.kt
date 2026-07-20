/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.logcat

public class IndexedPasskeyStorage(private val delegate: PasskeyStorage) : PasskeyStorage {

  private val metadataIndex = ConcurrentHashMap<String, PasskeyMetadata>()
  private val rpIdIndex = ConcurrentHashMap<String, MutableSet<String>>()
  @Volatile private var indexLoaded = false
  private val indexLoadMutex = Mutex()

  private fun credentialKey(id: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(id)
  }

  private suspend fun ensureIndexLoaded() {
    if (indexLoaded) return
    indexLoadMutex.withLock {
      if (indexLoaded) return
      withContext(Dispatchers.IO) {
        delegate
          .listMetadata()
          .fold(
            success = { metadataList ->
              metadataList.forEach { metadata -> indexMetadata(metadata) }
              indexLoaded = true
            },
            failure = { error ->
              logcat(LogPriority.ERROR) { "Failed to load passkey index: $error" }
            },
          )
      }
    }
  }

  private fun indexMetadata(metadata: PasskeyMetadata) {
    val key = credentialKey(metadata.credentialId)
    metadataIndex[key] = metadata
    rpIdIndex.getOrPut(metadata.rpId) { ConcurrentHashMap.newKeySet() }.add(key)
  }

  private fun removeFromIndex(metadata: PasskeyMetadata) {
    val key = credentialKey(metadata.credentialId)
    metadataIndex.remove(key)
    val rpSet = rpIdIndex[metadata.rpId]
    rpSet?.remove(key)
    if (rpSet?.isEmpty() == true) {
      rpIdIndex.remove(metadata.rpId)
    }
  }

  override suspend fun listMetadata(rpId: String?): Result<List<PasskeyMetadata>, Throwable> {
    ensureIndexLoaded()

    return withContext(Dispatchers.Default) {
      try {
        val metadata =
          if (rpId != null) {
            rpIdIndex[rpId]?.mapNotNull { metadataIndex[it] } ?: emptyList()
          } else {
            metadataIndex.values.toList()
          }
        Ok(metadata)
      } catch (e: Exception) {
        Err(e)
      }
    }
  }

  override suspend fun loadForSigning(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable> {
    return delegate.loadForSigning(credentialId)
  }

  override suspend fun saveCredential(credential: PasskeyCredential): Result<Unit, Throwable> {
    return delegate.saveCredential(credential).also { result ->
      if (result.isOk) {
        indexMetadata(PasskeyMetadata.fromPasskeyCredential(credential))
      }
    }
  }

  override suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable> {
    val key = credentialKey(credentialId)
    val metadata = metadataIndex[key]

    return delegate
      .deleteCredential(credentialId)
      .fold(
        success = { deleted ->
          if (deleted && metadata != null) {
            removeFromIndex(metadata)
          }
          Ok(deleted)
        },
        failure = { Err(it) },
      )
  }

  override suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable> {
    val key = credentialKey(credentialId)
    val existing = metadataIndex[key]

    return if (existing != null) {
      delegate.updateSignCount(credentialId, newSignCount).also { result ->
        if (result.isOk) {
          metadataIndex[key] = existing.copy(signCount = newSignCount)
        }
      }
    } else {
      delegate.updateSignCount(credentialId, newSignCount)
    }
  }

  public fun clearIndex() {
    metadataIndex.clear()
    rpIdIndex.clear()
    indexLoaded = false
  }

  public fun indexedCredentialCount(): Int = metadataIndex.size

  public fun indexedRpIds(): Set<String> = rpIdIndex.keys.toSet()

  public fun hasRpId(rpId: String): Boolean {
    return rpIdIndex.containsKey(rpId)
  }

  public fun credentialCountForRp(rpId: String): Int {
    return rpIdIndex[rpId]?.size ?: 0
  }
}
