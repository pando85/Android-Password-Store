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
import com.github.michaelbull.result.getOrElse
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.logcat

public class IndexedPasskeyStorage(
  private val delegate: PasskeyStorage,
  private val generationProvider: RepositoryGenerationProvider? = null,
) : PasskeyStorage,
  PasskeyRepositoryState {

  private data class IndexedEntry(
    val metadata: PasskeyMetadata,
    val sourceVersion: CredentialSourceVersion?,
  )

  private val metadataIndex = ConcurrentHashMap<String, IndexedEntry>()
  private val rpIdIndex = ConcurrentHashMap<String, MutableSet<String>>()
  @Volatile private var indexLoaded = false
  @Volatile private var trackedGeneration: RepositoryGeneration? = null
  @Volatile private var inMergeConflict = false
  private val indexLoadMutex = Mutex()

  private fun credentialKey(id: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(id)
  }

  private suspend fun ensureIndexLoaded() {
    if (generationProvider == null) {
      loadIndexIfNeeded()
      return
    }
    val currentGen = resolveCurrentGeneration() ?: return
    if (indexLoaded && trackedGeneration == currentGen) return
    indexLoadMutex.withLock {
      if (indexLoaded && trackedGeneration == currentGen) return
      rebuildIndex(currentGen)
    }
  }

  private suspend fun loadIndexIfNeeded() {
    if (indexLoaded) return
    indexLoadMutex.withLock {
      if (indexLoaded) return
      rebuildIndex(trackedGeneration)
    }
  }

  private suspend fun resolveCurrentGeneration(): RepositoryGeneration? {
    val provider = generationProvider ?: return null
    return try {
      RepositoryGeneration(
        repositoryIdentity = provider.repositoryIdentity(),
        gitHead = provider.currentGitHead(),
        worktreeGeneration = provider.currentWorktreeGeneration(),
      )
    } catch (e: Exception) {
      logcat(LogPriority.WARN) { "Failed to resolve repository generation: $e" }
      null
    }
  }

  private suspend fun rebuildIndex(generation: RepositoryGeneration?) {
    withContext(Dispatchers.IO) {
      metadataIndex.clear()
      rpIdIndex.clear()
      if (generationProvider != null) {
        inMergeConflict = generationProvider.isInMergeOrRebaseState()
      }
      delegate
        .listMetadata()
        .fold(
          success = { metadataList ->
            metadataList.forEach { metadata ->
              val version =
                delegate
                  .resolveSourceVersion(metadata.credentialId)
                  .getOrElse { null }
              indexMetadata(metadata, version)
            }
            indexLoaded = true
            trackedGeneration = generation
          },
          failure = { error ->
            logcat(LogPriority.ERROR) { "Failed to load passkey index: $error" }
            indexLoaded = false
          },
        )
    }
  }

  private fun indexMetadata(metadata: PasskeyMetadata, version: CredentialSourceVersion? = null) {
    val key = credentialKey(metadata.credentialId)
    metadataIndex[key] = IndexedEntry(metadata, version)
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
            rpIdIndex[rpId]?.mapNotNull { metadataIndex[it]?.metadata } ?: emptyList()
          } else {
            metadataIndex.values.map { it.metadata }
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
        val metadata = PasskeyMetadata.fromPasskeyCredential(credential)
        val version =
          delegate.resolveSourceVersion(credential.credentialId).getOrElse { null }
        indexMetadata(metadata, version)
        if (generationProvider != null) {
          trackedGeneration = resolveCurrentGeneration()
        }
      }
    }
  }

  override suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable> {
    val key = credentialKey(credentialId)
    val entry = metadataIndex[key]

    return delegate
      .deleteCredential(credentialId)
      .fold(
        success = { deleted ->
          if (deleted && entry != null) {
            removeFromIndex(entry.metadata)
          }
          if (deleted && generationProvider != null) {
            trackedGeneration = resolveCurrentGeneration()
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
          val updatedMetadata = existing.metadata.copy(signCount = newSignCount)
          metadataIndex[key] = IndexedEntry(updatedMetadata, existing.sourceVersion)
        }
      }
    } else {
      delegate.updateSignCount(credentialId, newSignCount)
    }
  }

  override suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): Result<CredentialSourceVersion?, Throwable> {
    return delegate.resolveSourceVersion(credentialId)
  }

  public suspend fun getSourceVersion(
    credentialId: ByteArray
  ): CredentialSourceVersion? {
    val key = credentialKey(credentialId)
    return metadataIndex[key]?.sourceVersion
  }

  override suspend fun invalidate(reason: InvalidationReason) {
    logcat { "Invalidating passkey index: $reason" }
    indexLoadMutex.withLock {
      metadataIndex.clear()
      rpIdIndex.clear()
      indexLoaded = false
      trackedGeneration = null
    }
  }

  override suspend fun currentGeneration(): RepositoryGeneration {
    return resolveCurrentGeneration()
      ?: RepositoryGeneration(
        repositoryIdentity = "unknown",
        gitHead = null,
        worktreeGeneration = 0L,
      )
  }

  override suspend fun onGitSyncCompleted(syncResult: GitSyncResult) {
    if (syncResult.hasConflicts && syncResult.affectsPasskeys()) {
      inMergeConflict = true
      invalidate(InvalidationReason.MERGE_CONFLICT)
      return
    }
    if (syncResult.affectsPasskeys()) {
      invalidate(InvalidationReason.GIT_SYNC_COMPLETED)
    }
  }

  override suspend fun onCredentialSaved() {
    invalidate(InvalidationReason.LOCAL_SAVE)
  }

  override suspend fun onCredentialUpdated() {
    invalidate(InvalidationReason.LOCAL_UPDATE)
  }

  override suspend fun onCredentialDeleted() {
    invalidate(InvalidationReason.LOCAL_DELETE)
  }

  override suspend fun onRepositoryReinitialized() {
    invalidate(InvalidationReason.REPOSITORY_REINITIALIZED)
  }

  override suspend fun onGpgIdChanged() {
    invalidate(InvalidationReason.GPG_ID_CHANGED)
  }

  override fun isInMergeConflict(): Boolean = inMergeConflict

  public fun clearIndex() {
    metadataIndex.clear()
    rpIdIndex.clear()
    indexLoaded = false
    trackedGeneration = null
    inMergeConflict = false
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
