/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.passkeys.storage.RepositoryGenerationProvider
import java.io.File
import java.util.concurrent.atomic.AtomicLong
import logcat.LogPriority
import logcat.logcat
import org.eclipse.jgit.lib.Constants
import org.eclipse.jgit.lib.RepositoryState

class DefaultRepositoryGenerationProvider(private val repositoryRoot: File) :
  RepositoryGenerationProvider {

  private val worktreeGenerationCounter = AtomicLong(System.nanoTime())

  override suspend fun currentGitHead(): String? {
    val repo = PasswordRepository.repository ?: return null
    return try {
      val headRef = repo.findRef(Constants.HEAD) ?: return null
      if (headRef.isSymbolic) {
        headRef.target.objectId?.name()
      } else {
        headRef.objectId?.name()
      }
    } catch (e: Exception) {
      logcat(LogPriority.WARN) { "Failed to read Git HEAD: $e" }
      null
    }
  }

  override fun currentWorktreeGeneration(): Long {
    return worktreeGenerationCounter.get()
  }

  override fun bumpWorktreeGeneration() {
    worktreeGenerationCounter.incrementAndGet()
  }

  override fun repositoryIdentity(): String {
    return repositoryRoot.canonicalPath
  }

  override fun isInMergeOrRebaseState(): Boolean {
    val repo = PasswordRepository.repository ?: return false
    return try {
      val state = repo.repositoryState
      state.isRebasing || state == RepositoryState.MERGING
    } catch (e: Exception) {
      logcat(LogPriority.WARN) { "Failed to check repository state: $e" }
      false
    }
  }
}
