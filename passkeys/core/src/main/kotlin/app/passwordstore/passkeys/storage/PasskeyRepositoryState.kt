/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public interface PasskeyRepositoryState {

  public suspend fun invalidate(reason: InvalidationReason)

  public suspend fun currentGeneration(): RepositoryGeneration

  public suspend fun onGitSyncCompleted(syncResult: GitSyncResult)

  public suspend fun onCredentialSaved()

  public suspend fun onCredentialUpdated()

  public suspend fun onCredentialDeleted()

  public suspend fun onRepositoryReinitialized()

  public suspend fun onGpgIdChanged()

  public fun isInMergeConflict(): Boolean

  public fun isRepositoryBackedUp(): Boolean = false

  public fun hasRemote(): Boolean = false

  public fun setHasRemote(hasRemote: Boolean) {}

  public fun effectiveBackupState(credentialBackupEligible: Boolean): Boolean = false
}
