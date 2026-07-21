/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public interface RepositoryGenerationProvider {

  public suspend fun currentGitHead(): String?

  public fun currentWorktreeGeneration(): Long

  public fun bumpWorktreeGeneration()

  public fun repositoryIdentity(): String

  public fun isInMergeOrRebaseState(): Boolean
}
