/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public data class GitSyncResult(
  val oldHead: String?,
  val newHead: String?,
  val worktreeChanged: Boolean,
  val conflicts: List<String>,
) {

  public val headChanged: Boolean
    get() = oldHead != newHead

  public val hasConflicts: Boolean
    get() = conflicts.isNotEmpty()

  public fun affectsPasskeys(passkeyDirectory: String = "fido2"): Boolean {
    return headChanged ||
      worktreeChanged ||
      conflicts.any { it.startsWith(passkeyDirectory) || it == ".gpg-id" }
  }
}
