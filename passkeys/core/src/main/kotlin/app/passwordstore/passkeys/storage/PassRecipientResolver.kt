/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import com.github.michaelbull.result.Result
import java.io.File

/**
 * Resolves the encryption recipients for a passkey target file by walking the hierarchical `.gpg-id`
 * policy from the target directory upward to the repository root.
 *
 * The resolver must never fall back to a global key list. If the policy cannot be satisfied, it
 * returns a [RecipientPolicyError] and the caller must fail closed.
 */
public fun interface PassRecipientResolver<Key> {
  public suspend fun resolveFor(target: File): Result<List<Key>, RecipientPolicyError>
}
