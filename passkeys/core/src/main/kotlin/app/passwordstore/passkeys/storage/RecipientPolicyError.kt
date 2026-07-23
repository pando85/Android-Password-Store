/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public sealed interface RecipientPolicyError {
  public data object TargetOutsideRepository : RecipientPolicyError

  public data object SymlinkRejected : RecipientPolicyError

  public data object GpgIdNotFound : RecipientPolicyError

  public data class MalformedGpgId(val line: Int, val reason: String) : RecipientPolicyError

  public data class RecipientNotFound(val identifier: String) : RecipientPolicyError

  public data class AmbiguousRecipient(val identifier: String) : RecipientPolicyError

  public data class RecipientUnusable(val identifier: String) : RecipientPolicyError

  public data object EmptyRecipientSet : RecipientPolicyError
}
