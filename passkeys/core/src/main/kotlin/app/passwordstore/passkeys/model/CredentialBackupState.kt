/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.model

/**
 * The three valid WebAuthn Backup Eligibility (BE) and Backup State (BS) combinations.
 *
 * [serializedName] is the stable credential-file representation shared with soft-fido2. The invalid
 * `BE=0, BS=1` combination is intentionally unrepresentable.
 */
public enum class CredentialBackupState(public val serializedName: String) {
  NOT_ELIGIBLE("notEligible"),
  ELIGIBLE("eligible"),
  BACKED_UP("backedUp");

  public val isEligible: Boolean
    get() = this != NOT_ELIGIBLE

  public val isBackedUp: Boolean
    get() = this == BACKED_UP

  public companion object {
    public fun fromSerializedName(value: String): CredentialBackupState =
      entries.firstOrNull { it.serializedName == value }
        ?: throw IllegalArgumentException("Unknown credential backup state: '$value'")

    public fun fromFlags(
      backupEligible: Boolean,
      backupState: Boolean,
    ): CredentialBackupState =
      when {
        !backupEligible && !backupState -> NOT_ELIGIBLE
        backupEligible && !backupState -> ELIGIBLE
        backupEligible && backupState -> BACKED_UP
        else ->
          throw IllegalArgumentException("Invalid credential backup state: BS=1 requires BE=1")
      }
  }
}
