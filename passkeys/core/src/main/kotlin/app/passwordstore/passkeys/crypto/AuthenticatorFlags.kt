/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

/**
 * WebAuthn Level 3 authenticator data flags.
 *
 * See https://www.w3.org/TR/webauthn-3/#flags
 *
 * Bit assignments (byte 32 of authenticator data):
 *   0x01 — UP  (User Present)
 *   0x02 — UV  (User Verified) — reserved in spec but used by some implementations
 *   0x04 — UV  (User Verified)
 *   0x08 — BE  (Backup Eligibility)
 *   0x10 — BS  (Backup State)
 *   0x40 — AT  (Attested Credential Data)
 *   0x80 — ED  (Extension Data)
 */
public object AuthenticatorFlags {

  public const val FLAG_USER_PRESENT: Byte = 0x01
  public const val FLAG_USER_VERIFIED: Byte = 0x04
  public const val FLAG_BACKUP_ELIGIBLE: Byte = 0x08
  public const val FLAG_BACKUP_STATE: Byte = 0x10
  public const val FLAG_ATTESTED_CREDENTIAL_DATA: Byte = 0x40
  public const val FLAG_EXTENSION_DATA: Byte = 0x80.toByte()

  /**
   * Builds the authenticator data flags byte from the given parameters.
   *
   * Invariant: [backupState] must not be true when [backupEligible] is false.
   *
   * @throws IllegalStateException if backupState is true but backupEligible is false
   */
  public fun build(
    userPresent: Boolean,
    userVerified: Boolean,
    backupEligible: Boolean,
    backupState: Boolean,
    attestedCredentialData: Boolean = false,
    extensionData: Boolean = false,
  ): Byte {
    require(!backupState || backupEligible) {
      "BS=1 is invalid when BE=0: backup state requires backup eligibility"
    }
    var flags = 0
    if (userPresent) flags = flags or FLAG_USER_PRESENT.toInt()
    if (userVerified) flags = flags or FLAG_USER_VERIFIED.toInt()
    if (backupEligible) flags = flags or FLAG_BACKUP_ELIGIBLE.toInt()
    if (backupState) flags = flags or FLAG_BACKUP_STATE.toInt()
    if (attestedCredentialData) flags = flags or FLAG_ATTESTED_CREDENTIAL_DATA.toInt()
    if (extensionData) flags = flags or FLAG_EXTENSION_DATA.toInt()
    return flags.toByte()
  }
}
