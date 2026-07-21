/*
 * Copyright (C) 2014-2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PasskeyDecryptionErrorTest {

  @Test
  fun `NoRecipientPackets is singleton`() {
    val error1 = PasskeyDecryptionError.NoRecipientPackets
    val error2 = PasskeyDecryptionError.NoRecipientPackets
    assertTrue(error1 === error2)
  }

  @Test
  fun `MissingSecretKey contains recipient IDs`() {
    val recipientIds = setOf("0x1234567890ABCDEF", "0xFEDCBA0987654321")
    val error = PasskeyDecryptionError.MissingSecretKey(recipientIds)
    assertEquals(recipientIds, error.recipientIds)
  }

  @Test
  fun `KeyLocked contains key ID`() {
    val keyId = "0x1234567890ABCDEF"
    val error = PasskeyDecryptionError.KeyLocked(keyId)
    assertEquals(keyId, error.keyId)
  }

  @Test
  fun `IncorrectPassphrase contains key ID`() {
    val keyId = "0x1234567890ABCDEF"
    val error = PasskeyDecryptionError.IncorrectPassphrase(keyId)
    assertEquals(keyId, error.keyId)
  }

  @Test
  fun `IntegrityCheckFailed is singleton`() {
    val error1 = PasskeyDecryptionError.IntegrityCheckFailed
    val error2 = PasskeyDecryptionError.IntegrityCheckFailed
    assertTrue(error1 === error2)
  }

  @Test
  fun `MalformedCiphertext is singleton`() {
    val error1 = PasskeyDecryptionError.MalformedCiphertext
    val error2 = PasskeyDecryptionError.MalformedCiphertext
    assertTrue(error1 === error2)
  }

  @Test
  fun `UnsupportedFormat contains reason`() {
    val reason = "Unknown encryption algorithm"
    val error = PasskeyDecryptionError.UnsupportedFormat(reason)
    assertEquals(reason, error.reason)
  }

  @Test
  fun `all error types are PasskeyDecryptionError`() {
    val errors: List<PasskeyDecryptionError> =
      listOf(
        PasskeyDecryptionError.NoRecipientPackets,
        PasskeyDecryptionError.MissingSecretKey(setOf("0x123")),
        PasskeyDecryptionError.KeyLocked("0x123"),
        PasskeyDecryptionError.IncorrectPassphrase("0x123"),
        PasskeyDecryptionError.IntegrityCheckFailed,
        PasskeyDecryptionError.MalformedCiphertext,
        PasskeyDecryptionError.UnsupportedFormat("test"),
      )

    errors.forEach { error -> assertIs<PasskeyDecryptionError>(error) }
  }
}
