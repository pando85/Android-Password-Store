/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.model

import app.passwordstore.passkeys.cbor.Cbor
import app.passwordstore.passkeys.cbor.CborMap
import app.passwordstore.passkeys.cbor.CborValue
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class CredentialBackupStateCodecTest {

  @Test
  fun `canonical names match soft-fido2 serde`() {
    assertEquals("notEligible", CredentialBackupState.NOT_ELIGIBLE.serializedName)
    assertEquals("eligible", CredentialBackupState.ELIGIBLE.serializedName)
    assertEquals("backedUp", CredentialBackupState.BACKED_UP.serializedName)
  }

  @Test
  fun `serializer emits only canonical backup_state text`() {
    val cases =
      listOf(
        Triple(false, false, "notEligible"),
        Triple(true, false, "eligible"),
        Triple(true, true, "backedUp"),
      )

    for ((eligible, backedUp, expected) in cases) {
      val map = Cbor.parse(credential(eligible, backedUp).toCbor()).asMap()

      assertEquals(expected, map.getString("backup_state"))
      assertFalse(map.contains("backup_eligible"))
      assertEquals(null, map.getBoolean("backup_state"))
    }
  }

  @Test
  fun `all canonical states deserialize through full and metadata parsers`() {
    for (state in CredentialBackupState.entries) {
      val map = baseMap()
      map["backup_state"] = CborValue.TextString(state.serializedName)

      assertDecodedState(encode(map), state)
    }
  }

  @Test
  fun `valid legacy boolean combinations migrate`() {
    val cases =
      listOf(
        Triple(false, false, CredentialBackupState.NOT_ELIGIBLE),
        Triple(true, false, CredentialBackupState.ELIGIBLE),
        Triple(true, true, CredentialBackupState.BACKED_UP),
      )

    for ((eligible, backedUp, expected) in cases) {
      assertDecodedState(legacyEncoding(eligible, backedUp), expected)
    }
  }

  @Test
  fun `invalid legacy BS without BE is rejected`() {
    val bytes = legacyEncoding(backupEligible = false, backupState = true)

    assertFailsWith<IllegalArgumentException> { StoredCredential.fromCbor(bytes) }
    assertFailsWith<IllegalArgumentException> { StoredCredential.metadataFromCbor(bytes) }
  }

  @Test
  fun `missing backup fields default to eligible`() {
    val map = baseMap()

    assertDecodedState(encode(map), CredentialBackupState.ELIGIBLE)
  }

  @Test
  fun `canonical and legacy representations cannot be mixed`() {
    val map = baseMap()
    map["backup_state"] = CborValue.TextString("eligible")
    map["backup_eligible"] = CborValue.True
    val bytes = encode(map)

    assertFailsWith<IllegalArgumentException> { StoredCredential.fromCbor(bytes) }
    assertFailsWith<IllegalArgumentException> { StoredCredential.metadataFromCbor(bytes) }
  }

  @Test
  fun `unknown canonical state is rejected`() {
    val map = baseMap()
    map["backup_state"] = CborValue.TextString("syncedSomewhere")
    val bytes = encode(map)

    assertFailsWith<IllegalArgumentException> { StoredCredential.fromCbor(bytes) }
    assertFailsWith<IllegalArgumentException> { StoredCredential.metadataFromCbor(bytes) }
  }

  @Test
  fun `malformed backup fields are rejected instead of defaulted`() {
    val malformedState = baseMap()
    malformedState["backup_state"] = CborValue.UnsignedInteger(BigInteger.ZERO)

    val malformedEligible = baseMap()
    malformedEligible["backup_eligible"] = CborValue.TextString("true")

    for (bytes in listOf(encode(malformedState), encode(malformedEligible))) {
      assertFailsWith<IllegalArgumentException> { StoredCredential.fromCbor(bytes) }
      assertFailsWith<IllegalArgumentException> { StoredCredential.metadataFromCbor(bytes) }
    }
  }

  @Test
  fun `reencoding legacy credentials performs a canonical lazy migration`() {
    val legacy = StoredCredential.fromCbor(legacyEncoding(true, false))
    val migratedMap = Cbor.parse(legacy.toCbor()).asMap()

    assertEquals("eligible", migratedMap.getString("backup_state"))
    assertFalse(migratedMap.contains("backup_eligible"))
  }

  @Test
  fun `flag conversion makes invalid state unrepresentable`() {
    assertEquals(
      CredentialBackupState.NOT_ELIGIBLE,
      CredentialBackupState.fromFlags(false, false),
    )
    assertEquals(CredentialBackupState.ELIGIBLE, CredentialBackupState.fromFlags(true, false))
    assertEquals(CredentialBackupState.BACKED_UP, CredentialBackupState.fromFlags(true, true))
    assertFailsWith<IllegalArgumentException> {
      CredentialBackupState.fromFlags(backupEligible = false, backupState = true)
    }
  }

  private fun assertDecodedState(bytes: ByteArray, expected: CredentialBackupState) {
    val full = StoredCredential.fromCbor(bytes)
    val metadata = StoredCredential.metadataFromCbor(bytes)

    assertEquals(expected.isEligible, full.backupEligible)
    assertEquals(expected.isBackedUp, full.backupState)
    assertEquals(expected.isEligible, metadata.backupEligible)
    assertEquals(expected.isBackedUp, metadata.backupState)
  }

  private fun legacyEncoding(backupEligible: Boolean, backupState: Boolean): ByteArray {
    val map = baseMap()
    map["backup_eligible"] = if (backupEligible) CborValue.True else CborValue.False
    map["backup_state"] = if (backupState) CborValue.True else CborValue.False
    return encode(map)
  }

  private fun baseMap(): MutableMap<String, CborValue> {
    val map = Cbor.parse(credential().toCbor()).asMap().toMutableMap()
    map.remove("backup_state")
    map.remove("backup_eligible")
    return map
  }

  private fun encode(map: Map<String, CborValue>): ByteArray =
    Cbor.fromMap(CborMap.from(map)).toBytes()

  private fun credential(
    backupEligible: Boolean = true,
    backupState: Boolean = false,
  ): StoredCredential =
    StoredCredential(
      id = byteArrayOf(0x01, 0x02),
      rp = RelyingParty(id = "example.com"),
      user = User(id = byteArrayOf(0x03), name = "alice", displayName = "Alice"),
      signCount = 0u,
      alg = StoredCredential.ALG_ES256,
      privateKey = ByteArray(32).also { it[31] = 1 },
      created = 1_700_000_000L,
      backupEligible = backupEligible,
      backupState = backupState,
    )
}
