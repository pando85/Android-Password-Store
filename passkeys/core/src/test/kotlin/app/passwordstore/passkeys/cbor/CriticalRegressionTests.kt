/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.cbor

import app.passwordstore.passkeys.crypto.ES256CryptoHandler
import app.passwordstore.passkeys.model.RelyingParty
import app.passwordstore.passkeys.model.StoredCredential
import app.passwordstore.passkeys.model.User
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class CriticalRegressionTests {

  @Test
  fun `StoredCredential CBOR round trip preserves all fields`() {
    // Create a StoredCredential with realistic values including a generated private key
    val cryptoHandler = ES256CryptoHandler()
    val (privateKeyBytes, publicKeyBytes) = cryptoHandler.generateKeyPair()

    val credentialId = ByteArray(32) { (it % 256).toByte() } // Deterministic credential ID

    val original =
      StoredCredential(
        id = credentialId,
        rp = RelyingParty(id = "example.com", name = "Example Website"),
        user =
          User(
            id = "testuser".toByteArray(),
            name = "testuser@example.com",
            displayName = "Test User",
          ),
        signCount = 42u,
        alg = StoredCredential.ALG_ES256,
        privateKey = privateKeyBytes,
        publicKey = publicKeyBytes,
        created = 1234567890L,
        discoverable = true,
      )

    // Serialize to CBOR
    val serialized = original.toCbor()
    // Deserialize from CBOR
    val deserialized = StoredCredential.fromCbor(serialized)

    // Assert all fields match exactly
    assertArrayEquals("Credential ID should match", original.id, deserialized.id)
    assertArrayEquals("Private key should match", original.privateKey, deserialized.privateKey)
    assertArrayEquals("Public key should match", original.publicKey, deserialized.publicKey)
    assertEquals("RP ID should match", original.rp.id, deserialized.rp.id)
    assertEquals("RP name should match", original.rp.name, deserialized.rp.name)
    assertArrayEquals("User ID should match", original.user.id, deserialized.user.id)
    assertEquals("User name should match", original.user.name, deserialized.user.name)
    assertEquals(
      "User display name should match",
      original.user.displayName,
      deserialized.user.displayName,
    )
    assertEquals("Sign count should match", original.signCount, deserialized.signCount)
    assertEquals("Algorithm should match", original.alg, deserialized.alg)
    assertEquals("Created timestamp should match", original.created, deserialized.created)
    assertEquals("Discoverable flag should match", original.discoverable, deserialized.discoverable)
  }

  @Test
  fun `CBOR byte array serialization preserves all byte values`() {
    // Create a ByteArray with all possible byte values (0-255 represented as signed bytes)
    val allByteValues =
      ByteArray(256) { i ->
        ((i - 128) % 256).toByte()
      } // Covers all signed byte values from -128 to 127

    // Serialize via toCborIntegerArray
    val cborArray = allByteValues.toCborIntegerArray()

    // Deserialize back to ByteArray
    val recovered = cborArray.value.toByteArray()

    // Assert exact match - this catches any signed/unsigned byte conversion issues
    assertArrayEquals(allByteValues, recovered)
  }

  @Test
  fun `Full credential lifecycle round trip`() {
    val cryptoHandler = ES256CryptoHandler()
    val (privateKeyBytes, publicKeyBytes) = cryptoHandler.generateKeyPair()

    val credentialId = ByteArray(32) { (it % 16).toByte() } // Simple deterministic ID

    // Create original credential
    val original =
      StoredCredential(
        id = credentialId,
        rp = RelyingParty(id = "example.com", name = "Example Site"),
        user =
          User(
            id = "user123".toByteArray(),
            name = "user@example.com",
            displayName = "Example User",
          ),
        signCount = 100u,
        alg = StoredCredential.ALG_ES256,
        privateKey = privateKeyBytes,
        publicKey = publicKeyBytes,
        created = 1678886400L, // Some timestamp
        discoverable = false,
      )

    // Perform the full lifecycle: serialize → deserialize → create signing payload
    val serialized = original.toCbor()
    val deserialized = StoredCredential.fromCbor(serialized)

    // Verify the deserialized private key can still be used for signing
    // This is the key test - if the private key was corrupted, signing would fail
    val authenticatorData = "authData".toByteArray()
    val clientDataHash = "clientDataHash".toByteArray()

    // Try to sign with the deserialized credential's private key
    val signResult = cryptoHandler.sign(deserialized.privateKey, authenticatorData, clientDataHash)

    // If we get here without exception, the private key was preserved correctly
    assert(signResult.isOk) { "Signing with deserialized private key should succeed" }

    // Additionally verify all fields are identical
    assertArrayEquals("Credential ID should be preserved", original.id, deserialized.id)
    assertArrayEquals(
      "Private key should be preserved exactly",
      original.privateKey,
      deserialized.privateKey,
    )
    assertArrayEquals("Public key should be preserved", original.publicKey, deserialized.publicKey)
    assertEquals("Sign count should be preserved", original.signCount, deserialized.signCount)
  }
}
