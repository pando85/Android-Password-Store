/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

import com.github.michaelbull.result.getOrElse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ES256CryptoHandlerTest {

  private val cryptoHandler = ES256CryptoHandler()

  @Test
  fun `generateKeyPair returns non-empty keys`() {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()

    assertTrue(privateKey.isNotEmpty(), "Private key should not be empty")
    assertTrue(publicKey.isNotEmpty(), "Public key should not be empty")
  }

  @Test
  fun `generateKeyPair generates different keys each time`() {
    val (privateKey1, publicKey1) = cryptoHandler.generateKeyPair()
    val (privateKey2, publicKey2) = cryptoHandler.generateKeyPair()

    assertTrue(
      !privateKey1.contentEquals(privateKey2) || !publicKey1.contentEquals(publicKey2),
      "Key pairs should be different",
    )
  }

  @Test
  fun `sign and verify work correctly`() {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    val authenticatorData = ByteArray(37) { it.toByte() }
    val clientDataHash = ByteArray(32) { (it * 2).toByte() }

    val signResult = cryptoHandler.sign(privateKey, authenticatorData, clientDataHash)

    assertTrue(signResult.isOk, "Sign should succeed")

    val signature = signResult.getOrElse { throw AssertionError("Sign failed") }
    assertTrue(signature.isNotEmpty(), "Signature should not be empty")

    val verifyResult = cryptoHandler.verify(publicKey, signature, authenticatorData, clientDataHash)

    assertTrue(verifyResult.isOk, "Verify should succeed")
    assertTrue(verifyResult.getOrElse { false }, "Signature should be valid")
  }

  @Test
  fun `verify fails with wrong signature`() {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    val authenticatorData = ByteArray(37) { it.toByte() }
    val clientDataHash = ByteArray(32) { (it * 2).toByte() }

    val wrongSignature = ByteArray(70) { 0 }

    val verifyResult =
      cryptoHandler.verify(publicKey, wrongSignature, authenticatorData, clientDataHash)

    val isOkOrFalse = verifyResult.isOk && !verifyResult.getOrElse { true }
    assertTrue(
      isOkOrFalse || verifyResult.isErr,
      "Verify should fail or return false for wrong signature",
    )
  }

  @Test
  fun `createCredential returns valid credential`() {
    val result =
      cryptoHandler.createCredential(
        rpId = "example.com",
        userId = "user123".toByteArray(),
        userName = "testuser",
        userDisplayName = "Test User",
        challenge = ByteArray(32) { it.toByte() },
      )

    assertTrue(result.isOk, "Create credential should succeed")

    val credential = result.getOrElse { throw AssertionError("Create credential failed") }
    assertNotNull(credential.credentialId)
    assertNotNull(credential.privateKey)
    assertNotNull(credential.publicKey)
    assertEquals("example.com", credential.rpId)
    assertEquals("testuser", credential.user.name)
    assertEquals("Test User", credential.user.displayName)
    assertEquals(0u, credential.signCount)
  }

  @Test
  fun `getAssertion returns valid assertion`() {
    val credentialResult =
      cryptoHandler.createCredential(
        rpId = "example.com",
        userId = "user123".toByteArray(),
        userName = "testuser",
        userDisplayName = "Test User",
        challenge = ByteArray(32) { it.toByte() },
      )

    val credential = credentialResult.getOrElse {
      throw AssertionError("Credential creation failed")
    }

    val assertionResult =
      cryptoHandler.getAssertion(
        credential = credential,
        rpId = "example.com",
        challenge = ByteArray(32) { it.toByte() },
        origin = "https://example.com",
      )

    assertTrue(assertionResult.isOk, "Get assertion should succeed")

    val assertion = assertionResult.getOrElse { throw AssertionError("Get assertion failed") }
    assertNotNull(assertion.credentialId)
    assertNotNull(assertion.authenticatorData)
    assertNotNull(assertion.signature)
    assertNotNull(assertion.clientDataJSON)
    assertTrue(
      assertion.clientDataJSON.contains("\"type\":\"webauthn.get\""),
      "Client data should have correct type",
    )
    assertTrue(
      assertion.clientDataJSON.contains("\"crossOrigin\":false"),
      "Client data should have crossOrigin",
    )
    assertEquals(37, assertion.authenticatorData.size, "Authenticator data should be 37 bytes")
    assertEquals(
      0x05,
      assertion.authenticatorData[32].toInt() and 0xFF,
      "Authenticator flags should set UP and UV only",
    )
    assertTrue(
      assertion.signature.size in 68..72,
      "Signature should be DER-encoded (typically 68-72 bytes)",
    )
  }

  @Test
  fun `sign produces DER-encoded signature`() {
    val (privateKey, _) = cryptoHandler.generateKeyPair()
    val authenticatorData = ByteArray(37) { it.toByte() }
    val clientDataHash = ByteArray(32) { (it * 2).toByte() }

    val signResult = cryptoHandler.sign(privateKey, authenticatorData, clientDataHash)

    assertTrue(signResult.isOk, "Sign should succeed")
    val signature = signResult.getOrElse { throw AssertionError("Sign failed") }
    assertTrue(
      signature.size in 68..72,
      "DER signature should typically be 68-72 bytes, got ${signature.size}",
    )
  }
}
