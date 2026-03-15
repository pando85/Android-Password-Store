/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.provider

import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebAuthnModelsTest {

  @Test
  fun `WebAuthnGetRequest parses correctly`() {
    val json = """
      {
        "rpId": "example.com",
        "challenge": "dGVzdC1jaGFsbGVuZ2U",
        "allowCredentials": [
          {"type": "public-key", "id": "Y3JlZGVudGlhbC1pZA"}
        ],
        "userVerification": "required"
      }
    """.trimIndent()

    val request = PasskeyProviderUtils.json.decodeFromString<WebAuthnGetRequest>(json)

    assertEquals("example.com", request.rpId)
    assertEquals("dGVzdC1jaGFsbGVuZ2U", request.challenge)
    assertEquals(1, request.allowCredentials.size)
    assertEquals("public-key", request.allowCredentials[0].type)
    assertEquals("Y3JlZGVudGlhbC1pZA", request.allowCredentials[0].id)
    assertEquals("required", request.userVerification)
  }

  @Test
  fun `WebAuthnGetRequest handles missing optional fields`() {
    val json = """
      {
        "challenge": "dGVzdC1jaGFsbGVuZ2U"
      }
    """.trimIndent()

    val request = PasskeyProviderUtils.json.decodeFromString<WebAuthnGetRequest>(json)

    assertEquals(null, request.rpId)
    assertEquals("dGVzdC1jaGFsbGVuZ2U", request.challenge)
    assertTrue(request.allowCredentials.isEmpty())
  }

  @Test
  fun `WebAuthnCreateRequest parses correctly`() {
    val json = """
      {
        "rp": {"id": "example.com", "name": "Example Site"},
        "user": {"id": "dXNlci1pZA", "name": "testuser", "displayName": "Test User"},
        "challenge": "dGVzdC1jaGFsbGVuZ2U",
        "pubKeyCredParams": [
          {"type": "public-key", "alg": -7}
        ],
        "authenticatorSelection": {
          "authenticatorAttachment": "platform",
          "residentKey": "required",
          "userVerification": "required"
        }
      }
    """.trimIndent()

    val request = PasskeyProviderUtils.json.decodeFromString<WebAuthnCreateRequest>(json)

    assertEquals("example.com", request.rp.id)
    assertEquals("Example Site", request.rp.name)
    assertEquals("dXNlci1pZA", request.user.id)
    assertEquals("testuser", request.user.name)
    assertEquals("Test User", request.user.displayName)
    assertEquals(1, request.pubKeyCredParams.size)
    assertEquals(-7L, request.pubKeyCredParams[0].alg)
    assertEquals("platform", request.authenticatorSelection?.authenticatorAttachment)
    assertEquals("required", request.authenticatorSelection?.residentKey)
  }

  @Test
  fun `AssertionResponseJson serializes correctly`() {
    val response = AssertionResponseJson(
      id = "credential-id",
      rawId = "credential-id",
      type = "public-key",
      response = AssertionResponseData(
        clientDataJSON = "client-data",
        authenticatorData = "auth-data",
        signature = "signature",
        userHandle = "user-handle"
      )
    )

    val json = PasskeyProviderUtils.json.encodeToString(response)

    assertTrue(json.contains("\"id\":\"credential-id\""))
    assertTrue(json.contains("\"type\":\"public-key\""))
    assertTrue(json.contains("\"clientDataJSON\":\"client-data\""))
    assertTrue(json.contains("\"signature\":\"signature\""))
    assertTrue(json.contains("\"userHandle\":\"user-handle\""))
  }

  @Test
  fun `AttestationResponseJson serializes correctly`() {
    val response = AttestationResponseJson(
      id = "credential-id",
      rawId = "credential-id",
      type = "public-key",
      response = AttestationResponseData(
        clientDataJSON = "client-data",
        attestationObject = "attestation-obj",
        authenticatorData = "auth-data",
        publicKey = "public-key"
      )
    )

    val json = PasskeyProviderUtils.json.encodeToString(response)

    assertTrue(json.contains("\"id\":\"credential-id\""))
    assertTrue(json.contains("\"type\":\"public-key\""))
    assertTrue(json.contains("\"clientDataJSON\":\"client-data\""))
    assertTrue(json.contains("\"attestationObject\":\"attestation-obj\""))
  }

  @Test
  fun `ClientDataJson has correct structure`() {
    val clientData = ClientDataJson(
      type = "webauthn.get",
      challenge = "test-challenge",
      origin = "https://example.com"
    )

    val json = PasskeyProviderUtils.json.encodeToString(clientData)

    assertTrue(json.contains("\"type\":\"webauthn.get\""))
    assertTrue(json.contains("\"challenge\":\"test-challenge\""))
    assertTrue(json.contains("\"origin\":\"https://example.com\""))
  }

  @Test
  fun `PublicKeyCredentialDescriptor handles optional fields`() {
    val json = """
      {
        "type": "public-key",
        "id": "credential-id",
        "transports": ["internal", "hybrid"]
      }
    """.trimIndent()

    val descriptor = PasskeyProviderUtils.json.decodeFromString<PublicKeyCredentialDescriptor>(json)

    assertEquals("public-key", descriptor.type)
    assertEquals("credential-id", descriptor.id)
    assertEquals(listOf("internal", "hybrid"), descriptor.transports)
  }

  @Test
  fun `RpEntity handles null name`() {
    val json = """
      {
        "id": "example.com"
      }
    """.trimIndent()

    val rp = PasskeyProviderUtils.json.decodeFromString<RpEntity>(json)

    assertEquals("example.com", rp.id)
    assertEquals(null, rp.name)
  }

  @Test
  fun `UserEntity handles partial data`() {
    val json = """
      {
        "id": "user-id",
        "name": "testuser"
      }
    """.trimIndent()

    val user = PasskeyProviderUtils.json.decodeFromString<UserEntity>(json)

    assertEquals("user-id", user.id)
    assertEquals("testuser", user.name)
    assertEquals(null, user.displayName)
  }

  @Test
  fun `AuthenticatorSelection handles all optional fields`() {
    val json = """
      {
        "userVerification": "preferred"
      }
    """.trimIndent()

    val selection = PasskeyProviderUtils.json.decodeFromString<AuthenticatorSelection>(json)

    assertEquals(null, selection.authenticatorAttachment)
    assertEquals(null, selection.residentKey)
    assertEquals(null, selection.requireResidentKey)
    assertEquals("preferred", selection.userVerification)
  }

  @Test
  fun `PubKeyCredParam handles ES256 algorithm`() {
    val json = """
      {
        "type": "public-key",
        "alg": -7
      }
    """.trimIndent()

    val param = PasskeyProviderUtils.json.decodeFromString<PubKeyCredParam>(json)

    assertEquals("public-key", param.type)
    assertEquals(-7L, param.alg)
  }

  @Test
  fun `multiple allowCredentials parse correctly`() {
    val json = """
      {
        "challenge": "test",
        "allowCredentials": [
          {"type": "public-key", "id": "cred1"},
          {"type": "public-key", "id": "cred2"},
          {"type": "public-key", "id": "cred3"}
        ]
      }
    """.trimIndent()

    val request = PasskeyProviderUtils.json.decodeFromString<WebAuthnGetRequest>(json)

    assertEquals(3, request.allowCredentials.size)
    assertEquals("cred1", request.allowCredentials[0].id)
    assertEquals("cred2", request.allowCredentials[1].id)
    assertEquals("cred3", request.allowCredentials[2].id)
  }
}