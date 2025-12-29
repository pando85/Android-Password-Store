/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey.provider

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WebAuthnJsonParserTest {

  private val moshi: Moshi = Moshi.Builder()
    .addLast(KotlinJsonAdapterFactory())
    .build()
  private val parser = WebAuthnJsonParser(moshi)

  @Test
  fun parseCreationOptionsBasic() {
    val json = """
      {
        "rp": {"id": "example.com", "name": "Example Corp"},
        "user": {"id": "dXNlcjEyMw", "name": "user@example.com", "displayName": "Test User"},
        "challenge": "Y2hhbGxlbmdlMTIz",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}]
      }
    """.trimIndent()

    val options = parser.parseCreationOptions(json)

    assertNotNull(options)
    assertEquals("example.com", options.rp.id)
    assertEquals("Example Corp", options.rp.name)
    assertEquals("dXNlcjEyMw", options.user.id)
    assertEquals("user@example.com", options.user.name)
    assertEquals("Test User", options.user.displayName)
    assertEquals("Y2hhbGxlbmdlMTIz", options.challenge)
    assertEquals(1, options.pubKeyCredParams.size)
    assertEquals("public-key", options.pubKeyCredParams[0].type)
    assertEquals(-7, options.pubKeyCredParams[0].alg)
  }

  @Test
  fun parseCreationOptionsWithAllFields() {
    val json = """
      {
        "rp": {"id": "example.com", "name": "Example Corp"},
        "user": {"id": "dXNlcjEyMw", "name": "user@example.com", "displayName": "Test User"},
        "challenge": "Y2hhbGxlbmdlMTIz",
        "pubKeyCredParams": [
          {"type": "public-key", "alg": -7},
          {"type": "public-key", "alg": -257}
        ],
        "timeout": 60000,
        "excludeCredentials": [
          {"type": "public-key", "id": "Y3JlZDEyMw", "transports": ["internal", "usb"]}
        ],
        "authenticatorSelection": {
          "authenticatorAttachment": "platform",
          "residentKey": "required",
          "requireResidentKey": true,
          "userVerification": "required"
        },
        "attestation": "none"
      }
    """.trimIndent()

    val options = parser.parseCreationOptions(json)

    assertNotNull(options)
    assertEquals(60000L, options.timeout)
    assertEquals(2, options.pubKeyCredParams.size)
    assertEquals(1, options.excludeCredentials?.size)
    assertEquals("Y3JlZDEyMw", options.excludeCredentials?.get(0)?.id)
    assertEquals(listOf("internal", "usb"), options.excludeCredentials?.get(0)?.transports)
    assertEquals("platform", options.authenticatorSelection?.authenticatorAttachment)
    assertEquals("required", options.authenticatorSelection?.residentKey)
    assertEquals(true, options.authenticatorSelection?.requireResidentKey)
    assertEquals("required", options.authenticatorSelection?.userVerification)
    assertEquals("none", options.attestation)
  }

  @Test
  fun parseCreationOptionsWithoutRpId() {
    val json = """
      {
        "rp": {"name": "Example Corp"},
        "user": {"id": "dXNlcjEyMw", "name": "user@example.com", "displayName": "Test User"},
        "challenge": "Y2hhbGxlbmdlMTIz",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}]
      }
    """.trimIndent()

    val options = parser.parseCreationOptions(json)

    assertNotNull(options)
    assertNull(options.rp.id)
    assertEquals("Example Corp", options.rp.name)
  }

  @Test
  fun parseCreationOptionsInvalidJsonReturnsNull() {
    val result = parser.parseCreationOptions("not valid json")
    assertNull(result)
  }

  @Test
  fun parseCreationOptionsEmptyStringReturnsNull() {
    val result = parser.parseCreationOptions("")
    assertNull(result)
  }

  @Test
  fun parseRequestOptionsBasic() {
    val json = """
      {
        "challenge": "Y2hhbGxlbmdlMTIz",
        "rpId": "example.com"
      }
    """.trimIndent()

    val options = parser.parseRequestOptions(json)

    assertNotNull(options)
    assertEquals("Y2hhbGxlbmdlMTIz", options.challenge)
    assertEquals("example.com", options.rpId)
  }

  @Test
  fun parseRequestOptionsWithAllFields() {
    val json = """
      {
        "challenge": "Y2hhbGxlbmdlMTIz",
        "timeout": 60000,
        "rpId": "example.com",
        "allowCredentials": [
          {"type": "public-key", "id": "Y3JlZDEyMw", "transports": ["internal"]}
        ],
        "userVerification": "required"
      }
    """.trimIndent()

    val options = parser.parseRequestOptions(json)

    assertNotNull(options)
    assertEquals("Y2hhbGxlbmdlMTIz", options.challenge)
    assertEquals(60000L, options.timeout)
    assertEquals("example.com", options.rpId)
    assertEquals(1, options.allowCredentials?.size)
    assertEquals("Y3JlZDEyMw", options.allowCredentials?.get(0)?.id)
    assertEquals("required", options.userVerification)
  }

  @Test
  fun parseRequestOptionsInvalidJsonReturnsNull() {
    val result = parser.parseRequestOptions("not valid json")
    assertNull(result)
  }

  @Test
  fun buildCreateResponseContainsRequiredFields() {
    val credentialId = byteArrayOf(1, 2, 3, 4)
    val attestationObject = byteArrayOf(5, 6, 7, 8)
    val clientDataJson = """{"type":"webauthn.create"}""".toByteArray()
    val publicKeyCose = byteArrayOf(9, 10, 11, 12)

    val response = parser.buildCreateResponse(
      credentialId = credentialId,
      attestationObject = attestationObject,
      clientDataJson = clientDataJson,
      publicKeyCose = publicKeyCose,
    )

    assertTrue(response.contains("\"type\":\"public-key\""))
    assertTrue(response.contains("\"authenticatorAttachment\":\"platform\""))
    assertTrue(response.contains("\"publicKeyAlgorithm\":-7"))
    assertTrue(response.contains("\"transports\":[\"internal\"]"))
  }

  @Test
  fun buildCreateResponseIsValidJson() {
    val credentialId = byteArrayOf(1, 2, 3, 4)
    val attestationObject = byteArrayOf(5, 6, 7, 8)
    val clientDataJson = """{"type":"webauthn.create"}""".toByteArray()
    val publicKeyCose = byteArrayOf(9, 10, 11, 12)

    val response = parser.buildCreateResponse(
      credentialId = credentialId,
      attestationObject = attestationObject,
      clientDataJson = clientDataJson,
      publicKeyCose = publicKeyCose,
    )

    // Should be parseable back
    val adapter = moshi.adapter(CreateCredentialResponse::class.java)
    val parsed = adapter.fromJson(response)

    assertNotNull(parsed)
    assertEquals("public-key", parsed.type)
    assertEquals("platform", parsed.authenticatorAttachment)
    // id and rawId should be the same
    assertEquals(parsed.id, parsed.rawId)
  }

  @Test
  fun buildGetResponseContainsRequiredFields() {
    val credentialId = byteArrayOf(1, 2, 3, 4)
    val authenticatorData = byteArrayOf(5, 6, 7, 8)
    val signature = byteArrayOf(9, 10, 11, 12)
    val userHandle = byteArrayOf(13, 14, 15, 16)
    val clientDataJson = """{"type":"webauthn.get"}""".toByteArray()

    val response = parser.buildGetResponse(
      credentialId = credentialId,
      authenticatorData = authenticatorData,
      signature = signature,
      userHandle = userHandle,
      clientDataJson = clientDataJson,
    )

    assertTrue(response.contains("\"type\":\"public-key\""))
    assertTrue(response.contains("\"authenticatorAttachment\":\"platform\""))
    assertTrue(response.contains("\"signature\""))
    assertTrue(response.contains("\"authenticatorData\""))
    assertTrue(response.contains("\"userHandle\""))
  }

  @Test
  fun buildGetResponseWithNullUserHandle() {
    val credentialId = byteArrayOf(1, 2, 3, 4)
    val authenticatorData = byteArrayOf(5, 6, 7, 8)
    val signature = byteArrayOf(9, 10, 11, 12)
    val clientDataJson = """{"type":"webauthn.get"}""".toByteArray()

    val response = parser.buildGetResponse(
      credentialId = credentialId,
      authenticatorData = authenticatorData,
      signature = signature,
      userHandle = null,
      clientDataJson = clientDataJson,
    )

    // Should be parseable back
    val adapter = moshi.adapter(GetCredentialResponse::class.java)
    val parsed = adapter.fromJson(response)

    assertNotNull(parsed)
    assertNull(parsed.response.userHandle)
  }

  @Test
  fun fromBase64UrlDecodes() {
    // "test" in Base64URL is "dGVzdA"
    val decoded = "dGVzdA".fromBase64Url()
    assertEquals("test", String(decoded))
  }

  @Test
  fun fromBase64UrlHandlesPadding() {
    // Base64URL without padding
    val withoutPadding = "SGVsbG8".fromBase64Url()
    assertEquals("Hello", String(withoutPadding))

    // Base64URL with padding should also work
    val withPadding = "SGVsbG8=".fromBase64Url()
    assertEquals("Hello", String(withPadding))
  }

  @Test
  fun fromBase64UrlHandlesUrlSafeCharacters() {
    // Standard Base64 uses + and /, URL safe uses - and _
    // This encodes bytes that would have + and / in standard Base64
    val input = "abc-_123" // URL-safe encoded
    val decoded = input.fromBase64Url()
    assertNotNull(decoded)
  }
}
