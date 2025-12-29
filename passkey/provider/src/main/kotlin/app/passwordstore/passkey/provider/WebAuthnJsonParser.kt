/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey.provider

import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import org.apache.commons.codec.binary.Base64

/**
 * Parser for WebAuthn JSON request/response structures.
 *
 * Uses Moshi for proper JSON parsing instead of regex.
 */
public class WebAuthnJsonParser(
  private val moshi: Moshi = Moshi.Builder()
    .addLast(KotlinJsonAdapterFactory())
    .build(),
) {

  /**
   * Parse a PublicKeyCredentialCreationOptions JSON.
   */
  public fun parseCreationOptions(json: String): PublicKeyCredentialCreationOptions? {
    return try {
      val adapter = moshi.adapter(PublicKeyCredentialCreationOptions::class.java)
      adapter.fromJson(json)
    } catch (e: Exception) {
      null
    }
  }

  /**
   * Parse a PublicKeyCredentialRequestOptions JSON.
   */
  public fun parseRequestOptions(json: String): PublicKeyCredentialRequestOptions? {
    return try {
      val adapter = moshi.adapter(PublicKeyCredentialRequestOptions::class.java)
      adapter.fromJson(json)
    } catch (e: Exception) {
      null
    }
  }

  /**
   * Build a create credential response JSON.
   */
  public fun buildCreateResponse(
    credentialId: ByteArray,
    attestationObject: ByteArray,
    clientDataJson: ByteArray,
    publicKeyCose: ByteArray,
  ): String {
    val response = CreateCredentialResponse(
      id = credentialId.toBase64Url(),
      rawId = credentialId.toBase64Url(),
      type = "public-key",
      authenticatorAttachment = "platform",
      response = AuthenticatorAttestationResponse(
        clientDataJSON = clientDataJson.toBase64Url(),
        attestationObject = attestationObject.toBase64Url(),
        transports = listOf("internal"),
        publicKey = publicKeyCose.toBase64Url(),
        publicKeyAlgorithm = -7, // ES256
        authenticatorData = null,
      ),
    )
    val adapter = moshi.adapter(CreateCredentialResponse::class.java)
    return adapter.toJson(response)
  }

  /**
   * Build a get assertion response JSON.
   */
  public fun buildGetResponse(
    credentialId: ByteArray,
    authenticatorData: ByteArray,
    signature: ByteArray,
    userHandle: ByteArray?,
    clientDataJson: ByteArray,
  ): String {
    val response = GetCredentialResponse(
      id = credentialId.toBase64Url(),
      rawId = credentialId.toBase64Url(),
      type = "public-key",
      authenticatorAttachment = "platform",
      response = AuthenticatorAssertionResponse(
        clientDataJSON = clientDataJson.toBase64Url(),
        authenticatorData = authenticatorData.toBase64Url(),
        signature = signature.toBase64Url(),
        userHandle = userHandle?.toBase64Url(),
      ),
    )
    val adapter = moshi.adapter(GetCredentialResponse::class.java)
    return adapter.toJson(response)
  }

  private fun ByteArray.toBase64Url(): String =
    Base64.encodeBase64URLSafeString(this)
}

// === WebAuthn Data Classes ===

@JsonClass(generateAdapter = false)
public data class PublicKeyCredentialCreationOptions(
  val rp: RelyingPartyEntity,
  val user: UserEntity,
  val challenge: String,
  val pubKeyCredParams: List<PubKeyCredParam>,
  val timeout: Long? = null,
  val excludeCredentials: List<CredentialDescriptor>? = null,
  val authenticatorSelection: AuthenticatorSelectionCriteria? = null,
  val attestation: String? = null,
)

@JsonClass(generateAdapter = false)
public data class PublicKeyCredentialRequestOptions(
  val challenge: String,
  val timeout: Long? = null,
  val rpId: String? = null,
  val allowCredentials: List<CredentialDescriptor>? = null,
  val userVerification: String? = null,
)

@JsonClass(generateAdapter = false)
public data class RelyingPartyEntity(
  val id: String? = null,
  val name: String,
)

@JsonClass(generateAdapter = false)
public data class UserEntity(
  val id: String,
  val name: String,
  val displayName: String,
)

@JsonClass(generateAdapter = false)
public data class PubKeyCredParam(
  val type: String,
  val alg: Int,
)

@JsonClass(generateAdapter = false)
public data class CredentialDescriptor(
  val type: String,
  val id: String,
  val transports: List<String>? = null,
)

@JsonClass(generateAdapter = false)
public data class AuthenticatorSelectionCriteria(
  val authenticatorAttachment: String? = null,
  val residentKey: String? = null,
  val requireResidentKey: Boolean? = null,
  val userVerification: String? = null,
)

// === Response Data Classes ===

@JsonClass(generateAdapter = false)
public data class CreateCredentialResponse(
  val id: String,
  val rawId: String,
  val type: String,
  val authenticatorAttachment: String?,
  val response: AuthenticatorAttestationResponse,
)

@JsonClass(generateAdapter = false)
public data class AuthenticatorAttestationResponse(
  val clientDataJSON: String,
  val attestationObject: String,
  val transports: List<String>,
  val publicKey: String?,
  val publicKeyAlgorithm: Int,
  val authenticatorData: String?,
)

@JsonClass(generateAdapter = false)
public data class GetCredentialResponse(
  val id: String,
  val rawId: String,
  val type: String,
  val authenticatorAttachment: String?,
  val response: AuthenticatorAssertionResponse,
)

@JsonClass(generateAdapter = false)
public data class AuthenticatorAssertionResponse(
  val clientDataJSON: String,
  val authenticatorData: String,
  val signature: String,
  val userHandle: String?,
)

// === Extension functions for Base64 ===

public fun String.fromBase64Url(): ByteArray =
  Base64.decodeBase64(this)
