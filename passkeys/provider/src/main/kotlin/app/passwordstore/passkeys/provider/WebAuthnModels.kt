/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.provider

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
public data class WebAuthnGetRequest(
  @SerialName("rpId") val rpId: String? = null,
  @SerialName("challenge") val challenge: String,
  @SerialName("allowCredentials") val allowCredentials: List<PublicKeyCredentialDescriptor> = emptyList(),
  @SerialName("userVerification") val userVerification: String? = null,
  @SerialName("timeout") val timeout: Long? = null,
  @SerialName("origin") val origin: String? = null,
)

@Serializable
public data class WebAuthnCreateRequest(
  @SerialName("rp") val rp: RpEntity,
  @SerialName("user") val user: UserEntity,
  @SerialName("challenge") val challenge: String,
  @SerialName("pubKeyCredParams") val pubKeyCredParams: List<PubKeyCredParam> = emptyList(),
  @SerialName("timeout") val timeout: Long? = null,
  @SerialName("authenticatorSelection") val authenticatorSelection: AuthenticatorSelection? = null,
  @SerialName("attestation") val attestation: String? = null,
)

@Serializable
public data class PublicKeyCredentialDescriptor(
  @SerialName("type") val type: String,
  @SerialName("id") val id: String,
  @SerialName("transports") val transports: List<String>? = null,
  @SerialName("rpId") val rpId: String? = null,
)

@Serializable
public data class RpEntity(
  @SerialName("id") val id: String,
  @SerialName("name") val name: String? = null,
)

@Serializable
public data class UserEntity(
  @SerialName("id") val id: String,
  @SerialName("name") val name: String? = null,
  @SerialName("displayName") val displayName: String? = null,
)

@Serializable
public data class PubKeyCredParam(
  @SerialName("type") val type: String,
  @SerialName("alg") val alg: Long,
)

@Serializable
public data class AuthenticatorSelection(
  @SerialName("authenticatorAttachment") val authenticatorAttachment: String? = null,
  @SerialName("residentKey") val residentKey: String? = null,
  @SerialName("requireResidentKey") val requireResidentKey: Boolean? = null,
  @SerialName("userVerification") val userVerification: String? = null,
)

@Serializable
public data class AssertionResponseJson(
  @SerialName("id") val id: String,
  @SerialName("rawId") val rawId: String,
  @SerialName("type") val type: String,
  @SerialName("response") val response: AssertionResponseData,
  @SerialName("authenticatorAttachment") val authenticatorAttachment: String = "platform",
  @SerialName("clientExtensionResults") val clientExtensionResults: ClientExtensionResults = ClientExtensionResults(),
)

@Serializable
public data class AssertionResponseData(
  @SerialName("clientDataJSON") val clientDataJSON: String,
  @SerialName("authenticatorData") val authenticatorData: String,
  @SerialName("signature") val signature: String,
  @SerialName("userHandle") val userHandle: String? = null,
)

@Serializable
public data class AttestationResponseJson(
  @SerialName("id") val id: String,
  @SerialName("rawId") val rawId: String,
  @SerialName("type") val type: String,
  @SerialName("response") val response: AttestationResponseData,
  @SerialName("authenticatorAttachment") val authenticatorAttachment: String = "platform",
  @SerialName("clientExtensionResults") val clientExtensionResults: ClientExtensionResults = ClientExtensionResults(),
)

@Serializable
public data class ClientExtensionResults(
  @SerialName("credProps") val credProps: CredProps = CredProps(),
)

@Serializable
public data class CredProps(
  @SerialName("rk") val rk: Boolean = true,
)

@Serializable
public data class AttestationResponseData(
  @SerialName("clientDataJSON") val clientDataJSON: String,
  @SerialName("attestationObject") val attestationObject: String,
  @SerialName("transports") val transports: List<String> = listOf("internal"),
  @SerialName("publicKeyAlgorithm") val publicKeyAlgorithm: Long = -7L,
  @SerialName("authenticatorData") val authenticatorData: String,
  @SerialName("publicKey") val publicKey: String,
)

@Serializable
public data class ClientDataJson(
  @SerialName("type") val type: String,
  @SerialName("challenge") val challenge: String,
  @SerialName("origin") val origin: String,
  @SerialName("crossOrigin") val crossOrigin: Boolean = false,
)
