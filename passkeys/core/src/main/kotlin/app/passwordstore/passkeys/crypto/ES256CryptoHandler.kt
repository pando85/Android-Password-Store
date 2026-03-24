/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.datetime.Clock
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo

public class ES256CryptoHandler : PasskeyCryptoHandler {

  private val secureRandom = SecureRandom()

  override fun generateKeyPair(): Pair<ByteArray, ByteArray> {
    val keyPairGenerator = KeyPairGenerator.getInstance("EC")
    keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"), secureRandom)
    val keyPair = keyPairGenerator.generateKeyPair()

    val publicKeyBytes =
      SubjectPublicKeyInfo.getInstance(keyPair.public.encoded).publicKeyData.bytes
    val privateKeyBytes = keyPair.private.encoded

    return Pair(privateKeyBytes, publicKeyBytes)
  }

  override fun sign(
    privateKey: ByteArray,
    authenticatorData: ByteArray,
    clientDataHash: ByteArray,
  ): Result<ByteArray, Throwable> {
    if (privateKey.isEmpty()) return Err(IllegalArgumentException("Private key cannot be empty"))
    if (authenticatorData.isEmpty())
      return Err(IllegalArgumentException("Authenticator data cannot be empty"))
    if (clientDataHash.isEmpty())
      return Err(IllegalArgumentException("Client data hash cannot be empty"))

    return try {
      val keyFactory = java.security.KeyFactory.getInstance("EC")
      val keySpec = java.security.spec.PKCS8EncodedKeySpec(privateKey)
      val privateKeyObj = keyFactory.generatePrivate(keySpec)

      val dataToSign = authenticatorData + clientDataHash

      val signature = Signature.getInstance("SHA256withECDSA")
      signature.initSign(privateKeyObj)
      signature.update(dataToSign)
      val derSignature = signature.sign()

      Ok(derSignature)
    } catch (e: Exception) {
      Err(e)
    }
  }

  override fun verify(
    publicKey: ByteArray,
    signature: ByteArray,
    authenticatorData: ByteArray,
    clientDataHash: ByteArray,
  ): Result<Boolean, Throwable> {
    if (publicKey.isEmpty()) return Err(IllegalArgumentException("Public key cannot be empty"))
    if (signature.isEmpty()) return Err(IllegalArgumentException("Signature cannot be empty"))
    if (authenticatorData.isEmpty())
      return Err(IllegalArgumentException("Authenticator data cannot be empty"))
    if (clientDataHash.isEmpty())
      return Err(IllegalArgumentException("Client data hash cannot be empty"))

    return try {
      val keyFactory = java.security.KeyFactory.getInstance("EC")
      val keySpec = java.security.spec.X509EncodedKeySpec(unwrapRawPublicKey(publicKey))
      val publicKeyObj = keyFactory.generatePublic(keySpec)

      val dataToVerify = authenticatorData + clientDataHash

      val sig = Signature.getInstance("SHA256withECDSA")
      sig.initVerify(publicKeyObj)
      sig.update(dataToVerify)
      Ok(sig.verify(signature))
    } catch (e: Exception) {
      Err(e)
    }
  }

  override fun createCredential(
    rpId: String,
    userId: ByteArray,
    userName: String,
    userDisplayName: String,
    challenge: ByteArray,
  ): Result<PasskeyCredential, Throwable> {
    if (rpId.isBlank()) return Err(IllegalArgumentException("RP ID cannot be blank"))
    if (userId.isEmpty()) return Err(IllegalArgumentException("User ID cannot be empty"))

    return try {
      val (privateKey, publicKey) = generateKeyPair()
      val credentialId = generateCredentialId()

      Ok(
        PasskeyCredential(
          credentialId = credentialId,
          privateKey = privateKey,
          publicKey = publicKey,
          rpId = rpId,
          user = FidoUser(id = userId, name = userName, displayName = userDisplayName),
          signCount = 0u,
          createdAt = Clock.System.now(),
          transports = listOf("internal"),
          uvInitialized = true,
        )
      )
    } catch (e: Exception) {
      Err(e)
    }
  }

  override fun getAssertion(
    credential: PasskeyCredential,
    rpId: String,
    challenge: ByteArray,
    origin: String,
  ): Result<AssertionResult, Throwable> {
    if (rpId.isBlank()) return Err(IllegalArgumentException("RP ID cannot be blank"))
    if (challenge.isEmpty()) return Err(IllegalArgumentException("Challenge cannot be empty"))
    if (origin.isBlank()) return Err(IllegalArgumentException("Origin cannot be blank"))
    if (credential.privateKey.isEmpty())
      return Err(IllegalArgumentException("Credential has no private key"))

    return try {
      val authenticatorData = buildAuthenticatorData(rpId, credential.signCount)
      val (clientDataJson, clientDataHash) = buildClientData(challenge, origin, "webauthn.get")

      sign(credential.privateKey, authenticatorData, clientDataHash)
        .fold(
          success = { signature ->
            Ok(
              AssertionResult(
                credentialId = credential.credentialId,
                authenticatorData = authenticatorData,
                signature = signature,
                userHandle = credential.user.id,
                clientDataJSON = clientDataJson,
              )
            )
          },
          failure = { Err(it) },
        )
    } catch (e: Exception) {
      Err(e)
    }
  }

  private fun generateCredentialId(): ByteArray {
    val idBytes = ByteArray(32)
    secureRandom.nextBytes(idBytes)
    return idBytes
  }

  private fun buildAuthenticatorData(rpId: String, signCount: ULong): ByteArray {
    val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
    val flags = (FLAG_USER_PRESENT.toInt() or FLAG_USER_VERIFIED.toInt()).toByte()
    val signCountBytes =
      byteArrayOf(
        ((signCount shr 24) and 0xFFu).toByte(),
        ((signCount shr 16) and 0xFFu).toByte(),
        ((signCount shr 8) and 0xFFu).toByte(),
        (signCount and 0xFFu).toByte(),
      )
    return rpIdHash + flags + signCountBytes
  }

  private fun buildClientData(
    challenge: ByteArray,
    origin: String,
    type: String,
  ): Pair<String, ByteArray> {
    val clientDataJson =
      """{"type":"$type","challenge":"${java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(challenge)}","origin":"$origin","crossOrigin":false}"""
    return Pair(
      clientDataJson,
      MessageDigest.getInstance("SHA-256").digest(clientDataJson.toByteArray()),
    )
  }

  private fun unwrapRawPublicKey(rawPublicKey: ByteArray): ByteArray {
    require(rawPublicKey.size == 65 && rawPublicKey.first() == 0x04.toByte()) {
      "Expected 65-byte uncompressed P-256 public key starting with 0x04, got ${rawPublicKey.size} bytes starting with 0x${rawPublicKey.first().toInt().and(0xFF).toString(16)}"
    }
    return P256_EC_OID_PREFIX + rawPublicKey
  }

  public companion object {
    public const val FLAG_USER_PRESENT: Byte = 0x01
    public const val FLAG_USER_VERIFIED: Byte = 0x04
    public const val FLAG_ATTESTED_CREDENTIAL_DATA: Byte = 0x40

    private val P256_EC_OID_PREFIX =
      byteArrayOf(
        0x30,
        0x59,
        0x30,
        0x13,
        0x06,
        0x07,
        0x2A.toByte(),
        0x86.toByte(),
        0x48,
        0xCE.toByte(),
        0x3D,
        0x02,
        0x01,
        0x06,
        0x08,
        0x2A.toByte(),
        0x86.toByte(),
        0x48,
        0xCE.toByte(),
        0x3D,
        0x03,
        0x01,
        0x07,
        0x03,
        0x42,
        0x00,
      )
  }
}
