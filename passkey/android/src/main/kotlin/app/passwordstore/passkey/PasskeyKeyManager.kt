/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.passwordstore.util.coroutines.DispatcherProvider
import dagger.hilt.android.qualifiers.ApplicationContext
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPrivateKeySpec
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import kotlinx.coroutines.withContext
import logcat.logcat

/**
 * Manages EC key operations for passkeys using software keys.
 *
 * Unlike the Android KeyStore approach, this generates and manages EC keys in software.
 * The private keys are stored as raw bytes in the GPG-encrypted credential files,
 * allowing them to sync via git with Passless.
 *
 * Security is provided by:
 * - GPG encryption of the private key bytes
 * - Optional biometric authentication before decryption
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@Singleton
public class PasskeyKeyManager
@Inject
constructor(
  @ApplicationContext private val context: Context,
  private val dispatcherProvider: DispatcherProvider,
) {
  private companion object {
    private const val EC_CURVE = "secp256r1"
    private const val KEY_SIZE_BYTES = 32
  }

  /** Check if biometric authentication is available */
  public fun isBiometricAvailable(): Boolean {
    val biometricManager = BiometricManager.from(context)
    return biometricManager.canAuthenticate(
      BiometricManager.Authenticators.BIOMETRIC_STRONG or
        BiometricManager.Authenticators.DEVICE_CREDENTIAL
    ) == BiometricManager.BIOMETRIC_SUCCESS
  }

  /**
   * Generate a new EC key pair for a passkey credential.
   *
   * The key is generated in software and returned as raw bytes.
   * The caller is responsible for storing the private key securely (e.g., in a GPG-encrypted file).
   *
   * @return KeyPairData containing the private key bytes and public key in COSE format
   */
  public suspend fun generateKeyPair(): KeyPairData =
    withContext(dispatcherProvider.default()) {
      val keyPairGenerator = KeyPairGenerator.getInstance("EC")
      keyPairGenerator.initialize(ECGenParameterSpec(EC_CURVE), SecureRandom())
      val keyPair = keyPairGenerator.generateKeyPair()

      val privateKey = keyPair.private as ECPrivateKey
      val publicKey = keyPair.public as ECPublicKey

      // Extract raw private key bytes (32 bytes for P-256)
      val privateKeyBytes = privateKey.s.toByteArray().let { bytes ->
        when {
          bytes.size == KEY_SIZE_BYTES -> bytes
          bytes.size == KEY_SIZE_BYTES + 1 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, KEY_SIZE_BYTES + 1)
          bytes.size < KEY_SIZE_BYTES -> ByteArray(KEY_SIZE_BYTES - bytes.size) + bytes
          else -> bytes.copyOfRange(bytes.size - KEY_SIZE_BYTES, bytes.size)
        }
      }

      // Encode public key in COSE format
      val publicKeyCose = encodeCoseKey(publicKey)

      KeyPairData(
        privateKey = privateKeyBytes,
        publicKeyCose = publicKeyCose,
      )
    }

  /**
   * Sign data using an EC private key.
   *
   * @param privateKeyBytes The raw EC private key bytes (32 bytes for P-256)
   * @param data The data to sign
   * @return The ECDSA signature in DER format
   */
  public suspend fun sign(
    privateKeyBytes: ByteArray,
    data: ByteArray,
  ): ByteArray =
    withContext(dispatcherProvider.default()) {
      // Reconstruct the private key from raw bytes
      val privateKey = reconstructPrivateKey(privateKeyBytes)

      val signature = Signature.getInstance("SHA256withECDSA")
      signature.initSign(privateKey)
      signature.update(data)
      signature.sign()
    }

  /**
   * Sign data using an EC private key with biometric authentication.
   *
   * This shows a biometric prompt before signing. The biometric is for UX purposes only -
   * the actual key is not protected by biometric in hardware.
   *
   * @param privateKeyBytes The raw EC private key bytes (32 bytes for P-256)
   * @param data The data to sign
   * @param activity The activity to show the biometric prompt
   * @param title The title for the biometric prompt
   * @param subtitle The subtitle for the biometric prompt
   * @return The signature, or null if authentication failed/cancelled
   */
  public suspend fun signWithBiometric(
    privateKeyBytes: ByteArray,
    data: ByteArray,
    activity: FragmentActivity,
    title: String,
    subtitle: String,
  ): ByteArray? = suspendCoroutine { continuation ->
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle(title)
      .setSubtitle(subtitle)
      .setAllowedAuthenticators(
        BiometricManager.Authenticators.BIOMETRIC_STRONG or
          BiometricManager.Authenticators.DEVICE_CREDENTIAL
      )
      .build()

    val executor = ContextCompat.getMainExecutor(activity)
    val callback = object : BiometricPrompt.AuthenticationCallback() {
      override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        try {
          val privateKey = reconstructPrivateKey(privateKeyBytes)
          val signature = Signature.getInstance("SHA256withECDSA")
          signature.initSign(privateKey)
          signature.update(data)
          continuation.resume(signature.sign())
        } catch (e: Exception) {
          logcat { "Signing failed: ${e.message}" }
          continuation.resume(null)
        }
      }

      override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        logcat { "Biometric authentication error: $errorCode - $errString" }
        continuation.resume(null)
      }

      override fun onAuthenticationFailed() {
        // Don't resume here - the user can retry
      }
    }

    val biometricPrompt = BiometricPrompt(activity, executor, callback)
    biometricPrompt.authenticate(promptInfo)
  }

  /**
   * Get the public key (COSE format) from private key bytes.
   *
   * @param privateKeyBytes The raw EC private key bytes
   * @return The public key in COSE format
   */
  public suspend fun getPublicKey(privateKeyBytes: ByteArray): ByteArray =
    withContext(dispatcherProvider.default()) {
      val privateKey = reconstructPrivateKey(privateKeyBytes)
      
      // Derive public key from private key
      val keyFactory = KeyFactory.getInstance("EC")
      val ecSpec = java.security.spec.ECParameterSpec(
        privateKey.params.curve,
        privateKey.params.generator,
        privateKey.params.order,
        privateKey.params.cofactor
      )
      
      // Calculate public key point: G * d (generator point multiplied by private key scalar)
      val d = privateKey.s
      val publicKeyPoint = derivePublicKeyPoint(d, ecSpec)
      val publicKeySpec = java.security.spec.ECPublicKeySpec(publicKeyPoint, ecSpec)
      val publicKey = keyFactory.generatePublic(publicKeySpec) as ECPublicKey

      encodeCoseKey(publicKey)
    }

  // === Private helpers ===

  /**
   * Reconstruct an EC private key from raw bytes.
   */
  private fun reconstructPrivateKey(privateKeyBytes: ByteArray): ECPrivateKey {
    val keyFactory = KeyFactory.getInstance("EC")
    
    // Get EC parameters for P-256
    val ecGenSpec = ECGenParameterSpec(EC_CURVE)
    val tempKeyPairGen = KeyPairGenerator.getInstance("EC")
    tempKeyPairGen.initialize(ecGenSpec)
    val tempKeyPair = tempKeyPairGen.generateKeyPair()
    val ecParams = (tempKeyPair.private as ECPrivateKey).params

    // Create private key spec from raw bytes
    val s = BigInteger(1, privateKeyBytes)
    val privateKeySpec = ECPrivateKeySpec(s, ecParams)
    
    return keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey
  }

  /**
   * Derive the public key point from a private key scalar.
   */
  private fun derivePublicKeyPoint(
    d: BigInteger,
    ecSpec: java.security.spec.ECParameterSpec
  ): java.security.spec.ECPoint {
    // We can't easily do EC point multiplication in standard Java,
    // so we use a workaround: create a key pair generator, which internally
    // does the multiplication for us.
    // 
    // Actually, the cleanest approach is to use BouncyCastle or just
    // regenerate using the same seed. But since we're storing the private key,
    // we need a deterministic way to get the public key.
    //
    // The standard approach: use the ECPublicKey derived during key generation
    // and store both. But for loading from storage, we need to derive.
    //
    // For simplicity, let's use BouncyCastle's EC point multiplication:
    
    val bcSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1")
    val point = bcSpec.g.multiply(d).normalize()
    
    return java.security.spec.ECPoint(
      point.affineXCoord.toBigInteger(),
      point.affineYCoord.toBigInteger()
    )
  }

  /**
   * Encode an EC public key in COSE_Key format (RFC 8152).
   *
   * COSE_Key for EC2 (P-256):
   * {
   *   1: 2,          // kty: EC2
   *   3: -7,         // alg: ES256
   *   -1: 1,         // crv: P-256
   *   -2: x-coord,   // x
   *   -3: y-coord,   // y
   * }
   */
  private fun encodeCoseKey(publicKey: ECPublicKey): ByteArray {
    val point = publicKey.w

    // X and Y coordinates (32 bytes each for P-256)
    val x = point.affineX.toByteArray().let { bytes ->
      when {
        bytes.size == KEY_SIZE_BYTES -> bytes
        bytes.size == KEY_SIZE_BYTES + 1 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, KEY_SIZE_BYTES + 1)
        bytes.size < KEY_SIZE_BYTES -> ByteArray(KEY_SIZE_BYTES - bytes.size) + bytes
        else -> bytes.copyOfRange(bytes.size - KEY_SIZE_BYTES, bytes.size)
      }
    }
    val y = point.affineY.toByteArray().let { bytes ->
      when {
        bytes.size == KEY_SIZE_BYTES -> bytes
        bytes.size == KEY_SIZE_BYTES + 1 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, KEY_SIZE_BYTES + 1)
        bytes.size < KEY_SIZE_BYTES -> ByteArray(KEY_SIZE_BYTES - bytes.size) + bytes
        else -> bytes.copyOfRange(bytes.size - KEY_SIZE_BYTES, bytes.size)
      }
    }

    // Build CBOR map manually
    // A5 = map with 5 entries
    // 01 02 = key 1 (kty) : value 2 (EC2)
    // 03 26 = key 3 (alg) : value -7 (ES256, encoded as 0x26)
    // 20 01 = key -1 (crv) : value 1 (P-256)
    // 21 5820 <x> = key -2 (x) : bstr(32 bytes)
    // 22 5820 <y> = key -3 (y) : bstr(32 bytes)
    val cose = mutableListOf<Byte>()
    cose.add(0xA5.toByte()) // Map with 5 items

    // kty: EC2 (1: 2)
    cose.add(0x01)
    cose.add(0x02)

    // alg: ES256 (3: -7)
    cose.add(0x03)
    cose.add(0x26) // -7 in CBOR

    // crv: P-256 (-1: 1)
    cose.add(0x20) // -1 in CBOR
    cose.add(0x01)

    // x (-2: bstr)
    cose.add(0x21) // -2 in CBOR
    cose.add(0x58) // bstr, 1-byte length
    cose.add(0x20) // 32 bytes
    cose.addAll(x.toList())

    // y (-3: bstr)
    cose.add(0x22) // -3 in CBOR
    cose.add(0x58) // bstr, 1-byte length
    cose.add(0x20) // 32 bytes
    cose.addAll(y.toList())

    return cose.toByteArray()
  }
}

/**
 * Result of key pair generation.
 */
public data class KeyPairData(
  /** Raw EC private key bytes (32 bytes for P-256) */
  val privateKey: ByteArray,
  
  /** Public key in COSE format */
  val publicKeyCose: ByteArray,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false
    other as KeyPairData
    return privateKey.contentEquals(other.privateKey)
  }

  override fun hashCode(): Int = privateKey.contentHashCode()
}
