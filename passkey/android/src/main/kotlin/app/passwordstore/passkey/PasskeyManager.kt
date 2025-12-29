/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.fragment.app.FragmentActivity
import app.passwordstore.crypto.PGPDecryptOptions
import app.passwordstore.crypto.PGPEncryptOptions
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.crypto.PGPainlessCryptoHandler
import app.passwordstore.util.coroutines.DispatcherProvider
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.filterValues
import com.github.michaelbull.result.getOrThrow
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import logcat.logcat

/**
 * Main entry point for passkey operations.
 *
 * This class manages FIDO2/WebAuthn credential operations using:
 * - Software EC keys (not Android KeyStore) for Passless compatibility
 * - PGP encryption for credential storage (syncs via git)
 * - Optional biometric authentication for user verification
 *
 * The PasskeyManager is responsible for:
 * - Generating EC key pairs for credentials (via PasskeyKeyManager)
 * - Managing credential storage (via PasskeyRepository)
 * - PGP encryption/decryption of credentials
 * - Handling biometric authentication for signing
 * - Serializing credentials in Passless-compatible CBOR format
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@Singleton
public class PasskeyManager
@Inject
constructor(
  @ApplicationContext private val context: Context,
  private val repository: PasskeyRepository,
  private val keyManager: PasskeyKeyManager,
  private val serializer: PasskeySerializer,
  private val pgpKeyManager: PGPKeyManager,
  private val pgpCryptoHandler: PGPainlessCryptoHandler,
  private val dispatcherProvider: DispatcherProvider,
) {

  private val mutex = Mutex()
  private var isInitialized = false

  /**
   * Initialize the passkey subsystem.
   * Must be called before any other operations.
   */
  public suspend fun initialize(): Result<Unit, PasskeyException> =
    withContext(dispatcherProvider.default()) {
      mutex.withLock {
        if (isInitialized) {
          return@withContext Ok(Unit)
        }

        try {
          logcat { "PasskeyManager initialized" }
          isInitialized = true
          Ok(Unit)
        } catch (e: Exception) {
          logcat { "Failed to initialize PasskeyManager: ${e.message}" }
          Err(PasskeyException.InitializationFailed(e))
        }
      }
    }

  /**
   * Check if biometric authentication is available on this device.
   */
  public fun isBiometricAvailable(): Boolean = keyManager.isBiometricAvailable()

  /**
   * Create a new passkey credential.
   *
   * This generates an EC key pair in software, stores the credential
   * (encrypted with PGP), and returns the attestation object for the relying party.
   *
   * @param activity The activity for showing biometric prompt (if needed)
   * @param baseDir The password store base directory
   * @param rpId Relying party ID (e.g., "example.com")
   * @param rpName Relying party display name
   * @param userId User ID (opaque bytes from the RP)
   * @param userName User name (e.g., email)
   * @param userDisplayName User display name
   * @param challenge The challenge from the relying party
   * @param algorithms List of acceptable COSE algorithm IDs
   * @param pgpKeyIds PGP key identifiers for encryption
   * @param excludeCredentials Credentials to exclude (user already has these)
   * @param requireResidentKey Whether to require a discoverable credential
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return Result containing credential ID and attestation object
   */
  public suspend fun createCredential(
    activity: FragmentActivity,
    baseDir: File,
    rpId: String,
    rpName: String,
    userId: ByteArray,
    userName: String,
    userDisplayName: String,
    challenge: ByteArray,
    algorithms: List<Int>,
    pgpKeyIds: List<PGPIdentifier>,
    excludeCredentials: List<ByteArray> = emptyList(),
    requireResidentKey: Boolean = true,
    passkeysDir: String = PasskeyRepository.DEFAULT_PASSKEYS_DIR,
  ): Result<CreateCredentialOutput, PasskeyException> =
    withContext(dispatcherProvider.default()) {
      try {
        // Check if any excluded credentials exist
        for (excludedId in excludeCredentials) {
          val exists = repository.credentialExists(baseDir, excludedId, passkeysDir)
          if (exists) {
            return@withContext Err(
              PasskeyException.CredentialExists(
                "User already has a credential for this site"
              )
            )
          }
        }

        // Select algorithm (prefer ES256)
        val algorithm = selectAlgorithm(algorithms)
          ?: return@withContext Err(
            PasskeyException.UnsupportedAlgorithm("No supported algorithm found")
          )

        // Generate credential ID (32 random bytes)
        val credentialId = generateCredentialId()

        // Generate EC key pair in software
        val keyPairData = keyManager.generateKeyPair()

        // Create credential
        val now = System.currentTimeMillis() / 1000 // Unix timestamp in seconds
        val credential = PasskeyCredential(
          id = credentialId,
          rp = RelyingParty(id = rpId, name = rpName),
          user = User(id = userId, name = userName, displayName = userDisplayName),
          signCount = 0,
          alg = algorithm,
          privateKey = keyPairData.privateKey,
          created = now,
          discoverable = requireResidentKey,
          extensions = Extensions(),
        )

        // Serialize to CBOR
        val cborData = serializer.serialize(credential)

        // Encrypt with PGP
        val encryptedData = encryptWithPgp(cborData, pgpKeyIds)
          ?: return@withContext Err(
            PasskeyException.CreationFailed("Failed to encrypt credential with PGP")
          )

        // Store encrypted credential
        repository.storeCredential(baseDir, rpId, credentialId, encryptedData, passkeysDir)

        // Build authenticator data and attestation object
        val authenticatorData = buildAuthenticatorData(
          rpId = rpId,
          credentialId = credentialId,
          publicKeyCose = keyPairData.publicKeyCose,
          signCount = 0,
          userPresent = true,
          userVerified = true,
        )

        val attestationObject = buildAttestationObject(authenticatorData)

        logcat { "Created passkey for $rpId: ${credentialId.toHexString()}" }

        Ok(
          CreateCredentialOutput(
            credentialId = credentialId,
            attestationObject = attestationObject,
            publicKeyCose = keyPairData.publicKeyCose,
          )
        )
      } catch (e: Exception) {
        logcat { "Failed to create credential: ${e.message}" }
        Err(PasskeyException.CreationFailed(e.message ?: "Unknown error", e))
      }
    }

  /**
   * Get an assertion for authentication.
   *
   * This loads the credential, decrypts it with PGP, verifies user presence
   * via biometric authentication, signs the challenge, and returns the assertion.
   *
   * @param activity The activity for showing biometric prompt
   * @param baseDir The password store base directory
   * @param rpId Relying party ID
   * @param challenge The challenge from the relying party
   * @param pgpKeyId PGP key identifier for decryption
   * @param passphrase Passphrase for PGP key
   * @param pgpKeyIdsForReencrypt PGP key identifiers for re-encryption after sign count update
   * @param allowCredentials Optional list of allowed credential IDs
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return Result containing assertion data
   */
  public suspend fun getAssertion(
    activity: FragmentActivity,
    baseDir: File,
    rpId: String,
    challenge: ByteArray,
    pgpKeyId: PGPIdentifier,
    passphrase: CharArray,
    pgpKeyIdsForReencrypt: List<PGPIdentifier>,
    allowCredentials: List<ByteArray> = emptyList(),
    passkeysDir: String = PasskeyRepository.DEFAULT_PASSKEYS_DIR,
  ): Result<GetAssertionOutput, PasskeyException> =
    withContext(dispatcherProvider.default()) {
      try {
        // Find matching credentials
        val credentials = findMatchingCredentials(baseDir, rpId, allowCredentials, pgpKeyId, passphrase, passkeysDir)

        if (credentials.isEmpty()) {
          return@withContext Err(
            PasskeyException.NoCredentials("No matching credentials found")
          )
        }

        // TODO: If multiple credentials, prompt user to select
        val selectedCredential = credentials.first()

        // Build authenticator data
        val newSignCount = selectedCredential.signCount + 1
        val authenticatorData = buildAuthenticatorData(
          rpId = rpId,
          credentialId = null, // Not included in assertions
          publicKeyCose = null,
          signCount = newSignCount,
          userPresent = true,
          userVerified = true,
        )

        // Build the data to sign: authenticatorData || clientDataHash
        val clientDataHash = sha256(challenge)
        val signedData = authenticatorData + clientDataHash

        // Sign with biometric authentication
        val signature = keyManager.signWithBiometric(
          selectedCredential.privateKey,
          signedData,
          activity,
          "Authenticate",
          "Verify your identity to sign in to ${selectedCredential.rp.name ?: selectedCredential.rp.id}",
        ) ?: return@withContext Err(
          PasskeyException.AuthenticationFailed("Biometric authentication failed")
        )

        // Update credential with new sign count
        val updatedCredential = selectedCredential.copy(signCount = newSignCount)
        val updatedCborData = serializer.serialize(updatedCredential)
        val encryptedData = encryptWithPgp(updatedCborData, pgpKeyIdsForReencrypt)
        if (encryptedData != null) {
          repository.updateCredential(baseDir, rpId, selectedCredential.id, encryptedData, passkeysDir)
        }

        logcat { "Generated assertion for $rpId" }

        Ok(
          GetAssertionOutput(
            credentialId = selectedCredential.id,
            authenticatorData = authenticatorData,
            signature = signature,
            userHandle = if (selectedCredential.discoverable) {
              selectedCredential.user.id
            } else {
              null
            },
          )
        )
      } catch (e: Exception) {
        logcat { "Failed to get assertion: ${e.message}" }
        Err(PasskeyException.AssertionFailed(e.message ?: "Unknown error", e))
      }
    }

  /**
   * List all stored credentials.
   *
   * Note: This only returns metadata (not private keys) since we can't decrypt
   * without a passphrase. For full credential data, use loadCredential().
   *
   * @param baseDir The password store base directory
   * @param pgpKeyId PGP key identifier for decryption
   * @param passphrase Passphrase for PGP key
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return List of credentials
   */
  public suspend fun listCredentials(
    baseDir: File,
    pgpKeyId: PGPIdentifier,
    passphrase: CharArray,
    passkeysDir: String = PasskeyRepository.DEFAULT_PASSKEYS_DIR,
  ): List<PasskeyCredential> =
    withContext(dispatcherProvider.io()) {
      try {
        repository.listAllCredentials(baseDir, passkeysDir).mapNotNull { encryptedData ->
          decryptAndDeserialize(encryptedData, pgpKeyId, passphrase)
        }
      } catch (e: Exception) {
        logcat { "Failed to list credentials: ${e.message}" }
        emptyList()
      }
    }

  /**
   * List credentials for a specific relying party.
   *
   * @param baseDir The password store base directory
   * @param rpId The relying party ID
   * @param pgpKeyId PGP key identifier for decryption
   * @param passphrase Passphrase for PGP key
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return List of credentials for the specified RP
   */
  public suspend fun listCredentialsForRp(
    baseDir: File,
    rpId: String,
    pgpKeyId: PGPIdentifier,
    passphrase: CharArray,
    passkeysDir: String = PasskeyRepository.DEFAULT_PASSKEYS_DIR,
  ): List<PasskeyCredential> =
    withContext(dispatcherProvider.io()) {
      try {
        repository.listCredentialsForRp(baseDir, rpId, passkeysDir).mapNotNull { encryptedData ->
          decryptAndDeserialize(encryptedData, pgpKeyId, passphrase)
        }
      } catch (e: Exception) {
        logcat { "Failed to list credentials for RP: ${e.message}" }
        emptyList()
      }
    }

  /**
   * Delete a credential.
   *
   * @param baseDir The password store base directory
   * @param credentialId The credential ID to delete
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   * @return Result indicating success or failure
   */
  public suspend fun deleteCredential(
    baseDir: File,
    credentialId: ByteArray,
    passkeysDir: String = PasskeyRepository.DEFAULT_PASSKEYS_DIR,
  ): Result<Unit, PasskeyException> =
    withContext(dispatcherProvider.io()) {
      try {
        repository.deleteCredential(baseDir, credentialId, passkeysDir)
        logcat { "Deleted credential: ${credentialId.toHexString()}" }
        Ok(Unit)
      } catch (e: Exception) {
        logcat { "Failed to delete credential: ${e.message}" }
        Err(PasskeyException.DeletionFailed(e.message ?: "Unknown error", e))
      }
    }

  // === Private helpers ===

  private fun selectAlgorithm(algorithms: List<Int>): Int? {
    // Prefer ES256 (-7), then EdDSA (-8)
    // Note: We only support ES256 currently
    val preferred = listOf(-7)
    for (alg in preferred) {
      if (alg in algorithms) {
        return alg
      }
    }
    // If ES256 not in list, check if any algorithm is acceptable
    return if (-7 in algorithms || algorithms.isEmpty()) -7 else null
  }

  private fun generateCredentialId(): ByteArray {
    val bytes = ByteArray(32)
    SecureRandom().nextBytes(bytes)
    return bytes
  }

  private suspend fun findMatchingCredentials(
    baseDir: File,
    rpId: String,
    allowCredentials: List<ByteArray>,
    pgpKeyId: PGPIdentifier,
    passphrase: CharArray,
    passkeysDir: String,
  ): List<PasskeyCredential> {
    return if (allowCredentials.isEmpty()) {
      // Discoverable credential flow
      repository.listCredentialsForRp(baseDir, rpId, passkeysDir).mapNotNull { encryptedData ->
        decryptAndDeserialize(encryptedData, pgpKeyId, passphrase)?.takeIf { it.discoverable }
      }
    } else {
      // Allow list flow
      allowCredentials.mapNotNull { credId ->
        repository.loadCredential(baseDir, credId, passkeysDir)?.let { encryptedData ->
          decryptAndDeserialize(encryptedData, pgpKeyId, passphrase)?.takeIf { it.rp.id == rpId }
        }
      }
    }
  }

  private fun encryptWithPgp(data: ByteArray, pgpKeyIds: List<PGPIdentifier>): ByteArray? {
    return try {
      val keys = pgpKeyIds.map { pgpKeyManager.getKeyById(it) }.filterValues()
      if (keys.isEmpty()) return null

      val plaintextStream = ByteArrayInputStream(data)
      val outputStream = ByteArrayOutputStream()
      val encryptionOptions = PGPEncryptOptions.Builder().build()

      val result = pgpCryptoHandler.encrypt(
        keys = keys,
        passphrase = null,
        plaintextStream = plaintextStream,
        outputStream = outputStream,
        options = encryptionOptions,
      )

      if (result.isOk) outputStream.toByteArray() else null
    } catch (e: Exception) {
      logcat { "PGP encryption failed: ${e.message}" }
      null
    }
  }

  private fun decryptWithPgp(encryptedData: ByteArray, pgpKeyId: PGPIdentifier, passphrase: CharArray): ByteArray? {
    return try {
      val key = pgpKeyManager.getKeyById(pgpKeyId).getOrThrow()
      val ciphertextStream = ByteArrayInputStream(encryptedData)
      val outputStream = ByteArrayOutputStream()
      val decryptionOptions = PGPDecryptOptions.Builder().build()

      val result = pgpCryptoHandler.decrypt(
        key = key,
        passphrase = passphrase,
        ciphertextStream = ciphertextStream,
        outputStream = outputStream,
        options = decryptionOptions,
      )

      if (result.isOk) outputStream.toByteArray() else null
    } catch (e: Exception) {
      logcat { "PGP decryption failed: ${e.message}" }
      null
    }
  }

  private fun decryptAndDeserialize(
    encryptedData: ByteArray,
    pgpKeyId: PGPIdentifier,
    passphrase: CharArray,
  ): PasskeyCredential? {
    val decryptedData = decryptWithPgp(encryptedData, pgpKeyId, passphrase) ?: return null
    return serializer.deserialize(decryptedData)
  }

  private fun buildAuthenticatorData(
    rpId: String,
    credentialId: ByteArray?,
    publicKeyCose: ByteArray?,
    signCount: Int,
    userPresent: Boolean,
    userVerified: Boolean,
  ): ByteArray {
    val result = mutableListOf<Byte>()

    // RP ID hash (32 bytes)
    result.addAll(sha256(rpId.toByteArray()).toList())

    // Flags (1 byte)
    var flags = 0
    if (userPresent) flags = flags or 0x01
    if (userVerified) flags = flags or 0x04
    if (credentialId != null && publicKeyCose != null) flags = flags or 0x40
    result.add(flags.toByte())

    // Sign count (4 bytes, big-endian)
    result.add((signCount shr 24 and 0xFF).toByte())
    result.add((signCount shr 16 and 0xFF).toByte())
    result.add((signCount shr 8 and 0xFF).toByte())
    result.add((signCount and 0xFF).toByte())

    // Attested credential data (if present)
    if (credentialId != null && publicKeyCose != null) {
      // AAGUID (16 bytes)
      result.addAll(AAGUID.toList())

      // Credential ID length (2 bytes, big-endian)
      val credIdLen = credentialId.size
      result.add((credIdLen shr 8 and 0xFF).toByte())
      result.add((credIdLen and 0xFF).toByte())

      // Credential ID
      result.addAll(credentialId.toList())

      // Public key (COSE format)
      result.addAll(publicKeyCose.toList())
    }

    return result.toByteArray()
  }

  private fun buildAttestationObject(authenticatorData: ByteArray): ByteArray {
    // Build CBOR attestation object with "none" attestation
    // { "fmt": "none", "authData": <bytes>, "attStmt": {} }
    val result = mutableListOf<Byte>()

    // CBOR map with 3 items
    result.add(0xA3.toByte())

    // "fmt" -> "none"
    result.add(0x63) // text string, 3 bytes
    result.addAll("fmt".toByteArray().toList())
    result.add(0x64) // text string, 4 bytes
    result.addAll("none".toByteArray().toList())

    // "authData" -> bytes
    result.add(0x68) // text string, 8 bytes
    result.addAll("authData".toByteArray().toList())
    // Byte string header
    if (authenticatorData.size < 24) {
      result.add((0x40 + authenticatorData.size).toByte())
    } else if (authenticatorData.size < 256) {
      result.add(0x58)
      result.add(authenticatorData.size.toByte())
    } else {
      result.add(0x59)
      result.add((authenticatorData.size shr 8).toByte())
      result.add((authenticatorData.size and 0xFF).toByte())
    }
    result.addAll(authenticatorData.toList())

    // "attStmt" -> {}
    result.add(0x67) // text string, 7 bytes
    result.addAll("attStmt".toByteArray().toList())
    result.add(0xA0.toByte()) // empty map

    return result.toByteArray()
  }

  private fun sha256(data: ByteArray): ByteArray {
    return java.security.MessageDigest.getInstance("SHA-256").digest(data)
  }

  private fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

  public companion object {
    // AAGUID for "Android Password Store Passkey Authenticator"
    private val AAGUID = byteArrayOf(
      0x41, 0x50, 0x53, 0x2D, 0x50, 0x41, 0x53, 0x53,
      0x4B, 0x45, 0x59, 0x2D, 0x41, 0x55, 0x54, 0x48,
    )
  }
}

/**
 * Output of credential creation.
 */
public data class CreateCredentialOutput(
  val credentialId: ByteArray,
  val attestationObject: ByteArray,
  val publicKeyCose: ByteArray,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false
    other as CreateCredentialOutput
    return credentialId.contentEquals(other.credentialId)
  }

  override fun hashCode(): Int = credentialId.contentHashCode()
}

/**
 * Output of getting an assertion.
 */
public data class GetAssertionOutput(
  val credentialId: ByteArray,
  val authenticatorData: ByteArray,
  val signature: ByteArray,
  val userHandle: ByteArray?,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false
    other as GetAssertionOutput
    return credentialId.contentEquals(other.credentialId)
  }

  override fun hashCode(): Int = credentialId.contentHashCode()
}

/**
 * Exception types for passkey operations.
 */
public sealed class PasskeyException(message: String, cause: Throwable? = null) :
  Exception(message, cause) {

  public class InitializationFailed(cause: Throwable) :
    PasskeyException("Failed to initialize passkey system", cause)

  public class CredentialExists(message: String) :
    PasskeyException(message)

  public class CredentialNotFound(message: String) :
    PasskeyException(message)

  public class NoCredentials(message: String) :
    PasskeyException(message)

  public class UnsupportedAlgorithm(message: String) :
    PasskeyException(message)

  public class AuthenticationFailed(message: String) :
    PasskeyException(message)

  public class CreationFailed(message: String, cause: Throwable? = null) :
    PasskeyException(message, cause)

  public class AssertionFailed(message: String, cause: Throwable? = null) :
    PasskeyException(message, cause)

  public class DeletionFailed(message: String, cause: Throwable? = null) :
    PasskeyException(message, cause)
}
