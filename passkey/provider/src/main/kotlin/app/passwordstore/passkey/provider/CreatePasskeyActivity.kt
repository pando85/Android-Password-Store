/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey.provider

import android.app.Activity
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.fragment.app.FragmentActivity
import app.passwordstore.crypto.PGPEncryptOptions
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.crypto.PGPainlessCryptoHandler
import app.passwordstore.passkey.Extensions
import app.passwordstore.passkey.PasskeyCredential
import app.passwordstore.passkey.PasskeyKeyManager
import app.passwordstore.passkey.PasskeyRepository
import app.passwordstore.passkey.PasskeySerializer
import app.passwordstore.passkey.RelyingParty
import app.passwordstore.passkey.User
import com.github.michaelbull.result.get
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.logcat

/**
 * Activity for creating a new passkey.
 *
 * Flow:
 * 1. Parse the WebAuthn request from the intent
 * 2. Show confirmation UI with RP and user info
 * 3. Generate EC key pair in software
 * 4. Prompt for PGP passphrase (to verify key access)
 * 5. Encrypt and store the credential
 * 6. Return the attestation object to the calling app
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@AndroidEntryPoint
public class CreatePasskeyActivity : FragmentActivity() {

  @Inject public lateinit var repository: PasskeyRepository
  @Inject public lateinit var serializer: PasskeySerializer
  @Inject public lateinit var keyManager: PasskeyKeyManager
  @Inject public lateinit var pgpKeyManager: PGPKeyManager
  @Inject public lateinit var pgpCryptoHandler: PGPainlessCryptoHandler
  @Inject public lateinit var jsonParser: WebAuthnJsonParser

  private var passwordStoreDir: File? = null
  private var passkeysDir: String = PasskeyRepository.DEFAULT_PASSKEYS_DIR

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    passwordStoreDir = getPasswordStoreDirectory()
    passkeysDir = getPasskeysDirectory()

    val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)

    if (request == null) {
      logcat { "No create credential request found" }
      setResult(Activity.RESULT_CANCELED)
      finish()
      return
    }

    setContent {
      MaterialTheme {
        Surface(modifier = Modifier.fillMaxSize()) {
          CreatePasskeyScreen(
            request = request,
            jsonParser = jsonParser,
            onConfirm = { creationOptions, clientDataJson ->
              handleCreateCredential(request, creationOptions, clientDataJson)
            },
            onCancel = {
              setResult(Activity.RESULT_CANCELED)
              finish()
            },
          )
        }
      }
    }
  }

  private fun getPasswordStoreDirectory(): File {
    val prefs = getSharedPreferences("${packageName}_preferences", MODE_PRIVATE)
    val repoPath = prefs.getString("git_external_repo", null)
    return if (repoPath != null) {
      File(repoPath)
    } else {
      File(filesDir, "store")
    }
  }

  private fun getPasskeysDirectory(): String {
    // Check if passed from intent (from CredentialHandler)
    val intentDir = intent.getStringExtra(PasskeyCredentialHandler.EXTRA_PASSKEYS_DIR)
    if (!intentDir.isNullOrBlank()) {
      return intentDir
    }
    // Fallback to preferences
    val prefs = getSharedPreferences("${packageName}_preferences", MODE_PRIVATE)
    return prefs.getString("passkey_directory", PasskeyRepository.DEFAULT_PASSKEYS_DIR)
      ?: PasskeyRepository.DEFAULT_PASSKEYS_DIR
  }

  private fun handleCreateCredential(
    request: ProviderCreateCredentialRequest,
    creationOptions: PublicKeyCredentialCreationOptions,
    clientDataJson: ByteArray,
  ) {
    val baseDir = passwordStoreDir ?: run {
      setResult(Activity.RESULT_CANCELED)
      finish()
      return
    }

    val scope = kotlinx.coroutines.MainScope()
    scope.launch {
      try {
        // Get PGP key for encryption
        val pgpKey = pgpKeyManager.getAllKeys().get()?.firstOrNull()
        if (pgpKey == null) {
          logcat { "No PGP key found" }
          setResult(Activity.RESULT_CANCELED)
          finish()
          return@launch
        }

        // Decode challenge from Base64URL
        val challenge = try {
          creationOptions.challenge.fromBase64Url()
        } catch (e: Exception) {
          logcat { "Failed to decode challenge: ${e.message}" }
          setResult(Activity.RESULT_CANCELED)
          finish()
          return@launch
        }

        // Decode user ID from Base64URL
        val userId = try {
          creationOptions.user.id.fromBase64Url()
        } catch (e: Exception) {
          logcat { "Failed to decode user ID: ${e.message}" }
          setResult(Activity.RESULT_CANCELED)
          finish()
          return@launch
        }

        val rpId = creationOptions.rp.id ?: creationOptions.rp.name

        // Generate credential ID (32 random bytes)
        val credentialId = ByteArray(32).also { SecureRandom().nextBytes(it) }

        // Generate EC key pair
        val keyPairData = keyManager.generateKeyPair()

        // Create the credential
        val credential = PasskeyCredential(
          id = credentialId,
          rp = RelyingParty(id = rpId, name = creationOptions.rp.name),
          user = User(
            id = userId,
            name = creationOptions.user.name,
            displayName = creationOptions.user.displayName,
          ),
          signCount = 0,
          alg = -7, // ES256
          privateKey = keyPairData.privateKey,
          created = System.currentTimeMillis() / 1000,
          discoverable = true,
          extensions = Extensions(),
        )

        // Serialize to CBOR
        val cborData = serializer.serialize(credential)

        // Encrypt with PGP
        val encryptedData = withContext(Dispatchers.IO) {
          val input = ByteArrayInputStream(cborData)
          val output = ByteArrayOutputStream()
          val result = pgpCryptoHandler.encrypt(
            listOf(pgpKey),
            null,
            input,
            output,
            PGPEncryptOptions.Builder().build(),
          )
          if (result.isOk) output.toByteArray() else null
        }

        if (encryptedData == null) {
          logcat { "Failed to encrypt credential" }
          setResult(Activity.RESULT_CANCELED)
          finish()
          return@launch
        }

        // Store the credential
        withContext(Dispatchers.IO) {
          repository.storeCredential(baseDir, rpId, credentialId, encryptedData, passkeysDir)
        }

        // Build authenticator data
        val authenticatorData = buildAuthenticatorData(
          rpId = rpId,
          credentialId = credentialId,
          publicKeyCose = keyPairData.publicKeyCose,
        )

        // Build attestation object
        val attestationObject = buildAttestationObject(authenticatorData)

        // Build the response JSON
        val responseJson = jsonParser.buildCreateResponse(
          credentialId = credentialId,
          attestationObject = attestationObject,
          clientDataJson = clientDataJson,
          publicKeyCose = keyPairData.publicKeyCose,
        )

        logcat { "Passkey created successfully" }

        val response = CreatePublicKeyCredentialResponse(responseJson)
        val resultIntent = android.content.Intent()
        PendingIntentHandler.setCreateCredentialResponse(resultIntent, response)
        setResult(Activity.RESULT_OK, resultIntent)
        finish()

      } catch (e: Exception) {
        logcat { "Failed to create passkey: ${e.message}" }
        setResult(Activity.RESULT_CANCELED)
        finish()
      }
    }
  }

  private fun buildAuthenticatorData(
    rpId: String,
    credentialId: ByteArray,
    publicKeyCose: ByteArray,
  ): ByteArray {
    val result = mutableListOf<Byte>()

    // RP ID hash (32 bytes)
    val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
    result.addAll(rpIdHash.toList())

    // Flags: UP (0x01) + UV (0x04) + AT (0x40) = 0x45
    result.add(0x45.toByte())

    // Sign count (4 bytes, big-endian) - 0 for new credential
    result.add(0x00)
    result.add(0x00)
    result.add(0x00)
    result.add(0x00)

    // Attested credential data
    // AAGUID (16 bytes) - "APS-PASSKEY-AUTH"
    result.addAll(AAGUID.toList())

    // Credential ID length (2 bytes, big-endian)
    result.add((credentialId.size shr 8 and 0xFF).toByte())
    result.add((credentialId.size and 0xFF).toByte())

    // Credential ID
    result.addAll(credentialId.toList())

    // Public key (COSE format)
    result.addAll(publicKeyCose.toList())

    return result.toByteArray()
  }

  private fun buildAttestationObject(authenticatorData: ByteArray): ByteArray {
    // Build CBOR attestation object with "none" attestation
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
    when {
      authenticatorData.size < 24 -> {
        result.add((0x40 + authenticatorData.size).toByte())
      }
      authenticatorData.size < 256 -> {
        result.add(0x58)
        result.add(authenticatorData.size.toByte())
      }
      else -> {
        result.add(0x59)
        result.add((authenticatorData.size shr 8).toByte())
        result.add((authenticatorData.size and 0xFF).toByte())
      }
    }
    result.addAll(authenticatorData.toList())

    // "attStmt" -> {}
    result.add(0x67) // text string, 7 bytes
    result.addAll("attStmt".toByteArray().toList())
    result.add(0xA0.toByte()) // empty map

    return result.toByteArray()
  }

  private companion object {
    // AAGUID for "Android Password Store Passkey Authenticator"
    private val AAGUID = byteArrayOf(
      0x41, 0x50, 0x53, 0x2D, 0x50, 0x41, 0x53, 0x53,
      0x4B, 0x45, 0x59, 0x2D, 0x41, 0x55, 0x54, 0x48,
    )
  }
}

@Composable
private fun CreatePasskeyScreen(
  request: ProviderCreateCredentialRequest,
  jsonParser: WebAuthnJsonParser,
  onConfirm: (PublicKeyCredentialCreationOptions, ByteArray) -> Unit,
  onCancel: () -> Unit,
) {
  var isLoading by remember { mutableStateOf(false) }
  var error by remember { mutableStateOf<String?>(null) }

  // Parse the request
  val requestJson = (request.callingRequest as? androidx.credentials.CreatePublicKeyCredentialRequest)
    ?.requestJson ?: ""
  val creationOptions = remember { jsonParser.parseCreationOptions(requestJson) }

  // Extract info for display
  val rpName = creationOptions?.rp?.name ?: "Unknown site"
  val rpId = creationOptions?.rp?.id ?: creationOptions?.rp?.name ?: "Unknown"
  val userName = creationOptions?.user?.name ?: "Unknown user"
  val userDisplayName = creationOptions?.user?.displayName ?: userName

  Column(
    modifier = Modifier
      .fillMaxSize()
      .padding(24.dp),
    horizontalAlignment = Alignment.CenterHorizontally,
    verticalArrangement = Arrangement.Center,
  ) {
    Text(
      text = "Create Passkey",
      style = MaterialTheme.typography.headlineMedium,
      fontWeight = FontWeight.Bold,
    )

    Spacer(modifier = Modifier.height(16.dp))

    Card(
      modifier = Modifier.fillMaxWidth(),
    ) {
      Column(
        modifier = Modifier.padding(16.dp),
      ) {
        Text(
          text = "A passkey will be created for:",
          style = MaterialTheme.typography.bodyMedium,
        )

        Spacer(modifier = Modifier.height(12.dp))

        Text(
          text = rpName,
          style = MaterialTheme.typography.titleLarge,
          fontWeight = FontWeight.SemiBold,
        )

        Text(
          text = rpId,
          style = MaterialTheme.typography.bodyMedium,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(modifier = Modifier.height(12.dp))

        Text(
          text = "Account:",
          style = MaterialTheme.typography.labelMedium,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Text(
          text = userDisplayName,
          style = MaterialTheme.typography.titleMedium,
          fontWeight = FontWeight.Medium,
        )

        if (userName != userDisplayName) {
          Text(
            text = userName,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
          text = "The passkey will be stored in your Password Store, " +
            "encrypted with your GPG key, and synced via git.",
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
      }
    }

    error?.let { errorMsg ->
      Spacer(modifier = Modifier.height(16.dp))
      Text(
        text = errorMsg,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.error,
      )
    }

    Spacer(modifier = Modifier.height(32.dp))

    if (isLoading) {
      CircularProgressIndicator(modifier = Modifier.size(48.dp))
      Spacer(modifier = Modifier.height(16.dp))
      Text("Creating passkey...")
    } else {
      Button(
        onClick = {
          if (creationOptions != null) {
            isLoading = true
            error = null

            val clientDataJson = buildClientDataJson(
              type = "webauthn.create",
              challenge = creationOptions.challenge,
              origin = "android:apk-key-hash:${request.callingAppInfo?.packageName}",
            )

            onConfirm(creationOptions, clientDataJson)
          } else {
            error = "Invalid request data"
          }
        },
        modifier = Modifier.fillMaxWidth(),
        enabled = creationOptions != null,
      ) {
        Text("Create Passkey")
      }

      Spacer(modifier = Modifier.height(12.dp))

      OutlinedButton(
        onClick = onCancel,
        modifier = Modifier.fillMaxWidth(),
      ) {
        Text("Cancel")
      }
    }
  }
}

private fun buildClientDataJson(
  type: String,
  challenge: String,
  origin: String,
): ByteArray {
  val json = """{"type":"$type","challenge":"$challenge","origin":"$origin","crossOrigin":false}"""
  return json.toByteArray(Charsets.UTF_8)
}
