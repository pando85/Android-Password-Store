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
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.fragment.app.FragmentActivity
import app.passwordstore.crypto.PGPDecryptOptions
import app.passwordstore.crypto.PGPEncryptOptions
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.crypto.PGPainlessCryptoHandler
import app.passwordstore.passkey.PasskeyCredential
import app.passwordstore.passkey.PasskeyKeyManager
import app.passwordstore.passkey.PasskeyRepository
import app.passwordstore.passkey.PasskeySerializer
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getOrThrow
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.logcat

/**
 * Activity for authenticating with a passkey.
 *
 * Flow:
 * 1. Receive credential ID and RP ID from intent
 * 2. Prompt for PGP passphrase
 * 3. Decrypt the credential file
 * 4. Show biometric prompt and sign the challenge
 * 5. Return the assertion to the calling app
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@AndroidEntryPoint
public class GetPasskeyActivity : FragmentActivity() {

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

    val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
    val credentialId = intent.getByteArrayExtra(PasskeyCredentialHandler.EXTRA_CREDENTIAL_ID)
    val rpId = intent.getStringExtra(PasskeyCredentialHandler.EXTRA_RP_ID)

    if (request == null || credentialId == null || rpId == null) {
      logcat { "Missing required data: request=$request, credentialId=$credentialId, rpId=$rpId" }
      setResult(Activity.RESULT_CANCELED)
      finish()
      return
    }

    setContent {
      MaterialTheme {
        Surface(modifier = Modifier.fillMaxSize()) {
          GetPasskeyScreen(
            rpId = rpId,
            credentialId = credentialId,
            request = request,
            onAuthenticate = { passphrase ->
              handleAuthentication(request, rpId, credentialId, passphrase)
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

  private fun handleAuthentication(
    request: ProviderGetCredentialRequest,
    rpId: String,
    credentialId: ByteArray,
    passphrase: CharArray,
  ) {
    val baseDir = passwordStoreDir ?: run {
      setResult(Activity.RESULT_CANCELED)
      finish()
      return
    }

    val scope = kotlinx.coroutines.MainScope()
    scope.launch {
      try {
        // Get PGP key
        val pgpKey = pgpKeyManager.getAllKeys().get()?.firstOrNull()
        if (pgpKey == null) {
          logcat { "No PGP key found" }
          setResult(Activity.RESULT_CANCELED)
          finish()
          return@launch
        }

        // Load and decrypt the credential
        val encryptedData = withContext(Dispatchers.IO) {
          repository.loadCredential(baseDir, rpId, credentialId, passkeysDir)
        }
        if (encryptedData == null) {
          logcat { "Credential not found" }
          setResult(Activity.RESULT_CANCELED)
          finish()
          return@launch
        }

        val decryptedData = withContext(Dispatchers.IO) {
          val input = ByteArrayInputStream(encryptedData)
          val output = ByteArrayOutputStream()
          val result = pgpCryptoHandler.decrypt(
            pgpKey,
            passphrase,
            input,
            output,
            PGPDecryptOptions.Builder().build(),
          )
          if (result.isOk) output.toByteArray() else null
        }
        if (decryptedData == null) {
          logcat { "Failed to decrypt credential" }
          setResult(Activity.RESULT_CANCELED)
          finish()
          return@launch
        }

        val credential = serializer.deserialize(decryptedData)
        if (credential == null) {
          logcat { "Failed to deserialize credential" }
          setResult(Activity.RESULT_CANCELED)
          finish()
          return@launch
        }

        // Parse request options
        val publicKeyOption = request.credentialOptions
          .filterIsInstance<GetPublicKeyCredentialOption>()
          .firstOrNull()
        val requestJson = publicKeyOption?.requestJson ?: ""
        val requestOptions = jsonParser.parseRequestOptions(requestJson)

        if (requestOptions == null) {
          logcat { "Failed to parse request options" }
          setResult(Activity.RESULT_CANCELED)
          finish()
          return@launch
        }

        // Decode challenge
        val challenge = try {
          requestOptions.challenge.fromBase64Url()
        } catch (e: Exception) {
          logcat { "Failed to decode challenge: ${e.message}" }
          setResult(Activity.RESULT_CANCELED)
          finish()
          return@launch
        }

        // Build authenticator data
        val newSignCount = credential.signCount + 1
        val authenticatorData = buildAuthenticatorData(rpId, newSignCount)

        // Build data to sign: authenticatorData || SHA256(clientDataJSON)
        val clientDataJson = buildClientDataJson(
          type = "webauthn.get",
          challenge = requestOptions.challenge,
          origin = "android:apk-key-hash:${request.callingAppInfo?.packageName}",
        )
        val clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataJson)
        val signedData = authenticatorData + clientDataHash

        // Sign with biometric
        val signature = keyManager.signWithBiometric(
          credential.privateKey,
          signedData,
          this@GetPasskeyActivity,
          "Sign in",
          "Use your passkey to sign in to ${credential.rp.name ?: credential.rp.id}",
        )

        if (signature == null) {
          logcat { "Signing failed or cancelled" }
          setResult(Activity.RESULT_CANCELED)
          finish()
          return@launch
        }

        // Update sign count and re-encrypt
        val updatedCredential = credential.copy(signCount = newSignCount)
        val updatedCbor = serializer.serialize(updatedCredential)
        withContext(Dispatchers.IO) {
          val input = ByteArrayInputStream(updatedCbor)
          val output = ByteArrayOutputStream()
          val encResult = pgpCryptoHandler.encrypt(
            listOf(pgpKey),
            null,
            input,
            output,
            PGPEncryptOptions.Builder().build(),
          )
          if (encResult.isOk) {
            repository.updateCredential(baseDir, rpId, credentialId, output.toByteArray(), passkeysDir)
          }
        }

        // Build response
        val responseJson = jsonParser.buildGetResponse(
          credentialId = credential.id,
          authenticatorData = authenticatorData,
          signature = signature,
          userHandle = if (credential.discoverable) credential.user.id else null,
          clientDataJson = clientDataJson,
        )

        val response = PublicKeyCredential(responseJson)
        val resultIntent = android.content.Intent()
        PendingIntentHandler.setGetCredentialResponse(
          resultIntent,
          androidx.credentials.GetCredentialResponse(response),
        )
        setResult(Activity.RESULT_OK, resultIntent)
        finish()

      } catch (e: Exception) {
        logcat { "Authentication failed: ${e.message}" }
        setResult(Activity.RESULT_CANCELED)
        finish()
      }
    }
  }

  private fun buildAuthenticatorData(rpId: String, signCount: Int): ByteArray {
    val result = mutableListOf<Byte>()

    // RP ID hash (32 bytes)
    val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
    result.addAll(rpIdHash.toList())

    // Flags: UP (0x01) + UV (0x04) = 0x05
    result.add(0x05.toByte())

    // Sign count (4 bytes, big-endian)
    result.add((signCount shr 24 and 0xFF).toByte())
    result.add((signCount shr 16 and 0xFF).toByte())
    result.add((signCount shr 8 and 0xFF).toByte())
    result.add((signCount and 0xFF).toByte())

    return result.toByteArray()
  }

  private fun buildClientDataJson(type: String, challenge: String, origin: String): ByteArray {
    val json = """{"type":"$type","challenge":"$challenge","origin":"$origin","crossOrigin":false}"""
    return json.toByteArray(Charsets.UTF_8)
  }
}

@Composable
private fun GetPasskeyScreen(
  rpId: String,
  credentialId: ByteArray,
  request: ProviderGetCredentialRequest,
  onAuthenticate: (CharArray) -> Unit,
  onCancel: () -> Unit,
) {
  var passphrase by remember { mutableStateOf("") }
  var passwordVisible by remember { mutableStateOf(false) }
  var isLoading by remember { mutableStateOf(false) }
  var error by remember { mutableStateOf<String?>(null) }
  val scope = rememberCoroutineScope()

  Column(
    modifier = Modifier
      .fillMaxSize()
      .padding(24.dp),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    Spacer(modifier = Modifier.height(32.dp))

    Icon(
      imageVector = Icons.Default.Key,
      contentDescription = null,
      modifier = Modifier.size(64.dp),
      tint = MaterialTheme.colorScheme.primary,
    )

    Spacer(modifier = Modifier.height(24.dp))

    Text(
      text = "Sign in with Passkey",
      style = MaterialTheme.typography.headlineMedium,
      fontWeight = FontWeight.Bold,
    )

    Spacer(modifier = Modifier.height(8.dp))

    Text(
      text = rpId,
      style = MaterialTheme.typography.titleMedium,
      color = MaterialTheme.colorScheme.primary,
    )

    Spacer(modifier = Modifier.height(32.dp))

    Text(
      text = "Enter your passphrase to unlock the passkey",
      style = MaterialTheme.typography.bodyMedium,
      color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    Spacer(modifier = Modifier.height(16.dp))

    OutlinedTextField(
      value = passphrase,
      onValueChange = { 
        passphrase = it
        error = null
      },
      label = { Text("Passphrase") },
      singleLine = true,
      visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
      keyboardOptions = KeyboardOptions(
        keyboardType = KeyboardType.Password,
        imeAction = ImeAction.Done,
      ),
      keyboardActions = KeyboardActions(
        onDone = {
          if (passphrase.isNotEmpty() && !isLoading) {
            isLoading = true
            onAuthenticate(passphrase.toCharArray())
          }
        }
      ),
      trailingIcon = {
        IconButton(onClick = { passwordVisible = !passwordVisible }) {
          Icon(
            imageVector = if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
            contentDescription = if (passwordVisible) "Hide password" else "Show password",
          )
        }
      },
      isError = error != null,
      modifier = Modifier.fillMaxWidth(),
    )

    if (error != null) {
      Spacer(modifier = Modifier.height(8.dp))
      Text(
        text = error!!,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.error,
      )
    }

    Spacer(modifier = Modifier.height(24.dp))

    Button(
      onClick = {
        if (passphrase.isNotEmpty()) {
          isLoading = true
          onAuthenticate(passphrase.toCharArray())
        }
      },
      enabled = passphrase.isNotEmpty() && !isLoading,
      modifier = Modifier.fillMaxWidth(),
    ) {
      if (isLoading) {
        CircularProgressIndicator(
          modifier = Modifier.size(24.dp),
          color = MaterialTheme.colorScheme.onPrimary,
        )
      } else {
        Text("Authenticate")
      }
    }

    Spacer(modifier = Modifier.weight(1f))

    OutlinedButton(
      onClick = onCancel,
      modifier = Modifier.fillMaxWidth(),
    ) {
      Text("Cancel")
    }
  }
}
