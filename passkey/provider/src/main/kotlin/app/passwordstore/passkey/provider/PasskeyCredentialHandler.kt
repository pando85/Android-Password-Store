/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey.provider

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.PublicKeyCredentialEntry
import app.passwordstore.passkey.CredentialIndex
import app.passwordstore.passkey.PasskeyRepository
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.runBlocking
import logcat.logcat

/**
 * Handles credential requests from the CredentialProviderService.
 *
 * This class processes the Begin* requests which return entries for the system UI,
 * and prepares PendingIntents that will launch our activities when the user selects an entry.
 *
 * The index information (rpId, credentialId) comes from the directory structure:
 *   {passkeysDir}/{rpId}/{credentialId}.gpg
 * 
 * No decryption is needed to list available credentials - only to use them.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@Singleton
public class PasskeyCredentialHandler @Inject constructor(
  private val repository: PasskeyRepository,
  private val jsonParser: WebAuthnJsonParser,
) {

  public companion object {
    public const val EXTRA_RP_ID: String = "rp_id"
    public const val EXTRA_RP_NAME: String = "rp_name"
    public const val EXTRA_USER_ID: String = "user_id"
    public const val EXTRA_USER_NAME: String = "user_name"
    public const val EXTRA_USER_DISPLAY_NAME: String = "user_display_name"
    public const val EXTRA_CREDENTIAL_ID: String = "credential_id"
    public const val EXTRA_REQUEST_JSON: String = "request_json"
    public const val EXTRA_CALLING_PACKAGE: String = "calling_package"
    public const val EXTRA_CLIENT_DATA_HASH: String = "client_data_hash"
    public const val EXTRA_PASSKEYS_DIR: String = "passkeys_dir"

    private const val CREATE_REQUEST_CODE = 1001
    private const val GET_REQUEST_CODE = 1002
  }

  private var passwordStoreDir: File? = null
  private var passkeysDir: String = PasskeyRepository.DEFAULT_PASSKEYS_DIR

  /**
   * Set the password store directory for credential lookups.
   */
  public fun setPasswordStoreDir(dir: File) {
    passwordStoreDir = dir
  }

  /**
   * Set the passkeys directory (relative path within password store).
   */
  public fun setPasskeysDir(dir: String) {
    passkeysDir = dir
  }

  /**
   * Handle BeginGetCredentialRequest - return entries for matching credentials.
   *
   * The system calls this to get a list of credentials that match the request.
   * We return PublicKeyCredentialEntry items that the system will display to the user.
   * 
   * This uses only the directory structure (no decryption needed).
   */
  public fun handleBeginGetCredential(
    context: Context,
    request: BeginGetCredentialRequest,
  ): BeginGetCredentialResponse {
    logcat { "Processing BeginGetCredentialRequest" }

    val credentialEntries = mutableListOf<PublicKeyCredentialEntry>()

    for (option in request.beginGetCredentialOptions) {
      when (option) {
        is BeginGetPublicKeyCredentialOption -> {
          logcat { "Found PublicKeyCredential option" }

          // Parse the request JSON properly
          val requestJson = option.requestJson
          val requestOptions = jsonParser.parseRequestOptions(requestJson)

          val rpId = requestOptions?.rpId
          if (rpId != null) {
            // Query stored credentials for this RP (from directory structure only)
            val credentialIndices = getCredentialIndicesForRp(rpId, requestOptions.allowCredentials)

            if (credentialIndices.isNotEmpty()) {
              // Create an entry for each matching credential
              credentialIndices.forEachIndexed { index, credIndex ->
                val pendingIntent = createGetCredentialPendingIntent(
                  context,
                  credIndex,
                  requestJson,
                  request.callingAppInfo?.packageName,
                  requestCode = GET_REQUEST_CODE + index,
                )

                // Since we don't decrypt, we use the credential ID as display
                // The actual user info will be shown after decryption in the activity
                val credIdShort = credIndex.credentialId.toHexString().take(8) + "..."
                
                val entry = PublicKeyCredentialEntry.Builder(
                  context,
                  "Passkey for ${credIndex.rpId}", // Username placeholder
                  pendingIntent,
                  option,
                )
                  .setDisplayName(credIdShort)
                  .build()

                credentialEntries.add(entry)
              }
            } else {
              logcat { "No credentials found for RP: $rpId" }
            }
          }
        }
        else -> {
          logcat { "Unsupported credential option: ${option.javaClass.simpleName}" }
        }
      }
    }

    return BeginGetCredentialResponse.Builder()
      .setCredentialEntries(credentialEntries)
      .build()
  }

  /**
   * Handle BeginCreateCredentialRequest - return entries for where to create the credential.
   *
   * The system calls this when an app wants to create a new credential.
   * We return CreateEntry items representing where the credential can be stored.
   */
  public fun handleBeginCreateCredential(
    context: Context,
    request: BeginCreateCredentialRequest,
  ): BeginCreateCredentialResponse {
    logcat { "Processing BeginCreateCredentialRequest" }

    val createEntries = mutableListOf<CreateEntry>()

    when (request) {
      is BeginCreatePublicKeyCredentialRequest -> {
        logcat { "Creating PublicKeyCredential" }

        val requestJson = request.requestJson
        val creationOptions = jsonParser.parseCreationOptions(requestJson)

        val rpId = creationOptions?.rp?.id ?: creationOptions?.rp?.name
        val rpName = creationOptions?.rp?.name

        val pendingIntent = createCreateCredentialPendingIntent(
          context,
          rpId,
          rpName,
          creationOptions?.user,
          requestJson,
          request.callingAppInfo?.packageName,
        )

        val entry = CreateEntry.Builder(
          "Password Store", // Account name / provider name
          pendingIntent,
        )
          .setDescription("Store passkey in Password Store")
          .build()

        createEntries.add(entry)
      }
    }

    return BeginCreateCredentialResponse.Builder()
      .setCreateEntries(createEntries)
      .build()
  }

  /**
   * Query credential indices for a relying party (from directory structure only).
   */
  private fun getCredentialIndicesForRp(
    rpId: String,
    allowCredentials: List<CredentialDescriptor>?,
  ): List<CredentialIndex> {
    val baseDir = passwordStoreDir ?: return emptyList()

    return runBlocking {
      val allIndices = repository.listCredentialIndexForRp(baseDir, rpId, passkeysDir)

      if (allowCredentials.isNullOrEmpty()) {
        // Discoverable credential flow - return all credentials for this RP
        allIndices
      } else {
        // Allow list flow - filter by credential IDs
        val allowedIds = allowCredentials.mapNotNull { desc ->
          try {
            desc.id.fromBase64Url()
          } catch (e: Exception) {
            null
          }
        }
        allIndices.filter { credIndex ->
          allowedIds.any { it.contentEquals(credIndex.credentialId) }
        }
      }
    }
  }

  /**
   * Create a PendingIntent that launches the GetPasskeyActivity.
   */
  private fun createGetCredentialPendingIntent(
    context: Context,
    credIndex: CredentialIndex,
    requestJson: String,
    callingPackage: String?,
    requestCode: Int,
  ): PendingIntent {
    val intent = Intent().apply {
      setClassName(context.packageName, "app.passwordstore.passkey.provider.GetPasskeyActivity")
      putExtra(EXTRA_RP_ID, credIndex.rpId)
      putExtra(EXTRA_CREDENTIAL_ID, credIndex.credentialId)
      putExtra(EXTRA_REQUEST_JSON, requestJson)
      putExtra(EXTRA_CALLING_PACKAGE, callingPackage)
      putExtra(EXTRA_PASSKEYS_DIR, passkeysDir)
    }

    return PendingIntent.getActivity(
      context,
      requestCode,
      intent,
      PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
  }

  /**
   * Create a PendingIntent that launches the CreatePasskeyActivity.
   */
  private fun createCreateCredentialPendingIntent(
    context: Context,
    rpId: String?,
    rpName: String?,
    user: UserEntity?,
    requestJson: String,
    callingPackage: String?,
  ): PendingIntent {
    val intent = Intent().apply {
      setClassName(context.packageName, "app.passwordstore.passkey.provider.CreatePasskeyActivity")
      putExtra(EXTRA_RP_ID, rpId)
      putExtra(EXTRA_RP_NAME, rpName)
      user?.let {
        putExtra(EXTRA_USER_ID, it.id)
        putExtra(EXTRA_USER_NAME, it.name)
        putExtra(EXTRA_USER_DISPLAY_NAME, it.displayName)
      }
      putExtra(EXTRA_REQUEST_JSON, requestJson)
      putExtra(EXTRA_CALLING_PACKAGE, callingPackage)
      putExtra(EXTRA_PASSKEYS_DIR, passkeysDir)
    }

    return PendingIntent.getActivity(
      context,
      CREATE_REQUEST_CODE,
      intent,
      PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
  }

  private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }
}
