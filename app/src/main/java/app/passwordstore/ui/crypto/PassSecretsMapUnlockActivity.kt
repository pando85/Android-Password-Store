/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.crypto

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.core.content.edit
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.passsecrets.PassSecretsMapStore
import app.passwordstore.util.extensions.wipe
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.getError
import com.github.michaelbull.result.getOrThrow
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import java.io.File
import kotlinx.coroutines.withContext
import logcat.asLog
import logcat.logcat

/** Authenticates once and loads all Pass-Secrets metadata for an identity into process memory. */
@AndroidEntryPoint
class PassSecretsMapUnlockActivity : BasePGPActivity() {

  private var metadataLoaded = false

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    supportActionBar?.hide()
    requireKeysExist {
      requireDecryptionKeysExist(relativeParentPath) { ids -> getPersistentAndDecrypt(ids) }
    }
  }

  override suspend fun decryptWithPassphrase(
    passphrases: Map<String, CharArray?>,
    identifiers: List<PGPIdentifier>,
    onSuccess: suspend (String) -> Unit,
  ) {
    val primaryFile = File(fullPath)
    val primaryResults = decryptFile(primaryFile, passphrases, identifiers)
    val lastResult = primaryResults.lastOrNull()

    if (lastResult != null && lastResult.second.isOk) {
      loadMetadata(primaryFile, lastResult.second.getOrThrow())
      metadataLoaded = true

      // `.secrets.gpg` and `.mask.gpg` belong to the same exact identity. Reuse the successful
      // authentication to load the sibling too, avoiding a second passphrase/biometric prompt.
      val identity = primaryFile.parentFile
      if (identity != null) {
        listOf(PassSecretsMapStore.MAP_FILE_NAME, PassSecretsMapStore.MASK_FILE_NAME)
          .map { File(identity, it) }
          .filter { it.isFile && it != primaryFile }
          .forEach { sibling ->
            val siblingResults = decryptFile(sibling, passphrases, identifiers)
            val siblingResult = siblingResults.lastOrNull()
            if (siblingResult != null && siblingResult.second.isOk) {
              loadMetadata(sibling, siblingResult.second.getOrThrow())
            } else {
              siblingResults.forEach { result ->
                result.second.getError()?.let { error -> logcat { error.asLog() } }
              }
              // Keep the good primary metadata but do not repeatedly prompt just because an
              // optional sibling is corrupt or was encrypted inconsistently.
              PassSecretsMapStore.skip(primaryFile)
            }
          }
      }

      onSuccess(lastResult.first)
      setResult(RESULT_OK)
      finish()
    } else {
      passphrases.values.forEach { it?.wipe() }
      val incorrectPassphrase =
        primaryResults
          .filter { result ->
            if (result.second.getError() is IncorrectPassphraseException) {
              persistentPassphrases.edit { remove(result.first) }
              cachedPassphrases[result.first]?.wipe()
              cachedPassphrases.remove(result.first)
              true
            } else {
              result.second.getError()?.let { error -> logcat { error.asLog() } }
              false
            }
          }
          .any()

      if (incorrectPassphrase) decrypt(identifiers, isError = true) else finish()
    }

    if (!settings.getBoolean(PreferenceKeys.CACHE_PASSPHRASE, false)) {
      cachedPassphrases.values.forEach { it.wipe() }
      cachedPassphrases.clear()
    }
  }

  private suspend fun decryptFile(
    file: File,
    passphrases: Map<String, CharArray?>,
    identifiers: List<PGPIdentifier>,
  ) =
    withContext(dispatcherProvider.io()) {
      val message = file.readBytes().inputStream()
      repository.decrypt(passphrases, identifiers, message, ByteArrayOutputStream())
    }

  private fun loadMetadata(file: File, decryptedOutput: ByteArrayOutputStream) {
    val decryptedBytes = decryptedOutput.toByteArray()
    decryptedOutput.wipe()
    try {
      when (file.name) {
        PassSecretsMapStore.MAP_FILE_NAME ->
          PassSecretsMapStore.putMap(
            file,
            PassSecretsMapStore.parse(decryptedBytes.decodeToString()),
          )
        PassSecretsMapStore.MASK_FILE_NAME ->
          PassSecretsMapStore.putMask(
            file,
            PassSecretsMapStore.parseMask(decryptedBytes.decodeToString()),
          )
        else -> error("Unsupported Pass-Secrets metadata file: $file")
      }
    } finally {
      decryptedBytes.wipe()
    }
  }

  override fun onDestroy() {
    if (!metadataLoaded) PassSecretsMapStore.skip(File(fullPath))
    super.onDestroy()
  }

  companion object {

    fun newIntent(context: Context, metadataFile: File, repositoryRoot: File): Intent {
      return Intent(context, PassSecretsMapUnlockActivity::class.java).apply {
        putExtra(EXTRA_FILE_PATH, metadataFile.absolutePath)
        putExtra(EXTRA_REPO_PATH, repositoryRoot.absolutePath)
      }
    }
  }
}
