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

/** Authenticates and decrypts a Pass-Secrets map into the process-local mapping cache. */
@AndroidEntryPoint
class PassSecretsMapUnlockActivity : BasePGPActivity() {

  private var mapLoaded = false

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
    val message = withContext(dispatcherProvider.io()) { File(fullPath).readBytes().inputStream() }
    val outputStream = ByteArrayOutputStream()
    val results = repository.decrypt(passphrases, identifiers, message, outputStream)
    val lastResult = results.lastOrNull()

    if (lastResult != null && lastResult.second.isOk) {
      val decryptedOutput = lastResult.second.getOrThrow()
      val decryptedBytes = decryptedOutput.toByteArray()
      decryptedOutput.wipe()
      val mappings = PassSecretsMapStore.parse(decryptedBytes.decodeToString())
      decryptedBytes.wipe()

      PassSecretsMapStore.put(File(fullPath), mappings)
      mapLoaded = true
      onSuccess(lastResult.first)
      setResult(RESULT_OK)
      finish()
    } else {
      passphrases.values.forEach { it?.wipe() }
      val incorrectPassphrase =
        results
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

  override fun onDestroy() {
    if (!mapLoaded) PassSecretsMapStore.skip(File(fullPath))
    super.onDestroy()
  }

  companion object {

    fun newIntent(context: Context, mapFile: File, repositoryRoot: File): Intent {
      return Intent(context, PassSecretsMapUnlockActivity::class.java).apply {
        putExtra(EXTRA_FILE_PATH, mapFile.absolutePath)
        putExtra(EXTRA_REPO_PATH, repositoryRoot.absolutePath)
      }
    }
  }
}
