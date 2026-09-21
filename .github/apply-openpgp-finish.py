from pathlib import Path


def read(path: str) -> str:
    return Path(path).read_text()


def write(path: str, text: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text)


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    if text.count(old) != 1:
        raise RuntimeError(f"{path}: expected exactly one marker, got {text.count(old)}: {old[:80]!r}")
    write(path, text.replace(old, new, 1))


def replace_between(path: str, start: str, end: str, replacement: str) -> None:
    text = read(path)
    i = text.find(start)
    if i < 0:
        raise RuntimeError(f"{path}: start marker not found: {start!r}")
    j = text.find(end, i)
    if j < 0:
        raise RuntimeError(f"{path}: end marker not found: {end!r}")
    write(path, text[:i] + replacement + text[j:])


# Repair accidental unrelated edits from the bootstrap commits.
replace_once(
    "app/src/main/java/app/passwordstore/util/settings/PreferenceKeys.kt",
    'const val AUTOFILL_SAVE_DIRECTORY = "autofill_save_directory"',
    'const val AUTOFILL_SAVE_DIRECTORY = "oreo_autofill_save_directory"',
)
replace_once(
    "gradle/libs.versions.toml",
    'build-agp = { module = "com.android.tools:gradle", version.ref = "agp" }',
    'build-agp = { module = "com.android.tools.build:gradle", version.ref = "agp" }',
)

# Make OpenPGP providers discoverable without relying on QUERY_ALL_PACKAGES.
replace_once(
    "app/src/main/AndroidManifest.xml",
    '  android:installLocation="auto">\n\n  <uses-permission',
    '  android:installLocation="auto">\n\n  <queries>\n    <intent>\n      <action android:name="org.openintents.openpgp.IOpenPgpService2" />\n    </intent>\n  </queries>\n\n  <uses-permission',
)

# Base activity: external provider becomes a first-class backend for all password flows.
base = "app/src/main/java/app/passwordstore/ui/crypto/BasePGPActivity.kt"
replace_once(
    base,
    "import app.passwordstore.data.crypto.CryptoRepository\n",
    "import app.passwordstore.data.crypto.CryptoRepository\n"
    "import app.passwordstore.data.crypto.OpenPgpActivityInteractionHandler\n"
    "import app.passwordstore.data.crypto.OpenPgpApiBackend\n"
    "import app.passwordstore.data.crypto.OpenPgpProviderRepository\n",
)
replace_once(
    base,
    "  private var retries = 0\n",
    "  private var retries = 0\n\n"
    "  private val openPgpInteractionHandler = OpenPgpActivityInteractionHandler(this)\n",
)
replace_once(
    base,
    "  @Inject lateinit var repository: CryptoRepository\n  @Inject lateinit var dispatcherProvider: DispatcherProvider\n",
    "  @Inject lateinit var repository: CryptoRepository\n"
    "  @Inject lateinit var openPgpProviderRepository: OpenPgpProviderRepository\n"
    "  @Inject lateinit var dispatcherProvider: DispatcherProvider\n",
)
replace_once(
    base,
    "  protected fun requireKeysExist(onKeysExist: () -> Unit) {\n    onKeyListCallback = onKeysExist\n    lifecycleScope.launch {\n",
    "  protected fun requireKeysExist(onKeysExist: () -> Unit) {\n"
    "    onKeyListCallback = onKeysExist\n"
    "    if (openPgpProviderRepository.hasSelectedProvider()) {\n"
    "      onKeysExist()\n"
    "      return\n"
    "    }\n"
    "    lifecycleScope.launch {\n",
)

new_require_encrypt = '''  protected fun requireEncryptionKeysExist(
    subDir: String,
    onKeysExist: (List<PGPIdentifier>) -> Unit,
  ) {
    val ids = getPGPIdentifiers(subDir)
    if (ids.isNullOrEmpty()) {
      val (title, message) =
        if (ids == null) {
          resources.getString(R.string.missing_gpg_id_dialog_title) to
            resources.getString(R.string.missing_gpg_id_dialog_message)
        } else {
          resources.getString(R.string.invalid_gpg_id_dialog_title) to
            resources.getString(R.string.invalid_gpg_id_dialog_message)
        }
      openKeyManagerDialog(title, message) {
        val intent = PGPKeyListActivity.newIntent(this@BasePGPActivity, keySelection = true)
        intent.putExtra("SUB_PATH", subDir)
        keySelectAction.launch(intent)
      }
      return
    }

    if (openPgpProviderRepository.hasSelectedProvider()) {
      lifecycleScope.launch {
        val missing = ids.filterNot(repository::hasKey)
        if (missing.isEmpty()) {
          onKeysExist(ids)
          return@launch
        }
        when (
          val result =
            openPgpProviderRepository.ensurePublicKeys(missing, openPgpInteractionHandler)
        ) {
          is OpenPgpApiBackend.OperationResult.Success -> onKeysExist(ids)
          OpenPgpApiBackend.OperationResult.Cancelled -> Unit
          is OpenPgpApiBackend.OperationResult.UserInteractionRequired ->
            snackbar(message = getString(R.string.openpgp_provider_interaction_failed))
          is OpenPgpApiBackend.OperationResult.Failure ->
            snackbar(
              message =
                getString(
                  R.string.openpgp_provider_operation_failed,
                  result.error.message ?: getString(R.string.error),
                )
            )
        }
      }
      return
    }

    val idsWithKey = ids.filter { repository.hasKey(it) }
    if (idsWithKey.isEmpty()) {
      val title = resources.getString(R.string.no_pgp_keys_dialog_title)
      val missingKeysForIds = ids.joinToString(", ")
      val message = resources.getString(R.string.no_pgp_keys_dialog_message) + missingKeysForIds
      openKeyManagerDialog(title, message) {
        keyImportAction.launch(PGPKeyListActivity.newIntent(this@BasePGPActivity))
      }
    } else {
      onKeysExist(ids)
    }
  }

'''
replace_between(
    base,
    "  protected fun requireEncryptionKeysExist(\n",
    "  protected fun requireDecryptionKeysExist(\n",
    new_require_encrypt,
)

new_require_decrypt = '''  protected fun requireDecryptionKeysExist(
    subDir: String,
    onKeysExist: (List<PGPIdentifier>) -> Unit,
  ) {
    val ids = getPGPIdentifiers(subDir)
    if (ids.isNullOrEmpty()) {
      val (title, message) =
        if (ids == null) {
          resources.getString(R.string.missing_gpg_id_dialog_title) to
            resources.getString(R.string.missing_gpg_id_dialog_message)
        } else {
          resources.getString(R.string.invalid_gpg_id_dialog_title) to
            resources.getString(R.string.invalid_gpg_id_dialog_message)
        }
      openKeyManagerDialog(title, message) {
        val intent = PGPKeyListActivity.newIntent(this@BasePGPActivity, keySelection = true)
        intent.putExtra("SUB_PATH", subDir)
        keySelectAction.launch(intent)
      }
      return
    }

    if (openPgpProviderRepository.hasSelectedProvider()) {
      onKeysExist(ids)
      return
    }

    val idsWithKey = ids.filter { repository.hasKey(it) }
    val idsWithDecryptionKey = idsWithKey.filter { repository.hasDecKey(it) }

    if (idsWithDecryptionKey.isEmpty()) {
      val title = resources.getString(R.string.no_decryption_keys_dialog_title)
      val missingDecKeysForIds =
        if (idsWithKey.isNotEmpty()) {
          ids
            .map { id ->
              if (id in idsWithKey) "\\n${id}: ${getString(R.string.pgp_public_only)}"
              else "\\n${id}: ${getString(R.string.pgp_unknown)}"
            }
            .joinToString()
        } else {
          ids.joinToString(", ")
        }
      val message =
        resources.getString(R.string.no_decryption_keys_dialog_message) + missingDecKeysForIds
      openKeyManagerDialog(title, message) {
        keyImportAction.launch(PGPKeyListActivity.newIntent(this@BasePGPActivity))
      }
    } else {
      onKeysExist(ids)
    }
  }

'''
replace_between(
    base,
    "  protected fun requireDecryptionKeysExist(\n",
    "  /**\n   * Copies a provided [password]",
    new_require_decrypt,
)
replace_once(
    base,
    "  protected fun getPersistentAndDecrypt(identifiers: List<PGPIdentifier>, action: String? = null) {\n    // Detect AES key invalidation",
    "  protected fun getPersistentAndDecrypt(identifiers: List<PGPIdentifier>, action: String? = null) {\n"
    "    if (openPgpProviderRepository.hasSelectedProvider()) {\n"
    "      decrypt(identifiers)\n"
    "      return\n"
    "    }\n\n"
    "    // Detect AES key invalidation",
)
replace_once(
    base,
    "  protected fun decrypt(identifiers: List<PGPIdentifier>, isError: Boolean = false) {\n    val passphrases = cachedPassphrases.filterKeys {",
    "  protected fun decrypt(identifiers: List<PGPIdentifier>, isError: Boolean = false) {\n"
    "    if (openPgpProviderRepository.hasSelectedProvider()) {\n"
    "      lifecycleScope.launch(dispatcherProvider.main()) { decryptWithOpenPgpProvider() }\n"
    "      return\n"
    "    }\n"
    "    val passphrases = cachedPassphrases.filterKeys {",
)
replace_once(
    base,
    "  /** Subclass-specific implementations */\n  open suspend fun decryptWithPassphrase(\n",
    "  protected suspend fun decryptUsingOpenPgpProvider(\n"
    "    ciphertext: ByteArray\n"
    "  ): OpenPgpApiBackend.OperationResult<ByteArray> =\n"
    "    openPgpProviderRepository.decrypt(ciphertext, openPgpInteractionHandler)\n\n"
    "  protected open suspend fun decryptWithOpenPgpProvider() {}\n\n"
    "  /** Subclass-specific implementations */\n"
    "  open suspend fun decryptWithPassphrase(\n",
)

# Password viewer: consume provider plaintext using the existing secure byte/char conversion path.
decrypt_activity = "app/src/main/java/app/passwordstore/ui/crypto/DecryptActivity.kt"
replace_once(
    decrypt_activity,
    "import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException\n",
    "import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException\n"
    "import app.passwordstore.data.crypto.OpenPgpApiBackend\n",
)
replace_once(
    decrypt_activity,
    "  override suspend fun decryptWithPassphrase(\n",
    '''  override suspend fun decryptWithOpenPgpProvider() {
    val ciphertext = withContext(dispatcherProvider.io()) { File(fullPath).readBytes() }
    try {
      when (val result = decryptUsingOpenPgpProvider(ciphertext)) {
        is OpenPgpApiBackend.OperationResult.Success -> {
          val plaintextBytes = result.value
          try {
            val plaintextChars = plaintextBytes.toCharArray()
            try {
              val entry = passwordEntryFactory.create(plaintextChars)
              encryptedEntryChars = AESEncryption.encrypt(plaintextChars)
              entry.clearExtraChars()
              createPasswordUI(entry)
            } finally {
              plaintextChars.wipe()
            }
          } finally {
            plaintextBytes.wipe()
          }
        }
        OpenPgpApiBackend.OperationResult.Cancelled -> finish()
        is OpenPgpApiBackend.OperationResult.UserInteractionRequired ->
          snackbar(message = getString(R.string.openpgp_provider_interaction_failed))
        is OpenPgpApiBackend.OperationResult.Failure ->
          snackbar(
            message =
              getString(
                R.string.openpgp_provider_operation_failed,
                result.error.message ?: getString(R.string.error),
              )
          )
      }
    } finally {
      ciphertext.wipe()
    }
  }

  override suspend fun decryptWithPassphrase(
''',
)

# Autofill decryption uses the same provider backend and still returns an Autofill dataset.
autofill = "app/src/main/java/app/passwordstore/ui/autofill/AutofillDecryptActivity.kt"
replace_once(
    autofill,
    "import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException\n",
    "import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException\n"
    "import app.passwordstore.data.crypto.OpenPgpApiBackend\n",
)
replace_once(
    autofill,
    "  override suspend fun decryptWithPassphrase(\n",
    '''  override suspend fun decryptWithOpenPgpProvider() {
    val encryptedFile = File(filePath)
    val ciphertext = withContext(dispatcherProvider.io()) { encryptedFile.readBytes() }
    try {
      when (val result = decryptUsingOpenPgpProvider(ciphertext)) {
        is OpenPgpApiBackend.OperationResult.Success -> {
          val plaintextBytes = result.value
          try {
            val plaintextChars = plaintextBytes.toCharArray()
            val entry =
              try {
                passwordEntryFactory.create(plaintextChars)
              } finally {
                plaintextChars.wipe()
              }
            entry.clearExtra()
            val directoryStructure = AutofillPreferences.directoryStructure(this)
            val credentials =
              AutofillPreferences.credentialsFromStoreEntry(
                this,
                encryptedFile,
                entry,
                directoryStructure,
              )
            val fillInDataset =
              AutofillResponseBuilder.makeFillInDataset(
                this@AutofillDecryptActivity,
                credentials,
                clientState,
                action,
              )
            withContext(dispatcherProvider.main()) {
              setResult(
                RESULT_OK,
                Intent().apply {
                  putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, fillInDataset)
                },
              )
              if (entry.hasTotp()) {
                val otp = entry.currentOtp
                val remainingTime = otp.remainingTime.inWholeSeconds
                copyTextToClipboard(otp.value.toCharArray(), isSensitive = false)
                otpTimer?.shutdownNow()
                val otpTimerNew = Executors.newSingleThreadScheduledExecutor()
                otpTimer = otpTimerNew
                otpTimerNew.schedule(
                  { copyTextToClipboard(entry.currentOtp.value.toCharArray(), isSensitive = false) },
                  remainingTime,
                  TimeUnit.SECONDS,
                )
              }
              entry.clear()
              finish()
            }
          } finally {
            plaintextBytes.wipe()
          }
        }
        OpenPgpApiBackend.OperationResult.Cancelled -> finish()
        is OpenPgpApiBackend.OperationResult.UserInteractionRequired -> {
          snackbar(message = getString(R.string.openpgp_provider_interaction_failed))
          finish()
        }
        is OpenPgpApiBackend.OperationResult.Failure -> {
          snackbar(
            message =
              getString(
                R.string.openpgp_provider_operation_failed,
                result.error.message ?: getString(R.string.error),
              )
          )
          finish()
        }
      }
    } finally {
      ciphertext.wipe()
    }
  }

  override suspend fun decryptWithPassphrase(
''',
)

# Scope OpenPGP UI permission/decryption requests to the full Credential Provider transaction.
passkey_activity = "app/src/main/java/app/passwordstore/passkeys/AppPasskeyProviderActivity.kt"
replace_once(
    passkey_activity,
    "import app.passwordstore.data.repo.PasswordRepository\n",
    "import app.passwordstore.data.crypto.OpenPgpActivityInteractionHandler\n"
    "import app.passwordstore.data.crypto.OpenPgpInteractionCoordinator\n"
    "import app.passwordstore.data.repo.PasswordRepository\n",
)
replace_once(
    passkey_activity,
    "  @Inject lateinit var signatureCounterTransaction: SignatureCounterTransaction\n",
    "  @Inject lateinit var signatureCounterTransaction: SignatureCounterTransaction\n"
    "  @Inject lateinit var openPgpInteractionCoordinator: OpenPgpInteractionCoordinator\n",
)
replace_once(
    passkey_activity,
    "  @Inject\n  @app.passwordstore.injection.prefs.PGPPassphrases\n",
    "  private val openPgpInteractionHandler = OpenPgpActivityInteractionHandler(this)\n\n"
    "  @Inject\n  @app.passwordstore.injection.prefs.PGPPassphrases\n",
)
replace_once(
    passkey_activity,
    "    PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)?.let {\n      handleGetCredential(it)\n      return\n    }\n\n    PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)?.let {\n      handleCreateCredential(it)\n      return\n    }",
    "    PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)?.let {\n"
    "      openPgpInteractionCoordinator.withHandler(openPgpInteractionHandler) {\n"
    "        handleGetCredential(it)\n"
    "      }\n"
    "      return\n"
    "    }\n\n"
    "    PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)?.let {\n"
    "      openPgpInteractionCoordinator.withHandler(openPgpInteractionHandler) {\n"
    "        handleCreateCredential(it)\n"
    "      }\n"
    "      return\n"
    "    }",
)

# Provider-backed recipient resolver: import missing public certs, then retry strict .gpg-id resolution.
write(
    "app/src/main/java/app/passwordstore/passkeys/OpenPgpPassRecipientResolver.kt",
    '''/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKey
import app.passwordstore.data.crypto.OpenPgpApiBackend
import app.passwordstore.data.crypto.OpenPgpInteractionCoordinator
import app.passwordstore.data.crypto.OpenPgpProviderRepository
import app.passwordstore.passkeys.storage.PassRecipientResolver
import app.passwordstore.passkeys.storage.RecipientPolicyError
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.io.File

/** Adds provider public-certificate retrieval without weakening hierarchical `.gpg-id` policy. */
class OpenPgpPassRecipientResolver(
  private val delegate: PassRecipientResolver<PGPKey>,
  private val providerRepository: OpenPgpProviderRepository,
  private val interactionCoordinator: OpenPgpInteractionCoordinator,
) : PassRecipientResolver<PGPKey> {

  override suspend fun resolveFor(target: File): Result<List<PGPKey>, RecipientPolicyError> {
    return delegate.resolveFor(target).fold(
      success = { Ok(it) },
      failure = { error ->
        if (
          error !is RecipientPolicyError.RecipientNotFound ||
            !providerRepository.hasSelectedProvider()
        ) {
          return@fold Err(error)
        }

        val identifier = PGPIdentifier.fromString(error.identifier) ?: return@fold Err(error)
        when (
          providerRepository.ensurePublicKeys(
            listOf(identifier),
            OpenPgpApiBackend.InteractionHandler { pendingIntent ->
              interactionCoordinator.interact(pendingIntent)
            },
          )
        ) {
          is OpenPgpApiBackend.OperationResult.Success -> delegate.resolveFor(target)
          else -> Err(error)
        }
      },
    )
  }
}
''',
)

passkeys_module = "app/src/main/java/app/passwordstore/injection/passkeys/PasskeysModule.kt"
replace_once(
    passkeys_module,
    "import app.passwordstore.passkeys.OpenPgpPasskeyDecryptor\n",
    "import app.passwordstore.passkeys.OpenPgpPassRecipientResolver\n"
    "import app.passwordstore.passkeys.OpenPgpPasskeyDecryptor\n",
)
replace_once(
    passkeys_module,
    "  fun providePassRecipientResolver(\n    @ApplicationContext context: Context,\n    keyManager: PGPKeyManager,\n  ): PassRecipientResolver<PGPKey> {\n    val repositoryRoot = File(context.filesDir, \"store\")\n    return DefaultPassRecipientResolver(repositoryRoot, keyManager)\n  }",
    "  fun providePassRecipientResolver(\n"
    "    @ApplicationContext context: Context,\n"
    "    keyManager: PGPKeyManager,\n"
    "    providerRepository: OpenPgpProviderRepository,\n"
    "    interactionCoordinator: OpenPgpInteractionCoordinator,\n"
    "  ): PassRecipientResolver<PGPKey> {\n"
    "    val repositoryRoot = File(context.filesDir, \"store\")\n"
    "    val localResolver = DefaultPassRecipientResolver(repositoryRoot, keyManager)\n"
    "    return OpenPgpPassRecipientResolver(\n"
    "      localResolver,\n"
    "      providerRepository,\n"
    "      interactionCoordinator,\n"
    "    )\n"
    "  }",
)

# Provider preference and explicit permission grant.
write(
    "app/src/main/java/app/passwordstore/ui/settings/PGPSettings.kt",
    '''/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.settings

import android.content.Intent
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.data.crypto.OpenPgpActivityInteractionHandler
import app.passwordstore.data.crypto.OpenPgpApiBackend
import app.passwordstore.ui.pgp.PGPKeyListActivity
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.settings.PreferenceKeys
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import de.Maxr1998.modernpreferences.PreferenceScreen
import de.Maxr1998.modernpreferences.helpers.onClick
import de.Maxr1998.modernpreferences.helpers.pref
import de.Maxr1998.modernpreferences.helpers.switch
import kotlinx.coroutines.launch

class PGPSettings(private val activity: FragmentActivity) : SettingsProvider {

  private val backend = OpenPgpApiBackend(activity.applicationContext)
  private val interactionHandler = OpenPgpActivityInteractionHandler(activity)

  override fun provideSettings(builder: PreferenceScreen.Builder) {
    builder.apply {
      pref("_") {
        titleRes = R.string.pref_pgp_key_manager_title
        persistent = false
        onClick {
          (activity as SettingsActivity)
            .repositorySettings
            .sshKeyAction
            .launch(Intent(activity, PGPKeyListActivity::class.java))
          false
        }
      }
      pref("_openpgp_provider") {
        titleRes = R.string.pref_openpgp_provider_title
        summaryRes = R.string.pref_openpgp_provider_summary
        persistent = false
        onClick {
          showOpenPgpProviderDialog()
          false
        }
      }
      switch(PreferenceKeys.ASCII_ARMOR) {
        titleRes = R.string.pref_pgp_ascii_armor_title
        persistent = true
      }
    }
  }

  private fun showOpenPgpProviderDialog() {
    val providers = backend.providers()
    val current = activity.sharedPrefs.getString(PreferenceKeys.OPENPGP_PROVIDER_PACKAGE, null)
    val labels =
      listOf(activity.getString(R.string.pref_openpgp_provider_internal)) +
        providers.map { "${it.label} (${it.packageName})" }
    val checked =
      providers.indexOfFirst { it.packageName == current }.let { if (it < 0) 0 else it + 1 }

    MaterialAlertDialogBuilder(activity)
      .setTitle(R.string.pref_openpgp_provider_title)
      .setSingleChoiceItems(labels.toTypedArray(), checked) { dialog, which ->
        dialog.dismiss()
        if (which == 0) {
          activity.sharedPrefs.edit { remove(PreferenceKeys.OPENPGP_PROVIDER_PACKAGE) }
          return@setSingleChoiceItems
        }

        val provider = providers[which - 1]
        activity.lifecycleScope.launch {
          when (val result = backend.checkPermission(provider.packageName, interactionHandler)) {
            is OpenPgpApiBackend.OperationResult.Success ->
              activity.sharedPrefs.edit {
                putString(PreferenceKeys.OPENPGP_PROVIDER_PACKAGE, provider.packageName)
              }
            OpenPgpApiBackend.OperationResult.Cancelled -> Unit
            is OpenPgpApiBackend.OperationResult.UserInteractionRequired ->
              showProviderError(activity.getString(R.string.openpgp_provider_interaction_failed))
            is OpenPgpApiBackend.OperationResult.Failure ->
              showProviderError(
                activity.getString(
                  R.string.openpgp_provider_operation_failed,
                  result.error.message ?: activity.getString(R.string.error),
                )
              )
          }
        }
      }
      .setNegativeButton(R.string.dialog_cancel, null)
      .show()
  }

  private fun showProviderError(message: String) {
    MaterialAlertDialogBuilder(activity)
      .setTitle(R.string.pref_openpgp_provider_title)
      .setMessage(message)
      .setPositiveButton(android.R.string.ok, null)
      .show()
  }
}
''',
)

# Strings used by provider selection and operation failures.
replace_once(
    "app/src/main/res/values/strings.xml",
    '  <string name="pref_pgp_key_manager_title">Key manager</string>\n',
    '  <string name="pref_pgp_key_manager_title">Key manager</string>\n'
    '  <string name="pref_openpgp_provider_title">OpenPGP backend</string>\n'
    '  <string name="pref_openpgp_provider_summary">Use APS keys or delegate private-key operations to a compatible OpenPGP provider.</string>\n'
    '  <string name="pref_openpgp_provider_internal">Internal key manager</string>\n'
    '  <string name="openpgp_provider_interaction_failed">The OpenPGP provider interaction could not be completed.</string>\n'
    '  <string name="openpgp_provider_operation_failed">External OpenPGP provider operation failed: %1$s</string>\n',
)

# Focused tests for the interaction continuation contract and coroutine scoping.
write(
    "app/src/test/java/app/passwordstore/data/crypto/OpenPgpApiBackendTest.kt",
    '''/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.app.PendingIntent
import android.content.Intent
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.runBlocking
import org.openintents.openpgp.util.OpenPgpApi
import org.robolectric.RuntimeEnvironment
import org.robolectric.RobolectricTestRunner
import org.junit.runner.RunWith

@RunWith(RobolectricTestRunner::class)
class OpenPgpApiBackendTest {

  @Test
  fun `decrypt returns provider output on success`() = runBlocking {
    val executor = FakeExecutor { _, _, _ ->
      OpenPgpApiCall(result(OpenPgpApi.RESULT_CODE_SUCCESS), byteArrayOf(1, 2, 3))
    }
    val backend = OpenPgpApiBackend(executor)

    val result = backend.decrypt("provider", byteArrayOf(9))

    assertContentEquals(byteArrayOf(1, 2, 3), assertIs<OpenPgpApiBackend.OperationResult.Success<ByteArray>>(result).value)
  }

  @Test
  fun `provider continuation intent is used after user interaction`() = runBlocking {
    val pendingIntent =
      PendingIntent.getActivity(
        RuntimeEnvironment.getApplication(),
        7,
        Intent("interaction"),
        PendingIntent.FLAG_IMMUTABLE,
      )
    val seenActions = mutableListOf<String?>()
    val executor = FakeExecutor { _, request, _ ->
      seenActions += request.action
      if (seenActions.size == 1) {
        OpenPgpApiCall(
          result(OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED).apply {
            putExtra(OpenPgpApi.RESULT_INTENT, pendingIntent)
          },
          byteArrayOf(),
        )
      } else {
        OpenPgpApiCall(result(OpenPgpApi.RESULT_CODE_SUCCESS), byteArrayOf(4))
      }
    }
    val backend = OpenPgpApiBackend(executor)

    val operation =
      backend.decrypt(
        "provider",
        byteArrayOf(9),
        OpenPgpApiBackend.InteractionHandler {
          OpenPgpApiBackend.InteractionResult.Completed(Intent("continued"))
        },
      )

    assertIs<OpenPgpApiBackend.OperationResult.Success<ByteArray>>(operation)
    assertEquals(listOf(OpenPgpApi.ACTION_DECRYPT_VERIFY, "continued"), seenActions)
  }

  @Test
  fun `interaction is surfaced when no foreground handler exists`() = runBlocking {
    val pendingIntent =
      PendingIntent.getActivity(
        RuntimeEnvironment.getApplication(),
        8,
        Intent("interaction"),
        PendingIntent.FLAG_IMMUTABLE,
      )
    val executor = FakeExecutor { _, _, _ ->
      OpenPgpApiCall(
        result(OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED).apply {
          putExtra(OpenPgpApi.RESULT_INTENT, pendingIntent)
        },
        byteArrayOf(),
      )
    }

    val operation = OpenPgpApiBackend(executor).decrypt("provider", byteArrayOf(9))

    assertIs<OpenPgpApiBackend.OperationResult.UserInteractionRequired>(operation)
  }

  private fun result(code: Int): Intent =
    Intent().apply { putExtra(OpenPgpApi.RESULT_CODE, code) }

  private class FakeExecutor(
    private val executeBlock: suspend (String, Intent, ByteArray?) -> OpenPgpApiCall
  ) : OpenPgpApiExecutor {
    override fun providers(): List<OpenPgpApiBackend.Provider> = emptyList()

    override suspend fun execute(
      providerPackage: String,
      request: Intent,
      input: ByteArray?,
    ): OpenPgpApiCall = executeBlock(providerPackage, request, input)
  }
}
''',
)
write(
    "app/src/test/java/app/passwordstore/data/crypto/OpenPgpInteractionCoordinatorTest.kt",
    '''/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.app.PendingIntent
import android.content.Intent
import kotlin.test.Test
import kotlin.test.assertIs
import kotlinx.coroutines.runBlocking
import org.junit.runner.RunWith
import org.robolectric.RuntimeEnvironment
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class OpenPgpInteractionCoordinatorTest {

  @Test
  fun `handler is visible only inside its coroutine scope`() = runBlocking {
    val coordinator = OpenPgpInteractionCoordinator()
    val pendingIntent =
      PendingIntent.getActivity(
        RuntimeEnvironment.getApplication(),
        9,
        Intent("interaction"),
        PendingIntent.FLAG_IMMUTABLE,
      )

    assertIs<OpenPgpApiBackend.InteractionResult.Cancelled>(coordinator.interact(pendingIntent))

    coordinator.withHandler(
      OpenPgpApiBackend.InteractionHandler {
        OpenPgpApiBackend.InteractionResult.Completed(Intent("completed"))
      }
    ) {
      assertIs<OpenPgpApiBackend.InteractionResult.Completed>(coordinator.interact(pendingIntent))
    }

    assertIs<OpenPgpApiBackend.InteractionResult.Cancelled>(coordinator.interact(pendingIntent))
  }
}
''',
)
