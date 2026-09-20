from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one occurrence, found {count}: {old[:80]!r}")
    p.write_text(text.replace(old, new, 1))


# Restrict JitPack to the OpenKeychain API group only.
replace_once(
    "settings.gradle.kts",
    '    mavenCentral { mavenContent { releasesOnly() } }\n  }\n}\n\n// Experimental features',
    '    mavenCentral { mavenContent { releasesOnly() } }\n'
    '    maven("https://jitpack.io") {\n'
    '      content { includeGroup("com.github.open-keychain.open-keychain") }\n'
    '    }\n'
    '  }\n}\n\n// Experimental features',
)

replace_once(
    "gradle/libs.versions.toml",
    'thirdparty-modernAndroidPrefs = "de.maxr1998:modernandroidpreferences:2.4.0-beta2"\n',
    'thirdparty-modernAndroidPrefs = "de.maxr1998:modernandroidpreferences:2.4.0-beta2"\n'
    'thirdparty-openpgp-api = "com.github.open-keychain.open-keychain:openpgp-api:v5.7.1"\n',
)

replace_once(
    "app/build.gradle.kts",
    '  implementation(libs.thirdparty.modernAndroidPrefs)\n',
    '  implementation(libs.thirdparty.modernAndroidPrefs)\n'
    '  implementation(libs.thirdparty.openpgp.api)\n',
)

replace_once(
    "app/src/main/java/app/passwordstore/util/settings/PreferenceKeys.kt",
    '  const val ASCII_ARMOR = "pgpainless_ascii_armor"\n',
    '  const val ASCII_ARMOR = "pgpainless_ascii_armor"\n'
    '  const val OPENPGP_PROVIDER_PACKAGE = "openpgp_provider_package"\n',
)

strings = Path("app/src/main/res/values/strings.xml")
text = strings.read_text()
marker = "</resources>"
addition = '''  <string name="pref_openpgp_provider_title">OpenPGP provider</string>\n  <string name="pref_openpgp_provider_summary">Use an external OpenPGP provider for private-key operations. Encryption continues to use public certificates imported into Password Store.</string>\n  <string name="pref_openpgp_provider_internal">Internal key manager</string>\n  <string name="openpgp_provider_decryption_failed">The external OpenPGP provider could not decrypt this entry.</string>\n'''
if 'name="pref_openpgp_provider_title"' not in text:
    if text.count(marker) != 1:
        raise SystemExit("strings.xml: closing resources marker not unique")
    strings.write_text(text.replace(marker, addition + marker))

# Route interactive password decryption through the selected external provider.
decrypt = Path("app/src/main/java/app/passwordstore/ui/crypto/DecryptActivity.kt")
text = decrypt.read_text()
text = text.replace(
    'import androidx.core.content.edit\n',
    'import androidx.activity.result.IntentSenderRequest\n'
    'import androidx.activity.result.contract.ActivityResultContracts.StartIntentSenderForResult\n'
    'import androidx.core.content.edit\n',
    1,
)
text = text.replace(
    'import app.passwordstore.data.passfile.PasswordEntry\n',
    'import app.passwordstore.data.crypto.OpenPgpApiBackend\n'
    'import app.passwordstore.data.crypto.OpenPgpApiBackend.OperationResult\n'
    'import app.passwordstore.data.passfile.PasswordEntry\n',
    1,
)
text = text.replace(
    '  private val binding by viewBinding(DecryptLayoutBinding::inflate)\n\n'
    '  // temporarily AES-encrypted password entry\n',
    '  private val binding by viewBinding(DecryptLayoutBinding::inflate)\n'
    '  private val externalOpenPgpBackend by lazy { OpenPgpApiBackend(applicationContext) }\n'
    '  private var externalProviderPackage: String? = null\n'
    '  private val externalOpenPgpInteraction =\n'
    '    registerForActivityResult(StartIntentSenderForResult()) { result ->\n'
    '      if (result.resultCode == RESULT_OK) {\n'
    '        externalProviderPackage?.let(::decryptWithExternalProvider)\n'
    '      } else {\n'
    '        finish()\n'
    '      }\n'
    '    }\n\n'
    '  // temporarily AES-encrypted password entry\n',
    1,
)
text = text.replace(
    '    requireKeysExist {\n'
    '      requireDecryptionKeysExist(relativeParentPath) { ids -> getPersistentAndDecrypt(ids) }\n'
    '    }\n'
    '  }\n\n'
    '  override fun onDestroy() {',
    '    externalProviderPackage =\n'
    '      settings.getString(PreferenceKeys.OPENPGP_PROVIDER_PACKAGE, null)\n'
    '    externalProviderPackage?.let(::decryptWithExternalProvider)\n'
    '      ?: requireKeysExist {\n'
    '        requireDecryptionKeysExist(relativeParentPath) { ids -> getPersistentAndDecrypt(ids) }\n'
    '      }\n'
    '  }\n\n'
    '  private fun decryptWithExternalProvider(providerPackage: String) {\n'
    '    lifecycleScope.launch {\n'
    '      val ciphertext = withContext(dispatcherProvider.io()) { File(fullPath).readBytes() }\n'
    '      when (val result = externalOpenPgpBackend.decrypt(providerPackage, ciphertext)) {\n'
    '        is OperationResult.Success -> {\n'
    '          val plaintextBytes = result.value\n'
    '          val plaintextChars = plaintextBytes.toCharArray()\n'
    '          plaintextBytes.wipe()\n'
    '          val entry = passwordEntryFactory.create(plaintextChars)\n'
    '          encryptedEntryChars = AESEncryption.encrypt(plaintextChars)\n'
    '          plaintextChars.wipe()\n'
    '          entry.clearExtraChars()\n'
    '          createPasswordUI(entry)\n'
    '        }\n'
    '        is OperationResult.UserInteractionRequired -> {\n'
    '          externalOpenPgpInteraction.launch(\n'
    '            IntentSenderRequest.Builder(result.pendingIntent.intentSender).build()\n'
    '          )\n'
    '        }\n'
    '        is OperationResult.Failure -> {\n'
    '          snackbar(message = resources.getString(R.string.openpgp_provider_decryption_failed))\n'
    '        }\n'
    '      }\n'
    '    }\n'
    '  }\n\n'
    '  override fun onDestroy() {',
    1,
)
decrypt.write_text(text)

# Remove imports accidentally carried in while scaffolding the backend.
backend = Path("app/src/main/java/app/passwordstore/data/crypto/OpenPgpApiBackend.kt")
text = backend.read_text()
for imp in (
    'import com.github.michaelbull.result.Result\n',
    'import com.github.michaelbull.result.Err\n',
    'import com.github.michaelbull.result.Ok\n',
):
    text = text.replace(imp, '')
backend.write_text(text)
