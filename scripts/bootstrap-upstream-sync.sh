#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

UPSTREAM_URL="https://github.com/agrahn/Android-Password-Store.git"
UPSTREAM_BRANCH="develop"

if git remote get-url upstream >/dev/null 2>&1; then
  git remote set-url upstream "$UPSTREAM_URL"
else
  git remote add upstream "$UPSTREAM_URL"
fi

git fetch --quiet --no-tags upstream "$UPSTREAM_BRANCH"

find_pr_commit() {
  local pr="$1"
  local sha
  sha="$(git log "upstream/$UPSTREAM_BRANCH" --format='%H' --grep="#${pr}" -n 1)"
  if [[ -z "$sha" ]]; then
    echo "Unable to locate upstream PR #$pr on upstream/$UPSTREAM_BRANCH" >&2
    exit 10
  fi
  printf '%s' "$sha"
}

apply_pr_paths() {
  local pr="$1"
  shift
  local sha
  sha="$(find_pr_commit "$pr")"
  echo "Applying upstream #$pr from $sha"

  local path patch
  for path in "$@"; do
    patch="$(mktemp)"
    git diff --binary "${sha}^" "$sha" -- "$path" > "$patch"
    if [[ ! -s "$patch" ]]; then
      echo "Expected $path to change in upstream #$pr, but it did not." >&2
      rm -f "$patch"
      exit 11
    fi
    if ! git apply --3way --index --whitespace=nowarn "$patch"; then
      echo "Failed to three-way apply upstream #$pr path: $path" >&2
      rm -f "$patch"
      git status --short >&2 || true
      exit 12
    fi
    rm -f "$patch"
  done

  if ! git diff --cached --quiet; then
    git commit -m "chore(upstream): port upstream #$pr" -m "Selective port from agrahn/Android-Password-Store PR #$pr. Fork-owned passkey implementation is intentionally excluded unless explicitly listed."
  fi
}

# Small classic-app fixes and complete recent-password timestamp lifecycle.
apply_pr_paths 936 app/src/main/java/app/passwordstore/util/git/sshj/SshKey.kt

# #938 overlaps fork-specific password creation work. Apply only its timestamp-cache invariant.
python3 <<'PY'
from pathlib import Path
path = Path("app/src/main/java/app/passwordstore/ui/crypto/PasswordCreationActivity.kt")
text = path.read_text()
old = '''          // associate the new password name with the last name's timestamp in history
          val preference = getSharedPreferences("recent_password_history", Context.MODE_PRIVATE)
          val oldFilePathHash = "${fullPath.trimEnd('/')}/$suggestedName.gpg".base64()
          val timestamp = preference.getString(oldFilePathHash)
          if (timestamp != null) {
            preference.edit {
              remove(oldFilePathHash)
              putString(passwordFile.absolutePathString().base64(), timestamp)
            }
          }
'''
new = '''          // create/update timestamp on the current password file
          val preference = getSharedPreferences("recent_password_history", Context.MODE_PRIVATE)
          preference.edit {
            suggestedName?.let { oldFile ->
              val oldFilePathHash = "${fullPath.trimEnd('/')}/$oldFile.gpg".base64()
              remove(oldFilePathHash)
            }
            putString(
              passwordFile.absolutePathString().base64(),
              System.currentTimeMillis().toString(),
            )
          }
'''
if old not in text:
    raise SystemExit("Unable to locate fork timestamp block for upstream #938")
path.write_text(text.replace(old, new, 1))
PY
git add app/src/main/java/app/passwordstore/ui/crypto/PasswordCreationActivity.kt
git commit -m "chore(upstream): adapt upstream #938 timestamp lifecycle" -m "Preserve fork-specific password creation logic while updating recent-password timestamps on every create/edit."

apply_pr_paths 939 app/src/main/java/app/passwordstore/ui/passwords/PasswordStore.kt
apply_pr_paths 941 app/src/main/java/app/passwordstore/ui/passwords/PasswordStore.kt
apply_pr_paths 942 \
  app/src/main/java/app/passwordstore/ui/settings/RepositorySettings.kt \
  app/src/main/java/app/passwordstore/util/extensions/AndroidExtensions.kt

# #1000: keep the fork passkey stack out of this port. The classic Autofill call site and
# strings come from upstream; BasePGPActivity is adapted narrowly because the fork changed it.
apply_pr_paths 1000 app/src/main/java/app/passwordstore/ui/autofill/AutofillDecryptActivity.kt
python3 <<'PY'
from pathlib import Path
path = Path("app/src/main/java/app/passwordstore/ui/crypto/BasePGPActivity.kt")
text = path.read_text()
replacements = [
    (
        "  protected fun getPersistentAndDecrypt(identifiers: List<PGPIdentifier>) {",
        "  protected fun getPersistentAndDecrypt(identifiers: List<PGPIdentifier>, action: String? = null) {",
    ),
    (
        "      verifyPin(pinEncrypted, persistentIds, identifiers)",
        "      verifyPin(pinEncrypted, persistentIds, identifiers, action)",
    ),
    (
        "    identifiers: List<PGPIdentifier>,\n    isError: Boolean = false,",
        "    identifiers: List<PGPIdentifier>,\n    action: String?,\n    isError: Boolean = false,",
    ),
    (
        "        description = resources.getString(R.string.pin_entry_description),",
        '''        description =
          when (action) {
            "autofill" -> resources.getString(R.string.pin_entry_autofill_description)
            "passkey" -> resources.getString(R.string.pin_entry_passkey_description)
            else -> resources.getString(R.string.pin_entry_description)
          },''',
    ),
    (
        "            verifyPin(pinEncryptedUpdate, ids, identifiers, isError = true)",
        "            verifyPin(pinEncryptedUpdate, ids, identifiers, action, isError = true)",
    ),
]
for old, new in replacements:
    if old not in text:
        raise SystemExit(f"Unable to locate BasePGPActivity #1000 fragment: {old!r}")
    text = text.replace(old, new, 1)
path.write_text(text)
PY
git add app/src/main/java/app/passwordstore/ui/crypto/BasePGPActivity.kt
git commit -m "chore(upstream): adapt upstream #1000 fast unlock context" -m "Preserve fork-specific crypto/passkey code while carrying the Autofill/PIN context through BasePGPActivity."
apply_pr_paths 1000 app/src/main/res/values/strings.xml
apply_pr_paths 1000 app/src/main/res/values-de/strings.xml

apply_pr_paths 1007 app/src/main/java/app/passwordstore/util/shortcuts/ShortcutHandler.kt

# #1011: isolate fast-unlock PINs by PGP identity. The upstream PR contains a qualifier file
# accidentally named "as UnlockPins.kt"; adopt its content and normalize the filename here.
apply_pr_paths 1011 \
  app/src/main/java/app/passwordstore/Application.kt \
  app/src/main/java/app/passwordstore/injection/prefs/PreferenceModule.kt \
  "app/src/main/java/app/passwordstore/injection/prefs/as UnlockPins.kt"
git mv \
  "app/src/main/java/app/passwordstore/injection/prefs/as UnlockPins.kt" \
  app/src/main/java/app/passwordstore/injection/prefs/UnlockPins.kt
git commit -m "chore(upstream): normalize upstream #1011 qualifier filename"

# BasePGPActivity has fork-owned authentication/passkey changes, so port #1011 semantically.
python3 <<'PY'
from pathlib import Path

path = Path("app/src/main/java/app/passwordstore/ui/crypto/BasePGPActivity.kt")
text = path.read_text()

replacements = [
    (
        "import app.passwordstore.injection.prefs.SettingsPreferences\n",
        "import app.passwordstore.injection.prefs.SettingsPreferences\nimport app.passwordstore.injection.prefs.UnlockPins\n",
    ),
    (
        "import javax.inject.Inject\n",
        "import javax.inject.Inject\nimport kotlin.math.max\n",
    ),
    (
        "  @PGPPassphrases @Inject lateinit var persistentPassphrases: SharedPreferences\n\n",
        "  @PGPPassphrases @Inject lateinit var persistentPassphrases: SharedPreferences\n\n  @UnlockPins @Inject lateinit var unlockPins: SharedPreferences\n\n",
    ),
]
for old, new in replacements:
    if old not in text:
        raise SystemExit(f"Unable to locate #1011 BasePGPActivity fragment: {old!r}")
    text = text.replace(old, new, 1)

old_setup = '''                if (persistentPassphrases.getString("unlock_pin", null) == null) {
                  val pinDialog =
                    PinDialog.newInstance(
                      title = resources.getString(R.string.pin_new_entry_title),
                      description = resources.getString(R.string.pin_new_entry_description),
                      clearOnDismiss = passphrase,
                    )
                  pinDialog.show(supportFragmentManager, "PIN_DIALOG")
                  pinDialog.setFragmentResultListener(PinDialog.PIN_RESULT_KEY) { key, bundle ->
                    if (key == PinDialog.PIN_RESULT_KEY) {
                      val pin =
                        requireNotNull(bundle.getCharArray(PinDialog.PIN_KEY)) {
                          "returned PIN is null"
                        }
                      if (pin.size >= 4) {
                        persistentPassphrases.edit {
                          putString(
                            "unlock_pin", // reset and prepend PIN attempt counter
                            AESEncryption.encrypt(
                                charArrayOf('0', ':') + pin,
                                keyType = KeyType.PERSISTENT,
                              )
                              ?.concatToString(),
                          )
                          putString(
                            id,
                            AESEncryption.encrypt(passphrase, keyType = KeyType.PERSISTENT)
                              ?.concatToString(),
                          )
                          putLong(
                            PreferenceKeys.BIOMETRICS_AND_PIN_LAST_USE,
                            Instant.now().toEpochMilli(),
                          )
                        }
                      }
                      pin.wipe()
                    }
                  }
'''
new_setup = '''                if (unlockPins.getString(id, null) == null) {
                  val pinDialog =
                    PinDialog.newInstance(
                      title = resources.getString(R.string.pin_new_entry_title),
                      description = resources.getString(R.string.pin_new_entry_description),
                      clearOnDismiss = passphrase,
                    )
                  pinDialog.show(supportFragmentManager, "PIN_DIALOG")
                  pinDialog.setFragmentResultListener(PinDialog.PIN_RESULT_KEY) { key, bundle ->
                    if (key == PinDialog.PIN_RESULT_KEY) {
                      val pin = bundle.getCharArray(PinDialog.PIN_KEY)
                      if (pin != null && pin.size >= 4) {
                        unlockPins.edit {
                          putString(
                            id, // reset and prepend PIN attempt counter
                            AESEncryption.encrypt(
                                charArrayOf('0', ':') + pin,
                                keyType = KeyType.PERSISTENT,
                              )
                              ?.concatToString(),
                          )
                        }
                        persistentPassphrases.edit {
                          putString(
                            id,
                            AESEncryption.encrypt(passphrase, keyType = KeyType.PERSISTENT)
                              ?.concatToString(),
                          )
                          putLong(
                            PreferenceKeys.BIOMETRICS_AND_PIN_LAST_USE,
                            Instant.now().toEpochMilli(),
                          )
                        }
                      }
                      pin?.wipe()
                    }
                  }
'''
if old_setup not in text:
    raise SystemExit("Unable to locate global PIN setup block for #1011")
text = text.replace(old_setup, new_setup, 1)

old_timeout = '''    )
      persistentPassphrases.edit { clear() }

    val persistentIds =
      identifiers.map { it.toString() }.filter { persistentPassphrases.contains(it) }
    val pinEncrypted = persistentPassphrases.getString("unlock_pin", null)?.toCharArray()
'''
new_timeout = '''    ) {
      persistentPassphrases.edit { clear() }
      unlockPins.edit { clear() }
    }

    val persistentIds =
      identifiers.map { it.toString() }.filter { persistentPassphrases.contains(it) }
    val encryptedPins =
      unlockPins
        .getAll()
        .filterKeys { persistentIds.contains(it) }
        .mapValues { (it.value as String).toCharArray() }
'''
if old_timeout not in text:
    raise SystemExit("Unable to locate timeout/global PIN cache block for #1011")
text = text.replace(old_timeout, new_timeout, 1)

old_pin_branch = '''    } else if (
      !persistentIds.none() &&
        identifiers.map { it.toString() }.filter { cachedPassphrases.containsKey(it) }.none() &&
        AESEncryption.isHardwareBacked(KeyType.PERSISTENT) &&
        settings.getString(PreferenceKeys.PREF_FAST_UNLOCK_OPTION, "disabled") == "PIN" &&
        pinEncrypted != null
    ) {
      verifyPin(pinEncrypted, persistentIds, identifiers, action)
'''
new_pin_branch = '''    } else if (
      !encryptedPins.none() &&
        identifiers.map { it.toString() }.filter { cachedPassphrases.containsKey(it) }.none() &&
        AESEncryption.isHardwareBacked(KeyType.PERSISTENT) &&
        settings.getString(PreferenceKeys.PREF_FAST_UNLOCK_OPTION, "disabled") == "PIN"
    ) {
      verifyPin(encryptedPins, identifiers, action)
'''
if old_pin_branch not in text:
    raise SystemExit("Unable to locate global PIN branch for #1011")
text = text.replace(old_pin_branch, new_pin_branch, 1)

start_marker = "  /* Asks for and verifies the user PIN for unlocking a store entry. */\n  private fun verifyPin("
end_marker = "\n  protected fun decrypt(identifiers: List<PGPIdentifier>, isError: Boolean = false) {"
start = text.find(start_marker)
end = text.find(end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("Unable to locate verifyPin function boundaries for #1011")

new_verify = '''  /* Asks for and verifies the user PIN for unlocking a store entry. */
  private fun verifyPin(
    encryptedPins: Map<String, CharArray>,
    identifiers: List<PGPIdentifier>,
    action: String?,
    isError: Boolean = false,
  ) {
    val pinDialog =
      PinDialog.newInstance(
        title = resources.getString(R.string.pin_entry_title),
        description =
          when (action) {
            "autofill" -> resources.getString(R.string.pin_entry_autofill_description)
            "passkey" -> resources.getString(R.string.pin_entry_passkey_description)
            else -> resources.getString(R.string.pin_entry_description)
          },
      )
    if (isError) pinDialog.setError()
    pinDialog.show(supportFragmentManager, "PIN_DIALOG")
    pinDialog.setFragmentResultListener(PinDialog.PIN_RESULT_KEY) { key, bundle ->
      if (key == PinDialog.PIN_RESULT_KEY) {
        if (bundle.getBoolean(PinDialog.PIN_CANCEL)) {
          decrypt(identifiers)
        } else {
          val pin = requireNotNull(bundle.getCharArray(PinDialog.PIN_KEY)) { "returned PIN is null" }
          var pinRetries = 0
          var pinOk = false

          for ((id, encryptedPin) in encryptedPins) {
            val cachedPin =
              AESEncryption.decrypt(encryptedPin, keyType = KeyType.PERSISTENT)?.let { cached ->
                cached.copyOfRange(cached.indexOf(':') + 1, cached.size).also {
                  pinRetries =
                    max(
                      pinRetries,
                      cached
                        .copyOfRange(0, cached.indexOf(':'))
                        .concatToString()
                        .toIntOrNull() ?: MAX_RETRIES,
                    )
                  cached.wipe()
                }
              }
            pinOk = cachedPin?.let { it.contentEquals(pin) } ?: false
            cachedPin?.wipe()
            if (pinOk) {
              updatePinAttemptCounter(encryptedPins, 0)
              persistentPassphrases
                .getString(id, null)
                ?.toCharArray()
                ?.let { passEncrypted ->
                  AESEncryption.decrypt(passEncrypted, keyType = KeyType.PERSISTENT)
                }
                ?.let { pass ->
                  AESEncryption.encrypt(pass)?.let { cachedPassphrases.put(id, it) }
                  pass.wipe()
                }
              break
            }
          }

          pin.wipe()

          if (pinOk) {
            decrypt(identifiers)
          } else if (++pinRetries < MAX_RETRIES) {
            val encryptedPinsUpdated = updatePinAttemptCounter(encryptedPins, pinRetries)
            verifyPin(encryptedPinsUpdated, identifiers, action, isError = true)
          } else {
            // Reset only the relevant identities after the retry budget is exhausted.
            encryptedPins.keys.forEach { id ->
              cachedPassphrases.remove(id)
              persistentPassphrases.edit { remove(id) }
              unlockPins.edit { remove(id) }
            }
            decrypt(identifiers)
          }
        }
      }
    }
  }

  /** Updates and persists the shared retry counter for the relevant per-PGP-ID PINs. */
  private fun updatePinAttemptCounter(
    encryptedPins: Map<String, CharArray>,
    attempts: Int,
  ): Map<String, CharArray> {
    val updatedEncryptedPins = mutableMapOf<String, CharArray>()
    unlockPins.edit {
      encryptedPins.forEach { (id, encryptedPin) ->
        AESEncryption.decrypt(encryptedPin, keyType = KeyType.PERSISTENT)
          ?.let { cached ->
            cached.copyOfRange(cached.indexOf(':') + 1, cached.size).also { cached.wipe() }
          }
          ?.let { pin ->
            AESEncryption.encrypt(
                (attempts.toString() + ":").toCharArray() + pin,
                keyType = KeyType.PERSISTENT,
              )
              ?.let { updated ->
                putString(id, updated.concatToString())
                updatedEncryptedPins[id] = updated
              }
            pin.wipe()
          }
          ?: remove(id)
      }
    }
    if (attempts == 0) {
      persistentPassphrases.edit {
        putLong(PreferenceKeys.BIOMETRICS_AND_PIN_LAST_USE, Instant.now().toEpochMilli())
      }
    }
    return updatedEncryptedPins
  }
'''
text = text[:start] + new_verify + text[end:]
path.write_text(text)
PY
git add app/src/main/java/app/passwordstore/ui/crypto/BasePGPActivity.kt
git commit -m "fix(crypto): isolate fast-unlock PINs per PGP identity" -m "Semantic port of upstream #1011. Preserve fork-owned auth/passkey behavior while ensuring a PIN can unlock only the PGP identity it belongs to."

# PinDialog also diverged in the fork. Keep clear-on-dismiss wiping while adopting explicit
# cancel results needed by the per-identity PIN flow.
cat > app/src/main/java/app/passwordstore/ui/crypto/PinDialog.kt <<'EOF'
/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.crypto

import android.content.DialogInterface
import android.os.Bundle
import android.view.KeyEvent
import android.view.WindowManager
import androidx.appcompat.app.AlertDialog
import androidx.core.widget.doOnTextChanged
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.setFragmentResult
import app.passwordstore.R
import app.passwordstore.databinding.DialogPinEntryBinding
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.extensions.wipe
import com.google.android.material.dialog.MaterialAlertDialogBuilder

/** [DialogFragment] to request a PIN from the user and forward it along. */
class PinDialog : DialogFragment() {

  private val binding by unsafeLazy { DialogPinEntryBinding.inflate(layoutInflater) }
  private var isError: Boolean = false

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    isCancelable = false
  }

  override fun onCreateDialog(savedInstanceState: Bundle?): AlertDialog {
    val builder = MaterialAlertDialogBuilder(requireContext())
    builder.setView(binding.root)

    val titleText = requireArguments().getString(TITLE_TEXT_EXTRA)
    builder.setTitle(titleText)

    val descriptionText = requireArguments().getString(DESCRIPTION_TEXT_EXTRA)
    binding.descriptionText.setText(descriptionText)

    builder.setPositiveButton(android.R.string.ok) { _, _ -> setPinAndDismiss() }
    builder.setNegativeButton(android.R.string.cancel) { dialog, _ -> dialog.cancel() }

    val dialog = builder.create()
    dialog.setCanceledOnTouchOutside(false)
    dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE)
    dialog.setOnShowListener {
      var pinLength = 0
      if (isError) {
        binding.pinField.error = getString(R.string.pin_entry_wrong_input)
      }
      dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = false
      binding.pinEditText.apply {
        doOnTextChanged { s, _, _, _ ->
          s?.let {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = it.length >= 4
            pinLength = it.length
          }
          binding.pinField.error = null
        }
        setOnKeyListener { _, keyCode, _ ->
          if (keyCode == KeyEvent.KEYCODE_ENTER && pinLength >= 4) {
            setPinAndDismiss()
            return@setOnKeyListener true
          }
          keyCode == KeyEvent.KEYCODE_BACK
        }
      }
    }
    dialog.window?.setFlags(
      WindowManager.LayoutParams.FLAG_SECURE,
      WindowManager.LayoutParams.FLAG_SECURE,
    )
    return dialog
  }

  fun setError() {
    isError = true
  }

  override fun onDismiss(dialog: DialogInterface) {
    requireArguments().getCharArray(CLEAR_ON_DISMISS_TEXT_EXTRA)?.wipe()
    binding.pinEditText.text?.clear()
    super.onDismiss(dialog)
  }

  override fun onCancel(dialog: DialogInterface) {
    super.onCancel(dialog)
    setFragmentResult(PIN_RESULT_KEY, Bundle().also { it.putBoolean(PIN_CANCEL, true) })
  }

  private fun setPinAndDismiss() {
    val pin = binding.pinEditText.text?.let { CharArray(it.length) { i -> it[i] } }
    setFragmentResult(
      PIN_RESULT_KEY,
      Bundle().also {
        it.putCharArray(PIN_KEY, pin)
        it.putBoolean(PIN_CANCEL, false)
      },
    )
    dismissAllowingStateLoss()
  }

  companion object {

    private const val TITLE_TEXT_EXTRA = "title_text"
    private const val DESCRIPTION_TEXT_EXTRA = "description_text"
    private const val CLEAR_ON_DISMISS_TEXT_EXTRA = "clear_chars_text"

    const val PIN_RESULT_KEY = "pin_result"
    const val PIN_KEY = "pin"
    const val PIN_CANCEL = "cancel"

    fun newInstance(
      title: String,
      description: String,
      clearOnDismiss: CharArray? = null,
    ): PinDialog {
      val extras =
        Bundle().also {
          it.apply {
            putString(TITLE_TEXT_EXTRA, title)
            putString(DESCRIPTION_TEXT_EXTRA, description)
            putCharArray(CLEAR_ON_DISMISS_TEXT_EXTRA, clearOnDismiss)
          }
        }
      val fragment = PinDialog()
      fragment.arguments = extras
      return fragment
    }
  }
}
EOF
git add app/src/main/java/app/passwordstore/ui/crypto/PinDialog.kt
git commit -m "fix(crypto): adapt upstream #1011 PIN cancellation" -m "Keep fork secret-wiping behavior while returning an explicit cancellation result to the per-PGP-ID fast-unlock flow."

apply_pr_paths 1011 app/src/main/java/app/passwordstore/ui/settings/PasswordSettings.kt
apply_pr_paths 1011 app/src/main/java/app/passwordstore/util/extensions/AndroidExtensions.kt
apply_pr_paths 1011 app/src/main/java/app/passwordstore/util/settings/Migrations.kt
apply_pr_paths 1011 app/src/test/java/app/passwordstore/util/settings/MigrationsTest.kt

apply_pr_paths 1014 \
  app/src/main/java/app/passwordstore/ui/crypto/DecryptActivity.kt \
  app/src/main/java/app/passwordstore/ui/settings/PasswordSettings.kt \
  app/src/main/java/app/passwordstore/util/settings/PreferenceKeys.kt \
  app/src/main/res/values/strings.xml \
  app/src/main/res/values-de/strings.xml
apply_pr_paths 1016 app/src/main/java/app/passwordstore/util/autofill/Api30AutofillResponseBuilder.kt
apply_pr_paths 1022 app/src/main/AndroidManifest.xml
apply_pr_paths 1026 autofill-parser/src/main/java/com/github/androidpasswordstore/autofillparser/FeatureAndTrustDetection.kt
apply_pr_paths 1043 app/src/main/java/app/passwordstore/ui/pgp/PGPKeyListActivity.kt

# Generated data is adopted as one current snapshot rather than replaying update commits.
git checkout "upstream/$UPSTREAM_BRANCH" -- autofill-parser/src/main/assets/publicsuffixes
if ! git diff --cached --quiet; then
  git commit -m "chore(autofill): refresh Public Suffix List from upstream"
fi

# Keep the recurring tools executable in normal clones.
chmod +x scripts/upstream-audit.sh scripts/adopt-upstream-pr.sh scripts/mark-upstream-reviewed.sh

# One-time bootstrap machinery must not remain in the resulting PR.
rm -f scripts/bootstrap-upstream-sync.sh .github/workflows/bootstrap-upstream-sync.yml

git add -A
if ! git diff --cached --quiet; then
  git commit -m "chore(upstream): finalize recurring reconciliation tooling"
fi

# Normalize Kotlin/XML formatting after the selective ports.
./gradlew spotlessApply
git add -A
if ! git diff --cached --quiet; then
  git commit -m "style: format selective upstream ports"
fi

git push origin "HEAD:${GITHUB_REF_NAME}"
