/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.autofill

import android.content.Context
import androidx.core.content.edit
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.services.getDefaultUsername
import app.passwordstore.util.settings.DirectoryStructure
import app.passwordstore.util.settings.PreferenceKeys
import com.github.androidpasswordstore.autofillparser.Credentials
import java.io.File

object AutofillPreferences {

  fun directoryStructure(context: Context): DirectoryStructure {
    val value = context.sharedPrefs.getString(PreferenceKeys.DIRECTORY_STRUCTURE)
    return DirectoryStructure.fromValue(value)
  }

  /**
   * The configured relative directory Autofill-saved credentials should be placed under. Backed by
   * [PreferenceKeys.AUTOFILL_SAVE_DIRECTORY]. Returns null when unset, or when the configured value
   * is not a valid relative path (absolute, or containing "." or ".." components) — callers should
   * treat a null result as the repository root itself and resolve a non-null result against it.
   * This only affects saves made through the Autofill framework (the system "Save to Password
   * Store?" prompt) — it has no effect on entries created from within the app.
   */
  fun saveDirectory(context: Context): String? {
    return sanitizeSaveDirectory(
      context.sharedPrefs.getString(PreferenceKeys.AUTOFILL_SAVE_DIRECTORY)
    )
  }

  /**
   * Validates [value] as a relative path with no "." or ".." components, returning it unchanged if
   * valid. Invalid or blank input is rejected outright (returns null) rather than being mutated
   * into some other path, so a rejected value always falls back to the repository root instead of
   * silently landing somewhere the user didn't ask for.
   */
  internal fun sanitizeSaveDirectory(value: String?): String? {
    if (value.isNullOrBlank()) return null
    if (value.startsWith('/')) return null
    val segments = value.split('/')
    if (segments.any { it.isEmpty() || it == "." || it == ".." }) return null
    return segments.joinToString("/")
  }

  fun strictDomainSearch(context: Context): Boolean {
    return context.sharedPrefs.getBoolean(PreferenceKeys.STRICT_DOMAIN_SEARCH, true)
  }

  fun setStrictDomainSearch(context: Context, strict: Boolean) {
    context.sharedPrefs.edit { putBoolean(PreferenceKeys.STRICT_DOMAIN_SEARCH, strict) }
  }

  fun credentialsFromStoreEntry(
    context: Context,
    file: File,
    entry: PasswordEntry,
    directoryStructure: DirectoryStructure,
  ): Credentials {
    // Always give priority to a username stored in the encrypted extras
    val username =
      entry.username
        ?: directoryStructure.getUsernameFor(file)?.toCharArray()
        ?: context.getDefaultUsername()?.toCharArray()
    val totp = if (entry.hasTotp()) entry.currentOtp.value else null
    return Credentials(username, entry.password, totp)
  }
}
