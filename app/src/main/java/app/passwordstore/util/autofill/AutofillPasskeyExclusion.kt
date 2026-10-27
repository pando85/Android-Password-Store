/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.autofill

import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.passkeys.storage.PasskeyStorageConfig
import java.io.File
import java.io.IOException

/**
 * Classic (username/password) Autofill must never offer or fill passkey credentials.
 *
 * Passkey credentials are stored as encrypted CBOR below a dedicated repository-relative directory
 * (see [PasskeyStorageConfig.passkeyDirectory]). Decrypting such a file as a password entry would
 * expose private key material as "password" content, so these files are excluded from Autofill
 * suggestions and search results, and refused before decryption.
 */
object AutofillPasskeyExclusion {

  private val passkeyDirectory: String = PasskeyStorageConfig().passkeyDirectory

  /**
   * Returns true if [file] lies inside the passkey credential directory of [repositoryRoot]. With
   * [resolveLinks], symbolic links are resolved as well (requires file system access).
   */
  fun isPasskeyCredentialFile(
    file: File,
    repositoryRoot: File = PasswordRepository.getRepositoryDirectory(),
    resolveLinks: Boolean = true,
  ): Boolean {
    val passkeyRoot = File(repositoryRoot, passkeyDirectory)
    if (file.absoluteFile.normalize().startsWith(passkeyRoot.absoluteFile.normalize())) return true
    if (!resolveLinks) return false
    return try {
      file.canonicalFile.startsWith(passkeyRoot.canonicalFile)
    } catch (_: IOException) {
      false
    }
  }
}
