/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import com.github.michaelbull.result.Result

public interface PasskeyStorage {

  public suspend fun listMetadata(
    rpId: String? = null,
  ): Result<List<PasskeyMetadata>, Throwable>

  public suspend fun loadForSigning(
    credentialId: ByteArray,
  ): Result<SensitivePasskeyCredential, Throwable>

  public suspend fun saveCredential(credential: PasskeyCredential): Result<Unit, Throwable>

  public suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable>

  public suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable>
}

public data class PasskeyStorageConfig(
  public val passkeyDirectory: String = "fido2",
  public val fileExtension: String = ".gpg",
)
