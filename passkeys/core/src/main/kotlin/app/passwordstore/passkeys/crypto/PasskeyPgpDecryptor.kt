/*
 * Copyright (C) 2014-2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

import com.github.michaelbull.result.Result
import java.io.File

public interface PasskeyPgpDecryptor {

  public suspend fun decrypt(
    file: File,
    unlockContext: PgpUnlockContext,
  ): Result<ByteArray, PasskeyDecryptionError>
}

public interface PgpUnlockContext {
  public suspend fun unlockKey(keyId: String): CharArray?
}
