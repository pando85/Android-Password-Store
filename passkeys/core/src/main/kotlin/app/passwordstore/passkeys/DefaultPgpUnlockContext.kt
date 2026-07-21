/*
 * Copyright (C) 2014-2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import app.passwordstore.passkeys.crypto.PgpUnlockContext

public class DefaultPgpUnlockContext : PgpUnlockContext {
  override suspend fun unlockKey(keyId: String): CharArray? {
    return null
  }
}
