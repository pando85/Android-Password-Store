/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public sealed class SignatureCounterError {
  public data object CounterOverflow : SignatureCounterError()

  public data object PersistenceFailed : SignatureCounterError()

  public data class RollbackDetected(
    public val diskCounter: ULong,
    public val highWaterMark: ULong,
  ) : SignatureCounterError()

  public data object MergeConflict : SignatureCounterError()

  public data object FileChangedSinceSelection : SignatureCounterError()

  public data object LockAcquisitionFailed : SignatureCounterError()

  public data class MonotonicNotAllowed(val reason: String) : SignatureCounterError()
}
