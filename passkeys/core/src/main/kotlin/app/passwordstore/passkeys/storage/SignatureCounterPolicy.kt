/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public enum class SignatureCounterPolicy {
  ZERO_FOR_SYNCABLE,
  MONOTONIC_LOCAL,
}
