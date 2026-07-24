/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public sealed interface SourceValidationError {
  public data object CredentialDeleted : SourceValidationError
  public data object RepositoryChanged : SourceValidationError
  public data object VersionUnavailable : SourceValidationError
  public data object VersionMismatch : SourceValidationError
  public data object FileIdentityChanged : SourceValidationError
  public data object MergeOrRebaseInProgress : SourceValidationError
  public data object DuplicateCredentialId : SourceValidationError
  public data object PayloadPathMismatch : SourceValidationError
  public data object OperationCancelled : SourceValidationError
}
