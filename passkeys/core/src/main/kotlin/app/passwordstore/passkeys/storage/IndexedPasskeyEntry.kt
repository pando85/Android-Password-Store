/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.PasskeyMetadata

public data class IndexedPasskeyEntry(
  val metadata: PasskeyMetadata,
  val fileRef: PasskeyFileRef,
  val sourceVersion: CredentialSourceVersion,
  val repositoryGeneration: RepositoryGeneration,
)
