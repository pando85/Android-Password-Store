/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.crypto

import java.io.File

/** Resolve the directory scope used for hierarchical `.gpg-id` lookup and creation. */
internal fun resolveGpgIdScope(repoRoot: File, operationPath: File, subDir: String): String {
  // Existing callers have historically passed explicit scopes such as "/", "/foo", and
  // "/foo/". Preserve every explicit value exactly as supplied and recover only the invalid
  // empty state that can otherwise collapse to the physical repository root.
  if (subDir.isNotEmpty()) return subDir

  val root = repoRoot.canonicalFile
  val operationDirectory =
    if (operationPath.isDirectory) operationPath.canonicalFile
    else operationPath.parentFile?.canonicalFile ?: root

  require(operationDirectory.toPath().startsWith(root.toPath())) {
    "GPG recipient scope must stay inside the password repository"
  }

  val relativePath = operationDirectory.relativeTo(root).invariantSeparatorsPath
  return if (relativePath.isBlank() || relativePath == ".") "/" else relativePath
}
