/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.crypto

import java.io.File

/** Resolve the directory scope used for hierarchical `.gpg-id` lookup and creation. */
internal fun resolveGpgIdScope(repoRoot: File, operationPath: File, subDir: String): String {
  // Existing callers have historically passed explicit scopes such as "/", "/foo", and
  // "/foo/". Preserve those values exactly, but recover when an explicit scope is actually a
  // physical path inside the repository. This can happen when Android exposes the same private
  // storage through aliases such as /data/user/0 and /data/data.
  if (subDir.isNotEmpty()) {
    physicalScopeRelativeToRoot(repoRoot, subDir)?.let { return it }
    return subDir
  }

  val root = repoRoot.canonicalFile
  val operationDirectory =
    if (operationPath.isDirectory) operationPath.canonicalFile
    else operationPath.parentFile?.canonicalFile ?: root

  require(operationDirectory.toPath().startsWith(root.toPath())) {
    "GPG recipient scope must stay inside the password repository"
  }

  val relativePath = operationDirectory.relativeTo(root).invariantSeparatorsPath
  return relativePath.toGpgIdScope()
}

private fun physicalScopeRelativeToRoot(repoRoot: File, subDir: String): String? {
  val explicitScope = File(subDir)
  if (!explicitScope.isAbsolute) return null

  return runCatching {
      val root = repoRoot.canonicalFile
      val physicalScope = explicitScope.canonicalFile
      if (!physicalScope.toPath().startsWith(root.toPath())) return@runCatching null

      physicalScope.relativeTo(root).invariantSeparatorsPath.toGpgIdScope()
    }
    .getOrNull()
}

private fun String.toGpgIdScope(): String = if (isEmpty() || this == ".") "/" else this
