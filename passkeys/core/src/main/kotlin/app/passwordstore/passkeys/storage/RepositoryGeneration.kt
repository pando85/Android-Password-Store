/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public data class RepositoryGeneration(
  val repositoryIdentity: String,
  val gitHead: String?,
  val worktreeGeneration: Long,
)

public data class CredentialSourceVersion(
  val repositoryGeneration: RepositoryGeneration,
  val canonicalPath: String,
  val fileSize: Long,
  val modifiedAtMillis: Long,
  val ciphertextDigest: ByteArray,
) {

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is CredentialSourceVersion) return false
    if (repositoryGeneration != other.repositoryGeneration) return false
    if (canonicalPath != other.canonicalPath) return false
    if (fileSize != other.fileSize) return false
    if (modifiedAtMillis != other.modifiedAtMillis) return false
    if (!ciphertextDigest.contentEquals(other.ciphertextDigest)) return false
    return true
  }

  override fun hashCode(): Int {
    var result = repositoryGeneration.hashCode()
    result = 31 * result + canonicalPath.hashCode()
    result = 31 * result + fileSize.hashCode()
    result = 31 * result + modifiedAtMillis.hashCode()
    result = 31 * result + ciphertextDigest.contentHashCode()
    return result
  }
}
