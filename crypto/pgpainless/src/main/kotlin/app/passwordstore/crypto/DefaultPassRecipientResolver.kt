/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.passkeys.storage.PassRecipientResolver
import app.passwordstore.passkeys.storage.RecipientPolicyError
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Default [PassRecipientResolver] that walks the hierarchical `.gpg-id` policy from the target
 * directory upward to the repository root, parsing recipient identifiers with the same rules as
 * ordinary APS password entries, and resolving them to usable encryption certificates via
 * [PGPKeyManager].
 *
 * The resolver fails closed on any policy violation and never falls back to a global key list.
 */
public class DefaultPassRecipientResolver(
  private val repositoryRoot: File,
  private val keyManager: PGPKeyManager,
  private val gpgIdFileName: String = GPG_ID_FILE_NAME,
) : PassRecipientResolver<PGPKey> {

  override suspend fun resolveFor(target: File): Result<List<PGPKey>, RecipientPolicyError> =
    withContext(Dispatchers.IO) {
      val canonicalRoot = repositoryRoot.canonicalFile
      val canonicalTarget =
        try {
          target.canonicalFile
        } catch (e: Exception) {
          return@withContext com.github.michaelbull.result.Err(
            RecipientPolicyError.TargetOutsideRepository
          )
        }

      if (
        !canonicalTarget.path.startsWith(canonicalRoot.path + File.separator) &&
          canonicalTarget.path != canonicalRoot.path
      ) {
        return@withContext com.github.michaelbull.result.Err(
          RecipientPolicyError.TargetOutsideRepository
        )
      }

      val targetDir =
        if (canonicalTarget.isFile) canonicalTarget.parentFile ?: canonicalRoot else canonicalTarget

      if (hasSymlinkInPath(target, canonicalRoot)) {
        return@withContext com.github.michaelbull.result.Err(RecipientPolicyError.SymlinkRejected)
      }

      val gpgIdFile =
        findGpgIdFile(targetDir, canonicalRoot)
          ?: return@withContext com.github.michaelbull.result.Err(
            RecipientPolicyError.GpgIdNotFound
          )

      if (java.nio.file.Files.isSymbolicLink(gpgIdFile.toPath())) {
        val linkTarget =
          try {
            java.nio.file.Files.readSymbolicLink(gpgIdFile.toPath()).toFile().canonicalFile
          } catch (e: Exception) {
            return@withContext com.github.michaelbull.result.Err(
              RecipientPolicyError.SymlinkRejected
            )
          }
        if (
          !linkTarget.path.startsWith(canonicalRoot.path + File.separator) &&
            linkTarget.path != canonicalRoot.path
        ) {
          return@withContext com.github.michaelbull.result.Err(RecipientPolicyError.SymlinkRejected)
        }
      }

      val parsedIdentifiers =
        parseGpgIdFile(gpgIdFile)
          .fold(
            success = { it },
            failure = { error ->
              return@withContext com.github.michaelbull.result.Err(error)
            },
          )

      if (parsedIdentifiers.isEmpty()) {
        return@withContext com.github.michaelbull.result.Err(RecipientPolicyError.EmptyRecipientSet)
      }

      val resolvedKeys = mutableListOf<PGPKey>()
      val seenFingerprints = mutableSetOf<Long>()

      for (identifier in parsedIdentifiers) {
        val key =
          keyManager
            .getKeyById(identifier)
            .fold(
              success = { it },
              failure = {
                return@withContext com.github.michaelbull.result.Err(
                  RecipientPolicyError.RecipientNotFound(identifier.toString())
                )
              },
            )

        val cert = KeyUtils.tryParseCertificateOrKey(key)
        if (cert == null || !KeyUtils.isKeyUsable(cert)) {
          return@withContext com.github.michaelbull.result.Err(
            RecipientPolicyError.RecipientUnusable(identifier.toString())
          )
        }

        val primaryKeyId = KeyUtils.tryGetKeyId(cert).id
        if (!seenFingerprints.add(primaryKeyId)) {
          continue
        }
        resolvedKeys.add(key)
      }

      if (resolvedKeys.isEmpty()) {
        return@withContext com.github.michaelbull.result.Err(RecipientPolicyError.EmptyRecipientSet)
      }

      com.github.michaelbull.result.Ok(resolvedKeys)
    }

  private fun findGpgIdFile(startDir: File, root: File): File? {
    var current: File? = startDir
    while (current != null) {
      val candidate = File(current, gpgIdFileName)
      if (candidate.exists() && candidate.isFile) {
        return candidate
      }
      if (current.canonicalPath == root.canonicalPath) break
      current = current.parentFile ?: break
    }
    return null
  }

  private fun parseGpgIdFile(gpgIdFile: File): Result<List<PGPIdentifier>, RecipientPolicyError> {
    val lines =
      try {
        gpgIdFile.readLines()
      } catch (e: Exception) {
        return com.github.michaelbull.result.Err(
          RecipientPolicyError.MalformedGpgId(0, "Cannot read file: ${e.message}")
        )
      }

    val identifiers = mutableListOf<PGPIdentifier>()

    for ((index, rawLine) in lines.withIndex()) {
      val commentMatch = COMMENT_PATTERN.find(rawLine)
      val line =
        if (commentMatch != null) rawLine.substring(0, commentMatch.range.first) else rawLine
      val trimmed = line.trim()
      if (trimmed.isBlank() || trimmed == "gpg-id") continue

      if (SHORT_KEY_ID_PATTERN.matches(trimmed.removePrefix("0x"))) {
        return com.github.michaelbull.result.Err(RecipientPolicyError.AmbiguousRecipient(trimmed))
      }

      val identifier = PGPIdentifier.fromString(trimmed)
      if (identifier == null) {
        return com.github.michaelbull.result.Err(
          RecipientPolicyError.MalformedGpgId(index + 1, "Unrecognized identifier format")
        )
      }
      identifiers.add(identifier)
    }

    return com.github.michaelbull.result.Ok(identifiers)
  }

  private fun hasSymlinkInPath(target: File, root: File): Boolean {
    val canonicalRoot = root.canonicalFile
    var current = target
    while (true) {
      if (java.nio.file.Files.isSymbolicLink(current.toPath())) {
        return true
      }
      if (current.canonicalPath == canonicalRoot.path) break
      val parent = current.parentFile ?: break
      if (parent.canonicalPath == canonicalRoot.path) break
      current = parent
    }
    return false
  }

  public companion object {
    public const val GPG_ID_FILE_NAME: String = ".gpg-id"
    private val COMMENT_PATTERN = Regex("\\s*#|!")
    private val SHORT_KEY_ID_PATTERN = Regex("[a-fA-F0-9]{8}")
  }
}
