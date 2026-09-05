/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passsecrets

import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.data.crypto.CryptoRepository
import app.passwordstore.passsecrets.PassSecretsMapStore.MaskAssociation
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.extensions.wipe
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.unwrapError
import dagger.Reusable
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import javax.inject.Inject
import kotlinx.coroutines.withContext

/** Encrypts and commits Pass-Secrets metadata updates without ever persisting plaintext. */
@Reusable
class PassSecretsMapWriter
@Inject
constructor(
  private val repository: CryptoRepository,
  private val dispatcherProvider: DispatcherProvider,
) {

  sealed interface Update {
    val file: File

    data class Secrets(override val file: File, val values: Map<String, String>) : Update

    data class Mask(override val file: File, val associations: List<MaskAssociation>) : Update
  }

  private data class StagedUpdate(
    val update: Update,
    val temporaryFile: File,
    val originalCiphertext: ByteArray?,
  )

  suspend fun persist(updates: List<Update>) {
    if (updates.isEmpty()) return
    withContext(dispatcherProvider.io()) {
      require(updates.map { it.file.canonicalPath }.distinct().size == updates.size) {
        "Pass-Secrets metadata update contains duplicate target files"
      }

      val staged = mutableListOf<StagedUpdate>()
      try {
        updates.forEach { update -> staged += stage(update) }
        val committed = mutableListOf<StagedUpdate>()
        try {
          staged.forEach { stagedUpdate ->
            replace(stagedUpdate.temporaryFile, stagedUpdate.update.file)
            committed += stagedUpdate
          }
        } catch (error: Throwable) {
          committed.asReversed().forEach(::restoreBestEffort)
          throw error
        }

        updates.forEach { update ->
          when (update) {
            is Update.Secrets -> PassSecretsMapStore.putMap(update.file, update.values)
            is Update.Mask -> PassSecretsMapStore.putMask(update.file, update.associations)
          }
        }
      } finally {
        staged.forEach { stagedUpdate ->
          stagedUpdate.temporaryFile.delete()
          stagedUpdate.originalCiphertext?.wipe()
        }
      }
    }
  }

  private fun stage(update: Update): StagedUpdate {
    val target = update.file
    val identity = requireNotNull(target.parentFile) { "Metadata file has no parent: $target" }
    val plaintext =
      when (update) {
        is Update.Secrets -> PassSecretsMapStore.serializeMap(update.values)
        is Update.Mask -> PassSecretsMapStore.serializeMask(update.associations)
      }
    val plaintextBytes = plaintext.encodeToByteArray()
    val encryptedBytes =
      try {
        encrypt(identity, plaintextBytes)
      } finally {
        plaintextBytes.wipe()
      }

    val temporaryFile = File.createTempFile(".aps-pass-secrets-", ".tmp", identity)
    try {
      temporaryFile.writeBytes(encryptedBytes)
    } finally {
      encryptedBytes.wipe()
    }
    return StagedUpdate(
      update = update,
      temporaryFile = temporaryFile,
      originalCiphertext = target.takeIf { it.isFile }?.readBytes(),
    )
  }

  private fun encrypt(identity: File, plaintext: ByteArray): ByteArray {
    val identifiers = identifiersForIdentity(identity)
    val output = ByteArrayOutputStream()
    val (_, result) = repository.encrypt(identifiers, plaintext.inputStream(), output)
    if (result.isErr) throw result.unwrapError()
    val encryptedOutput = result.getOrThrow()
    return encryptedOutput.toByteArray().also { encryptedOutput.wipe() }
  }

  /** Pass-Secrets intentionally uses the exact identity `.gpg-id`; it never inherits a parent. */
  private fun identifiersForIdentity(identity: File): List<PGPIdentifier> {
    val gpgId = File(identity, ".gpg-id")
    require(gpgId.isFile) { "Pass-Secrets identity has no .gpg-id: $identity" }

    val identifiers = mutableListOf<PGPIdentifier>()
    gpgId.readLines().forEach { rawLine ->
      val line = rawLine.substringBefore(Regex("\\s*#|!")).trim()
      if (line.isBlank() || line == "gpg-id") return@forEach
      require(!line.removePrefix("0x").matches("[a-fA-F0-9]{8}".toRegex())) {
        "Short OpenPGP key IDs are not accepted in $gpgId"
      }
      val identifier =
        requireNotNull(PGPIdentifier.fromString(line)) { "Invalid OpenPGP identifier '$line' in $gpgId" }
      require(repository.hasKey(identifier)) { "OpenPGP key '$identifier' is not imported" }
      identifiers += identifier
    }
    require(identifiers.isNotEmpty()) { "Pass-Secrets identity has no usable recipients: $identity" }
    return identifiers
  }

  private fun replace(source: File, target: File) {
    try {
      Files.move(
        source.toPath(),
        target.toPath(),
        StandardCopyOption.ATOMIC_MOVE,
        StandardCopyOption.REPLACE_EXISTING,
      )
    } catch (_: AtomicMoveNotSupportedException) {
      Files.move(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
    }
  }

  private fun restoreBestEffort(stagedUpdate: StagedUpdate) {
    runCatching {
      val target = stagedUpdate.update.file
      val previous = stagedUpdate.originalCiphertext
      if (previous == null) {
        target.delete()
      } else {
        val restore = File.createTempFile(".aps-pass-secrets-restore-", ".tmp", target.parentFile)
        try {
          restore.writeBytes(previous)
          replace(restore, target)
        } finally {
          restore.delete()
        }
      }
    }
  }
}
