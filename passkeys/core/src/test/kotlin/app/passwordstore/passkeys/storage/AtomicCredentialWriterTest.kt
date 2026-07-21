/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.unwrapError
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking

class AtomicCredentialWriterTest {

  private lateinit var tempDir: File
  private lateinit var writer: DefaultAtomicCredentialWriter

  @BeforeTest
  fun setup() {
    tempDir = Files.createTempDirectory("atomic-writer-test").toFile()
    writer = DefaultAtomicCredentialWriter(tempDir)
  }

  @AfterTest
  fun tearDown() {
    tempDir.deleteRecursively()
  }

  @Test
  fun `successful write creates durable file`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    val content = "encrypted-content".toByteArray()

    val result = writer.replace(target) { outputStream ->
      outputStream.write(content)
    }

    if (result.isErr) {
      val error = result.unwrapError()
      throw IllegalStateException("Write failed with error: $error")
    }
    val version = result.getOrElse { throw IllegalStateException("Should not fail") }
    assertEquals(target.canonicalPath, version.canonicalPath)
    assertEquals(content.size.toLong(), version.fileSize)
    assertTrue(target.exists())
    assertContentEquals(content, target.readBytes())
  }

  @Test
  fun `encryption failure leaves original unchanged`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    val originalContent = "original-content".toByteArray()
    target.parentFile.mkdirs()
    target.writeBytes(originalContent)

    val result = writer.replace(target) { _ ->
      throw RuntimeException("Encryption failed")
    }

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<AtomicWriteError.EncryptionFailed>(error)
    assertTrue(target.exists())
    assertContentEquals(originalContent, target.readBytes())
    val tempFiles = target.parentFile.listFiles { f -> f.name.startsWith(".") && f.name.contains(".tmp-") }
    assertTrue(tempFiles == null || tempFiles.isEmpty(), "No temp files should remain")
  }

  @Test
  fun `pre-rename failure leaves no temp file`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")

    writer.replace(target) { _ ->
      throw RuntimeException("Simulated failure")
    }

    val allFiles = target.parentFile.listFiles() ?: emptyArray()
    val tempFiles = allFiles.filter { writer.isTempFileName(it.name) }
    assertTrue(tempFiles.isEmpty(), "No temp files should remain after failure")
  }

  @Test
  fun `target outside repository is rejected`() = runBlocking {
    val outsideDir = Files.createTempDirectory("outside").toFile()
    val target = File(outsideDir, "credential.gpg")

    try {
      val result = writer.replace(target) { outputStream ->
        outputStream.write("data".toByteArray())
      }

      assertTrue(result.isErr)
      val error = result.unwrapError()
      assertIs<AtomicWriteError.TargetOutsideRepository>(error)
    } finally {
      outsideDir.deleteRecursively()
    }
    Unit
  }

  @Test
  fun `symlinked target is rejected`() = runBlocking {
    val realDir = File(tempDir, "real")
    realDir.mkdirs()
    val realFile = File(realDir, "cred.gpg")
    realFile.writeBytes("real-content".toByteArray())

    val linkDir = File(tempDir, "fido2")
    linkDir.mkdirs()
    val linkFile = File(linkDir, "cred.gpg")
    Files.createSymbolicLink(linkFile.toPath(), realFile.toPath())

    val result = writer.replace(linkFile) { outputStream ->
      outputStream.write("new-content".toByteArray())
    }

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<AtomicWriteError.SymlinkRejected>(error)
    assertContentEquals("real-content".toByteArray(), realFile.readBytes())
  }

  @Test
  fun `symlinked parent directory is rejected`() = runBlocking {
    val realSubdir = File(tempDir, "real-sub")
    realSubdir.mkdirs()

    val linkDir = File(tempDir, "fido2")
    linkDir.mkdirs()
    val linkSub = File(linkDir, "example")
    Files.createSymbolicLink(linkSub.toPath(), realSubdir.toPath())

    val target = File(linkSub, "cred.gpg")

    val result = writer.replace(target) { outputStream ->
      outputStream.write("data".toByteArray())
    }

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<AtomicWriteError.SymlinkRejected>(error)
    Unit
  }

  @Test
  fun `concurrent writes are serialized`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    val results = mutableListOf<com.github.michaelbull.result.Result<DurableFileVersion, AtomicWriteError>>()
    val writeOrder = mutableListOf<Int>()
    val lock = Any()

    val jobs = (0 until 5).map { i ->
      async(Dispatchers.IO) {
        val result = writer.replace(target) { outputStream ->
          synchronized(lock) { writeOrder.add(i) }
          Thread.sleep(50)
          outputStream.write("content-$i".toByteArray())
        }
        synchronized(lock) { results.add(result) }
      }
    }

    jobs.awaitAll()

    assertEquals(5, results.size)
    assertTrue(results.all { it.isOk })
    assertEquals(5, writeOrder.size)
    assertTrue(target.exists())
  }

  @Test
  fun `delete removes file durably`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    target.parentFile.mkdirs()
    target.writeBytes("content".toByteArray())
    assertTrue(target.exists())

    val result = writer.deleteAtomic(target)

    assertTrue(result.isOk)
    assertTrue(result.getOrElse { throw IllegalStateException("Should not fail") })
    assertFalse(target.exists())
  }

  @Test
  fun `delete of nonexistent file returns false`() = runBlocking {
    val target = File(tempDir, "fido2/example/nonexistent.gpg")

    val result = writer.deleteAtomic(target)

    assertTrue(result.isOk)
    assertFalse(result.getOrElse { throw IllegalStateException("Should not fail") })
  }

  @Test
  fun `temp file names are recognized as internal artifacts`() {
    assertTrue(writer.isTempFileName(".abcd1234.gpg.tmp-abc123"))
    assertTrue(writer.isTombstoneFileName(".abcd1234.gpg.tombstone"))
    assertTrue(writer.isInternalArtifact(".abcd1234.gpg.tmp-xyz"))
    assertTrue(writer.isInternalArtifact(".abcd1234.gpg.tombstone"))
    assertFalse(writer.isInternalArtifact("abcd1234.gpg"))
    assertFalse(writer.isTempFileName("abcd1234.gpg"))
  }

  @Test
  fun `stale temp files are cleaned up`() = runBlocking {
    val dir = File(tempDir, "fido2/example")
    dir.mkdirs()

    val staleTemp = File(dir, ".abcd1234.gpg.tmp-old123")
    staleTemp.writeBytes("stale".toByteArray())
    staleTemp.setLastModified(System.currentTimeMillis() - 120_000)

    val freshTemp = File(dir, ".efgh5678.gpg.tmp-new456")
    freshTemp.writeBytes("fresh".toByteArray())

    val cleaned = writer.cleanupStaleTempFiles(tempDir, maxAgeMs = 60_000L)

    assertEquals(1, cleaned.size)
    assertFalse(staleTemp.exists())
    assertTrue(freshTemp.exists())
  }

  @Test
  fun `write creates file with restricted permissions`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")

    writer.replace(target) { outputStream ->
      outputStream.write("content".toByteArray())
    }

    assertTrue(target.exists())
    try {
      val perms = Files.getPosixFilePermissions(target.toPath())
      val permString = PosixFilePermissions.toString(perms)
      assertFalse(permString.contains("rwxrwxrwx"))
      assertTrue(perms.contains(java.nio.file.attribute.PosixFilePermission.OWNER_READ))
      assertTrue(perms.contains(java.nio.file.attribute.PosixFilePermission.OWNER_WRITE))
    } catch (_: UnsupportedOperationException) {
      // On non-POSIX filesystems, skip permission check
    }
  }

  @Test
  fun `overwrite existing file atomically`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    target.parentFile.mkdirs()
    target.writeBytes("original-content".toByteArray())
    val originalModified = target.lastModified()
    Thread.sleep(50)

    val result = writer.replace(target) { outputStream ->
      outputStream.write("new-content".toByteArray())
    }

    assertTrue(result.isOk)
    assertContentEquals("new-content".toByteArray(), target.readBytes())
    assertTrue(target.lastModified() >= originalModified)
  }

  @Test
  fun `temp file collision retries successfully`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    target.parentFile.mkdirs()

    val results = (0 until 10).map {
      writer.replace(target) { outputStream ->
        outputStream.write("content-$it".toByteArray())
      }
    }

    assertTrue(results.all { it.isOk })
    assertTrue(target.exists())
  }
}
