/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.crypto

import java.io.File
import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class GpgIdScopeTest {

  @Test
  fun preservesExplicitNestedScope() {
    val root = createTempDirectory().toFile()
    val nested = File(root, "ID-Pessoal/HG").apply { mkdirs() }

    assertEquals("ID-Pessoal/HG", resolveGpgIdScope(root, nested, "ID-Pessoal/HG"))
  }

  @Test
  fun preservesLegacyRootScope() {
    val root = createTempDirectory().toFile()

    assertEquals("/", resolveGpgIdScope(root, root, "/"))
  }

  @Test
  fun preservesLegacyCreationDirectoryScope() {
    val root = createTempDirectory().toFile()
    val nested = File(root, "ID-Pessoal/HG").apply { mkdirs() }

    assertEquals("/ID-Pessoal/HG", resolveGpgIdScope(root, nested, "/ID-Pessoal/HG"))
  }

  @Test
  fun preservesLegacyDecryptionParentScope() {
    val root = createTempDirectory().toFile()
    val nested = File(root, "ID-Pessoal/HG").apply { mkdirs() }

    assertEquals("/ID-Pessoal/HG/", resolveGpgIdScope(root, nested, "/ID-Pessoal/HG/"))
  }

  @Test
  fun preservesNonPhysicalExplicitScopeWithoutNormalization() {
    val root = createTempDirectory().toFile()
    val nested = File(root, "ID-Pessoal/HG").apply { mkdirs() }

    assertEquals(" ", resolveGpgIdScope(root, nested, " "))
  }

  @Test
  fun normalizesPhysicalScopeInsideRepository() {
    val root = createTempDirectory().toFile()
    val nested = File(root, "ID-Pessoal/HG").apply { mkdirs() }

    assertEquals("ID-Pessoal/HG", resolveGpgIdScope(root, nested, nested.absolutePath))
  }

  @Test
  fun normalizesCanonicalRepositoryAliasScope() {
    val temp = createTempDirectory()
    val physicalRoot = temp.resolve("physical-store").toFile().apply { mkdirs() }
    val aliasRootPath = temp.resolve("store")
    Files.createSymbolicLink(aliasRootPath, physicalRoot.toPath())
    val aliasRoot = aliasRootPath.toFile()
    val nested = File(physicalRoot, "ID-Pessoal/HG").apply { mkdirs() }
    val metadata = File(nested, ".secrets.gpg").apply { writeText("encrypted") }

    assertEquals(
      "ID-Pessoal/HG",
      resolveGpgIdScope(aliasRoot, metadata, nested.absolutePath),
    )
  }

  @Test
  fun normalizesPhysicalRepositoryRootToRootMarker() {
    val root = createTempDirectory().toFile()

    assertEquals("/", resolveGpgIdScope(root, root, root.absolutePath))
  }

  @Test
  fun recoversNestedScopeWhenSubDirIsLost() {
    val root = createTempDirectory().toFile()
    val nested = File(root, "ID-Pessoal/HG").apply { mkdirs() }

    assertEquals("ID-Pessoal/HG", resolveGpgIdScope(root, nested, ""))
  }

  @Test
  fun recoversParentScopeForExistingPassword() {
    val root = createTempDirectory().toFile()
    val nested = File(root, "ID-Pessoal/HG").apply { mkdirs() }
    val password = File(nested, "example.gpg").apply { writeText("encrypted") }

    assertEquals("ID-Pessoal/HG", resolveGpgIdScope(root, password, ""))
  }

  @Test
  fun recoversWhitespaceNamedDirectoryWithoutTreatingItAsRoot() {
    val root = createTempDirectory().toFile()
    val nested = File(root, " ").apply { mkdirs() }

    assertEquals(" ", resolveGpgIdScope(root, nested, ""))
  }

  @Test
  fun emptyScopeAtRepositoryRootUsesRootMarker() {
    val root = createTempDirectory().toFile()

    assertEquals("/", resolveGpgIdScope(root, root, ""))
  }

  @Test
  fun rejectsRecoveredScopeOutsideRepository() {
    val root = createTempDirectory().toFile()
    val outside =
      createTempDirectory().resolve("entry.gpg").toFile().apply { writeText("encrypted") }

    assertFailsWith<IllegalArgumentException> { resolveGpgIdScope(root, outside, "") }
  }
}
