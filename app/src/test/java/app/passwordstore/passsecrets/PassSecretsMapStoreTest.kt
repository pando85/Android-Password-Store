/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passsecrets

import app.passwordstore.data.password.PasswordItem
import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class PassSecretsMapStoreTest {

  @get:Rule val tempFolder = TemporaryFolder()

  private lateinit var root: File

  @BeforeTest
  fun setup() {
    PassSecretsMapStore.clear()
    root = tempFolder.newFolder("store")
  }

  @AfterTest
  fun tearDown() {
    PassSecretsMapStore.clear()
    tempFolder.root.deleteRecursively()
  }

  @Test
  fun `parser handles whitespace and equals signs in descriptions`() {
    val parsed =
      PassSecretsMapStore.parse(
        """
        Abcde/FgXyz = GitHub personal
        Qwert/Asdfg=service = production
        """.trimIndent()
      )

    assertEquals("GitHub personal", parsed["Abcde/FgXyz"])
    assertEquals("service = production", parsed["Qwert/Asdfg"])
  }

  @Test
  fun `parser ignores malformed unsafe empty and pending entries`() {
    val parsed =
      PassSecretsMapStore.parse(
        """
        malformed line
        /absolute/path = nope
        foo/../bar = nope
        foo\\bar = nope
        valid/path =
        pending/path = (pendente)
        good/path = Good value
        """.trimIndent()
      )

    assertEquals(mapOf("good/path" to "Good value"), parsed)
  }

  @Test
  fun `parser uses last value for duplicate keys`() {
    val parsed = PassSecretsMapStore.parse("Foo/Bar = first\nFoo/Bar = second")
    assertEquals("second", parsed["Foo/Bar"])
  }

  @Test
  fun `mapped name resolves relative to nearest identity`() {
    val identity = identity(root, "Work")
    val password = password(identity, "Abcde/FgXyz")
    val mapFile = File(identity, PassSecretsMapStore.MAP_FILE_NAME)
    PassSecretsMapStore.put(mapFile, mapOf("Abcde/FgXyz" to "GitHub work"))

    assertEquals("GitHub work", PassSecretsMapStore.mappedName(password, root))
  }

  @Test
  fun `nested identity with own map overrides parent identity`() {
    val parent = identity(root, "Parent")
    val child = identity(parent, "Nested")
    val password = password(child, "Abcde")
    PassSecretsMapStore.put(
      File(parent, PassSecretsMapStore.MAP_FILE_NAME),
      mapOf("Nested/Abcde" to "Wrong parent mapping"),
    )
    PassSecretsMapStore.put(
      File(child, PassSecretsMapStore.MAP_FILE_NAME),
      mapOf("Abcde" to "Correct child mapping"),
    )

    assertEquals("Correct child mapping", PassSecretsMapStore.mappedName(password, root))
  }

  @Test
  fun `nested identity without map never inherits parent mapping`() {
    val parent = identity(root, "Parent")
    val child = identity(parent, "Nested", withMap = false)
    val password = password(child, "Abcde")
    PassSecretsMapStore.put(
      File(parent, PassSecretsMapStore.MAP_FILE_NAME),
      mapOf("Nested/Abcde" to "Must not leak across boundary"),
    )

    assertNull(PassSecretsMapStore.mappedName(password, root))
    assertNull(PassSecretsMapStore.claimForDirectory(child, root))
  }

  @Test
  fun `claim is automatic once per map until resolved`() {
    val identity = identity(root, "Work")
    val mapFile = File(identity, PassSecretsMapStore.MAP_FILE_NAME)

    assertEquals(mapFile.absolutePath, PassSecretsMapStore.claimForDirectory(identity, root)?.absolutePath)
    assertNull(PassSecretsMapStore.claimForDirectory(identity, root))

    PassSecretsMapStore.put(mapFile, emptyMap())
    assertNull(PassSecretsMapStore.claimForDirectory(identity, root))
  }

  @Test
  fun `skipped map does not immediately prompt again`() {
    val identity = identity(root, "Work")
    val mapFile = File(identity, PassSecretsMapStore.MAP_FILE_NAME)

    assertEquals(mapFile.absolutePath, PassSecretsMapStore.claimForDirectory(identity, root)?.absolutePath)
    PassSecretsMapStore.skip(mapFile)
    assertNull(PassSecretsMapStore.claimForDirectory(identity, root))
  }

  @Test
  fun `changing map invalidates loaded labels and permits a new unlock`() {
    val identity = identity(root, "Work")
    val password = password(identity, "Abcde")
    val mapFile = File(identity, PassSecretsMapStore.MAP_FILE_NAME)
    PassSecretsMapStore.put(mapFile, mapOf("Abcde" to "Old name"))
    assertEquals("Old name", PassSecretsMapStore.mappedName(password, root))

    mapFile.appendText("changed")

    assertNull(PassSecretsMapStore.mappedName(password, root))
    assertEquals(mapFile.absolutePath, PassSecretsMapStore.claimForDirectory(identity, root)?.absolutePath)
  }

  @Test
  fun `changing skipped map permits retry`() {
    val identity = identity(root, "Work")
    val mapFile = File(identity, PassSecretsMapStore.MAP_FILE_NAME)
    PassSecretsMapStore.claimForDirectory(identity, root)
    PassSecretsMapStore.skip(mapFile)
    assertNull(PassSecretsMapStore.claimForDirectory(identity, root))

    mapFile.appendText("changed")

    assertEquals(mapFile.absolutePath, PassSecretsMapStore.claimForDirectory(identity, root)?.absolutePath)
  }

  @Test
  fun `clear removes both decrypted labels and prompt suppression`() {
    val identity = identity(root, "Work")
    val password = password(identity, "Abcde")
    val mapFile = File(identity, PassSecretsMapStore.MAP_FILE_NAME)
    PassSecretsMapStore.put(mapFile, mapOf("Abcde" to "GitHub"))
    assertEquals("GitHub", PassSecretsMapStore.mappedName(password, root))

    PassSecretsMapStore.clear()

    assertNull(PassSecretsMapStore.mappedName(password, root))
    assertEquals(mapFile.absolutePath, PassSecretsMapStore.claimForDirectory(identity, root)?.absolutePath)
  }

  @Test
  fun `metadata files are always recognized separately from passwords`() {
    val identity = identity(root, "Work")
    assertTrue(PassSecretsMapStore.isMetadataFile(File(identity, ".secrets.gpg")))
    File(identity, ".mask.gpg").writeText("ciphertext")
    assertTrue(PassSecretsMapStore.isMetadataFile(File(identity, ".mask.gpg")))
    assertFalse(PassSecretsMapStore.isMetadataFile(password(identity, "Abcde")))
  }

  @Test
  fun `resolver ignores files outside repository root`() {
    val outside = tempFolder.newFolder("outside")
    val identity = identity(outside, "Work")
    val password = password(identity, "Abcde")
    PassSecretsMapStore.put(
      File(identity, PassSecretsMapStore.MAP_FILE_NAME),
      mapOf("Abcde" to "Outside"),
    )

    assertNull(PassSecretsMapStore.mappedName(password, root))
    assertNull(PassSecretsMapStore.claimForDirectory(identity, root))
  }

  @Test
  fun `password item displays mapped name but remains searchable by physical codename`() {
    val identity = identity(root, "Work")
    val password = password(identity, "Abcde/FgXyz")
    val item =
      PasswordItem.newPassword(
        password.name,
        password,
        root,
        mappedName = "github.com / personal",
      )

    assertEquals("github.com / personal", item.toString())
    assertTrue(item.matchesSearch("github.com"))
    assertTrue(item.matchesSearch("FgXyz"))
    assertTrue(item.matchesSearch("abcde"))
    assertFalse(item.matchesSearch("gitlab"))
  }

  @Test
  fun `mapped duplicate labels do not collapse physical identity`() {
    val identity = identity(root, "Work")
    val first = password(identity, "Abcde")
    val second = password(identity, "FgXyz")
    val firstItem = PasswordItem.newPassword(first.name, first, root, mappedName = "GitHub")
    val secondItem = PasswordItem.newPassword(second.name, second, root, mappedName = "GitHub")

    assertEquals(firstItem.toString(), secondItem.toString())
    assertNotEquals(firstItem.file.absolutePath, secondItem.file.absolutePath)
    assertFalse(firstItem == secondItem)
  }

  @Test
  fun `strict domain matching checks mapped description tokens and physical path`() {
    val identity = identity(root, "Work")
    val mapped = password(identity, "Abcde")
    val physical = password(identity, "gitlab.com")
    val regex = Regex("(?:^|/)(?:(?:[^/@]+\\.)?github\\.com)(?:\\.gpg|/)")
    val gitlabRegex = Regex("(?:^|/)(?:(?:[^/@]+\\.)?gitlab\\.com)(?:\\.gpg|/)")
    val mappedItem = PasswordItem.newPassword(mapped.name, mapped, root, "github.com / personal")
    val physicalItem = PasswordItem.newPassword(physical.name, physical, root)

    assertTrue(mappedItem.matchesStrictDomain(regex))
    assertTrue(physicalItem.matchesStrictDomain(gitlabRegex))
    assertFalse(mappedItem.matchesStrictDomain(gitlabRegex))
  }

  private fun identity(parent: File, name: String, withMap: Boolean = true): File {
    val dir = File(parent, name).apply { mkdirs() }
    File(dir, ".gpg-id").writeText("0123456789ABCDEF\n")
    if (withMap) File(dir, PassSecretsMapStore.MAP_FILE_NAME).writeText("ciphertext")
    return dir
  }

  private fun password(identity: File, relativePath: String): File {
    val file = File(identity, "$relativePath.gpg")
    file.parentFile?.mkdirs()
    file.writeText("encrypted")
    return file
  }
}
