/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.password

import android.content.Context
import android.content.Intent
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.ui.main.LaunchActivity
import java.io.File

data class PasswordItem(
  val name: String,
  val parent: PasswordItem? = null,
  val type: Char,
  val file: File,
  val rootDir: File,
  val mappedName: String? = null,
  val aliases: List<String> = emptyList(),
) : Comparable<PasswordItem> {

  val physicalName = name.replace("\\.gpg$".toRegex(), "")

  val fullPathToParent = PasswordRepository.getParentPath(file.absolutePath, rootDir.absolutePath)

  val physicalLongName =
    PasswordRepository.getLongName(fullPathToParent, rootDir.absolutePath, physicalName)

  val longName = PasswordRepository.getLongName(fullPathToParent, rootDir.absolutePath, toString())

  val searchableName = buildList {
    add(physicalLongName)
    if (mappedName != null) add(longName)
    addAll(aliases)
  }
    .joinToString(" ")

  fun matchesSearch(filter: String): Boolean = searchableName.contains(filter, ignoreCase = true)

  fun matchesStrictDomain(regex: Regex): Boolean {
    val physicalPath =
      try {
        file.relativeTo(rootDir).path
      } catch (_: IllegalArgumentException) {
        return false
      }
    if (regex.containsMatchIn(physicalPath)) return true

    val logicalTokens = buildList {
      mappedName?.split(Regex("[\\s/]+"))?.filterTo(this) { it.isNotBlank() }
      aliases.forEach { alias ->
        add(alias)
        if ('@' in alias) add(alias.substringAfterLast('@'))
      }
    }
    return logicalTokens.any { token -> regex.containsMatchIn("$token.gpg") }
  }

  override fun equals(other: Any?): Boolean {
    return (other is PasswordItem) && (other.file == file)
  }

  override fun compareTo(other: PasswordItem): Int {
    return (type + toString()).compareTo(other.type + other.toString(), ignoreCase = true)
  }

  override fun toString(): String {
    return mappedName ?: physicalName
  }

  override fun hashCode(): Int {
    return 0
  }

  /** Creates an [Intent] to launch this [PasswordItem] through the authentication process. */
  fun createAuthEnabledIntent(context: Context): Intent {
    val intent = Intent(context, LaunchActivity::class.java)
    // Intent extras may outlive the current UI process through Android shortcuts. Keep the
    // persisted identity physical even when a Pass-Secrets label is currently unlocked.
    intent.putExtra("NAME", physicalName)
    intent.putExtra(BasePGPActivity.EXTRA_FILE_PATH, file.absolutePath)
    intent.putExtra(
      BasePGPActivity.EXTRA_REPO_PATH,
      PasswordRepository.getRepositoryDirectory().absolutePath,
    )
    intent.action = LaunchActivity.ACTION_DECRYPT_PASS
    return intent
  }

  companion object {

    const val TYPE_CATEGORY = 'c'
    const val TYPE_PASSWORD = 'p'
    const val TYPE_GPG_ID = 'g'
    const val TYPE_OTHER = 'o' // unknown type, no effort is made to decrypt or display contents

    @JvmStatic
    fun newCategory(name: String, file: File, parent: PasswordItem, rootDir: File): PasswordItem {
      return PasswordItem(name, parent, TYPE_CATEGORY, file, rootDir)
    }

    @JvmStatic
    fun newCategory(name: String, file: File, rootDir: File): PasswordItem {
      return PasswordItem(name, null, TYPE_CATEGORY, file, rootDir)
    }

    @JvmStatic
    fun newPassword(
      name: String,
      file: File,
      parent: PasswordItem,
      rootDir: File,
      mappedName: String? = null,
      aliases: List<String> = emptyList(),
    ): PasswordItem {
      return PasswordItem(name, parent, TYPE_PASSWORD, file, rootDir, mappedName, aliases)
    }

    @JvmStatic
    fun newPassword(
      name: String,
      file: File,
      rootDir: File,
      mappedName: String? = null,
      aliases: List<String> = emptyList(),
    ): PasswordItem {
      return PasswordItem(name, null, TYPE_PASSWORD, file, rootDir, mappedName, aliases)
    }

    @JvmStatic
    fun newGpgIdItem(name: String, file: File, parent: PasswordItem, rootDir: File): PasswordItem {
      return PasswordItem(name, parent, TYPE_GPG_ID, file, rootDir)
    }

    @JvmStatic
    fun newGpgIdItem(name: String, file: File, rootDir: File): PasswordItem {
      return PasswordItem(name, null, TYPE_GPG_ID, file, rootDir)
    }

    @JvmStatic
    fun newOtherItem(name: String, file: File, parent: PasswordItem, rootDir: File): PasswordItem {
      return PasswordItem(name, parent, TYPE_OTHER, file, rootDir)
    }

    @JvmStatic
    fun newOtherItem(name: String, file: File, rootDir: File): PasswordItem {
      return PasswordItem(name, null, TYPE_OTHER, file, rootDir)
    }
  }
}
