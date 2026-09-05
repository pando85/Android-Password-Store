/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.passwords

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.view.KeyEvent
import android.view.Menu
import android.view.MenuItem
import android.view.MenuItem.OnActionExpandListener
import android.view.WindowManager
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SearchView
import androidx.appcompat.widget.SearchView.OnQueryTextListener
import androidx.core.content.edit
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.commit
import androidx.lifecycle.flowWithLifecycle
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.data.password.PasswordItem
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.databinding.ActivityPwdstoreBinding
import app.passwordstore.passsecrets.PassSecretsMutationService
import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.ui.crypto.DecryptActivity
import app.passwordstore.ui.crypto.PassSecretsMapUnlockActivity
import app.passwordstore.ui.crypto.PasswordCreationActivity
import app.passwordstore.ui.dialogs.FolderCreationDialogFragment
import app.passwordstore.ui.folderselect.SelectFolderActivity
import app.passwordstore.ui.git.base.BaseGitActivity
import app.passwordstore.ui.onboarding.activity.OnboardingActivity
import app.passwordstore.ui.pgp.PGPKeyListActivity
import app.passwordstore.ui.settings.SettingsActivity
import app.passwordstore.util.autofill.AutofillMatcher
import app.passwordstore.util.extensions.base64
import app.passwordstore.util.extensions.commitChange
import app.passwordstore.util.extensions.enableEdgeToEdgeView
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.isInsideRepository
import app.passwordstore.util.extensions.launchActivity
import app.passwordstore.util.extensions.listFilesRecursively
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.settings.AuthMode
import app.passwordstore.util.settings.PreferenceKeys
import app.passwordstore.util.shortcuts.ShortcutHandler
import app.passwordstore.util.viewmodel.FilterMode
import app.passwordstore.util.viewmodel.SearchableRepositoryViewModel
import com.github.michaelbull.result.fold
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import dagger.hilt.android.AndroidEntryPoint
import java.io.File
import java.lang.Character.UnicodeBlock
import javax.inject.Inject
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.LogPriority.INFO
import logcat.logcat

const val PASSWORD_FRAGMENT_TAG = "PasswordsList"

@AndroidEntryPoint
class PasswordStore : BaseGitActivity() {

  @Inject lateinit var shortcutHandler: ShortcutHandler
  @Inject lateinit var passSecretsMutationService: PassSecretsMutationService
  private lateinit var searchItem: MenuItem
  private val settings by lazy { sharedPrefs }

  private val binding by viewBinding(ActivityPwdstoreBinding::inflate)
  private val model: SearchableRepositoryViewModel by viewModels()
  private var pendingPassSecretsOperation: (() -> Unit)? = null

  private val passSecretsUnlockAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      val operation = pendingPassSecretsOperation
      pendingPassSecretsOperation = null
      if (result.resultCode == RESULT_OK) operation?.invoke()
    }

  private val gpgKeySelectAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == AppCompatActivity.RESULT_OK) {
        val data = result.data ?: return@registerForActivityResult
        val selectedKeyId =
          data.getStringExtra(PGPKeyListActivity.EXTRA_SELECTED_KEY)
            ?: return@registerForActivityResult
        val gpgIdentifierFile = File(currentDir.absolutePath, ".gpg-id")
        gpgIdentifierFile.writeText(selectedKeyId + "\n")
        runBlocking {
          commitChange(getString(R.string.git_commit_gpg_id, getString(R.string.app_name)))
        }
        refreshPasswordList()
      }
    }

  private val listRefreshAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == RESULT_OK) refreshPasswordList()
    }

  private val passwordMoveAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      val intentData = result.data ?: return@registerForActivityResult
      val filesToMove =
        requireNotNull(intentData.getStringArrayExtra("Files")) {
          "'Files' intent extra must be set"
        }
      val target =
        File(
          requireNotNull(intentData.getStringExtra(SelectFolderActivity.SELECTED_FOLDER_PATH)) {
            "'SELECTED_FOLDER_PATH' intent extra must be set"
          }
        )
      if (!target.isDirectory) {
        logcat(ERROR) { "Tried moving passwords to a non-existing folder." }
        return@registerForActivityResult
      }

      val moves =
        filesToMove
          .map { File(it) }
          .filter { source -> source.exists() }
          .map { source -> source to File(target, source.name) }
          .filter { (source, destination) -> source.canonicalPath != destination.canonicalPath }
      if (moves.isEmpty()) {
        getPasswordFragment()?.dismissActionMode()
        return@registerForActivityResult
      }

      logcat { "Moving passwords to ${target.absolutePath}" }
      logcat { moves.joinToString(", ") { (source, _) -> source.absolutePath } }

      val conflict = moves.firstOrNull { (source, destination) ->
        destination.exists() && source.canonicalPath != destination.canonicalPath
      }
      if (conflict != null) {
        val repositoryPath = PasswordRepository.getRepositoryDirectory().absolutePath
        val (source, destination) = conflict
        val sourceLongName =
          PasswordRepository.getLongName(
            requireNotNull(source.parent),
            repositoryPath,
            source.nameWithoutExtension,
          )
        val destinationLongName =
          PasswordRepository.getLongName(
            requireNotNull(destination.parent),
            repositoryPath,
            destination.nameWithoutExtension,
          )
        MaterialAlertDialogBuilder(this)
          .setTitle(resources.getString(R.string.password_exists_title))
          .setMessage(
            resources.getString(
              R.string.password_exists_message,
              destinationLongName,
              sourceLongName,
            )
          )
          .setPositiveButton(R.string.dialog_ok) { _, _ -> performPasswordMoves(moves, target) }
          .setNegativeButton(R.string.dialog_cancel, null)
          .show()
      } else {
        performPasswordMoves(moves, target)
      }
    }

  override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
    if (
      (keyCode == KeyEvent.KEYCODE_SEARCH ||
        keyCode == KeyEvent.KEYCODE_F && event.isCtrlPressed) && !searchItem.isActionViewExpanded
    ) {
      searchItem.expandActionView()
      return true
    }

    val c = event.unicodeChar.toChar()
    val printable = isPrintable(c)
    if (printable && !searchItem.isActionViewExpanded) {
      searchItem.expandActionView()
      (searchItem.actionView as SearchView).setQuery(c.toString(), true)
      return true
    }
    return super.onKeyDown(keyCode, event)
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    enableEdgeToEdgeView(binding.root)
    setContentView(binding.root)

    onBackPressedDispatcher.addCallback(
      this,
      object : OnBackPressedCallback(true) {
        override fun handleOnBackPressed() {
          if (getPasswordFragment()?.onBackPressedInActivity() != true) finishAndRemoveTask()
        }
      },
    )

    lifecycleScope.launch {
      model.currentDir.flowWithLifecycle(lifecycle).collect { dir ->
        val basePath = PasswordRepository.getRepositoryDirectory().absoluteFile
        supportActionBar?.apply {
          if (dir != basePath) title = dir.name else setTitle(R.string.app_name)
        }
      }
    }
  }

  override fun onStart() {
    super.onStart()
    refreshPasswordList()
  }

  override fun onResume() {
    super.onResume()
    checkLocalRepository()
    refreshPasswordList()
    if (settings.getBoolean(PreferenceKeys.SEARCH_ON_START, false) && ::searchItem.isInitialized) {
      if (!searchItem.isActionViewExpanded) searchItem.expandActionView()
    }
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    val menuRes =
      when {
        gitSettings.authMode == AuthMode.None -> R.menu.main_menu_no_auth
        PasswordRepository.isGitRepo() -> R.menu.main_menu_git
        else -> R.menu.main_menu_non_git
      }
    menuInflater.inflate(menuRes, menu)
    return super.onCreateOptionsMenu(menu)
  }

  override fun onPrepareOptionsMenu(menu: Menu): Boolean {
    invalidateOptionsMenu()
    searchItem = menu.findItem(R.id.action_search)
    val searchView = searchItem.actionView as SearchView
    searchView.setOnQueryTextListener(
      object : OnQueryTextListener {
        override fun onQueryTextSubmit(s: String): Boolean {
          searchView.clearFocus()
          return true
        }

        override fun onQueryTextChange(s: String): Boolean {
          val filter = s.trim()
          val filterMode =
            if (settings.getString(PreferenceKeys.SEARCH_FILTER_MODE, "exact") == "fuzzy")
              FilterMode.Fuzzy
            else FilterMode.Exact
          if (filter.isEmpty())
            model.navigateTo(newDirectory = model.currentDir.value, pushPreviousLocation = false)
          else model.search(filter, filterMode = filterMode)
          return true
        }
      }
    )

    searchItem.setOnActionExpandListener(
      object : OnActionExpandListener {
        override fun onMenuItemActionCollapse(item: MenuItem): Boolean {
          refreshPasswordList()
          return true
        }

        override fun onMenuItemActionExpand(item: MenuItem): Boolean = true
      }
    )
    if (
      settings.getBoolean(PreferenceKeys.SEARCH_ON_START, false) ||
        intent.action == Intent.ACTION_SEARCH
    ) {
      searchItem.expandActionView()
    }
    return super.onPrepareOptionsMenu(menu)
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean {
    val id = item.itemId
    val initBefore =
      MaterialAlertDialogBuilder(this)
        .setMessage(resources.getString(R.string.creation_dialog_text))
        .setPositiveButton(resources.getString(R.string.dialog_ok), null)
    when (id) {
      R.id.user_pref -> {
        runCatching { launchActivity(SettingsActivity::class.java) }
          .onErr { e -> e.printStackTrace() }
      }
      R.id.git_push -> {
        if (!PasswordRepository.isInitialized) initBefore.show() else runGitOperation(GitOp.PUSH)
      }
      R.id.git_pull -> {
        if (!PasswordRepository.isInitialized) initBefore.show() else runGitOperation(GitOp.PULL)
      }
      R.id.git_sync -> {
        if (!PasswordRepository.isInitialized) initBefore.show() else runGitOperation(GitOp.SYNC)
      }
      R.id.refresh -> refreshPasswordList()
      android.R.id.home -> onBackPressedDispatcher.onBackPressed()
      else -> return super.onOptionsItemSelected(item)
    }
    return true
  }

  private fun getPasswordFragment(): PasswordFragment? {
    return supportFragmentManager.findFragmentByTag(PASSWORD_FRAGMENT_TAG) as? PasswordFragment
  }

  fun clearSearch() {
    if (searchItem.isActionViewExpanded) searchItem.collapseActionView()
  }

  fun runGitOperation(operation: GitOp) = lifecycleScope.launch {
    launchGitOperation(operation)
      .fold(success = { refreshPasswordList() }, failure = { promptOnErrorHandler(it) })
  }

  private fun checkLocalRepository() {
    PasswordRepository.initialize()
    checkLocalRepository(PasswordRepository.getRepositoryDirectory())
  }

  private fun checkLocalRepository(localDir: File?) {
    if (localDir != null && settings.getBoolean(PreferenceKeys.REPOSITORY_INITIALIZED, false)) {
      if (
        getPasswordFragment() == null || settings.getBoolean(PreferenceKeys.REPO_CHANGED, false)
      ) {
        settings.edit { putBoolean(PreferenceKeys.REPO_CHANGED, false) }
        val args = Bundle()
        args.putString(REQUEST_ARG_PATH, PasswordRepository.getRepositoryDirectory().absolutePath)

        if (intent.getBooleanExtra("matchWith", false)) args.putBoolean("matchWith", true)
        supportActionBar?.apply {
          show()
          setDisplayHomeAsUpEnabled(false)
        }
        supportFragmentManager.popBackStack(null, FragmentManager.POP_BACK_STACK_INCLUSIVE)
        supportFragmentManager.commit {
          replace(R.id.main_layout, PasswordFragment.newInstance(args), PASSWORD_FRAGMENT_TAG)
        }
      }
    } else {
      launchActivity(OnboardingActivity::class.java)
    }
  }

  fun decryptPassword(item: PasswordItem) {
    val authDecryptIntent = item.createAuthEnabledIntent(this)
    val decryptIntent =
      Intent(authDecryptIntent).setComponent(ComponentName(this, DecryptActivity::class.java))

    startActivity(decryptIntent)
    shortcutHandler.addDynamicShortcut(item, authDecryptIntent)
  }

  private fun validateState(): Boolean {
    if (!PasswordRepository.isInitialized) {
      MaterialAlertDialogBuilder(this)
        .setMessage(resources.getString(R.string.creation_dialog_text))
        .setPositiveButton(resources.getString(R.string.dialog_ok), null)
        .show()
      return false
    }
    return true
  }

  fun createPassword() {
    if (!validateState()) return
    val currentDir = currentDir
    logcat(INFO) { "Adding file to : ${currentDir.absolutePath}" }
    val intent = Intent(this, PasswordCreationActivity::class.java)
    intent.putExtra(BasePGPActivity.EXTRA_FILE_PATH, currentDir.absolutePath)
    intent.putExtra(
      BasePGPActivity.EXTRA_REPO_PATH,
      PasswordRepository.getRepositoryDirectory().absolutePath,
    )
    listRefreshAction.launch(intent)
  }

  fun createFolder() {
    if (!validateState()) return
    FolderCreationDialogFragment.newInstance(currentDir.path, setGpgKey = true)
      .show(supportFragmentManager, null)
  }

  fun deletePasswords(selectedItems: List<PasswordItem>) {
    var size = 0
    selectedItems.forEach { item ->
      if (item.file.isFile) size++ else size += item.file.listFilesRecursively().size
    }
    if (size == 0) {
      performDelete(selectedItems)
      return
    }
    MaterialAlertDialogBuilder(this)
      .setMessage(resources.getQuantityString(R.plurals.delete_dialog_text, size, size))
      .setPositiveButton(resources.getString(R.string.dialog_yes)) { _, _ ->
        performDelete(selectedItems)
      }
      .setNegativeButton(resources.getString(R.string.dialog_no), null)
      .show()
  }

  private fun performDelete(selectedItems: List<PasswordItem>) {
    val targets = selectedItems.map { it.file }
    val repositoryRoot = PasswordRepository.getRepositoryDirectory()
    withUnlockedPassSecretsMetadata(
      required = {
        passSecretsMutationService.requiredMetadataForDelete(targets, repositoryRoot)
      },
      action = {
        lifecycleScope.launch {
          try {
            val filesToDelete = targets.flatMap { target ->
              if (target.isDirectory) target.listFilesRecursively() else listOf(target)
            }
            val plan = passSecretsMutationService.planDelete(targets, repositoryRoot)
            withContext(dispatcherProvider.io()) { passSecretsMutationService.commitDelete(plan) }

            val preference = getSharedPreferences("recent_password_history", 0)
            preference.edit {
              filesToDelete.forEach { file -> remove(file.absolutePath.base64()) }
            }
            AutofillMatcher.updateMatches(applicationContext, delete = filesToDelete)

            val fmt =
              targets.joinToString(separator = ", ") { target ->
                target.toRelativeString(repositoryRoot)
              }
            commitChange(resources.getString(R.string.git_commit_remove_text, fmt))
            updateFabSync()
            getPasswordFragment()?.dismissActionMode()
            refreshPasswordList()
          } catch (error: Throwable) {
            showPassSecretsMutationError(error)
          }
        }
      },
    )
  }

  fun movePasswords(values: List<PasswordItem>) {
    val intent = Intent(this, SelectFolderActivity::class.java)
    val fileLocations = values.map { it.file.absolutePath }.toTypedArray()
    intent.putExtra("Files", fileLocations)
    val repoPath = PasswordRepository.getRepositoryDirectory().absolutePath
    val relPath = PasswordRepository.getRelativePath(currentDir.absolutePath, repoPath)
    if (!relPath.isEmpty()) intent.putExtra(REQUEST_ARG_PATH, relPath)
    passwordMoveAction.launch(intent)
  }

  private fun performPasswordMoves(moves: List<Pair<File, File>>, target: File) {
    val repositoryRoot = PasswordRepository.getRepositoryDirectory()
    withUnlockedPassSecretsMetadata(
      required = { passSecretsMutationService.requiredMetadataForMoves(moves, repositoryRoot) },
      action = {
        lifecycleScope.launch {
          try {
            val sourceDestinationMap = buildSourceDestinationMap(moves)
            val plan = passSecretsMutationService.planMoves(moves, repositoryRoot)
            withContext(dispatcherProvider.io()) { passSecretsMutationService.commitMoves(plan) }
            updateHistoryAfterMove(sourceDestinationMap)
            AutofillMatcher.updateMatches(applicationContext, sourceDestinationMap)

            val repositoryPath = repositoryRoot.absolutePath
            if (moves.size == 1) {
              val (source, destination) = moves.single()
              val sourceLongName =
                PasswordRepository.getLongName(
                  requireNotNull(source.parent),
                  repositoryPath,
                  source.nameWithoutExtension,
                )
              val destinationLongName =
                PasswordRepository.getLongName(
                  requireNotNull(destination.parent),
                  repositoryPath,
                  destination.nameWithoutExtension,
                )
              commitChange(
                resources.getString(
                  R.string.git_commit_move_text,
                  sourceLongName,
                  destinationLongName,
                )
              )
            } else {
              val relativePath =
                PasswordRepository.getRelativePath("${target.absolutePath}/", repositoryPath)
              commitChange(
                resources.getString(R.string.git_commit_move_multiple_text, relativePath)
              )
            }
            updateFabSync()
            getPasswordFragment()?.dismissActionMode()
            getPasswordFragment()?.scrollToOnNextRefresh(moves.first().second)
            refreshPasswordList(target)
          } catch (error: Throwable) {
            showPassSecretsMutationError(error)
          }
        }
      },
    )
  }

  enum class CategoryRenameError(val resource: Int) {
    None(0),
    EmptyField(R.string.message_category_error_empty_field),
    CategoryExists(R.string.message_category_error_category_exists),
    DestinationOutsideRepo(R.string.message_error_destination_outside_repo),
  }

  private fun renameCategory(
    oldCategory: PasswordItem,
    error: CategoryRenameError = CategoryRenameError.None,
  ) {
    val view = layoutInflater.inflate(R.layout.folder_dialog_fragment, null)
    val newCategoryEditText = view.findViewById<TextInputEditText>(R.id.folder_name_text)
    val folderNameViewContainer = view.findViewById<TextInputLayout>(R.id.folder_name_container)

    if (error != CategoryRenameError.None) folderNameViewContainer.error = getString(error.resource)

    val dialog =
      MaterialAlertDialogBuilder(this)
        .setTitle(R.string.title_rename_folder)
        .setView(view)
        .setMessage(getString(R.string.message_rename_folder, oldCategory.name))
        .setPositiveButton(R.string.dialog_ok) { _, _ ->
          val newCategory = File("${oldCategory.file.parent}/${newCategoryEditText.text}")
          when {
            !newCategory.isInsideRepository() ->
              renameCategory(oldCategory, CategoryRenameError.DestinationOutsideRepo)
            newCategoryEditText.text.isNullOrBlank() ->
              renameCategory(oldCategory, CategoryRenameError.EmptyField)
            newCategory.exists() -> renameCategory(oldCategory, CategoryRenameError.CategoryExists)
            else -> performCategoryRename(oldCategory, newCategory)
          }
        }
        .setNegativeButton(R.string.dialog_cancel, null)
        .create()

    dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE)
    dialog.show()
  }

  private fun performCategoryRename(oldCategory: PasswordItem, newCategory: File) {
    val repositoryRoot = PasswordRepository.getRepositoryDirectory()
    withUnlockedPassSecretsMetadata(
      required = {
        passSecretsMutationService.requiredMetadataForMove(
          oldCategory.file,
          newCategory,
          repositoryRoot,
        )
      },
      action = {
        lifecycleScope.launch {
          try {
            val sourceDestinationMap =
              buildSourceDestinationMap(listOf(oldCategory.file to newCategory))
            val categoryPreference = getSharedPreferences("recent_password_history", 0)
            val categoryTimestamp =
              categoryPreference.getString(oldCategory.file.absolutePath.base64())
            val plan =
              passSecretsMutationService.planMove(oldCategory.file, newCategory, repositoryRoot)
            withContext(dispatcherProvider.io()) { passSecretsMutationService.commitMove(plan) }
            updateHistoryAfterMove(sourceDestinationMap)
            if (categoryTimestamp != null) {
              categoryPreference.edit {
                remove(oldCategory.file.absolutePath.base64())
                putString(newCategory.absolutePath.base64(), categoryTimestamp)
              }
            }
            AutofillMatcher.updateMatches(applicationContext, sourceDestinationMap)

            commitChange(
              resources.getString(
                R.string.git_commit_move_text,
                oldCategory.name,
                newCategory.name,
              )
            )
            updateFabSync()
            refreshPasswordList(newCategory)
          } catch (error: Throwable) {
            showPassSecretsMutationError(error)
          }
        }
      },
    )
  }

  fun renameCategory(categories: List<PasswordItem>) {
    for (oldCategory in categories) renameCategory(oldCategory)
  }

  private fun withUnlockedPassSecretsMetadata(required: () -> List<File>, action: () -> Unit) {
    try {
      val nextMetadata = required().firstOrNull()
      if (nextMetadata == null) {
        pendingPassSecretsOperation = null
        action()
        return
      }
      pendingPassSecretsOperation = { withUnlockedPassSecretsMetadata(required, action) }
      passSecretsUnlockAction.launch(
        PassSecretsMapUnlockActivity.newIntent(
          this,
          nextMetadata,
          PasswordRepository.getRepositoryDirectory(),
        )
      )
    } catch (error: Throwable) {
      pendingPassSecretsOperation = null
      showPassSecretsMutationError(error)
    }
  }

  private fun showPassSecretsMutationError(error: Throwable) {
    val message =
      when (error) {
        is PassSecretsMutationService.ReencryptionRequiredException ->
          getString(R.string.pass_secrets_reencryption_required)
        is PassSecretsMutationService.ProtectedIdentityMarkerException ->
          getString(R.string.pass_secrets_identity_marker_protected)
        else -> getString(R.string.pass_secrets_mutation_error, error.message ?: error.toString())
      }
    MaterialAlertDialogBuilder(this)
      .setTitle(R.string.error)
      .setMessage(message)
      .setPositiveButton(android.R.string.ok, null)
      .show()
  }

  private fun buildSourceDestinationMap(moves: List<Pair<File, File>>): Map<File, File> {
    return buildMap {
      moves.forEach { (source, destination) ->
        if (source.isDirectory) {
          source.listFilesRecursively().forEach { child ->
            put(child, destination.resolve(child.relativeTo(source)))
          }
        } else {
          put(source, destination)
        }
      }
    }
  }

  private fun updateHistoryAfterMove(sourceDestinationMap: Map<File, File>) {
    val preference = getSharedPreferences("recent_password_history", 0)
    preference.edit {
      sourceDestinationMap.forEach { (source, destination) ->
        val sourceHash = source.absolutePath.base64()
        val timestamp = preference.getString(sourceHash)
        remove(sourceHash)
        if (timestamp != null) putString(destination.absolutePath.base64(), timestamp)
      }
    }
  }

  private fun updateFabSync() {
    runOnUiThread { getPasswordFragment()?.updateFabSync() }
  }

  fun refreshPasswordList(target: File? = null) {
    val relativeTargetPath = target?.let {
      require(it.isInsideRepository()) { "Trying to access target outside the repository" }
      val repoPath = PasswordRepository.getRepositoryDirectory().absolutePath
      PasswordRepository.getRelativePath(target.absolutePath, repoPath)
    }
    if (relativeTargetPath != null) {
      model.reset()
      model.navigateTo(PasswordRepository.getRepositoryDirectory(), pushPreviousLocation = false)
      relativeTargetPath.trim('/').split('/').forEach { item ->
        val file = File(model.currentDir.value, item)
        if (file.isDirectory) {
          if (file == model.currentDir.value) model.forceRefresh()
          else model.navigateTo(file, pushPreviousLocation = true)
        } else getPasswordFragment()?.scrollToOnNextRefresh(file)
      }
    } else if (model.currentDir.value.isDirectory) {
      model.forceRefresh()
    } else {
      model.reset()
    }
    supportActionBar?.setDisplayHomeAsUpEnabled(model.canNavigateBack)
    updateFabSync()
  }

  private val currentDir: File
    get() = getPasswordFragment()?.currentDir ?: PasswordRepository.getRepositoryDirectory()

  fun matchPasswordWithApp(item: PasswordItem) {
    val repoPath = PasswordRepository.getRepositoryDirectory().absolutePath
    val path =
      PasswordRepository.getRelativePath(item.file.absolutePath, "$repoPath/").replace(".gpg", "")
    val data = Intent()
    data.putExtra("path", path)
    setResult(RESULT_OK, data)
    finish()
  }

  companion object {

    const val REQUEST_ARG_PATH = "PATH"

    private fun isPrintable(c: Char): Boolean {
      val block = UnicodeBlock.of(c)
      return (!Character.isISOControl(c) && block != null && block !== UnicodeBlock.SPECIALS)
    }
  }
}
