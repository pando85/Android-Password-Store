/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.crypto

import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.ImageDecoder
import android.os.Build
import android.os.Bundle
import android.provider.MediaStore
import android.text.InputType
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.core.content.edit
import androidx.core.view.isVisible
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.errors.NoKeysProvidedException
import app.passwordstore.crypto.errors.UnusableKeyException
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.passfile.joinToCharArray
import app.passwordstore.data.passfile.splitToCharArrayListAt
import app.passwordstore.data.passfile.trimEnd
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.databinding.PasswordCreationActivityBinding
import app.passwordstore.passsecrets.PassSecretsMapStore
import app.passwordstore.passsecrets.PassSecretsMutationService
import app.passwordstore.ui.dialogs.DicewarePasswordGeneratorDialogFragment
import app.passwordstore.ui.dialogs.OtpImportDialogFragment
import app.passwordstore.ui.dialogs.PasswordGeneratorDialogFragment
import app.passwordstore.ui.folderselect.SelectFolderActivity
import app.passwordstore.ui.passwords.PasswordStore
import app.passwordstore.util.autofill.AutofillPreferences
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.extensions.asLog
import app.passwordstore.util.extensions.base64
import app.passwordstore.util.extensions.commitChange
import app.passwordstore.util.extensions.enableEdgeToEdgeView
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.isInsideRepository
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.toByteArray
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.extensions.wipe
import app.passwordstore.util.settings.DirectoryStructure
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.onOk
import com.github.michaelbull.result.runCatching
import com.github.michaelbull.result.unwrapError
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.zxing.BinaryBitmap
import com.google.zxing.LuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.integration.android.IntentIntegrator
import com.google.zxing.integration.android.IntentIntegrator.QR_CODE
import com.google.zxing.qrcode.QRCodeReader
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.nio.CharBuffer
import javax.inject.Inject
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

@AndroidEntryPoint
class PasswordCreationActivity : BasePGPActivity() {

  private val binding by viewBinding(PasswordCreationActivityBinding::inflate)
  @Inject lateinit var passwordEntryFactory: PasswordEntry.Factory
  @Inject lateinit var passSecretsMutationService: PassSecretsMutationService

  private val suggestedName by unsafeLazy { intent.getStringExtra(EXTRA_FILE_NAME) }
  private val suggestedPhysicalName by unsafeLazy {
    intent.getStringExtra(EXTRA_PHYSICAL_FILE_NAME) ?: suggestedName
  }
  private val suggestedEntryChars by unsafeLazy { intent.getCharArrayExtra(EXTRA_ENTRY) }
  private val shouldGeneratePassword by unsafeLazy {
    intent.getBooleanExtra(EXTRA_GENERATE_PASSWORD, false)
  }
  private val editing by unsafeLazy { intent.getBooleanExtra(EXTRA_EDITING, false) }
  /** A new entry suggested by Autofill: [suggestedName] is the web origin or app name. */
  private val autofilling by unsafeLazy { !editing && suggestedName != null }
  private val directoryStructure by unsafeLazy { AutofillPreferences.directoryStructure(this) }
  private var copy: Boolean = false
  private var pendingSave = false

  private val passSecretsUnlockAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (!pendingSave) return@registerForActivityResult
      if (result.resultCode == RESULT_OK) {
        updateMappedSuggestedNameAfterUnlock()
        continueSave()
      } else {
        pendingSave = false
      }
    }

  private val otpImportAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == RESULT_OK) {
        binding.otpImportButton.isVisible = false
        val intentResult = IntentIntegrator.parseActivityResult(RESULT_OK, result.data)
        val contents = "${intentResult.contents}\n"
        binding.extraContent.text?.let { currentExtras ->
          if (currentExtras.isNotEmpty() && currentExtras.last() != '\n')
            binding.extraContent.append("\n$contents")
          else binding.extraContent.append(contents)
        }
        snackbar(message = getString(R.string.otp_import_success))
      } else {
        snackbar(message = getString(R.string.otp_import_failure_generic))
      }
    }

  private val imageImportAction =
    registerForActivityResult(ActivityResultContracts.GetContent()) { imageUri ->
      if (imageUri == null) {
        snackbar(message = getString(R.string.otp_import_failure_no_selection))
        return@registerForActivityResult
      }
      val bitmap =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          ImageDecoder.decodeBitmap(ImageDecoder.createSource(contentResolver, imageUri))
            .copy(Bitmap.Config.ARGB_8888, true)
        } else {
          @Suppress("DEPRECATION") MediaStore.Images.Media.getBitmap(contentResolver, imageUri)
        }
      val intArray = IntArray(bitmap.width * bitmap.height)
      bitmap.getPixels(intArray, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
      val source: LuminanceSource = RGBLuminanceSource(bitmap.width, bitmap.height, intArray)
      val binaryBitmap = BinaryBitmap(HybridBinarizer(source))

      val reader = QRCodeReader()
      runCatching {
        val result = reader.decode(binaryBitmap)
        val text = result.text
        binding.extraContent.text?.let { currentExtras ->
          if (currentExtras.isNotEmpty() && currentExtras.last() != '\n')
            binding.extraContent.append("\n$text")
          else binding.extraContent.append(text)
        }
        snackbar(message = getString(R.string.otp_import_success))
        binding.otpImportButton.isVisible = false
      }
        .onErr { snackbar(message = getString(R.string.otp_import_failure_generic)) }
    }

  override fun onDestroy() {
    with(binding) {
      username.text?.clear()
      password.text?.clear()
      extraContent.text?.clear()
    }
    super.onDestroy()
  }

  private val selectFolderAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == RESULT_OK) {
        result.data?.getStringExtra(SelectFolderActivity.SELECTED_FOLDER_PATH)?.let { fullPath ->
          val relPath = PasswordRepository.getRelativePath(fullPath, repoPath)
          val path = if (relPath.isEmpty()) "/" else relPath
          binding.directory.setText(path)
        }
      }
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    supportActionBar?.setDisplayHomeAsUpEnabled(true)
    title =
      if (editing) getString(R.string.edit_password) else getString(R.string.new_password_title)
    with(binding) {
      enableEdgeToEdgeView(root)
      setContentView(root)

      generatePassword.setOnClickListener { generatePassword() }
      otpImportButton.setOnClickListener {
        supportFragmentManager.setFragmentResultListener(
          OTP_RESULT_REQUEST_KEY,
          this@PasswordCreationActivity,
        ) { requestKey, bundle ->
          if (requestKey == OTP_RESULT_REQUEST_KEY) {
            val contents = bundle.getString(RESULT)
            extraContent.text?.let { currentExtras ->
              if (currentExtras.isNotEmpty() && currentExtras.last() != '\n')
                extraContent.append("\n$contents")
              else extraContent.append(contents)
            }
          }
        }
        val hasCamera = packageManager?.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY) == true
        if (hasCamera) {
          val items =
            arrayOf(
              getString(R.string.otp_import_qr_code),
              getString(R.string.otp_import_from_file),
              getString(R.string.otp_import_manual_entry),
            )
          MaterialAlertDialogBuilder(this@PasswordCreationActivity)
            .setItems(items) { _, index ->
              when (index) {
                0 ->
                  otpImportAction.launch(
                    IntentIntegrator(this@PasswordCreationActivity)
                      .setOrientationLocked(false)
                      .setBeepEnabled(false)
                      .setDesiredBarcodeFormats(QR_CODE)
                      .createScanIntent()
                  )
                1 -> {
                  runCatching { imageImportAction.launch("image/*") }
                    .onErr { e ->
                      logcat(ERROR) { e.asLog() }
                      e.message?.let { message -> snackbar(message = message) }
                    }
                }
                2 -> OtpImportDialogFragment().show(supportFragmentManager, "OtpImport")
              }
            }
            .show()
        } else {
          OtpImportDialogFragment().show(supportFragmentManager, "OtpImport")
        }
      }

      directory.inputType = InputType.TYPE_NULL
      val relPath = PasswordRepository.getRelativePath(fullPath, repoPath)
      directory.setText(if (relPath.isEmpty()) "/" else relPath)

      directory.setOnClickListener {
        val intent = Intent(this@PasswordCreationActivity, SelectFolderActivity::class.java)
        intent.putExtra(PasswordStore.REQUEST_ARG_PATH, directory.text.toString().trimEnd('/'))
        selectFolderAction.launch(intent)
      }

      val suggestedEntry: PasswordEntry? = suggestedEntryChars?.let { encrypted ->
        AESEncryption.decrypt(encrypted)?.let { decrypted ->
          passwordEntryFactory.create(decrypted).also { decrypted.wipe() }
        }
      }

      /*
       * input fields
       */

      // visibilities
      if (editing) {
        nameInputLayout.visibility = View.GONE
        filenameInputLayout.visibility = View.VISIBLE
        if (suggestedEntry?.username == null) {
          usernameInputLayout.visibility = View.GONE
          insertUsername.apply {
            visibility = View.VISIBLE
            setOnClickListener { toggleUsernameInput(isChecked) }
          }
        } else {
          usernameInputLayout.visibility = View.VISIBLE
        }
        insertUsername.isChecked = suggestedEntry?.username != null
      } else if (autofilling) {
        when (directoryStructure) {
          DirectoryStructure.EncryptedUsername -> {}
          DirectoryStructure.FileBased -> insertUsername.visibility = View.VISIBLE
          DirectoryStructure.DirectoryBased -> {
            filenameInputLayout.visibility = View.VISIBLE
            insertUsername.visibility = View.VISIBLE
          }
        }
      } else { // new entry via app UI
        when (directoryStructure) {
          DirectoryStructure.EncryptedUsername -> {}
          DirectoryStructure.FileBased -> {
            nameInputLayout.visibility = View.GONE
            insertUsername.visibility = View.VISIBLE
          }
          DirectoryStructure.DirectoryBased -> {
            nameInputLayout.visibility = View.GONE
            usernameInputLayout.visibility = View.GONE
            filenameInputLayout.visibility = View.VISIBLE
            insertUsername.apply {
              visibility = View.VISIBLE
              setOnClickListener { toggleUsernameInput(isChecked) }
            }
          }
        }
      }

      // pre-sets
      if (editing) {
        filename.setText(suggestedName)
      } else if (autofilling) {
        name.setText(suggestedName)
      }

      suggestedEntry?.username?.let {
        val charBuf = CharBuffer.wrap(it)
        username.setText(charBuf)
        charBuf.array().wipe()
      }

      suggestedEntry?.password?.let {
        val charBuf = CharBuffer.wrap(it)
        password.setText(charBuf)
        charBuf.array()?.wipe()
        password.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
      }
      suggestedEntry?.extraContentChars?.let {
        val charBuf =
          if (it.last() == '\n') CharBuffer.wrap(it.copyOfRange(0, it.size - 1))
          else CharBuffer.wrap(it)
        extraContent.setText(charBuf)
        charBuf.array().wipe()
      }
      suggestedEntry?.clear()
      if (shouldGeneratePassword) {
        generatePassword()
        password.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
      }
    }
    listOf(binding.name, binding.username, binding.filename, binding.extraContent).forEach {
      it.doAfterTextChanged { updateViewState() }
    }
    updateViewState()
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.pgp_handler_new_password, menu)
    return true
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean {
    when (item.itemId) {
      android.R.id.home -> {
        setResult(RESULT_CANCELED)
        onBackPressedDispatcher.onBackPressed()
      }
      R.id.save_password -> beginSave(copyPassword = false)
      R.id.save_and_copy_password -> beginSave(copyPassword = true)
      else -> return super.onOptionsItemSelected(item)
    }
    return true
  }

  private fun beginSave(copyPassword: Boolean) {
    copy = copyPassword
    pendingSave = true
    continueSave()
  }

  private fun continueSave() {
    if (!pendingSave) return
    val repositoryRoot = File(repoPath)
    val destinationDirectory = destination().directory
    val sourceFile = sourcePasswordFile()
    val requiredMetadata =
      passSecretsMutationService.requiredMetadataForPasswordWrite(
        sourceFile,
        destinationDirectory,
        repositoryRoot,
      )
    val nextMetadata = requiredMetadata.firstOrNull()
    if (nextMetadata != null) {
      passSecretsUnlockAction.launch(
        PassSecretsMapUnlockActivity.newIntent(this, nextMetadata, repositoryRoot)
      )
      return
    }

    pendingSave = false
    requireKeysExist {
      requireEncryptionKeysExist(binding.directory.text.toString()) { ids -> encrypt(ids) }
    }
  }

  private fun updateMappedSuggestedNameAfterUnlock() {
    if (!editing) return
    val source = sourcePasswordFile() ?: return
    val mappedName = PassSecretsMapStore.mappedName(source, File(repoPath)) ?: return
    if (binding.filename.text?.toString() == suggestedName) binding.filename.setText(mappedName)
  }

  private fun sourcePasswordFile(): File? {
    if (!editing) return null
    val physicalName = suggestedPhysicalName ?: return null
    return File(fullPath.trimEnd('/'), "$physicalName.gpg")
  }

  /** Where an entry is written: the [directory] and the requested (logical) entry name. */
  private data class Destination(val directory: File, val requestedName: String)

  private fun isMappedDirectory(directory: File): Boolean =
    PassSecretsMapStore.mapFileForDirectory(directory, File(repoPath)) != null

  /**
   * Computes the destination of the entry from the input fields, following the directory structure
   * setting (password file organisation) for new entries:
   * - `.../example.org.gpg` (encrypted username),
   * - `.../[example.org/]john@doe.org.gpg` (file-based),
   * - `.../[example.org/john@doe.org/]password.gpg` (directory-based),
   *
   * where the bracketed parts are only added for entries created via Autofill. Inside a
   * Pass-Secrets mapped directory no plaintext sub-directories are created; the structure becomes
   * part of the (encrypted) logical entry name instead.
   */
  private fun destination(): Destination {
    with(binding) {
      val selected = selectedDirectory()
      val editName = name.text?.toString()?.trim().orEmpty()
      val editUsername = username.text?.toString()?.trim().orEmpty()
      val editFilename = filename.text?.toString()?.trim().orEmpty()
      if (editing) return Destination(selected, editFilename)
      val components =
        when (directoryStructure) {
          DirectoryStructure.EncryptedUsername -> listOf(editName)
          DirectoryStructure.FileBased ->
            if (autofilling) listOf(editName, editUsername) else listOf(editUsername)
          DirectoryStructure.DirectoryBased ->
            if (autofilling) listOf(editName, editUsername, editFilename) else listOf(editFilename)
        }
      if (isMappedDirectory(selected)) {
        return Destination(selected, components.joinToString("/"))
      }
      val directory = components.dropLast(1).fold(selected) { parent, child -> File(parent, child) }
      return Destination(directory, components.last())
    }
  }

  private fun isInvalidPathComponent(value: String, mappedDestination: Boolean): Boolean =
    !mappedDestination &&
      (value.contains('/') || value.contains('\\') || value == "." || value == "..")

  /** Checks the input fields required by the current mode, showing a message if invalid. */
  private fun validateInput(): Boolean {
    with(binding) {
      val mappedDestination = isMappedDirectory(selectedDirectory())
      val editName = name.text?.toString()?.trim().orEmpty()
      val editUsername = username.text?.toString()?.trim().orEmpty()
      val editFilename = filename.text?.toString()?.trim().orEmpty()

      // name (domain), e.g. example.org
      if (autofilling || !editing && directoryStructure == DirectoryStructure.EncryptedUsername) {
        if (editName.isBlank()) {
          name.requestFocus()
          snackbar(message = resources.getString(R.string.empty_name_toast_text))
          return false
        } else if (isInvalidPathComponent(editName, mappedDestination)) {
          name.requestFocus()
          snackbar(message = resources.getString(R.string.invalid_name_text))
          return false
        }
      }

      // username, if it is part of the file path
      if (
        (autofilling && directoryStructure != DirectoryStructure.EncryptedUsername) ||
          (!editing && directoryStructure == DirectoryStructure.FileBased)
      ) {
        if (editUsername.isBlank()) {
          username.requestFocus()
          snackbar(message = resources.getString(R.string.empty_username_toast_text))
          return false
        } else if (isInvalidPathComponent(editUsername, mappedDestination)) {
          username.requestFocus()
          snackbar(message = resources.getString(R.string.invalid_username_text))
          return false
        }
      }

      // file name
      if (editing || directoryStructure == DirectoryStructure.DirectoryBased) {
        if (editFilename.isBlank()) {
          filename.requestFocus()
          snackbar(message = resources.getString(R.string.file_toast_text))
          return false
        } else if (isInvalidPathComponent(editFilename, mappedDestination)) {
          filename.requestFocus()
          snackbar(message = resources.getString(R.string.invalid_filename_text))
          return false
        }
      }
    }
    return true
  }

  private fun toggleUsernameInput(show: Boolean) {
    with(binding) {
      if (show) {
        usernameInputLayout.visibility = View.VISIBLE
        username.requestFocus()
      } else {
        username.text?.clear()
        usernameInputLayout.visibility = View.GONE
      }
    }
  }

  private fun selectedDirectory(): File {
    val relative = binding.directory.text.toString().trim().trim('/')
    return File(repoPath, relative)
  }

  private fun generatePassword() {
    supportFragmentManager.setFragmentResultListener(PASSWORD_RESULT_REQUEST_KEY, this) {
      requestKey,
      bundle ->
      if (requestKey == PASSWORD_RESULT_REQUEST_KEY) {
        binding.password.setText(bundle.getCharSequence(RESULT))
      }
    }
    when (settings.getString(PreferenceKeys.PREF_KEY_PWGEN_TYPE) ?: KEY_PWGEN_TYPE_DICEWARE) {
      KEY_PWGEN_TYPE_CLASSIC ->
        PasswordGeneratorDialogFragment().show(supportFragmentManager, "generator")
      KEY_PWGEN_TYPE_DICEWARE ->
        DicewarePasswordGeneratorDialogFragment().show(supportFragmentManager, "generator")
    }
  }

  private fun updateViewState() =
    with(binding) {
      // Use PasswordEntry to parse extras for OTP
      val entry = passwordEntryFactory.create("PLACEHOLDER\n${extraContent.text}".toCharArray())
      val hasTotp = entry.hasTotp()
      entry.clear()
      otpImportButton.isVisible = !hasTotp
    }

  /** Encrypts the password and extra content, then atomically updates Pass-Secrets metadata. */
  private fun encrypt(identifiers: List<PGPIdentifier>) {
    with(binding) {
      if (!validateInput()) return@with
      val editUsername = username.text?.let { CharArray(it.length) { i -> it[i] } } ?: charArrayOf()
      val editPass = password.text?.let { CharArray(it.length) { i -> it[i] } } ?: charArrayOf()
      var editExtra =
        extraContent.text?.let { CharArray(it.length) { i -> it[i] } } ?: charArrayOf()
      val (destinationDirectory, requestedName) = destination()

      if (editPass.isEmpty() && editExtra.isEmpty()) {
        password.requestFocus()
        snackbar(message = resources.getString(R.string.empty_toast_text))
        return@with
      }

      if (!editExtra.isEmpty()) {
        editExtra = editExtra.let {
          val extraLines = it.splitToCharArrayListAt('\n').map { line -> line.trimEnd() }
          it.wipe()
          val trimmed = extraLines.joinToCharArray('\n')?.trimEnd()
          val withLineFeed = trimmed?.let { value -> value + '\n' }
          trimmed?.wipe()
          withLineFeed ?: charArrayOf()
        }
      }

      if (copy && editPass.isNotEmpty()) {
        clearTimer?.shutdownNow()
        clearTimer = copyPasswordToClipboard(editPass.copyOf(editPass.size))
      }

      // ensure destination dir exists
      destinationDirectory.toPath().createDirectories()
      if (!destinationDirectory.toPath().exists()) { // should not happen
        snackbar(message = "Failed to create directory ${destinationDirectory.path}")
        return@with
      }

      lifecycleScope.launch(dispatcherProvider.main()) {
        runCatching {
          val plan =
            passSecretsMutationService.planPasswordWrite(
              sourcePasswordFile(),
              destinationDirectory,
              requestedName,
              File(repoPath),
            )
          if (!plan.destinationFile.isInsideRepository()) {
            snackbar(message = getString(R.string.message_error_destination_outside_repo))
            return@runCatching
          }

          val contentChars =
            if (
              !editUsername.isEmpty() &&
                (editing ||
                  insertUsername.isChecked ||
                  directoryStructure == DirectoryStructure.EncryptedUsername)
            )
              editPass + "\nusername: ".toCharArray() + editUsername + '\n' + editExtra
            else editPass + '\n' + editExtra
          val contentBytes = contentChars.toByteArray()
          contentChars.wipe()

          val (succeededUserEmails, result) =
            withContext(dispatcherProvider.io()) {
              repository.encrypt(
                identifiers,
                ByteArrayInputStream(contentBytes),
                ByteArrayOutputStream(),
              )
            }
          contentBytes.wipe()

          if (result.isErr) throw result.unwrapError()
          if (succeededUserEmails.isNullOrEmpty()) throw UnusableKeyException

          val failedUserEmails =
            identifiers
              .map { id ->
                repository.getEmailFromKeyId(id)
                  ?: run {
                    if (!repository.hasKey(id))
                      "\n${id}: ${getString(R.string.pgp_unknown_key_identifier)}"
                    else
                      "\n${id}: ${getString(R.string.password_creation_file_encryption_failed_expired_key)}"
                  }
              }
              .distinct()
              .filter { it !in succeededUserEmails }

          val encryptedOutput = result.getOrThrow()
          val encryptedBytes = encryptedOutput.toByteArray()
          encryptedOutput.wipe()
          try {
            passSecretsMutationService.commitPasswordWrite(plan, encryptedBytes)
          } finally {
            encryptedBytes.wipe()
          }

          val preference = getSharedPreferences("recent_password_history", 0)
          preference.edit {
            sourcePasswordFile()?.let { oldFile -> remove(oldFile.absolutePath.base64()) }
            putString(
              plan.destinationFile.absolutePath.base64(),
              System.currentTimeMillis().toString(),
            )
          }

          val returnIntent = Intent()
          returnIntent.putExtra(RETURN_EXTRA_CREATED_FILE, plan.destinationFile.absolutePath)
          returnIntent.putExtra(RETURN_EXTRA_NAME, plan.logicalName)
          returnIntent.putExtra(
            RETURN_EXTRA_LONG_NAME,
            PasswordRepository.getLongName(
              destinationDirectory.absolutePath,
              repoPath,
              plan.logicalName,
            ),
          )

          if (shouldGeneratePassword) {
            // credentials to be filled into the Autofill form after creation
            if (!editPass.isEmpty()) returnIntent.putExtra(RETURN_EXTRA_PASSWORD, editPass.copyOf())
            if (!editUsername.isEmpty())
              returnIntent.putExtra(RETURN_EXTRA_USERNAME, editUsername.copyOf())
          }

          editPass.wipe()
          editUsername.wipe()
          editExtra.wipe()

          val commitMessageRes =
            if (editing) R.string.git_commit_edit_text else R.string.git_commit_add_text
          val physicalLongName =
            PasswordRepository.getLongName(
              destinationDirectory.absolutePath,
              repoPath,
              plan.destinationFile.nameWithoutExtension,
            )
          lifecycleScope.launch {
            commitChange(resources.getString(commitMessageRes, physicalLongName)).onOk {
              setResult(RESULT_OK, returnIntent)
              val dialog =
                MaterialAlertDialogBuilder(this@PasswordCreationActivity)
                  .setCancelable(false)
                  .setPositiveButton(android.R.string.ok) { _, _ -> finish() }
              var messageText =
                getString(
                  R.string.password_creation_file_encryption_succeeded_ids_message,
                  succeededUserEmails.joinToString(),
                )
              if (failedUserEmails.isNotEmpty()) {
                dialog.setTitle(R.string.password_creation_file_encryption_partial_success_title)
                messageText +=
                  getString(
                    R.string.password_creation_file_encryption_failed_ids_message,
                    failedUserEmails.joinToString(),
                  )
              } else {
                val title =
                  if (editing)
                    getString(R.string.password_creation_edit_file_encryption_success_title)
                  else getString(R.string.password_creation_new_file_encryption_success_title)
                dialog.setTitle(title)
              }
              dialog.setMessage(messageText)
              dialog.show()
            }
          }
        }
          .onErr { e ->
            logcat(ERROR) { e.asLog() }
            editPass.wipe()
            editUsername.wipe()
            editExtra.wipe()
            setResult(RESULT_CANCELED)
            val errMessage =
              when (e) {
                is IOException -> getString(R.string.password_creation_file_write_fail_message)
                is NoKeysProvidedException ->
                  getString(R.string.password_creation_no_keys_provided_message)
                is UnusableKeyException ->
                  getString(R.string.password_creation_unusable_encryption_key_error_message)
                else -> e.message ?: e.toString()
              }
            MaterialAlertDialogBuilder(this@PasswordCreationActivity)
              .setIcon(R.drawable.ic_crossmark_red_24dp)
              .setTitle(getString(R.string.error))
              .setMessage(errMessage)
              .setCancelable(false)
              .setPositiveButton(android.R.string.ok, null)
              .show()
          }
      }
    }
  }

  companion object {

    private const val KEY_PWGEN_TYPE_CLASSIC = "classic"
    private const val KEY_PWGEN_TYPE_DICEWARE = "diceware"
    const val PASSWORD_RESULT_REQUEST_KEY = "PASSWORD_GENERATOR"
    const val OTP_RESULT_REQUEST_KEY = "OTP_IMPORT"
    const val RESULT = "RESULT"
    const val RETURN_EXTRA_CREATED_FILE = "CREATED_FILE"
    const val RETURN_EXTRA_NAME = "NAME"
    const val RETURN_EXTRA_LONG_NAME = "LONG_NAME"
    const val RETURN_EXTRA_USERNAME = "USERNAME"
    const val RETURN_EXTRA_PASSWORD = "PASSWORD"
    const val EXTRA_FILE_NAME = "EXTRA_FILENAME"
    const val EXTRA_PHYSICAL_FILE_NAME = "EXTRA_PHYSICAL_FILENAME"
    const val EXTRA_ENTRY = "EXTRA_ENTRY"
    const val EXTRA_GENERATE_PASSWORD = "EXTRA_GENERATE_PASSWORD"
    const val EXTRA_EDITING = "EXTRA_EDITING"
  }
}
