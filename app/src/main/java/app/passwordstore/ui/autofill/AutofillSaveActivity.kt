/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.os.Bundle
import android.view.autofill.AutofillManager
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.appcompat.app.AppCompatActivity
import app.passwordstore.data.passfile.joinToCharArray
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.ui.crypto.PasswordCreationActivity
import app.passwordstore.util.autofill.AutofillMatcher
import app.passwordstore.util.autofill.AutofillPasskeyExclusion
import app.passwordstore.util.autofill.AutofillPreferences
import app.passwordstore.util.autofill.AutofillResponseBuilder
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.extensions.wipe
import com.github.androidpasswordstore.autofillparser.AutofillAction
import com.github.androidpasswordstore.autofillparser.Credentials
import com.github.androidpasswordstore.autofillparser.FormOrigin
import dagger.hilt.android.AndroidEntryPoint
import java.io.File
import java.nio.file.Path
import logcat.LogPriority.ERROR
import logcat.logcat

@AndroidEntryPoint
class AutofillSaveActivity : AppCompatActivity() {

  companion object {

    private const val EXTRA_ENTRY = "app.passwordstore.autofill.oreo.ui.EXTRA_ENTRY"
    private const val EXTRA_NAME = "app.passwordstore.autofill.oreo.ui.EXTRA_NAME"
    private const val EXTRA_SHOULD_MATCH_APP =
      "app.passwordstore.autofill.oreo.ui.EXTRA_SHOULD_MATCH_APP"
    private const val EXTRA_SHOULD_MATCH_WEB =
      "app.passwordstore.autofill.oreo.ui.EXTRA_SHOULD_MATCH_WEB"
    private const val EXTRA_GENERATE_PASSWORD =
      "app.passwordstore.autofill.oreo.ui.EXTRA_GENERATE_PASSWORD"

    private var saveRequestCode = 1

    fun makeSaveIntentSender(
      context: Context,
      credentials: Credentials?,
      formOrigin: FormOrigin,
      clientState: Bundle,
    ): IntentSender {
      val identifier =
        formOrigin.getPrettyIdentifier(context, untrusted = false) // web origin or app name
      // Prevent directory traversals
      val origin =
        identifier.replace('\\', '_').replace('/', '_').trimStart('.').takeUnless { it.isBlank() }
          ?: formOrigin.identifier
      // The username is always passed on so that it can be pre-filled for every password file
      // organisation (directory structure).
      val clearCredentials = credentials?.let {
        listOf(
            it.password ?: charArrayOf(),
            "\nusername: ".toCharArray(),
            it.username ?: charArrayOf(),
          )
          .joinToCharArray()
      }
      val encryptedCredentials = AESEncryption.encrypt(clearCredentials)
      credentials?.password?.wipe()
      clearCredentials?.wipe()

      val intent =
        Intent(context, AutofillSaveActivity::class.java).apply {
          putExtras(
            Bundle().also {
              it.apply {
                putBundle(AutofillManager.EXTRA_CLIENT_STATE, clientState)
                putString(EXTRA_NAME, origin)
                putCharArray(EXTRA_ENTRY, encryptedCredentials)
                putString(
                  EXTRA_SHOULD_MATCH_APP,
                  formOrigin.identifier.takeIf { formOrigin is FormOrigin.App },
                )
                putString(
                  EXTRA_SHOULD_MATCH_WEB,
                  formOrigin.identifier.takeIf { formOrigin is FormOrigin.Web },
                )
                putBoolean(EXTRA_GENERATE_PASSWORD, credentials == null)
              }
            }
          )
        }
      return PendingIntent.getActivity(
          context,
          saveRequestCode++,
          intent,
          PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        .intentSender
    }
  }

  /**
   * Searches for existing records related to the web origin/app name [origin] in the password store
   * and returns the folder containing them (`<folder>/<origin>/` or `<folder>/<origin>.gpg`), so
   * that new related logins are saved close to existing ones. Passkey credentials are ignored.
   */
  private fun findExistingFolderFor(repo: File, origin: String): File? {
    fun List<Path>.firstClassicParent(): File? {
      val match =
        map(Path::toFile).firstOrNull {
          !AutofillPasskeyExclusion.isPasskeyCredentialFile(it, repo)
        }
      return match?.parentFile
    }
    return PasswordRepository.findByName(repo.absolutePath, origin, PasswordRepository.TYPE_DIR)
      .firstClassicParent()
      ?: PasswordRepository.findByName(
          repo.absolutePath,
          "$origin.gpg",
          PasswordRepository.TYPE_FILE,
        )
        .firstClassicParent()
  }

  private val formOrigin by unsafeLazy {
    val shouldMatchApp: String? = intent.getStringExtra(EXTRA_SHOULD_MATCH_APP)
    val shouldMatchWeb: String? = intent.getStringExtra(EXTRA_SHOULD_MATCH_WEB)
    if (shouldMatchApp != null && shouldMatchWeb == null) {
      FormOrigin.App(shouldMatchApp)
    } else if (shouldMatchApp == null && shouldMatchWeb != null) {
      FormOrigin.Web(shouldMatchWeb)
    } else {
      null
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val repo = PasswordRepository.getRepositoryDirectory()
    val origin = intent.getStringExtra(EXTRA_NAME) ?: throw NullPointerException()
    val destinationFolder =
      findExistingFolderFor(repo, origin)
        ?: AutofillPreferences.saveDirectory(this)?.let(repo::resolve)
        ?: repo
    val saveIntent =
      Intent(this, PasswordCreationActivity::class.java).apply {
        putExtras(
          Bundle().also {
            it.apply {
              putString(BasePGPActivity.EXTRA_REPO_PATH, repo.absolutePath)
              putString(
                BasePGPActivity.EXTRA_FILE_PATH,
                destinationFolder.absolutePath,
              )
              putString(PasswordCreationActivity.EXTRA_FILE_NAME, origin)
              putCharArray(
                PasswordCreationActivity.EXTRA_ENTRY,
                intent.getCharArrayExtra(EXTRA_ENTRY),
              )
              putBoolean(
                PasswordCreationActivity.EXTRA_GENERATE_PASSWORD,
                intent.getBooleanExtra(EXTRA_GENERATE_PASSWORD, false),
              )
            }
          }
        )
      }
    registerForActivityResult(StartActivityForResult()) { result ->
        val data = result.data
        if (result.resultCode == RESULT_OK && data != null) {
          val createdPath = data.getStringExtra("CREATED_FILE") ?: throw NullPointerException()
          formOrigin?.let { AutofillMatcher.addMatchFor(this, it, File(createdPath)) }
          val password = data.getCharArrayExtra("PASSWORD")
          val resultIntent =
            if (password != null) {
              // Password was generated and should be filled into a form.
              val username = data.getCharArrayExtra("USERNAME")
              val clientState =
                intent?.getBundleExtra(AutofillManager.EXTRA_CLIENT_STATE)
                  ?: run {
                    logcat(ERROR) { "AutofillSaveActivity started without EXTRA_CLIENT_STATE" }
                    finish()
                    return@registerForActivityResult
                  }
              val credentials = Credentials(username, password, null)
              val fillInDataset =
                AutofillResponseBuilder.makeFillInDataset(
                  this,
                  credentials,
                  clientState,
                  AutofillAction.Generate,
                )
              Intent().apply {
                putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, fillInDataset)
              }
            } else {
              // Password was extracted from a form, there is nothing to fill.
              Intent()
            }
          setResult(RESULT_OK, resultIntent)
        } else {
          setResult(RESULT_CANCELED)
        }
        finish()
      }
      .launch(saveIntent)
  }
}
