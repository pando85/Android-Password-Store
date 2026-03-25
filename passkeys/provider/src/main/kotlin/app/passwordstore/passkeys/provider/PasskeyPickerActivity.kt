/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.provider

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContract
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import app.passwordstore.passkeys.model.PasskeyCredential

public class PasskeyPickerActivity : AppCompatActivity() {

  private var credentials: List<CredentialSummary> = emptyList()

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    val credentialIds = intent?.getStringArrayExtra(EXTRA_CREDENTIAL_IDS) ?: emptyArray()
    val userNames = intent?.getStringArrayExtra(EXTRA_USER_NAMES) ?: emptyArray()
    val displayNames = intent?.getStringArrayExtra(EXTRA_DISPLAY_NAMES) ?: emptyArray()
    val rpId = intent?.getStringExtra(EXTRA_RP_ID) ?: ""

    credentials = credentialIds.mapIndexed { index, id ->
      CredentialSummary(
        credentialId = id,
        userName = userNames.getOrNull(index) ?: "",
        displayName = displayNames.getOrNull(index) ?: "",
      )
    }

    val recyclerView =
      RecyclerView(this).apply {
        layoutManager = LinearLayoutManager(this@PasskeyPickerActivity)
        adapter =
          CredentialAdapter(credentials) { credential ->
            val resultIntent =
              Intent().apply { putExtra(EXTRA_SELECTED_CREDENTIAL_ID, credential.credentialId) }
            setResult(Activity.RESULT_OK, resultIntent)
            finish()
          }
        setPadding(16, 16, 16, 16)
      }
    setContentView(recyclerView)

    title = rpId
  }

  private class CredentialAdapter(
    private val credentials: List<CredentialSummary>,
    private val onCredentialSelected: (CredentialSummary) -> Unit,
  ) : RecyclerView.Adapter<CredentialViewHolder>() {

    override fun onCreateViewHolder(
      parent: android.view.ViewGroup,
      viewType: Int,
    ): CredentialViewHolder {
      val view =
        TextView(parent.context).apply {
          setPadding(48, 32, 48, 32)
          textSize = 16f
          gravity = Gravity.START or Gravity.CENTER_VERTICAL
          setOnClickListener { tag?.let { onCredentialSelected(it as CredentialSummary) } }
        }
      return CredentialViewHolder(view)
    }

    override fun onBindViewHolder(holder: CredentialViewHolder, position: Int) {
      holder.bind(credentials[position])
    }

    override fun getItemCount(): Int = credentials.size
  }

  private class CredentialViewHolder(private val textView: TextView) :
    RecyclerView.ViewHolder(textView) {

    fun bind(credential: CredentialSummary) {
      val displayText = buildString {
        append(credential.displayName.ifEmpty { credential.userName })
        if (credential.displayName.isNotEmpty() && credential.userName.isNotEmpty()) {
          append("\n")
          append(credential.userName)
        }
      }
      textView.text = displayText
      textView.tag = credential
    }
  }

  public data class CredentialSummary(
    public val credentialId: String,
    public val userName: String,
    public val displayName: String,
  )

  public class Contract : ActivityResultContract<PickerInput, String?>() {
    override fun createIntent(context: Context, input: PickerInput): Intent {
      return Intent(context, PasskeyPickerActivity::class.java).apply {
        putExtra(EXTRA_CREDENTIAL_IDS, input.credentialIds.toTypedArray())
        putExtra(EXTRA_USER_NAMES, input.userNames.toTypedArray())
        putExtra(EXTRA_DISPLAY_NAMES, input.displayNames.toTypedArray())
        putExtra(EXTRA_RP_ID, input.rpId)
      }
    }

    override fun parseResult(resultCode: Int, intent: Intent?): String? {
      return if (resultCode == Activity.RESULT_OK) {
        intent?.getStringExtra(EXTRA_SELECTED_CREDENTIAL_ID)
      } else {
        null
      }
    }
  }

  public data class PickerInput(
    public val credentialIds: List<String>,
    public val userNames: List<String>,
    public val displayNames: List<String>,
    public val rpId: String,
  ) {
    public companion object {
      public fun fromCredentials(credentials: List<PasskeyCredential>, rpId: String): PickerInput {
        return PickerInput(
          credentialIds = credentials.map { it.credentialIdBase64() },
          userNames = credentials.map { it.user.name },
          displayNames = credentials.map { it.user.displayName },
          rpId = rpId,
        )
      }
    }
  }

  public companion object {
    public const val EXTRA_CREDENTIAL_IDS: String = "extra_credential_ids"
    public const val EXTRA_USER_NAMES: String = "extra_user_names"
    public const val EXTRA_DISPLAY_NAMES: String = "extra_display_names"
    public const val EXTRA_RP_ID: String = "extra_rp_id"
    public const val EXTRA_SELECTED_CREDENTIAL_ID: String = "extra_selected_credential_id"
  }
}
