/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.provider

import android.content.Context
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.annotation.RequiresApi
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.storage.PasskeyStorage
import com.github.michaelbull.result.fold
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import logcat.LogPriority
import logcat.logcat

public object PasskeyAutofillHelper {

  @RequiresApi(android.os.Build.VERSION_CODES.O)
  public fun addPasskeyDatasets(
    builder: FillResponse.Builder,
    context: Context,
    usernameAutofillId: AutofillId?,
    rpId: String,
    passkeyStorage: PasskeyStorage,
    maxDatasets: Int = 3,
  ): Int {
    if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.O) return 0
    if (usernameAutofillId == null) return 0

    val credentials = runBlocking(Dispatchers.IO) {
      passkeyStorage.listCredentials(rpId).fold(
        success = { it },
        failure = {
          logcat(LogPriority.WARN) { "Failed to load passkeys for $rpId: $it" }
          emptyList()
        }
      )
    }

    if (credentials.isEmpty()) return 0

    var datasetCount = 0
    for (credential in credentials.take(maxDatasets)) {
      val dataset = makePasskeyDataset(context, usernameAutofillId, credential)
      if (dataset != null) {
        builder.addDataset(dataset)
        datasetCount++
      }
    }

    return datasetCount
  }

  @RequiresApi(android.os.Build.VERSION_CODES.O)
  private fun makePasskeyDataset(
    context: Context,
    usernameAutofillId: AutofillId,
    credential: PasskeyCredential,
  ): Dataset? {
    val builder = Dataset.Builder(createRemoteViews(context, credential.displayNameOrName()))
    builder.setValue(usernameAutofillId, AutofillValue.forText(credential.user.name))
    return builder.build()
  }

  @RequiresApi(android.os.Build.VERSION_CODES.O)
  private fun createRemoteViews(context: Context, displayText: String): RemoteViews {
    val packageName = context.packageName
    return RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
      setTextViewText(android.R.id.text1, "Passkey: $displayText")
    }
  }

  public fun hasPasskeysForRp(
    passkeyStorage: PasskeyStorage,
    rpId: String,
  ): Boolean {
    return runBlocking(Dispatchers.IO) {
      passkeyStorage.listCredentials(rpId).fold(
        success = { it.isNotEmpty() },
        failure = { false }
      )
    }
  }

  public fun extractRpIdFromPackageName(packageName: String): String {
    val parts = packageName.split(".")
    return if (parts.size >= 2) {
      "${parts.last()}.${parts[parts.size - 2]}"
    } else {
      packageName
    }
  }

  public fun extractRpIdFromWebDomain(domain: String): String {
    val parts = domain.removePrefix("www.").removePrefix("m.").split(".")
    return if (parts.size >= 2) {
      parts.takeLast(2).joinToString(".")
    } else {
      domain
    }
  }

  public fun matchRpId(possibleRpIds: Collection<String>, targetRpId: String): String? {
    return possibleRpIds.find { it.equals(targetRpId, ignoreCase = true) }
      ?: possibleRpIds.find { rpId ->
        val normalizedTarget = targetRpId.lowercase().removePrefix("www.").removePrefix("m.")
        val normalizedRp = rpId.lowercase().removePrefix("www.").removePrefix("m.")
        normalizedTarget == normalizedRp || normalizedTarget.endsWith(".$normalizedRp") || normalizedRp.endsWith(".$normalizedTarget")
      }
  }
}