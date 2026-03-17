/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import androidx.fragment.app.FragmentActivity
import app.passwordstore.R
import app.passwordstore.passkeys.provider.PasskeyAuthenticator
import app.passwordstore.util.auth.BiometricAuthenticator
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

@Singleton
class BiometricPasskeyAuthenticator @Inject constructor() : PasskeyAuthenticator {

  override suspend fun authenticateForPasskey(
    activity: FragmentActivity,
    rpId: String,
  ): PasskeyAuthenticator.Result = suspendCancellableCoroutine { continuation ->
    BiometricAuthenticator.authenticate(
      activity = activity,
      dialogTitleRes = R.string.passkey_auth_title,
      dialogDescriptionRes = R.string.passkey_auth_description,
      allowPin = true,
    ) { result ->
      if (continuation.isActive) {
        continuation.resume(convertResult(result))
      }
    }
  }

  override suspend fun authenticateForCreation(
    activity: FragmentActivity,
    rpId: String,
  ): PasskeyAuthenticator.Result = suspendCancellableCoroutine { continuation ->
    BiometricAuthenticator.authenticate(
      activity = activity,
      dialogTitleRes = R.string.passkey_create_auth_title,
      dialogDescriptionRes = R.string.passkey_auth_description,
      allowPin = true,
    ) { result ->
      if (continuation.isActive) {
        continuation.resume(convertResult(result))
      }
    }
  }

  override fun canAuthenticate(activity: FragmentActivity): Boolean {
    return BiometricAuthenticator.canAuthenticate(activity, allowPin = true)
  }

  private fun convertResult(result: BiometricAuthenticator.Result): PasskeyAuthenticator.Result {
    return when (result) {
      is BiometricAuthenticator.Result.Success -> PasskeyAuthenticator.Result.Success
      is BiometricAuthenticator.Result.Failure ->
        PasskeyAuthenticator.Result.Failure(result.message.toString())
      is BiometricAuthenticator.Result.Retry ->
        PasskeyAuthenticator.Result.Failure("Authentication retry required")
      is BiometricAuthenticator.Result.HardwareUnavailableOrDisabled ->
        PasskeyAuthenticator.Result.NotAvailable
      is BiometricAuthenticator.Result.CanceledByUser -> PasskeyAuthenticator.Result.Canceled
      is BiometricAuthenticator.Result.CanceledBySystem -> PasskeyAuthenticator.Result.Canceled
    }
  }
}
