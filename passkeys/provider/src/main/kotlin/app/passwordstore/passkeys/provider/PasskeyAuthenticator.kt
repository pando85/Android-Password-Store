/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.provider

import androidx.fragment.app.FragmentActivity

/**
 * Interface for handling user verification before passkey operations.
 *
 * WebAuthn requires user verification (biometrics, PIN, etc.) before creating or using passkeys.
 * Implementations should integrate with the platform's biometric authentication system.
 */
public interface PasskeyAuthenticator {

  /** Result of an authentication attempt. */
  public sealed class Result {
    /** Authentication was successful. */
    public data object Success : Result()

    /** User canceled the authentication prompt. */
    public data object Canceled : Result()

    /** Authentication is not available on this device. */
    public data object NotAvailable : Result()

    /** Authentication failed with an error. */
    public data class Failure(val message: String) : Result()
  }

  /**
   * Authenticates the user before using a passkey for authentication.
   *
   * @param activity The activity context for showing the biometric prompt
   * @param rpId The Relying Party ID for display purposes
   * @return The result of the authentication attempt
   */
  public suspend fun authenticateForPasskey(activity: FragmentActivity, rpId: String): Result

  /**
   * Authenticates the user before creating a new passkey.
   *
   * @param activity The activity context for showing the biometric prompt
   * @param rpId The Relying Party ID for display purposes
   * @return The result of the authentication attempt
   */
  public suspend fun authenticateForCreation(activity: FragmentActivity, rpId: String): Result

  /**
   * Checks if biometric authentication is available on this device.
   *
   * @param activity The activity context
   * @return True if authentication is possible
   */
  public fun canAuthenticate(activity: FragmentActivity): Boolean
}
