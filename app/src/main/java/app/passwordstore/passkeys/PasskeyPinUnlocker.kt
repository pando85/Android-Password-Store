/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkeys

import android.annotation.SuppressLint
import android.content.SharedPreferences
import app.passwordstore.injection.prefs.PGPPassphrases
import app.passwordstore.injection.prefs.UnlockPins
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import javax.inject.Inject

/**
 * Validates the app's Fast Unlock PIN before unwrapping the PGP passphrase.
 *
 * PIN failure counters require durable writes before reporting an authentication result. Using
 * apply() would allow an app crash to reset the counter, so these writes use commit() deliberately.
 */
@SuppressLint("ApplySharedPref")
class PasskeyPinUnlocker
@Inject
constructor(
  @UnlockPins private val unlockPins: SharedPreferences,
  @PGPPassphrases private val persistentPassphrases: SharedPreferences,
) {
  sealed interface Result {
    data class Unlocked(val passphrase: CharArray) : Result

    data object Incorrect : Result

    data object LockedOut : Result

    data object Unavailable : Result
  }

  fun unlock(
    persistedId: String,
    encryptedPassphrase: CharArray,
    candidatePin: CharArray,
  ): Result {
    val encryptedPin =
      unlockPins.getString(persistedId, null)?.toCharArray() ?: return Result.Unavailable
    val plaintextPin =
      try {
        AESEncryption.decrypt(encryptedPin, keyType = KeyType.PERSISTENT)
      } finally {
        encryptedPin.fill('\u0000')
      } ?: return Result.Unavailable
    val record =
      try {
        PasskeyPinPolicy.parse(plaintextPin)
      } finally {
        plaintextPin.fill('\u0000')
      } ?: return Result.Unavailable

    try {
      if (record.attempts >= MAX_RETRIES) {
        invalidate(persistedId)
        return Result.LockedOut
      }

      if (!PasskeyPinPolicy.constantTimeEquals(record.pin, candidatePin)) {
        val attempts = record.attempts + 1
        if (attempts >= MAX_RETRIES) {
          invalidate(persistedId)
          return Result.LockedOut
        }
        if (!storeAttempts(persistedId, attempts, record.pin)) return Result.Unavailable
        return Result.Incorrect
      }

      val passphrase =
        AESEncryption.decrypt(encryptedPassphrase, keyType = KeyType.PERSISTENT)
          ?: return Result.Unavailable
      if (!storeAttempts(persistedId, 0, record.pin)) {
        passphrase.fill('\u0000')
        return Result.Unavailable
      }
      return Result.Unlocked(passphrase)
    } finally {
      record.pin.fill('\u0000')
    }
  }

  private fun storeAttempts(id: String, attempts: Int, pin: CharArray): Boolean {
    val plaintext = (attempts.toString() + ":").toCharArray() + pin
    val ciphertext =
      try {
        AESEncryption.encrypt(plaintext, KeyType.PERSISTENT)
      } finally {
        plaintext.fill('\u0000')
      } ?: return false
    return try {
      unlockPins.edit().putString(id, ciphertext.concatToString()).commit()
    } finally {
      ciphertext.fill('\u0000')
    }
  }

  private fun invalidate(id: String) {
    unlockPins.edit().remove(id).commit()
    persistentPassphrases.edit().remove(id).commit()
  }

  private companion object {
    const val MAX_RETRIES = 3
  }
}
