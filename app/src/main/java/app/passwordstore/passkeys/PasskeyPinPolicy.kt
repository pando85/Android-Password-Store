/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkeys

/** Strict format of the existing Fast Unlock PIN record: '<attempts>:<pin>'. */
internal object PasskeyPinPolicy {
  data class Record(val attempts: Int, val pin: CharArray)

  fun parse(plaintext: CharArray): Record? {
    val separator = plaintext.indexOf(':')
    if (separator <= 0 || separator == plaintext.lastIndex) return null
    val count =
      plaintext.copyOfRange(0, separator).concatToString().toIntOrNull() ?: return null
    if (count !in 0..3) return null
    return Record(count, plaintext.copyOfRange(separator + 1, plaintext.size))
  }

  fun constantTimeEquals(expected: CharArray, actual: CharArray): Boolean {
    var difference = expected.size xor actual.size
    for (i in 0 until maxOf(expected.size, actual.size)) {
      val left = if (i < expected.size) expected[i].code else 0
      val right = if (i < actual.size) actual[i].code else 0
      difference = difference or (left xor right)
    }
    return difference == 0
  }
}
