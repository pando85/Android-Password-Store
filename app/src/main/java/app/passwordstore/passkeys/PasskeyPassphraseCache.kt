/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.sync.Mutex

@Singleton
open class PasskeyPassphraseCache @Inject constructor() {

  private val cache = ConcurrentHashMap<String, CharArray>()
  private val getRequestMutex = Mutex()

  /** Serialize get-credential requests sharing this temporary PGP passphrase store. */
  suspend fun <T> withExclusiveGetRequest(block: suspend () -> T): T {
    getRequestMutex.lock()
    try {
      clear()
      return block()
    } finally {
      clear()
      getRequestMutex.unlock()
    }
  }

  @Synchronized
  open fun put(keyId: String, passphrase: CharArray) {
    val encrypted =
      try {
        AESEncryption.encrypt(passphrase, KeyType.TEMPORARY)
      } finally {
        passphrase.fill('\u0000')
      } ?: return
    cache.put(keyId, encrypted)?.fill('\u0000')
  }

  @Synchronized
  open fun get(keyId: String): CharArray? {
    val encrypted = cache[keyId] ?: return null
    return AESEncryption.decrypt(encrypted, KeyType.TEMPORARY)
  }

  @Synchronized
  open fun contains(keyId: String): Boolean = cache.containsKey(keyId)

  @Synchronized
  open fun clear() {
    cache.values.forEach { it.fill('\u0000') }
    cache.clear()
  }
}
