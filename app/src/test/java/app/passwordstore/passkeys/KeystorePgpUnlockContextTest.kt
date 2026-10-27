/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkeys

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking

class KeystorePgpUnlockContextTest {

  @Test
  fun `unlockKey returns null when cache is empty`() = runBlocking {
    val cache = TestPassphraseCache()
    val context = KeystorePgpUnlockContext(cache)
    assertNull(context.unlockKey("some-key-id"))
  }

  @Test
  fun `unlockKey returns null for unknown key`() = runBlocking {
    val cache = TestPassphraseCache()
    cache.putDirect("known-key", "passphrase".toCharArray())
    val context = KeystorePgpUnlockContext(cache)
    assertNull(context.unlockKey("unknown-key"))
  }

  @Test
  fun `passkey requests cannot clear another in-flight unlock session`() = runBlocking {
    val cache = TestPassphraseCache()
    val releaseFirst = CompletableDeferred<Unit>()
    val firstStarted = CompletableDeferred<Unit>()
    val secondStarted = CompletableDeferred<Unit>()
    val first =
      async(start = CoroutineStart.UNDISPATCHED) {
        cache.withExclusiveGetRequest {
          firstStarted.complete(Unit)
          releaseFirst.await()
        }
      }
    firstStarted.await()
    val second =
      async(start = CoroutineStart.UNDISPATCHED) {
        cache.withExclusiveGetRequest { secondStarted.complete(Unit) }
      }
    assertFalse(secondStarted.isCompleted)
    releaseFirst.complete(Unit)
    first.await()
    second.await()
    assertTrue(secondStarted.isCompleted)
    assertEquals(4, cache.clearCount)
  }

  private class TestPassphraseCache : PasskeyPassphraseCache() {
    var clearCount = 0

    override fun clear() {
      clearCount++
      super.clear()
    }

    private val store = mutableMapOf<String, CharArray>()

    fun putDirect(keyId: String, passphrase: CharArray) {
      store[keyId] = passphrase
    }

    override fun get(keyId: String): CharArray? = store[keyId]?.copyOf()

    override fun contains(keyId: String): Boolean = store.containsKey(keyId)
  }
}
