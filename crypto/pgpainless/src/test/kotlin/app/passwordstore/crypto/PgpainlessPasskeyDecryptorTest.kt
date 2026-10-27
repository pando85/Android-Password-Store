/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.crypto

import app.passwordstore.crypto.CryptoConstants.KEY_ID
import app.passwordstore.crypto.CryptoConstants.KEY_PASSPHRASE
import app.passwordstore.crypto.CryptoConstants.PLAIN_TEXT
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.passkeys.crypto.PgpUnlockContext
import app.passwordstore.passkeys.security.PasskeyInputLimits
import com.github.michaelbull.result.unwrap
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class PgpainlessPasskeyDecryptorTest {

  @get:Rule val temporaryFolder: TemporaryFolder = TemporaryFolder()

  @Test
  fun `unlocks a key encrypted to its subkey with the passphrase cached by primary key ID`() =
    runTest {
      val cryptoHandler = PGPainlessCryptoHandler()
      val keyManager = PGPKeyManager(temporaryFolder.root.absolutePath)
      keyManager.addKey(PGPKey(TestUtils.getArmoredSecretKey())).unwrap()
      val ciphertext = ByteArrayOutputStream()
      cryptoHandler
        .encrypt(
          listOf(PGPKey(TestUtils.getArmoredPublicKey())),
          null,
          PLAIN_TEXT.byteInputStream(),
          ciphertext,
          PGPEncryptOptions.Builder().build(),
        )
        .unwrap()
      val recipientPrimaryKeyIds =
        PgpainlessPasskeyDecryptor(cryptoHandler, keyManager)
          .inspectRecipientPrimaryKeyIds(ciphertext.toByteArray(), PasskeyInputLimits.DEFAULT)
      assertEquals(setOf(KeyId(KEY_ID).toString()), recipientPrimaryKeyIds)

      val unlockContext =
        object : PgpUnlockContext {
          override suspend fun unlockKey(keyId: String) =
            KEY_PASSPHRASE.toCharArray().takeIf { keyId == KeyId(KEY_ID).toString() }
        }

      val plaintext =
        PgpainlessPasskeyDecryptor(cryptoHandler, keyManager)
          .decryptFromBytes(ciphertext.toByteArray(), unlockContext)
          .unwrap()

      assertEquals(PLAIN_TEXT, plaintext.bytes().decodeToString())
    }
}
