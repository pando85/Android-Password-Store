/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.injection.passkeys

import android.content.Context
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.crypto.PGPainlessCryptoHandler
import app.passwordstore.passkeys.BiometricPasskeyAuthenticator
import app.passwordstore.passkeys.DefaultWebAuthnCallerVerifier
import app.passwordstore.passkeys.crypto.ES256CryptoHandler
import app.passwordstore.passkeys.crypto.PasskeyCryptoHandler
import app.passwordstore.passkeys.provider.PasskeyAuthenticator
import app.passwordstore.passkeys.provider.caller.WebAuthnCallerVerifier
import app.passwordstore.passkeys.storage.FilePasskeyStorage
import app.passwordstore.passkeys.storage.IndexedPasskeyStorage
import app.passwordstore.passkeys.storage.PasskeyStorage
import app.passwordstore.passkeys.storage.PasskeyStorageConfig
import com.github.michaelbull.result.get
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import java.io.File
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object PasskeysModule {

  @Provides
  @Singleton
  fun providePasskeyCryptoHandler(): PasskeyCryptoHandler = ES256CryptoHandler()

  @Provides
  @Singleton
  fun providePasskeyAuthenticator(): PasskeyAuthenticator = BiometricPasskeyAuthenticator()

  @Provides
  @Singleton
  fun provideCallerVerifier(@ApplicationContext context: Context): WebAuthnCallerVerifier =
    DefaultWebAuthnCallerVerifier(context)

  @Provides
  @Singleton
  fun providePasskeyStorage(
    @ApplicationContext context: Context,
    cryptoHandler: PGPainlessCryptoHandler,
    keyManager: PGPKeyManager,
  ): PasskeyStorage {
    val repositoryRoot = File(context.filesDir, "store")
    val passkeyConfig = PasskeyStorageConfig(passkeyDirectory = "fido2", fileExtension = ".gpg")
    val fileStorage =
      FilePasskeyStorage(
        repositoryRoot = repositoryRoot,
        cryptoHandler = cryptoHandler,
        decryptionKeys = { keyManager.getAllKeys().get() ?: emptyList() },
        decryptionPassphrase = { null },
        encryptionKeys = { keyManager.getAllKeys().get() ?: emptyList() },
        decryptionOptions = app.passwordstore.crypto.PGPDecryptOptions.Builder().build(),
        encryptionOptions = app.passwordstore.crypto.PGPEncryptOptions.Builder().build(),
        config = passkeyConfig,
      )
    return IndexedPasskeyStorage(fileStorage)
  }
}
