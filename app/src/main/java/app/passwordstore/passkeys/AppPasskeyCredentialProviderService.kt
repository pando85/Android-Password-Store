/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import androidx.annotation.RequiresApi
import app.passwordstore.passkeys.crypto.PasskeyCryptoHandler
import app.passwordstore.passkeys.provider.PasskeyCredentialProviderService
import app.passwordstore.passkeys.storage.PasskeyRemoteRefresher
import app.passwordstore.passkeys.storage.PasskeyRepositoryState
import app.passwordstore.passkeys.storage.PasskeyStorage
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.EntryPointAccessors
import dagger.hilt.components.SingletonComponent

@RequiresApi(34)
class AppPasskeyCredentialProviderService : PasskeyCredentialProviderService() {

  private val entryPoint: PasskeysEntryPoint
    get() = EntryPointAccessors.fromApplication(applicationContext)

  override val passkeyStorage: PasskeyStorage
    get() = entryPoint.passkeyStorage()

  override val cryptoHandler: PasskeyCryptoHandler
    get() = entryPoint.passkeyCryptoHandler()

  override val providerActivity: Class<out android.app.Activity>
    get() = AppPasskeyProviderActivity::class.java

  override val remoteRefresher: PasskeyRemoteRefresher
    get() = entryPoint.remoteRefresher()

  override val passkeyRepositoryState: PasskeyRepositoryState
    get() = entryPoint.passkeyRepositoryState()

  @EntryPoint
  @InstallIn(SingletonComponent::class)
  interface PasskeysEntryPoint {

    fun passkeyStorage(): PasskeyStorage

    fun passkeyCryptoHandler(): PasskeyCryptoHandler

    fun remoteRefresher(): PasskeyRemoteRefresher

    fun passkeyRepositoryState(): PasskeyRepositoryState
  }
}
