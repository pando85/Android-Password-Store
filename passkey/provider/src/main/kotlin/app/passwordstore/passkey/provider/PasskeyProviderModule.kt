/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey.provider

import com.squareup.moshi.Moshi
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * Hilt module providing dependencies for the passkey provider.
 */
@Module
@InstallIn(SingletonComponent::class)
public object PasskeyProviderModule {

  @Provides
  @Singleton
  public fun provideMoshi(): Moshi = Moshi.Builder().build()

  @Provides
  @Singleton
  public fun provideWebAuthnJsonParser(moshi: Moshi): WebAuthnJsonParser =
    WebAuthnJsonParser(moshi)
}
