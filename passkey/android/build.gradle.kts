/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
plugins {
  id("com.github.android-password-store.android-library")
  id("com.github.android-password-store.kotlin-android")
  alias(libs.plugins.hilt)
  alias(libs.plugins.kotlin.composeCompiler)
  alias(libs.plugins.ksp)
}

android {
  namespace = "app.passwordstore.passkey"
  buildFeatures { compose = true }
}

dependencies {
  implementation(platform(libs.compose.bom))
  ksp(libs.dagger.hilt.compiler)
  implementation(libs.androidx.annotation)
  implementation(libs.androidx.biometricKtx)
  implementation(libs.androidx.core.ktx)
  implementation(libs.androidx.fragment.ktx)
  implementation(libs.bundles.androidxLifecycle)
  implementation(libs.compose.foundation.core)
  implementation(libs.compose.foundation.layout)
  implementation(libs.compose.material.icons.extended)
  implementation(libs.compose.material3)
  implementation(libs.compose.ui.core)
  implementation(libs.dagger.hilt.android)
  implementation(libs.kotlinx.collections.immutable)
  implementation(libs.kotlinx.coroutines.android)
  implementation(libs.kotlinx.coroutines.core)
  implementation(libs.thirdparty.bouncycastle.bcprov)
  implementation(libs.thirdparty.cbor)
  implementation(libs.thirdparty.kotlinResult)
  implementation(libs.thirdparty.logcat)
  implementation(projects.coroutineUtils)
  implementation(projects.crypto.common)
  implementation(projects.crypto.pgpainless)
  testImplementation(libs.bundles.testDependencies)
  testImplementation(libs.kotlinx.coroutines.test)
}
