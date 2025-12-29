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
  namespace = "app.passwordstore.passkey.provider"

  defaultConfig {
    // Credential Provider requires API 34+
    minSdk = 34
  }

  buildFeatures {
    compose = true
    android.androidResources.enable = true
  }
}

dependencies {
  implementation(platform(libs.compose.bom))
  ksp(libs.dagger.hilt.compiler)
  implementation(projects.passkey.android)
  implementation(projects.crypto.common)
  implementation(projects.crypto.pgpainless)
  implementation(libs.androidx.activity.compose)
  implementation(libs.androidx.annotation)
  implementation(libs.androidx.core.ktx)
  implementation(libs.androidx.credentials)
  implementation(libs.androidx.fragment.ktx)
  implementation(libs.compose.foundation.core)
  implementation(libs.compose.foundation.layout)
  implementation(libs.compose.material.icons.extended)
  implementation(libs.compose.material3)
  implementation(libs.compose.ui.core)
  implementation(libs.dagger.hilt.android)
  implementation(libs.kotlinx.coroutines.android)
  implementation(libs.kotlinx.coroutines.core)
  implementation(libs.thirdparty.commons.codec)
  implementation(libs.thirdparty.kotlinResult)
  implementation(libs.thirdparty.logcat)
  implementation(libs.thirdparty.moshi)
  implementation(libs.thirdparty.moshi.kotlin)
  testImplementation(libs.bundles.testDependencies)
}
