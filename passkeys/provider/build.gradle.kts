/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("UnstableApiUsage")

plugins {
  id("com.github.android-password-store.android-library")
  id("com.github.android-password-store.kotlin-android")
  alias(libs.plugins.kotlin.serialization)
}

android {
  defaultConfig {
    minSdk = 26
    consumerProguardFiles("consumer-rules.pro")
  }
  namespace = "app.passwordstore.passkeys.provider"
}

dependencies {
  api(projects.passkeys.core)
  implementation(libs.androidx.annotation)
  implementation(libs.androidx.appcompat)
  implementation(libs.androidx.core.ktx)
  implementation(libs.androidx.credentials)
  implementation(libs.androidx.recyclerview)
  implementation(libs.kotlinx.coroutines.core)
  implementation(libs.kotlinx.datetime)
  implementation(libs.kotlinx.serialization.json)
  implementation(libs.thirdparty.bouncycastle.bcprov)
  implementation(libs.thirdparty.kotlinResult)
  implementation(libs.thirdparty.logcat)
  testImplementation(libs.bundles.testDependencies)
}
