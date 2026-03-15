/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
plugins {
  id("com.github.android-password-store.kotlin-jvm-library")
  alias(libs.plugins.kotlin.serialization)
}

dependencies {
  api(projects.crypto.common)
  implementation(libs.thirdparty.kotlinResult)
  implementation(libs.thirdparty.bouncycastle.bcprov)
  implementation(libs.thirdparty.logcat)
  implementation(libs.kotlinx.coroutines.core)
  implementation(libs.kotlinx.datetime)
  implementation(libs.kotlinx.serialization.json)
  testImplementation(libs.bundles.testDependencies)
}