/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
import org.gradle.api.tasks.testing.Test

plugins {
  id("com.github.android-password-store.android-library")
  id("com.github.android-password-store.kotlin-android")
}

android {
  namespace = "app.passwordstore.passgen.diceware"
  buildFeatures { android.androidResources.enable = true }
}

tasks.withType<Test> {
  classpath += files("src/test/resources")
}

dependencies {
  implementation(libs.dagger.hilt.core)
  testImplementation(libs.bundles.testDependencies)
}
