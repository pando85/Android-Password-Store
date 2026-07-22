/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.provider.caller

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class BrowserAllowlistTest {

  @Test
  fun `default allowlist contains only browsers with verified certificate pins`() {
    val packages = BrowserAllowlist.DEFAULT_ALLOWLIST.map { it.packageName }
    assertEquals(
      setOf("com.android.chrome", "org.mozilla.fenix", "org.mozilla.firefox"),
      packages.toSet(),
    )
  }

  @Test
  fun `default allowlist pins installed Chrome and Mozilla release certificates`() {
    val entries = BrowserAllowlist.DEFAULT_ALLOWLIST.associateBy { it.packageName }

    assertTrue(
      entries
        .getValue("com.android.chrome")
        .signingCertificateDigestSha256
        .contains("F0FD6C5B410F25CB25C3B53346C8972FAE30F8EE7411DF910480AD6B2D60DB83")
    )
    assertTrue(
      entries
        .getValue("org.mozilla.fenix")
        .signingCertificateDigestSha256
        .contains("5004779088E7F988D5BC5CC5F8798FEBF4F8CD084A1B2A46EFD4C8EE4AEAF211")
    )
  }

  @Test
  fun `findEntry returns entry for known browser`() {
    val entry = BrowserAllowlist.findEntry(BrowserAllowlist.DEFAULT_ALLOWLIST, "com.android.chrome")
    assertNotNull(entry)
    assertEquals("com.android.chrome", entry.packageName)
    assertTrue(entry.signingCertificateDigestSha256.isNotEmpty())
  }

  @Test
  fun `findEntry returns null for unknown package`() {
    val entry = BrowserAllowlist.findEntry(BrowserAllowlist.DEFAULT_ALLOWLIST, "com.evil.app")
    assertNull(entry)
  }

  @Test
  fun `isCertificateAccepted returns true for matching digest`() {
    val entry =
      TrustedBrowserEntry(
        packageName = "com.test",
        signingCertificateDigestSha256 = setOf("AABB", "CCDD"),
      )
    assertTrue(BrowserAllowlist.isCertificateAccepted(entry, "aabb"))
    assertTrue(BrowserAllowlist.isCertificateAccepted(entry, "CCDD"))
  }

  @Test
  fun `isCertificateAccepted returns false for non-matching digest`() {
    val entry =
      TrustedBrowserEntry(
        packageName = "com.test",
        signingCertificateDigestSha256 = setOf("AABB"),
      )
    assertFalse(BrowserAllowlist.isCertificateAccepted(entry, "ZZZZ"))
  }

  @Test
  fun `isCertificateAccepted is case insensitive`() {
    val entry =
      TrustedBrowserEntry(
        packageName = "com.test",
        signingCertificateDigestSha256 = setOf("aaBBccDD"),
      )
    assertTrue(BrowserAllowlist.isCertificateAccepted(entry, "AABBCCDD"))
    assertTrue(BrowserAllowlist.isCertificateAccepted(entry, "aabbccdd"))
  }

  @Test
  fun `privileged allowlist uses AndroidX browser schema`() {
    val entry =
      TrustedBrowserEntry(
        packageName = "org.mozilla.fenix",
        signingCertificateDigestSha256 = setOf("AABBCCDD"),
      )
    val app =
      Json.parseToJsonElement(BrowserAllowlist.toPrivilegedAllowlistJson(entry))
        .jsonObject["apps"]
        ?.jsonArray
        ?.single()
        ?.jsonObject
    val info = app?.get("info")?.jsonObject

    assertEquals("android", app?.get("type")?.jsonPrimitive?.content)
    assertEquals("org.mozilla.fenix", info?.get("package_name")?.jsonPrimitive?.content)
    assertEquals(
      "AA:BB:CC:DD",
      info
        ?.get("signatures")
        ?.jsonArray
        ?.single()
        ?.jsonObject
        ?.get("cert_fingerprint_sha256")
        ?.jsonPrimitive
        ?.content,
    )
  }
}
