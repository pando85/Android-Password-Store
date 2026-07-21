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

class BrowserAllowlistTest {

  @Test
  fun `default allowlist contains major browsers`() {
    val packages = BrowserAllowlist.DEFAULT_ALLOWLIST.map { it.packageName }
    assertTrue("com.android.chrome" in packages)
    assertTrue("org.mozilla.firefox" in packages)
    assertTrue("com.microsoft.emmx" in packages)
    assertTrue("com.brave.browser" in packages)
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
}
