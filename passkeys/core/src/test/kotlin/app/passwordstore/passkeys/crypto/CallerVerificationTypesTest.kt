/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals

class CallerVerificationTypesTest {

  @Test
  fun `VerifiedWebAuthnContext equality works with byte arrays`() {
    val ctx1 = VerifiedWebAuthnContext(
      callingPackage = "com.example",
      origin = "https://example.com",
      clientDataHash = byteArrayOf(1, 2, 3),
      callerType = CallerType.PRIVILEGED_BROWSER,
      signingCertificateDigests = setOf("abc"),
    )
    val ctx2 = VerifiedWebAuthnContext(
      callingPackage = "com.example",
      origin = "https://example.com",
      clientDataHash = byteArrayOf(1, 2, 3),
      callerType = CallerType.PRIVILEGED_BROWSER,
      signingCertificateDigests = setOf("abc"),
    )
    assertEquals(ctx1, ctx2)
    assertEquals(ctx1.hashCode(), ctx2.hashCode())
  }

  @Test
  fun `VerifiedWebAuthnContext inequality on different origin`() {
    val ctx1 = VerifiedWebAuthnContext(
      callingPackage = "com.example",
      origin = "https://example.com",
      clientDataHash = null,
      callerType = CallerType.NATIVE_APP,
      signingCertificateDigests = setOf("abc"),
    )
    val ctx2 = ctx1.copy(origin = "https://other.com")
    assertNotEquals(ctx1, ctx2)
  }

  @Test
  fun `CallerVerificationError errorCode returns stable codes`() {
    assertEquals("CALLER_INFO_MISSING", CallerVerificationError.MissingCallingAppInfo("get").errorCode())
    assertEquals("INVALID_RP_ID", CallerVerificationError.InvalidRpId("bad", "reason").errorCode())
    assertEquals("ORIGIN_RP_MISMATCH", CallerVerificationError.OriginRpIdMismatch("https://a.com", "b.com").errorCode())
    assertEquals("ASSET_LINK_FAILED", CallerVerificationError.AssetLinkVerificationFailed("rp", "reason").errorCode())
    assertEquals("UNTRUSTED_BROWSER", CallerVerificationError.UntrustedBrowser("pkg", "reason").errorCode())
    assertEquals("BROWSER_CERT_MISMATCH", CallerVerificationError.BrowserCertificateMismatch("pkg").errorCode())
    assertEquals("UNSUPPORTED_ALGORITHM", CallerVerificationError.UnsupportedAlgorithm(listOf(-257)).errorCode())
    assertEquals("MALFORMED_REQUEST", CallerVerificationError.MalformedRequest("field", "reason").errorCode())
  }

  @Test
  fun `CallerVerificationDiagnostic toString does not leak secrets`() {
    val diag = CallerVerificationDiagnostic(
      callerPackage = "com.evil",
      callerType = null,
      requestedRpId = "example.com",
      stage = "get",
      errorCode = "ASSET_LINK_FAILED",
      message = "No matching statement",
    )
    val str = diag.toString()
    assert(str.contains("com.evil"))
    assert(str.contains("example.com"))
    assert(!str.contains("private"))
    assert(!str.contains("key"))
    assert(!str.contains("challenge"))
  }

  @Test
  fun `CallerType enum has expected values`() {
    assertEquals(2, CallerType.entries.size)
    assertIs<CallerType>(CallerType.NATIVE_APP)
    assertIs<CallerType>(CallerType.PRIVILEGED_BROWSER)
  }
}
