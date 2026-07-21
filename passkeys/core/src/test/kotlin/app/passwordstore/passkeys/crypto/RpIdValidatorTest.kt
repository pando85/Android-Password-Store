/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RpIdValidatorTest {

  @Test
  fun `valid domain names pass syntax check`() {
    assertTrue(RpIdValidator.validateRpIdSyntax("example.com"))
    assertTrue(RpIdValidator.validateRpIdSyntax("login.example.com"))
    assertTrue(RpIdValidator.validateRpIdSyntax("sub.domain.example.co.uk"))
    assertTrue(RpIdValidator.validateRpIdSyntax("localhost"))
    assertTrue(RpIdValidator.validateRpIdSyntax("a"))
  }

  @Test
  fun `blank or empty RP IDs fail`() {
    assertFalse(RpIdValidator.validateRpIdSyntax(""))
    assertFalse(RpIdValidator.validateRpIdSyntax("   "))
  }

  @Test
  fun `RP IDs with schemes fail`() {
    assertFalse(RpIdValidator.validateRpIdSyntax("https://example.com"))
    assertFalse(RpIdValidator.validateRpIdSyntax("http://example.com"))
    assertFalse(RpIdValidator.validateRpIdSyntax("android:apk-key-hash:abc"))
  }

  @Test
  fun `RP IDs with ports fail`() {
    assertFalse(RpIdValidator.validateRpIdSyntax("example.com:443"))
    assertFalse(RpIdValidator.validateRpIdSyntax("example.com:8080"))
  }

  @Test
  fun `RP IDs with paths fail`() {
    assertFalse(RpIdValidator.validateRpIdSyntax("example.com/path"))
    assertFalse(RpIdValidator.validateRpIdSyntax("example.com/"))
  }

  @Test
  fun `RP IDs with query or fragment fail`() {
    assertFalse(RpIdValidator.validateRpIdSyntax("example.com?query"))
    assertFalse(RpIdValidator.validateRpIdSyntax("example.com#fragment"))
  }

  @Test
  fun `RP IDs with at-sign fail`() {
    assertFalse(RpIdValidator.validateRpIdSyntax("user@example.com"))
  }

  @Test
  fun `RP IDs starting or ending with dot fail`() {
    assertFalse(RpIdValidator.validateRpIdSyntax(".example.com"))
    assertFalse(RpIdValidator.validateRpIdSyntax("example.com."))
  }

  @Test
  fun `RP IDs with consecutive dots fail`() {
    assertFalse(RpIdValidator.validateRpIdSyntax("example..com"))
  }

  @Test
  fun `RP IDs with invalid label characters fail`() {
    assertFalse(RpIdValidator.validateRpIdSyntax("example_.com"))
    assertFalse(RpIdValidator.validateRpIdSyntax("-example.com"))
    assertFalse(RpIdValidator.validateRpIdSyntax("example-.com"))
  }

  @Test
  fun `exact origin match is valid`() {
    assertTrue(RpIdValidator.isValidOriginForRpId("https://example.com", "example.com"))
  }

  @Test
  fun `subdomain origin is valid for parent RP ID`() {
    assertTrue(RpIdValidator.isValidOriginForRpId("https://login.example.com", "example.com"))
  }

  @Test
  fun `unrelated origin is invalid for RP ID`() {
    assertFalse(RpIdValidator.isValidOriginForRpId("https://evil.com", "example.com"))
  }

  @Test
  fun `partial domain suffix is not valid`() {
    assertFalse(RpIdValidator.isValidOriginForRpId("https://notexample.com", "example.com"))
  }

  @Test
  fun `non-https origins are rejected`() {
    assertFalse(RpIdValidator.isValidOriginForRpId("http://example.com", "example.com"))
    assertFalse(RpIdValidator.isValidOriginForRpId("ftp://example.com", "example.com"))
  }

  @Test
  fun `android app origins are detected`() {
    assertTrue(RpIdValidator.isAndroidAppOrigin("android:apk-key-hash:abc123"))
    assertFalse(RpIdValidator.isAndroidAppOrigin("https://example.com"))
  }

  @Test
  fun `registrable suffix check works`() {
    assertTrue(RpIdValidator.isRegistrableSuffix("example.com", "example.com"))
    assertTrue(RpIdValidator.isRegistrableSuffix("example.com", "login.example.com"))
    assertFalse(RpIdValidator.isRegistrableSuffix("example.com", "notexample.com"))
  }
}
