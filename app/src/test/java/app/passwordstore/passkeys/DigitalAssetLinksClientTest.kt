/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json

class DigitalAssetLinksClientTest {

  @Test
  fun `parses standard Android app asset link fields`() {
    val statements =
      Json.decodeFromString<List<AssetLinkStatement>>(
        """
        [{
          "relation": ["delegate_permission/common.handle_all_urls"],
          "target": {
            "namespace": "android_app",
            "package_name": "com.github.android",
            "sha256_cert_fingerprints": [
              "DF:08:C9:F2:D8:09:18:9D:9D:50:64:97:C1:57:45:A7:39:5A:41:53:6E:FB:43:3E:3A:EE:1A:ED:BE:11:B2:61"
            ]
          }
        }]
        """
      )

    assertEquals(
      listOf("delegate_permission/common.handle_all_urls"),
      statements.single().relation,
    )
    assertEquals("com.github.android", statements.single().target?.packageName)
    assertEquals(1, statements.single().target?.sha256CertFingerprints?.size)
    val fingerprint = statements.single().target?.sha256CertFingerprints?.single().orEmpty()
    val digest =
      Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(fingerprint.split(':').map { it.toInt(16).toByte() }.toByteArray())
    assertTrue(statements.single().matchesAndroidApp("com.github.android", setOf(digest)))
    assertFalse(statements.single().matchesAndroidApp("com.attacker.app", setOf(digest)))
    assertFalse(statements.single().matchesAndroidApp("com.github.android", setOf("not-a-digest")))
  }

  @Test
  fun `rejects nonstandard relation names`() {
    val statement =
      AssetLinkStatement(
        relation = listOf("delegate_permission/common_get_login_creds"),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = "com.github.android",
            sha256CertFingerprints = listOf("AA:BB"),
          ),
      )

    assertFalse(statement.matchesAndroidApp("com.github.android", setOf("qrs")))
  }
}
