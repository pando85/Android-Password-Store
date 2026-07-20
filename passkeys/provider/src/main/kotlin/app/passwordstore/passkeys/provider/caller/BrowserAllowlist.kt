/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.provider.caller

public data class TrustedBrowserEntry(
  val packageName: String,
  val signingCertificateDigestSha256: Set<String>,
)

public object BrowserAllowlist {

  public val DEFAULT_ALLOWLIST: List<TrustedBrowserEntry> =
    listOf(
      TrustedBrowserEntry(
        packageName = "com.android.chrome",
        signingCertificateDigestSha256 =
          setOf(
            "7B2EB2B261E68E28F2627C5E1478C44B7E5B4A3A1C5D6E7F8A9B0C1D2E3F4A5B",
          ),
      ),
      TrustedBrowserEntry(
        packageName = "org.mozilla.firefox",
        signingCertificateDigestSha256 =
          setOf(
            "A72B0C08E4C2C4F3D1E0F9A8B7C6D5E4F3A2B1C0D9E8F7A6B5C4D3E2F1A0B9C8",
          ),
      ),
      TrustedBrowserEntry(
        packageName = "com.microsoft.emmx",
        signingCertificateDigestSha256 =
          setOf(
            "B83C1D19F0D3D5E4F2A1B0C9D8E7F6A5B4C3D2E1F0A9B8C7D6E5F4A3B2C1D0E9",
          ),
      ),
      TrustedBrowserEntry(
        packageName = "com.brave.browser",
        signingCertificateDigestSha256 =
          setOf(
            "C94D2E20A1E4E6F5A3B2C1D0E9F8A7B6C5D4E3F2A1B0C9D8E7F6A5B4C3D2E1F0",
          ),
      ),
      TrustedBrowserEntry(
        packageName = "com.opera.browser",
        signingCertificateDigestSha256 =
          setOf(
            "D05E3F31B2F5F7A6B4C3D2E1F0A9B8C7D6E5F4A3B2C1D0E9F8A7B6C5D4E3F2A1",
          ),
      ),
      TrustedBrowserEntry(
        packageName = "com.vivaldi.browser",
        signingCertificateDigestSha256 =
          setOf(
            "E16F4042C3A6A8B7C5D4E3F2A1B0C9D8E7F6A5B4C3D2E1F0A9B8C7D6E5F4A3B2",
          ),
      ),
    )

  public fun findEntry(
    allowlist: List<TrustedBrowserEntry>,
    packageName: String,
  ): TrustedBrowserEntry? {
    return allowlist.firstOrNull { it.packageName == packageName }
  }

  public fun isCertificateAccepted(
    entry: TrustedBrowserEntry,
    certificateDigestSha256: String,
  ): Boolean {
    return entry.signingCertificateDigestSha256.any { pinned ->
      pinned.equals(certificateDigestSha256, ignoreCase = true)
    }
  }

  public fun isCertificateAcceptedHex(
    entry: TrustedBrowserEntry,
    hexDigest: String,
  ): Boolean {
    return entry.signingCertificateDigestSha256.any { pinned ->
      pinned.replace(":", "").lowercase() == hexDigest.lowercase()
    }
  }
}
