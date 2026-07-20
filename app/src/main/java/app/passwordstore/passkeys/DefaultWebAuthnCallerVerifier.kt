/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import app.passwordstore.passkeys.crypto.CallerType
import app.passwordstore.passkeys.crypto.CallerVerificationDiagnostic
import app.passwordstore.passkeys.crypto.CallerVerificationError
import app.passwordstore.passkeys.crypto.RpIdValidator
import app.passwordstore.passkeys.crypto.VerifiedWebAuthnContext
import app.passwordstore.passkeys.provider.caller.BrowserAllowlist
import app.passwordstore.passkeys.provider.caller.TrustedBrowserEntry
import app.passwordstore.passkeys.provider.caller.WebAuthnCallerVerifier
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import java.security.MessageDigest
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.logcat

public class DefaultWebAuthnCallerVerifier(
  private val context: Context,
  private val browserAllowlist: List<TrustedBrowserEntry> = BrowserAllowlist.DEFAULT_ALLOWLIST,
  private val diagnosticSink: (CallerVerificationDiagnostic) -> Unit = { diag ->
    logcat(LogPriority.WARN) { "CallerVerification: $diag" }
  },
) : WebAuthnCallerVerifier {

  private val assetLinksClient = DigitalAssetLinksClient()
  private val assetLinkCache = AssetLinkCache(maxEntries = 64, ttlMs = 5 * 60 * 1_000L)

  override suspend fun verifyGetRequest(
    request: ProviderGetCredentialRequest,
    rpId: String,
  ): Result<VerifiedWebAuthnContext, CallerVerificationError> {
    return verifyCaller(request.callingAppInfo, rpId, "get")
  }

  override suspend fun verifyCreateRequest(
    request: ProviderCreateCredentialRequest,
    rpId: String,
  ): Result<VerifiedWebAuthnContext, CallerVerificationError> {
    return verifyCaller(request.callingAppInfo, rpId, "create")
  }

  private suspend fun verifyCaller(
    callingAppInfo: CallingAppInfo?,
    rpId: String,
    stage: String,
  ): Result<VerifiedWebAuthnContext, CallerVerificationError> {
    val normalizedRpId = rpId.trim().lowercase()
    if (!RpIdValidator.validateRpIdSyntax(normalizedRpId)) {
      return Err(CallerVerificationError.InvalidRpId(rpId, "invalid syntax"))
    }

    if (callingAppInfo == null) {
      emitDiagnostic(null, null, normalizedRpId, stage, "CALLER_INFO_MISSING", "No calling app info")
      return Err(CallerVerificationError.MissingCallingAppInfo(stage))
    }

    val packageName = callingAppInfo.packageName
    if (packageName.isNullOrBlank()) {
      emitDiagnostic(null, null, normalizedRpId, stage, "PACKAGE_NAME_MISSING", "Blank package name")
      return Err(CallerVerificationError.MissingPackageName(stage))
    }

    val browserEntry = BrowserAllowlist.findEntry(browserAllowlist, packageName)
    if (browserEntry != null) {
      return verifyBrowserCaller(callingAppInfo, browserEntry, normalizedRpId, stage)
    }

    return verifyNativeCaller(callingAppInfo, packageName, normalizedRpId, stage)
  }

  private fun verifyBrowserCaller(
    callingAppInfo: CallingAppInfo,
    browserEntry: TrustedBrowserEntry,
    rpId: String,
    stage: String,
  ): Result<VerifiedWebAuthnContext, CallerVerificationError> {
    val packageName = callingAppInfo.packageName
    val certDigests = getSigningCertificateDigests(packageName)

    if (certDigests.isEmpty()) {
      emitDiagnostic(packageName, null, rpId, stage, "SIGNING_CERT_MISSING", "No signing certs")
      return Err(CallerVerificationError.BrowserCertificateMismatch(packageName))
    }

    val certMatchesPinned =
      certDigests.any { digest ->
        val hexDigest = normalizeBase64UrlToHex(digest)
        hexDigest != null && BrowserAllowlist.isCertificateAcceptedHex(browserEntry, hexDigest)
      }
    if (!certMatchesPinned) {
      emitDiagnostic(packageName, null, rpId, stage, "BROWSER_CERT_MISMATCH", "Cert not pinned")
      return Err(CallerVerificationError.BrowserCertificateMismatch(packageName))
    }

    val verifiedOrigin = callingAppInfo.getOrigin()
    if (verifiedOrigin.isNullOrBlank()) {
      emitDiagnostic(packageName, null, rpId, stage, "UNTRUSTED_BROWSER", "No verified origin")
      return Err(CallerVerificationError.UntrustedBrowser(packageName, "No verified origin from framework"))
    }

    if (!RpIdValidator.isValidOriginForRpId(verifiedOrigin, rpId)) {
      emitDiagnostic(packageName, null, rpId, stage, "ORIGIN_RP_MISMATCH", "Origin/RP mismatch")
      return Err(CallerVerificationError.OriginRpIdMismatch(verifiedOrigin, rpId))
    }

    logcat { "Browser caller verified: pkg=$packageName, rpId=$rpId, origin=$verifiedOrigin" }
    return Ok(
      VerifiedWebAuthnContext(
        callingPackage = packageName,
        origin = verifiedOrigin,
        clientDataHash = null,
        callerType = CallerType.PRIVILEGED_BROWSER,
        signingCertificateDigests = certDigests,
      )
    )
  }

  private suspend fun verifyNativeCaller(
    callingAppInfo: CallingAppInfo,
    packageName: String,
    rpId: String,
    stage: String,
  ): Result<VerifiedWebAuthnContext, CallerVerificationError> {
    val certDigests = getSigningCertificateDigests(packageName)

    if (certDigests.isEmpty()) {
      emitDiagnostic(packageName, null, rpId, stage, "SIGNING_CERT_MISSING", "No signing certs")
      return Err(CallerVerificationError.MissingSigningCertificate(stage))
    }

    val cacheKey = AssetLinkCacheKey(rpId, packageName, certDigests)
    if (assetLinkCache.get(cacheKey)) {
      val androidOrigin = "android:apk-key-hash:${certDigests.first()}"
      logcat { "Native caller verified (cached): pkg=$packageName, rpId=$rpId" }
      return Ok(
        VerifiedWebAuthnContext(
          callingPackage = packageName,
          origin = androidOrigin,
          clientDataHash = null,
          callerType = CallerType.NATIVE_APP,
          signingCertificateDigests = certDigests,
        )
      )
    }

    val assetLinksResult =
      withContext(Dispatchers.IO) { assetLinksClient.fetchAssetLinks(rpId) }

    val statements =
      if (assetLinksResult.isOk) {
        assetLinksResult.value
      } else {
        val error = assetLinksResult.error
        emitDiagnostic(packageName, null, rpId, stage, "ASSET_LINK_FAILED", error.reason)
        return Err(
          CallerVerificationError.AssetLinkVerificationFailed(rpId, error.reason)
        )
      }

    val matched =
      statements.any { statement ->
        val target = statement.target ?: return@any false
        val isDelegatePermissionRelation =
          statement.relation?.any { rel ->
            rel == "delegate_permission/common_handle" ||
              rel == "delegate_permission/common_get_login_creds"
          } ?: false
        val isAndroidNamespace = target.namespace == "android_app"
        val packageMatches = target.packageName == packageName
        val certMatches =
          target.sha256CertFingerprint?.let { fingerprint ->
            val normalizedFingerprint = normalizeCertFingerprint(fingerprint)
            certDigests.any { digest ->
              val normalizedDigest = normalizeBase64UrlToHex(digest)
              normalizedFingerprint != null &&
                normalizedDigest != null &&
                normalizedFingerprint == normalizedDigest
            }
          } ?: false
        isDelegatePermissionRelation && isAndroidNamespace && packageMatches && certMatches
      }

    if (!matched) {
      emitDiagnostic(packageName, null, rpId, stage, "ASSET_LINK_FAILED", "No matching statement")
      return Err(
        CallerVerificationError.AssetLinkVerificationFailed(
          rpId,
          "No matching Digital Asset Links statement for $packageName",
        )
      )
    }

    assetLinkCache.put(cacheKey)
    val androidOrigin = "android:apk-key-hash:${certDigests.first()}"
    logcat { "Native caller verified: pkg=$packageName, rpId=$rpId" }
    return Ok(
      VerifiedWebAuthnContext(
        callingPackage = packageName,
        origin = androidOrigin,
        clientDataHash = null,
        callerType = CallerType.NATIVE_APP,
        signingCertificateDigests = certDigests,
      )
    )
  }

  private fun getSigningCertificateDigests(packageName: String): Set<String> {
    return try {
      val packageInfo =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        } else {
          @Suppress("DEPRECATION")
          context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
        }

      val signingCerts =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          packageInfo.signingInfo?.apkContentsSigners
        } else {
          @Suppress("DEPRECATION") packageInfo.signatures
        }

      signingCerts
        ?.map { cert ->
          val encoded = (cert as android.content.pm.Signature).toByteArray()
          val digest = MessageDigest.getInstance("SHA-256").digest(encoded)
          Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        }
        ?.toSet() ?: emptySet()
    } catch (e: PackageManager.NameNotFoundException) {
      logcat(LogPriority.WARN) { "Package not found during cert extraction: $packageName" }
      emptySet()
    } catch (e: Exception) {
      logcat(LogPriority.ERROR) { "Failed to get signing certs for $packageName: $e" }
      emptySet()
    }
  }

  private fun normalizeCertFingerprint(fingerprint: String): String? {
    return try {
      fingerprint.replace(":", "").lowercase()
    } catch (_: Exception) {
      null
    }
  }

  private fun normalizeBase64UrlToHex(base64Url: String): String? {
    return try {
      val bytes = Base64.getUrlDecoder().decode(base64Url)
      bytes.joinToString("") { "%02x".format(it) }
    } catch (_: Exception) {
      null
    }
  }

  private fun emitDiagnostic(
    callerPackage: String?,
    callerType: CallerType?,
    requestedRpId: String?,
    stage: String,
    errorCode: String,
    message: String,
  ) {
    diagnosticSink(
      CallerVerificationDiagnostic(
        callerPackage = callerPackage,
        callerType = callerType,
        requestedRpId = requestedRpId,
        stage = stage,
        errorCode = errorCode,
        message = message,
      )
    )
  }
}
