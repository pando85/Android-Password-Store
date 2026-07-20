/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
internal data class AssetLinkStatement(
  @SerialName("relation") val relation: List<String>? = null,
  @SerialName("target") val target: AssetLinkTarget? = null,
)

@Serializable
internal data class AssetLinkTarget(
  @SerialName("namespace") val namespace: String? = null,
  @SerialName("site") val site: String? = null,
  @SerialName("package_name") val packageName: String? = null,
  @SerialName("sha256_cert_fingerprint") val sha256CertFingerprint: String? = null,
)

internal class DigitalAssetLinksClient(
  private val connectTimeoutMs: Int = 5_000,
  private val readTimeoutMs: Int = 5_000,
) {

  private val json = Json { ignoreUnknownKeys = true }

  fun fetchAssetLinks(rpId: String): Result<List<AssetLinkStatement>, AssetLinkFetchError> {
    val url = URL("https://$rpId/.well-known/assetlinks.json")
    val connection =
      try {
        url.openConnection() as HttpsURLConnection
      } catch (e: Exception) {
        return Err(AssetLinkFetchError.TlsError(e.message ?: "Unknown TLS error"))
      }
    return try {
      connection.connectTimeout = connectTimeoutMs
      connection.readTimeout = readTimeoutMs
      connection.requestMethod = "GET"
      connection.setRequestProperty("Accept", "application/json")
      connection.instanceFollowRedirects = false
      connection.connect()

      val responseCode = connection.responseCode
      if (responseCode != HttpURLConnection.HTTP_OK) {
        return Err(AssetLinkFetchError.HttpError(responseCode, "HTTP $responseCode from $rpId"))
      }

      val body = BufferedReader(InputStreamReader(connection.inputStream, Charsets.UTF_8)).use { it.readText() }

      val statements =
        try {
          json.decodeFromString<List<AssetLinkStatement>>(body)
        } catch (e: Exception) {
          return Err(AssetLinkFetchError.ParseError(e.message ?: "Failed to parse asset links"))
        }

      Ok(statements)
    } catch (e: javax.net.ssl.SSLException) {
      Err(AssetLinkFetchError.TlsError(e.message ?: "TLS error"))
    } catch (e: java.net.SocketTimeoutException) {
      Err(AssetLinkFetchError.Timeout("Connection timed out fetching asset links from $rpId"))
    } catch (e: java.net.UnknownHostException) {
      Err(AssetLinkFetchError.DnsError("Could not resolve $rpId"))
    } catch (e: Exception) {
      Err(AssetLinkFetchError.NetworkError(e.message ?: "Unknown network error"))
    } finally {
      connection.disconnect()
    }
  }
}

internal sealed class AssetLinkFetchError(val reason: String) {
  class Timeout(reason: String) : AssetLinkFetchError(reason)
  class TlsError(reason: String) : AssetLinkFetchError(reason)
  class HttpError(val statusCode: Int, reason: String) : AssetLinkFetchError(reason)
  class ParseError(reason: String) : AssetLinkFetchError(reason)
  class DnsError(reason: String) : AssetLinkFetchError(reason)
  class NetworkError(reason: String) : AssetLinkFetchError(reason)
}
