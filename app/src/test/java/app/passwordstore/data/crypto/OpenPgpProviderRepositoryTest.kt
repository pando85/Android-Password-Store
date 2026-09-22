/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.content.Context
import android.content.Intent
import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.unwrap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlinx.coroutines.runBlocking
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.openintents.openpgp.util.OpenPgpApi
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class OpenPgpProviderRepositoryTest {

  @get:Rule val temporaryFolder = TemporaryFolder()

  @Test
  fun `provider is consulted on every public key resolution`() = runBlocking {
    val certificate = certificate()
    val keyId = KeyUtils.tryGetKeyId(certificate).id
    var getKeyCalls = 0
    val backend =
      OpenPgpApiBackend(
        FakeExecutor { _, request, _ ->
          when (request.action) {
            OpenPgpApi.ACTION_GET_KEY -> {
              getKeyCalls++
              OpenPgpApiCall(success(), certificate.getEncoded())
            }
            else -> error("Unexpected action ${request.action}")
          }
        }
      )
    val repository = repository(backend)

    assertIs<OpenPgpApiBackend.OperationResult.Success<List<PGPKey>>>(
      repository.resolvePublicKeys(listOf(PGPIdentifier.KeyId(keyId)))
    )
    assertIs<OpenPgpApiBackend.OperationResult.Success<List<PGPKey>>>(
      repository.resolvePublicKeys(listOf(PGPIdentifier.KeyId(keyId)))
    )

    assertEquals(2, getKeyCalls)
  }

  @Test
  fun `ambiguous user id resolution fails closed`() = runBlocking {
    var getKeyCalls = 0
    val backend =
      OpenPgpApiBackend(
        FakeExecutor { _, request, _ ->
          when (request.action) {
            OpenPgpApi.ACTION_GET_KEY_IDS ->
              OpenPgpApiCall(
                success().apply { putExtra(OpenPgpApi.RESULT_KEY_IDS, longArrayOf(1L, 2L)) },
                byteArrayOf(),
              )
            OpenPgpApi.ACTION_GET_KEY -> {
              getKeyCalls++
              error("Ambiguous IDs must not fetch a certificate")
            }
            else -> error("Unexpected action ${request.action}")
          }
        }
      )
    val repository = repository(backend)

    val result = repository.resolvePublicKeys(listOf(PGPIdentifier.UserId("alice@example.com")))

    val failure = assertIs<OpenPgpApiBackend.OperationResult.Failure>(result)
    assertIs<OpenPgpAmbiguousRecipientException>(failure.error)
    assertEquals(0, getKeyCalls)
  }

  @Test
  fun `ensure public keys only exposes a complete fresh resolution`() = runBlocking {
    val certificate = certificate()
    val keyId = KeyUtils.tryGetKeyId(certificate).id
    val identifier = PGPIdentifier.KeyId(keyId)
    val backend =
      OpenPgpApiBackend(
        FakeExecutor { _, request, _ ->
          when (request.action) {
            OpenPgpApi.ACTION_GET_KEY -> OpenPgpApiCall(success(), certificate.getEncoded())
            else -> error("Unexpected action ${request.action}")
          }
        }
      )
    val repository = repository(backend)

    assertNull(repository.resolvedPublicKeysFor(listOf(identifier)))
    assertIs<OpenPgpApiBackend.OperationResult.Success<Unit>>(
      repository.ensurePublicKeys(listOf(identifier))
    )
    assertEquals(1, repository.resolvedPublicKeysFor(listOf(identifier))?.size)
  }

  private fun certificate() =
    PGPKeyManager(temporaryFolder.root.absolutePath)
      .generateKey("Alice <alice@example.com>", null)
      .unwrap()
      .let(KeyUtils::tryParseCertificateOrKey)
      .let { parsed ->
        require(parsed is OpenPGPKey)
        parsed.toCertificate()
      }

  private fun repository(backend: OpenPgpApiBackend): OpenPgpProviderRepository {
    val context = RuntimeEnvironment.getApplication()
    val preferences = context.getSharedPreferences("openpgp-provider-test", Context.MODE_PRIVATE)
    preferences.edit().clear().putString(PreferenceKeys.OPENPGP_PROVIDER_PACKAGE, PROVIDER).commit()
    return OpenPgpProviderRepository(backend, preferences)
  }

  private fun success(): Intent =
    Intent().apply { putExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_SUCCESS) }

  private class FakeExecutor(
    private val executeBlock: suspend (String, Intent, ByteArray?) -> OpenPgpApiCall
  ) : OpenPgpApiExecutor {
    override fun providers(): List<OpenPgpApiBackend.Provider> =
      listOf(OpenPgpApiBackend.Provider(PROVIDER, "Provider"))

    override suspend fun execute(
      providerPackage: String,
      request: Intent,
      input: ByteArray?,
    ): OpenPgpApiCall = executeBlock(providerPackage, request, input)
  }

  private companion object {
    const val PROVIDER = "org.example.openpgp"
  }
}
