/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.provider.caller

import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import app.passwordstore.passkeys.crypto.CallerVerificationError
import app.passwordstore.passkeys.crypto.VerifiedWebAuthnContext
import com.github.michaelbull.result.Result

public interface WebAuthnCallerVerifier {

  public suspend fun verifyGetRequest(
    request: ProviderGetCredentialRequest,
    rpId: String,
  ): Result<VerifiedWebAuthnContext, CallerVerificationError>

  public suspend fun verifyCreateRequest(
    request: ProviderCreateCredentialRequest,
    rpId: String,
  ): Result<VerifiedWebAuthnContext, CallerVerificationError>
}
