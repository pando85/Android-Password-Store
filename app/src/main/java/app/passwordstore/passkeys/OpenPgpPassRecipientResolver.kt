/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import app.passwordstore.crypto.DefaultPassRecipientResolver
import app.passwordstore.crypto.PGPKey
import app.passwordstore.data.crypto.OpenPgpAmbiguousRecipientException
import app.passwordstore.data.crypto.OpenPgpApiBackend
import app.passwordstore.data.crypto.OpenPgpInteractionCoordinator
import app.passwordstore.data.crypto.OpenPgpProviderRepository
import app.passwordstore.passkeys.storage.PassRecipientResolver
import app.passwordstore.passkeys.storage.RecipientPolicyError
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.io.File

/** Resolves pass recipients from the selected provider without weakening `.gpg-id` policy. */
class OpenPgpPassRecipientResolver(
  private val delegate: DefaultPassRecipientResolver,
  private val providerRepository: OpenPgpProviderRepository,
  private val interactionCoordinator: OpenPgpInteractionCoordinator,
) : PassRecipientResolver<PGPKey> {

  override suspend fun resolveFor(target: File): Result<List<PGPKey>, RecipientPolicyError> {
    if (!providerRepository.hasSelectedProvider()) return delegate.resolveFor(target)

    val identifiers =
      delegate
        .resolveIdentifiersFor(target)
        .fold(
          success = { it },
          failure = {
            return Err(it)
          },
        )

    return when (
      val resolved =
        providerRepository.resolvePublicKeys(
          identifiers,
          OpenPgpApiBackend.InteractionHandler { pendingIntent ->
            interactionCoordinator.interact(pendingIntent)
          },
        )
    ) {
      is OpenPgpApiBackend.OperationResult.Success -> Ok(resolved.value)
      is OpenPgpApiBackend.OperationResult.Failure -> {
        val error = resolved.error
        if (error is OpenPgpAmbiguousRecipientException) {
          Err(RecipientPolicyError.AmbiguousRecipient(error.identifier))
        } else {
          Err(RecipientPolicyError.RecipientNotFound(identifiers.joinToString(", ")))
        }
      }
      is OpenPgpApiBackend.OperationResult.UserInteractionRequired ->
        Err(RecipientPolicyError.RecipientNotFound(identifiers.joinToString(", ")))
      OpenPgpApiBackend.OperationResult.Cancelled ->
        Err(RecipientPolicyError.RecipientNotFound(identifiers.joinToString(", ")))
    }
  }
}
