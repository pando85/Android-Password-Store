/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKey
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

/** Adds provider public-certificate retrieval without weakening hierarchical `.gpg-id` policy. */
class OpenPgpPassRecipientResolver(
  private val delegate: PassRecipientResolver<PGPKey>,
  private val providerRepository: OpenPgpProviderRepository,
  private val interactionCoordinator: OpenPgpInteractionCoordinator,
) : PassRecipientResolver<PGPKey> {

  override suspend fun resolveFor(target: File): Result<List<PGPKey>, RecipientPolicyError> {
    return delegate
      .resolveFor(target)
      .fold(
        success = { Ok(it) },
        failure = { error ->
          if (
            error !is RecipientPolicyError.RecipientNotFound ||
              !providerRepository.hasSelectedProvider()
          ) {
            return@fold Err(error)
          }

          val identifier = PGPIdentifier.fromString(error.identifier) ?: return@fold Err(error)
          when (
            providerRepository.ensurePublicKeys(
              listOf(identifier),
              OpenPgpApiBackend.InteractionHandler { pendingIntent ->
                interactionCoordinator.interact(pendingIntent)
              },
            )
          ) {
            is OpenPgpApiBackend.OperationResult.Success -> delegate.resolveFor(target)
            else -> Err(error)
          }
        },
      )
  }
}
