/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Key
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.passwordstore.passkey.CredentialIndex
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.toImmutableList

/**
 * UI state for the passkey list screen using index-based listing.
 *
 * Uses CredentialIndex which contains only rpId and credentialId,
 * extracted from the directory structure without decryption.
 */
public data class PasskeyIndexListState(
  val isLoading: Boolean = true,
  val credentials: ImmutableList<CredentialIndex> = emptyList<CredentialIndex>().toImmutableList(),
  val error: String? = null,
)

/**
 * Screen for displaying and managing stored passkeys.
 *
 * @param state The current UI state
 * @param onDeleteCredential Called when user confirms deletion of a credential
 * @param onNavigateBack Called when user wants to go back
 * @param modifier Modifier for the root layout
 */
@Composable
public fun PasskeyListScreen(
  state: PasskeyIndexListState,
  onDeleteCredential: (ByteArray) -> Unit,
  onNavigateBack: () -> Unit,
  modifier: Modifier = Modifier,
) {
  var credentialToDelete by remember { mutableStateOf<CredentialIndex?>(null) }

  Box(
    modifier = modifier.fillMaxSize(),
  ) {
    when {
      state.isLoading -> {
        CircularProgressIndicator(
          modifier = Modifier.align(Alignment.Center),
        )
      }
      state.error != null -> {
        Column(
          modifier = Modifier
            .align(Alignment.Center)
            .padding(16.dp),
          horizontalAlignment = Alignment.CenterHorizontally,
        ) {
          Text(
            text = "Error loading passkeys",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.error,
          )
          Spacer(modifier = Modifier.height(8.dp))
          Text(
            text = state.error,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
      }
      state.credentials.isEmpty() -> {
        EmptyState(
          modifier = Modifier.align(Alignment.Center),
        )
      }
      else -> {
        PasskeyList(
          credentials = state.credentials,
          onDeleteClick = { credentialToDelete = it },
        )
      }
    }
  }

  // Delete confirmation dialog
  credentialToDelete?.let { credential ->
    DeleteConfirmationDialog(
      credential = credential,
      onConfirm = {
        onDeleteCredential(credential.credentialId)
        credentialToDelete = null
      },
      onDismiss = { credentialToDelete = null },
    )
  }
}

@Composable
private fun EmptyState(modifier: Modifier = Modifier) {
  Column(
    modifier = modifier.padding(32.dp),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    Icon(
      imageVector = Icons.Default.Key,
      contentDescription = null,
      modifier = Modifier.size(64.dp),
      tint = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    Spacer(modifier = Modifier.height(16.dp))

    Text(
      text = "No passkeys yet",
      style = MaterialTheme.typography.titleLarge,
    )

    Spacer(modifier = Modifier.height(8.dp))

    Text(
      text = "Passkeys you create will appear here. " +
        "Use passkeys to sign in to websites and apps without passwords.",
      style = MaterialTheme.typography.bodyMedium,
      color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
  }
}

@Composable
private fun PasskeyList(
  credentials: ImmutableList<CredentialIndex>,
  onDeleteClick: (CredentialIndex) -> Unit,
) {
  // Group by RP ID
  val groupedCredentials = remember(credentials) {
    credentials.groupBy { it.rpId }
  }

  LazyColumn(
    contentPadding = PaddingValues(16.dp),
    verticalArrangement = Arrangement.spacedBy(12.dp),
  ) {
    groupedCredentials.forEach { (rpId, rpCredentials) ->
      item {
        Text(
          text = rpId,
          style = MaterialTheme.typography.labelLarge,
          color = MaterialTheme.colorScheme.primary,
          modifier = Modifier.padding(vertical = 8.dp),
        )
      }

      items(rpCredentials, key = { it.credentialId.contentHashCode() }) { credential ->
        PasskeyCard(
          credential = credential,
          onDeleteClick = { onDeleteClick(credential) },
        )
      }
    }
  }
}

@Composable
private fun PasskeyCard(
  credential: CredentialIndex,
  onDeleteClick: () -> Unit,
) {
  Card(
    modifier = Modifier.fillMaxWidth(),
    elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
  ) {
    Row(
      modifier = Modifier
        .fillMaxWidth()
        .padding(16.dp),
      verticalAlignment = Alignment.CenterVertically,
    ) {
      Icon(
        imageVector = Icons.Default.Key,
        contentDescription = null,
        modifier = Modifier.size(40.dp),
        tint = MaterialTheme.colorScheme.primary,
      )

      Spacer(modifier = Modifier.width(16.dp))

      Column(modifier = Modifier.weight(1f)) {
        Text(
          text = credential.rpId,
          style = MaterialTheme.typography.titleMedium,
          fontWeight = FontWeight.SemiBold,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )

        Text(
          text = "Credential ID: ${credential.credentialId.take(8).toByteArray().toHexString()}...",
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )
      }

      IconButton(onClick = onDeleteClick) {
        Icon(
          imageVector = Icons.Default.Delete,
          contentDescription = "Delete passkey",
          tint = MaterialTheme.colorScheme.error,
        )
      }
    }
  }
}

@Composable
private fun DeleteConfirmationDialog(
  credential: CredentialIndex,
  onConfirm: () -> Unit,
  onDismiss: () -> Unit,
) {
  AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text("Delete passkey?") },
    text = {
      Text(
        "Are you sure you want to delete the passkey for ${credential.rpId}? " +
          "You won't be able to use it to sign in anymore."
      )
    },
    confirmButton = {
      TextButton(
        onClick = onConfirm,
      ) {
        Text("Delete", color = MaterialTheme.colorScheme.error)
      }
    },
    dismissButton = {
      TextButton(onClick = onDismiss) {
        Text("Cancel")
      }
    },
  )
}

private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }
