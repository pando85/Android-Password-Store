/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey.ui

import android.os.Build
import androidx.annotation.RequiresApi
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import app.passwordstore.passkey.CredentialIndex
import app.passwordstore.passkey.PasskeyRepository
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.onSuccess
import dagger.hilt.android.lifecycle.HiltViewModel
import java.io.File
import javax.inject.Inject
import kotlinx.collections.immutable.toImmutableList
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import logcat.logcat

/**
 * ViewModel for the passkey list screen.
 *
 * Uses index-based listing which doesn't require decryption.
 * This shows RP ID and credential ID from the directory structure.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@HiltViewModel
public class PasskeyListViewModel
@Inject
constructor(
  private val passkeyRepository: PasskeyRepository,
) : ViewModel() {

  private val _state = MutableStateFlow(PasskeyIndexListState())
  public val state: StateFlow<PasskeyIndexListState> = _state.asStateFlow()

  private var baseDir: File? = null
  private var passkeysDir: String = PasskeyRepository.DEFAULT_PASSKEYS_DIR

  /**
   * Initialize the ViewModel with the password store base directory.
   *
   * No PGP credentials needed - uses index-based listing.
   *
   * @param passwordStoreDir The password store base directory
   * @param passkeysDir The relative directory for passkeys (default: "fido2")
   */
  public fun initialize(
    passwordStoreDir: File,
    passkeysDir: String = PasskeyRepository.DEFAULT_PASSKEYS_DIR,
  ) {
    this.baseDir = passwordStoreDir
    this.passkeysDir = passkeysDir
    loadCredentials()
  }

  /**
   * Load all stored credential indices (without decryption).
   */
  public fun loadCredentials() {
    val dir = baseDir ?: return

    viewModelScope.launch {
      _state.update { it.copy(isLoading = true, error = null) }

      try {
        val credentials = passkeyRepository.listAllCredentialIndex(dir, passkeysDir)
        _state.update {
          it.copy(
            isLoading = false,
            credentials = credentials.sortedBy { cred -> cred.rpId }.toImmutableList(),
          )
        }
      } catch (e: Exception) {
        logcat { "Failed to load credentials: ${e.message}" }
        _state.update {
          it.copy(
            isLoading = false,
            error = e.message ?: "Failed to load passkeys",
          )
        }
      }
    }
  }

  /**
   * Delete a credential.
   */
  public fun deleteCredential(credentialId: ByteArray) {
    val dir = baseDir ?: return

    viewModelScope.launch {
      try {
        val deleted = passkeyRepository.deleteCredential(dir, credentialId, passkeysDir)
        if (deleted) {
          logcat { "Deleted credential" }
          // Reload the list
          loadCredentials()
        } else {
          _state.update {
            it.copy(error = "Failed to delete passkey - not found")
          }
        }
      } catch (e: Exception) {
        logcat { "Failed to delete credential: ${e.message}" }
        _state.update {
          it.copy(error = e.message ?: "Failed to delete passkey")
        }
      }
    }
  }
}
