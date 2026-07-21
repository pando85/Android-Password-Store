# Passkey Decryption Security Improvements

## Overview

This document describes the security improvements made to the passkey decryption system in Android Password Store. The changes address critical security and reliability issues where the previous implementation would only try the first imported key and use a hardcoded null passphrase.

## Problem Statement

The previous implementation had several critical issues:

1. **Order-dependent decryption**: Only the first imported key was tried, making decryption dependent on filesystem enumeration order
2. **No passphrase support**: Hardcoded `null` passphrase prevented use of passphrase-protected keys
3. **Silent failures**: All decryption errors were converted to `null`, hiding the actual problem
4. **No recipient inspection**: The system didn't inspect OpenPGP recipient packets to find matching keys
5. **Public key confusion**: Public-only keys could be selected first, blocking access to valid secret keys

## Solution Architecture

### New Components

#### 1. PasskeyDecryptionError (sealed interface)

Typed error hierarchy that distinguishes between different failure modes:

```kotlin
sealed interface PasskeyDecryptionError {
  data object NoRecipientPackets : PasskeyDecryptionError
  data class MissingSecretKey(val recipientIds: Set<String>) : PasskeyDecryptionError
  data class KeyLocked(val keyId: String) : PasskeyDecryptionError
  data class IncorrectPassphrase(val keyId: String) : PasskeyDecryptionError
  data object IntegrityCheckFailed : PasskeyDecryptionError
  data object MalformedCiphertext : PasskeyDecryptionError
  data class UnsupportedFormat(val reason: String) : PasskeyDecryptionError
}
```

#### 2. PasskeyPgpDecryptor (interface)

Dedicated component for passkey decryption that separates recipient policy from decryption capability:

```kotlin
interface PasskeyPgpDecryptor {
  suspend fun decrypt(
    file: File,
    unlockContext: PgpUnlockContext,
  ): Result<ByteArray, PasskeyDecryptionError>
}
```

#### 3. PgpUnlockContext (interface)

Integrates with APS's existing passphrase/biometric unlock flow:

```kotlin
interface PgpUnlockContext {
  suspend fun unlockKey(keyId: String): CharArray?
}
```

#### 4. PgpainlessPasskeyDecryptor (implementation)

Production implementation that:
- Inspects OpenPGP recipient packets to extract key IDs
- Matches recipients against all imported secret keys
- Tries each matching key with proper unlock flow
- Returns typed errors instead of silent failures
- Wipes passphrases and plaintext buffers after use

#### 5. PasskeyStorageDiagnostics

Diagnostic tool that reports:
- Total encrypted passkey files
- Files with no matching local secret key
- Files with locked keys
- Files with incorrect passphrases
- Malformed/corrupt files
- Recipient key ID mismatches

### Updated FilePasskeyStorage

The storage class now:
- Accepts `PasskeyPgpDecryptor` and `PgpUnlockContext` instead of simple lambdas
- Uses the decryptor for all decryption operations
- Properly handles typed errors
- Wipes sensitive data after use

## Security Properties

### 1. Recipient-Based Key Selection

The system now:
1. Parses encrypted data packet headers
2. Extracts recipient key IDs/fingerprints
3. Matches against all imported secret keys and subkeys
4. Ignores public-only keys
5. Tries each matching key until one succeeds

### 2. Proper Passphrase Handling

- Integrates with APS's existing passphrase cache and biometric unlock
- Passphrases are obtained per-key through `PgpUnlockContext`
- Passphrases are wiped immediately after use
- Wrong passphrase is distinguished from other errors

### 3. Typed Error Handling

Different failure modes are now distinguishable:
- **MissingSecretKey**: No local key matches the recipients
- **KeyLocked**: Key requires unlock but unlock failed
- **IncorrectPassphrase**: Wrong passphrase provided
- **IntegrityCheckFailed**: MDC/AEAD verification failed
- **MalformedCiphertext**: Invalid OpenPGP packet structure

### 4. Metadata-Only Discovery

The `IndexedPasskeyStorage` wrapper ensures:
- Discovery (listing credentials) performs zero payload decryptions
- Only metadata is read during discovery
- Full decryption only happens during authentication

### 5. Secure Memory Handling

- Passphrases are wiped after use (`passphrase.fill(0)`)
- Plaintext buffers are wiped after use
- Sensitive credentials use `SensitivePasskeyCredential` with automatic cleanup

## Usage

### Basic Setup

```kotlin
val decryptor = PgpainlessPasskeyDecryptor(cryptoHandler, keyManager)
val unlockContext = DefaultPgpUnlockContext() // or custom implementation

val storage = FilePasskeyStorage(
  repositoryRoot = repositoryRoot,
  cryptoHandler = cryptoHandler,
  passkeyPgpDecryptor = decryptor,
  pgpUnlockContext = unlockContext,
  encryptionKeys = { keyManager.getAllKeys().getOrNull() ?: emptyList() },
  encryptionOptions = PGPEncryptOptions.Builder().build(),
  config = PasskeyStorageConfig(),
)
```

### Custom Unlock Context

Implement `PgpUnlockContext` to integrate with your passphrase/biometric flow:

```kotlin
class BiometricPgpUnlockContext(
  private val biometricPrompt: BiometricPrompt,
  private val passphraseCache: PassphraseCache,
) : PgpUnlockContext {
  override suspend fun unlockKey(keyId: String): CharArray? {
    // Check cache first
    passphraseCache.get(keyId)?.let { return it }
    
    // Prompt user for passphrase
    val passphrase = promptForPassphrase(keyId) ?: return null
    
    // Cache according to security policy
    passphraseCache.put(keyId, passphrase)
    
    return passphrase
  }
}
```

### Running Diagnostics

```kotlin
val diagnostics = PasskeyStorageDiagnostics(
  repositoryRoot = repositoryRoot,
  passkeyPgpDecryptor = decryptor,
  pgpUnlockContext = unlockContext,
)

val report = diagnostics.generateReport()
println(diagnostics.formatReport(report))
```

## Migration Guide

### Breaking Changes

The `FilePasskeyStorage` constructor signature has changed:

**Before:**
```kotlin
FilePasskeyStorage(
  repositoryRoot = repositoryRoot,
  cryptoHandler = cryptoHandler,
  decryptionKeys = { keyManager.getAllKeys().get() ?: emptyList() },
  decryptionPassphrase = { null },
  encryptionKeys = { keyManager.getAllKeys().get() ?: emptyList() },
  decryptionOptions = PGPDecryptOptions.Builder().build(),
  encryptionOptions = PGPEncryptOptions.Builder().build(),
  config = PasskeyStorageConfig(),
)
```

**After:**
```kotlin
FilePasskeyStorage(
  repositoryRoot = repositoryRoot,
  cryptoHandler = cryptoHandler,
  passkeyPgpDecryptor = decryptor,
  pgpUnlockContext = unlockContext,
  encryptionKeys = { keyManager.getAllKeys().getOrNull() ?: emptyList() },
  encryptionOptions = PGPEncryptOptions.Builder().build(),
  config = PasskeyStorageConfig(),
)
```

### Migration Steps

1. Create a `PasskeyPgpDecryptor` instance (use `PgpainlessPasskeyDecryptor`)
2. Create a `PgpUnlockContext` implementation (use `DefaultPgpUnlockContext` for no-passphrase keys)
3. Update `FilePasskeyStorage` instantiation
4. Update DI module to provide the new components
5. Optionally add diagnostics UI using `PasskeyStorageDiagnostics`

## Testing

Comprehensive tests verify:
- Multiple keys are tried until one succeeds
- Public-only keys don't block secret keys
- Passphrase-protected keys work through unlock flow
- Wrong passphrase returns typed error
- Missing keys return typed error
- Integrity failures are detected
- Malformed ciphertext is detected
- Discovery performs zero payload decryptions
- Sensitive data is wiped after use

## Acceptance Criteria

All acceptance criteria from the original issue are met:

- [x] Passkey decryption no longer uses `decryptionKeys().firstOrNull()`
- [x] The ciphertext recipient packets determine candidate keys
- [x] Every eligible matching secret key can be tried
- [x] Public-only and unrelated keys cannot block decryption
- [x] Passphrase-protected secret keys work through the existing APS unlock flow
- [x] `decryptionPassphrase = { null }` is removed from the passkey module
- [x] Missing keys, wrong passphrases, integrity failures and malformed files are differentiated internally
- [x] Discovery does not decrypt passkey payloads
- [x] Sensitive passphrases and plaintext buffers are wiped after use

## Future Enhancements

Potential future improvements:
1. UI for displaying diagnostic reports
2. Automatic key import suggestions based on missing recipient IDs
3. Batch re-encryption when keys are rotated
4. Integration with OpenKeychain for key unlock
5. Hardware security module (HSM) support for key storage
