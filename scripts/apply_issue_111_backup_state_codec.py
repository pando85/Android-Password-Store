from pathlib import Path

path = Path(
    "passkeys/core/src/main/kotlin/app/passwordstore/passkeys/model/StoredCredential.kt"
)
text = path.read_text()

old_serializer = '''    map["backup_eligible"] = if (backupEligible) CborValue.True else CborValue.False
    map["backup_state"] = if (backupState) CborValue.True else CborValue.False
'''
new_serializer = '''    val credentialBackupState =
      CredentialBackupState.fromFlags(
        backupEligible = backupEligible,
        backupState = backupState,
      )
    map["backup_state"] = CborValue.TextString(credentialBackupState.serializedName)
'''
assert text.count(old_serializer) == 1
text = text.replace(old_serializer, new_serializer, 1)

old_curve = '''    private val p256Curve by lazy { CustomNamedCurves.getByName("secp256r1") }

    public fun deriveP256PublicKey(privateKeyScalar: ByteArray): ByteArray {
'''
new_curve = '''    private val p256Curve by lazy { CustomNamedCurves.getByName("secp256r1") }

    /**
     * Decodes the canonical soft-fido2 representation and the legacy APS boolean representation.
     * Writers always emit the canonical text value, so legacy credentials migrate on their next
     * save without requiring an eager repository rewrite.
     */
    private fun parseBackupState(map: CborMap): CredentialBackupState {
      val hasBackupState = map.contains("backup_state")
      val hasBackupEligible = map.contains("backup_eligible")
      val canonicalState = map.getString("backup_state")

      if (canonicalState != null) {
        require(!hasBackupEligible) {
          "Credential mixes canonical 'backup_state' with legacy 'backup_eligible'"
        }
        return CredentialBackupState.fromSerializedName(canonicalState)
      }

      if (!hasBackupState && !hasBackupEligible) {
        // Existing Git/OpenPGP credentials are syncable under APS's established migration policy.
        return CredentialBackupState.ELIGIBLE
      }

      val legacyBackupEligible =
        if (hasBackupEligible) {
          map.getBoolean("backup_eligible")
            ?: throw IllegalArgumentException("Legacy 'backup_eligible' must be a CBOR boolean")
        } else {
          true
        }
      val legacyBackupState =
        if (hasBackupState) {
          map.getBoolean("backup_state")
            ?: throw IllegalArgumentException(
              "'backup_state' must be a canonical CBOR text value or legacy boolean"
            )
        } else {
          false
        }

      return CredentialBackupState.fromFlags(
        backupEligible = legacyBackupEligible,
        backupState = legacyBackupState,
      )
    }

    public fun deriveP256PublicKey(privateKeyScalar: ByteArray): ByteArray {
'''
assert text.count(old_curve) == 1
text = text.replace(old_curve, new_curve, 1)

old_parser = '''      val backupEligible = map.getBoolean("backup_eligible") ?: true
      val backupState = map.getBoolean("backup_state") ?: false
'''
new_parser = '''      val credentialBackupState = parseBackupState(map)
'''
assert text.count(old_parser) == 2
text = text.replace(old_parser, new_parser)

old_constructor = '''        backupEligible = backupEligible,
        backupState = backupState,
'''
new_constructor = '''        backupEligible = credentialBackupState.isEligible,
        backupState = credentialBackupState.isBackedUp,
'''
assert text.count(old_constructor) == 2
text = text.replace(old_constructor, new_constructor)

path.write_text(text)
