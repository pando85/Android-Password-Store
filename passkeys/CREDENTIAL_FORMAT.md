# Passkey credential format

APS and soft-fido2 share a CBOR map for portable Git/OpenPGP passkey credentials. This document records fields whose representation is part of the compatibility contract rather than an implementation detail.

## Credential backup state

The canonical representation is one CBOR text field:

```cbor
backup_state: "notEligible" | "eligible" | "backedUp"
```

| Value | WebAuthn BE | WebAuthn BS |
|---|---:|---:|
| `notEligible` | 0 | 0 |
| `eligible` | 1 | 0 |
| `backedUp` | 1 | 1 |

`BE=0, BS=1` is invalid.

APS releases that predate this contract wrote two booleans:

```cbor
backup_eligible: true
backup_state: false
```

Readers accept that legacy representation for migration. Writers must emit only the canonical text field and must not emit `backup_eligible`. A credential is therefore migrated lazily the next time it is saved or updated.

When neither legacy nor canonical backup fields are present, APS treats the existing Git/OpenPGP credential as `eligible`, matching the established migration policy for syncable credentials.

Canonical and legacy fields must not be mixed. Unknown text values, incorrect CBOR types, conflicting representations, and the invalid legacy combination `backup_eligible=false, backup_state=true` are rejected.
