# Upstream reconciliation

This repository intentionally diverges from [`agrahn/Android-Password-Store`](https://github.com/agrahn/Android-Password-Store), especially in the passkey implementation. Upstream remains valuable for classic Password Store, Autofill, PGP, Android platform, browser compatibility, and UX fixes, but it must not be merged wholesale.

## Policy

The review unit is an **upstream commit/PR**, not a Git merge. Every upstream change since `.github/upstream-sync-baseline` gets one disposition:

- **adopted** — cherry-picked or ported without semantic changes;
- **adapted** — the upstream invariant applies, but the implementation is rewritten for this fork;
- **already solved** — the fork already covers the same bug or invariant;
- **skipped** — dependency, CI, release, obsolete implementation, or otherwise intentionally not applicable.

Passkey-owned paths are protected by policy. Changes under `passkeys/`, the app passkey provider/injection packages, passkey provider XML, and passkey documentation are never mechanically adopted. Upstream passkey changes are treated as an interoperability/security test corpus: identify the invariant first, then verify or reimplement it in the fork architecture.

## Routine review

1. Run `scripts/upstream-audit.sh`. It fetches `agrahn/Android-Password-Store:develop` and produces a Markdown report for only the commits after the recorded review baseline.
2. Review the report by area. Pay particular attention to **PASSKEY-PROTECTED**, **AUTOFILL**, and **PGP/CRYPTO** entries.
3. For a clean classic-app PR, use `scripts/adopt-upstream-pr.sh <PR>`. The helper refuses passkey-owned changes unless `--allow-passkeys` is explicitly supplied.
4. For cross-cutting or security-sensitive changes, port the behaviour manually and preserve the upstream PR/commit in the commit message or PR description.
5. Run the full repository CI, including passkey compatibility tests.
6. Once **every** upstream commit in the report has a disposition, run `scripts/mark-upstream-reviewed.sh` and commit the baseline update.

The baseline is deliberately an upstream SHA rather than a merge base. Selective cherry-picks do not create ancestry with upstream, so using the Git merge base would repeatedly report the same historical commits forever.

## Automated audit

`.github/workflows/upstream-audit.yml` runs weekly and can also be started manually. When new upstream commits exist it creates or refreshes one issue named **Upstream reconciliation pending** containing the same categorized report. The workflow never modifies source code or moves the review baseline automatically.

This split is intentional: detection is automated; adoption remains explicit.

## Current reconciliation (2026-10-27)

Reviewed through upstream `5f320126e14b9324db7a84f33e48fa9fdbdc30ca` (`develop`), starting from `48ce3af5b4cd9b818d44edca4249a15d48e2170f`. The opencode skill `.opencode/skills/upstream-sync` describes how to repeat this.

| Upstream PR / commit | Disposition | Scope |
| --- | --- | --- |
| 6f66681c, 47692244, 0c2ab3c8, #1056, #1101, #1109 | adapted | Password creation and Autofill save honour the directory-structure setting, keep subfolders and pre-fill the username. Ported as one change; Pass-Secrets mapped directories keep their encrypted-name structure, and paths are still sanitised against traversal |
| 47692244 | adopted (partial) | Forward client state to the save flow; unique PendingIntent request codes. The upstream passkey (CredmanUtils) hunk was not taken |
| #1057, #1059, #1060, #1081, #1082 | adopted | Autofill inline suggestions with two parent levels, refactored search pane, whitespace-tolerant search, start-ellipsised paths |
| #1061, #1087 | adapted | Improved username lookup; the form origin comes from the Autofill client state, not a static field |
| #1062 | adopted | Persistent switches on the Autofill search pane |
| #1072 | adapted | More Autofill suggestions; matches stored by older versions are migrated rather than dropped |
| #1079 | adapted | Classic Autofill never offers or fills passkey files (`fido2/<rp>/<id>.gpg`); path-based `AutofillPasskeyExclusion` with tests |
| #1080 | adapted | Empty search results suppressed by filtering to non-hidden `*.gpg` files instead of toggling the global hidden-files setting |
| #1090, #1091, #1094 | adopted | Enable-Autofill switch in app settings |
| #1093 | adapted | Autofill improvements; repository lookups skip hidden directories and passkey files |
| #1095, #1097, #1100 | adopted/adapted | Username extraction from file path; missing create-entry suggestion; no fuzzy match on empty folder names |
| #1088, #1089, 20222228 | skipped | Shorten passkey/hex ids: passkeys are now excluded from Autofill, and the fork has no upstream passkey creation screen |
| 35a42948 | already solved | Passkey app-authenticity verification; the fork does its own caller verification |
| #1076, #1116, #1119 | adopted/adapted | Android 17 local-network runtime permission and connectivity probe, kept behind the fork's `GitOperationCoordinator`; probe socket is closed |
| #1112 | adopted | sshj 0.41.x fixes (fork is already on sshj 0.41.2) |
| #1129 | adopted | Dialog showing the SSH server authentication banner |
| #1162 | adopted | SSH host key verification fix; also applies to the headless passkey SSH path |
| #1168 | adapted | External/shared repository option (`Documents/PasswordStore`). Passkey providers now resolve their storage root from `PasswordRepository` so passkeys stay in the Git working tree |
| #1063, #1115 | adapted | Bouncy Castle and coroutines versions aligned through BOMs (including passkey module build wiring) |
| #1065 | adopted | Alert dialogs no longer clipped by the IME on short screens |
| #1149, #1152, 1c048ab5 | adopted | Spanish translation fix; empty git author email allowed; fastlane banner renamed |
| #1055, #1086, 324757ed, 2ccde523 | skipped | Upstream README/verification text, lint baseline for absent `bcpkix`, string tweaks to diverged fork strings, upstream typo fixes |
| PSL updates | adopted as snapshot | Public Suffix List refreshed once from `upstream/develop` |
| Kotlin/Compose/androidx/serialization bumps, renovate commits | skipped | Owned by Renovate. Fork lags upstream on `bouncycastle` 1.86 → 1.86.2, `serialization` 1.11.0 → 1.12.0, `test-parameter-injector` 1.24 → 1.25; fork keeps jgit 7.8.0 (upstream reverted to 6.2.0) |
| Changelog, release and snapshot-bump commits | skipped | Fork keeps its own changelog and release pipeline |

## Reconciliation (2026-08-29)

Reviewed through upstream `48ce3af5b4cd9b818d44edca4249a15d48e2170f` (`develop`). The initial reconciliation ports or adapts the following upstream work while keeping the fork-owned passkey implementation:

| Upstream PR | Disposition | Scope |
| --- | --- | --- |
| #936 | adopted | Avoid rebuilding the SSH key type lookup map on every parse |
| #938, #939, #941, #942 | adopted/adapted | Complete recent-password timestamp lifecycle: create/edit, delete, move, repository reset |
| #1000 | adapted | Contextual PIN wording for Autofill; no import of upstream's passkey UI |
| #1007 | adopted | Correct shortcut identity and LRU ordering |
| #1011 | adapted | Bind fast-unlock PIN state to each PGP ID, including migration/cleanup |
| #1014 | adopted | Optional concealment of extra password-entry content |
| #1016 | adopted | Reuse IME inline-presentation specs safely when suggestions outnumber specs |
| #1022 | adopted | Android 17 local-network permission for SSH |
| #1026 | adapted | Add Titanium/Helium to classic browser trust detection; passkey caller trust remains independently controlled |
| #1043 | adopted | Make system Back and toolbar Back consistent in the PGP key chooser |
| PSL updates | adopted as snapshot | Refresh the current Public Suffix List once instead of replaying generated-data commits |

Dependency-only upstream commits remain owned by Renovate. Upstream CI/release workflow changes are not synchronized because this fork has its own release and validation pipeline.
