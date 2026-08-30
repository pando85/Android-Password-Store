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

## Current reconciliation (2026-08-29)

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
