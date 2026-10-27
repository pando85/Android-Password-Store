---
name: upstream-sync
description: Sync this fork with upstream agrahn/Android-Password-Store by selectively porting non-passkey changes into a dated PR. Use when the user asks to sync, reconcile, pull or bring changes from upstream / agrahn.
---

## Purpose

Bring relevant upstream changes from [`agrahn/Android-Password-Store`](https://github.com/agrahn/Android-Password-Store) (`develop`) into this fork without importing upstream's passkey implementation. The full policy lives in `docs/upstream-reconciliation.md`; read it first.

Key facts:

- **Never `git merge upstream/develop`.** The fork has its own passkey/WebAuthn architecture. Changes are cherry-picked (`-x`) or ported one upstream commit/PR at a time.
- **The review baseline is an upstream SHA**, stored in `.github/upstream-sync-baseline`. It is *not* the Git merge-base: selective ports create no ancestry, so the merge-base stays old forever.
- **Passkey-owned paths are protected**: `passkeys/`, app passkey provider/injection packages, passkey provider XML, `PASSKEYS.md` and passkey docs. Upstream passkey changes are only an invariant/interoperability source; take the classic Password Store/Autofill part of mixed commits.
- **Dependency bumps are owned by the fork's Renovate.** Upstream CI, release, changelog and snapshot-bump commits are skipped. Only bump a dependency when a ported change requires it.

## Workflow

### 1. Audit

```bash
git fetch upstream            # remote: https://github.com/agrahn/Android-Password-Store.git
scripts/upstream-audit.sh "$SCRATCH/audit.md"
git rev-parse upstream/develop   # write down: this is the SHA you are reviewing up to
```

The report lists every upstream commit after the baseline plus changed files classified by area (PASSKEY-PROTECTED, AUTOFILL, PGP/CRYPTO, ...). Filter out dependency/action/PSL/release noise to get the list of meaningful commits.

### 2. Branch

```bash
DATE=$(date +%F)
git switch -c sync/upstream-$DATE main
```

### 3. Port by area, with subagents

Group the meaningful commits by area (e.g. autofill/password creation, SSH/git/network, misc UI/strings/build) and give each group to its own subagent in its own worktree so they run in parallel:

```bash
git worktree add -b sync/$DATE-<group> ../wt/<group> main
cp local.properties ../wt/<group>/   # untracked SDK config needed to build
```

Brief each subagent with: the worktree path, the exact upstream SHAs in its scope, the policy doc, the passkey boundary, "skip upstream CHANGELOG.md hunks", "no `clean`, no full lint (sibling builds)", and ask for a final table `| upstream SHA | PR | disposition | note |` covering **every** commit in scope. Use a stronger model for large or security-sensitive groups (autofill series, host-key verification, crypto); a cheaper one for mechanical groups.

Per commit:

- applies cleanly or with trivial conflicts → `git cherry-pick -x <sha>` (or `scripts/adopt-upstream-pr.sh <PR>`, which refuses passkey paths)
- needs rework → port manually, cite upstream SHA/PR in the commit message
- disposition is one of **adopted / adapted / already solved / skipped**

Also handle in one place:

- Public Suffix List: refresh `autofill-parser` PSL once from `upstream/develop` instead of replaying each update commit.
- Compare `gradle/libs.versions.toml` with upstream and list versions where the fork lags (report, don't bump unless needed).

### 4. Integrate

```bash
git switch sync/upstream-$DATE
git merge --no-ff sync/$DATE-<group>   # for each group; resolve strings.xml / CHANGELOG conflicts
./gradlew spotlessApply
CI=true ./gradlew lint spotlessCheck test -PslimTests assembleDebug
```

All checks must pass, including passkey compatibility tests. Then remove the temporary worktrees and branches (`git worktree remove ../wt/<group>`; `git branch -D sync/$DATE-<group>`).

### 5. Record

- Add a `## Reconciliation (<DATE>)` section to `docs/upstream-reconciliation.md` with the reviewed-through SHA and the disposition table (adopted/adapted rows individually, skipped categories summarised).
- Set the baseline to the SHA recorded in step 1 (do not run `scripts/mark-upstream-reviewed.sh` if upstream moved during the review — it writes the *current* upstream head):

  ```bash
  echo <reviewed-sha> > .github/upstream-sync-baseline
  ```

- Add user-visible changes to the `## [Unreleased]` section of `CHANGELOG.md`.

### 6. Pull request

```bash
git push -u origin sync/upstream-$DATE
gh pr create --repo pando85/Android-Password-Store --base main \
  --title "chore: sync upstream changes ($DATE)" --body-file <body.md>
```

PR body sections: Summary (upstream range `<old-baseline>..<reviewed-sha>`), Adopted/adapted changes (with upstream PR numbers), Skipped (with reasons), Passkey boundary, Lagging dependencies, Validation.

## Pitfalls

- `scripts/upstream-audit.sh` and `mark-upstream-reviewed.sh` reset the `upstream` remote URL to HTTPS.
- Upstream "autofill" commits sometimes touch passkey screens too (e.g. shortening passkey ids); port only the classic part.
- Upstream runtime-permission and SSH host-key changes are security relevant; review them rather than blindly cherry-picking.
- The fork's applicationId, CI workflows and release pipeline differ from upstream; never take upstream `.github/workflows/` or release commits.
- The external/shared repository option (upstream #1168, `PREF_SHARED_REPO`, `Documents/PasswordStore`) was deliberately removed: this fork is Git-only and keeps the store (and passkeys) in app-private storage. Skip later upstream changes that build on it.
