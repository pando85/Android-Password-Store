---
name: release
description: Prepare and publish a new Android Password Store release. Use when the user asks to release, cut a release, publish a new version, or tag a release.
---

## Purpose

Release a new version of Android Password Store using the existing version file, curated changelog, auto-tag workflow, and release workflow.

## When to use

Use this skill when:
- The user asks to release a new Android Password Store version
- The user asks to cut or publish a release
- The user asks to clear a snapshot version and tag a release

Do not use this for one-time release pipeline setup. Use `setup-android-release` for setup work.

## Prerequisites

Before releasing, verify:

1. **Working tree is clean** -- no uncommitted changes except user-approved release edits
2. **You are on `main`** -- releases happen from main
3. **Local main is up to date with origin/main**
4. **No commits ahead of origin/main** unless preparing the release branch/commit intentionally
5. **Repository has enough history and tags** to compare against the latest release tag

If the checkout was fetched with only the latest commit, fetch history and tags before reviewing commits:

```bash
git rev-parse --is-shallow-repository
git fetch --unshallow origin  # only if shallow
git fetch --tags origin
```

## Release Process

### Step 1: Verify State

```bash
git checkout main
git pull origin main
git status --short
git tag --sort=-creatordate | head -3
```

If the repo is shallow, unshallow it before using `git log` for release notes.

### Step 2: Determine Version

Read the current version:

```bash
grep 'versioning-plugin.versionName' app/version.properties
```

Release versions must not contain `-SNAPSHOT` or another pre-release suffix. The auto-tag workflow skips snapshot/pre-release versions.

### Step 3: Review Changes Since Last Release

```bash
LATEST_TAG=$(git tag --sort=-creatordate | head -1)
git log --oneline "$LATEST_TAG"..HEAD --no-merges
```

Ensure every user-facing change is represented in `CHANGELOG.md`. Dependency bumps can be grouped if they are not individually user-facing.

### Step 4: Update CHANGELOG.md

1. Review the `[Unreleased]` section.
2. Move entries into a new release section:
   ```markdown
   ## [<version>] - YYYY-MM-DD
   ```
3. Add a new empty `## [Unreleased]` section above the release section.
4. Keep fork/CI/signing-only changes in a `### Fork infrastructure` subsection when relevant.

### Step 5: Clear Snapshot Version

```bash
./gradlew :app:clearPreRelease
```

Verify `app/version.properties` version matches the changelog release section exactly.

### Step 6: Commit And Push Release

```bash
VERSION=$(grep 'versioning-plugin.versionName' app/version.properties | cut -d= -f2 | tr -d '[:space:]')
git add app/version.properties CHANGELOG.md
git commit -m "release: $VERSION"
git push origin main
```

The auto-tag workflow runs only when `app/version.properties` changes on `main` and the version is not a snapshot/pre-release.

### Step 7: Monitor Tag And Release Workflows

```bash
gh run list --limit 5
```

Expected flow:

1. `auto-tag.yml` creates signed tag `v<VERSION>`.
2. `release.yml` builds the signed APK.
3. `release.yml` publishes GitHub Release `v<VERSION>` using the matching `CHANGELOG.md` entry.

Do not manually create tags. CI handles tags and releases.

### Step 8: Start Next Development Cycle

After the release is published:

```bash
./gradlew :app:bumpSnapshot
```

Ensure `CHANGELOG.md` still has an empty `## [Unreleased]` section, then commit:

```bash
NEXT_VERSION=$(grep 'versioning-plugin.versionName' app/version.properties | cut -d= -f2 | tr -d '[:space:]')
git add app/version.properties CHANGELOG.md
git commit -m "chore: start $NEXT_VERSION"
git push origin main
```

## What Not To Do

| Mistake | Why it's wrong | Fix |
|---------|---------------|-----|
| Releasing with `-SNAPSHOT` in version | Auto-tag skips snapshots | Run `./gradlew :app:clearPreRelease` |
| Version/changelog mismatch | Release workflow cannot find notes | Match `app/version.properties` and `CHANGELOG.md` section |
| Manually creating tags | Auto-tag creates signed tags | Push the release commit to main |
| Skipping history/tag fetch in a shallow checkout | Commit review misses changes | Fetch full history/tags first |
| Committing version without changelog | Release notes are incomplete | Commit both files together |

## Key Files

| File | Role |
|------|------|
| `app/version.properties` | Version source for auto-tag and release workflows |
| `CHANGELOG.md` | Curated release notes read by release workflow |
| `.github/workflows/auto-tag.yml` | Creates signed tag on release version push |
| `.github/workflows/release.yml` | Builds signed APK and creates GitHub Release |
| `.opencode/skills/setup-android-release/SKILL.md` | One-time release pipeline setup guidance |

## Checklist

- [ ] On `main`, clean working tree
- [ ] Pulled latest `origin/main`
- [ ] Repository has full history/tags if using git log for release notes
- [ ] Reviewed commits since latest tag
- [ ] Updated `CHANGELOG.md` release section
- [ ] Ran `./gradlew :app:clearPreRelease`
- [ ] Verified version matches changelog section
- [ ] Committed `app/version.properties` and `CHANGELOG.md` together
- [ ] Pushed to main
- [ ] Confirmed auto-tag and release workflows passed
- [ ] Ran `./gradlew :app:bumpSnapshot` and committed next snapshot
