# Release Process

This document describes how to cut a release of Android Password Store (pando85 fork).

## Overview

Releases are fully automated via GitHub Actions:

1. **Auto-tag** (`.github/workflows/auto-tag.yml`): Watches `app/version.properties` on `main`.
   When a non-SNAPSHOT version is pushed, creates a GPG-signed git tag `v<version>`.
2. **Release** (`.github/workflows/release.yml`): Triggered by tag push. Builds a signed
   release APK and publishes it to GitHub Releases with auto-generated changelog.

## Cutting a release

```bash
# 1. Remove SNAPSHOT suffix
./gradlew :app:clearPreRelease

# 2. Commit and push
git add app/version.properties
git commit -m "release: $(grep 'versionName' app/version.properties | cut -d= -f2)"
git push origin main

# 3. Wait ~8 minutes for CI to build and publish

# 4. Verify
gh release view v$(grep 'versionName' app/version.properties | cut -d= -f2 | tr -d ' ')
```

## Starting the next development cycle

```bash
./gradlew :app:bumpSnapshot
git add app/version.properties
git commit -m "chore: start next SNAPSHOT"
git push origin main
```

## Required secrets

| Secret | Purpose | Source |
|--------|---------|--------|
| `PAT` | Push tags that trigger downstream workflows | `pass personal/github_pat_autotag` |
| `GPG_PRIVATE_KEY` | Sign git tags | `pass personal/github_gpg` |
| `KEYSTORE_BASE64` | Base64-encoded release signing keystore | `base64 -w0 keystore.jks` |
| `KEYSTORE_PASSWORD` | Keystore store + key password | `keystore.properties` |
| `KEY_ALIAS` | Key alias in keystore | `keystore.properties` |

## How it works

```
                        app/version.properties
                        versionName=1.17.0
                              │
                              ▼
                        push to main
                              │
                              ▼
                    ┌───────────────────┐
                    │   auto-tag.yml    │
                    │ GPG-signed tag    │
                    │   v1.17.0         │
                    └───────┬───────────┘
                            │ tag push
                            ▼
                    ┌───────────────────┐
                    │   release.yml     │
                    │ Build signed APK  │
                    │ GitHub Release    │
                    └───────────────────┘
```

The version follows semver with `-SNAPSHOT` for development builds.
`clearPreRelease` removes the suffix; `bumpSnapshot` increments and re-adds it.
