---
name: setup-android-release
description: Set up automated GitHub Actions release pipeline for Android apps with signed APKs, GPG-signed tags, and auto-tagging from version files. Use for one-time setup, not routine release cuts.
---

## Purpose

Set up a two-stage CI release pipeline for Android projects:
1. **Auto-tag**: When a release version is pushed (no `-SNAPSHOT`), create a GPG-signed git tag
2. **Release**: On tag push, build a signed release APK and publish it as a GitHub Release

## When to use

- User asks to set up release CI for an Android project
- User wants GitHub Releases with signed APKs
- User wants automatic tagging when version changes
- User mentions "release pipeline", "release workflow", or "auto-tag"
- User asks to create, fix, or redesign the release automation itself
- User asks about required signing/GPG/PAT secrets for the Android release pipeline

## Pre-release checklist (MANDATORY before pushing)

When the user asks to cut a release, follow this checklist IN ORDER:

1. **Review CHANGELOG.md**: Read the `[Unreleased]` section. If it's empty or doesn't
   exist, create it with entries for all notable changes since the last release.
   Categorize into: Added, Changed, Fixed, Security, Fork infrastructure.

2. **Review git log**: Run `git log --oneline <last-tag>..HEAD --no-merges` to find
   all commits since the last release. Ensure every user-facing change has an entry
   in CHANGELOG.md. Dependency bumps can be grouped ("Update Kotlin, Compose, Gradle").

3. **Rename changelog section**: Change `## [Unreleased]` to `## [version] - YYYY-MM-DD`
   using the target version and today's date.

4. **Add new [Unreleased] header**: Insert a blank `## [Unreleased]` section above
   the released version for the next development cycle.

5. **Verify version consistency**: The version in `app/version.properties` (after
   `clearPreRelease`) MUST match the CHANGELOG.md section header. Mismatch will
   cause the release workflow to fail.

6. **Commit both files together**: `git add app/version.properties CHANGELOG.md`
   — never commit version without changelog.

## Prerequisites

The project must have:
- A version file (e.g. `app/version.properties`) with a semver version name
- A Gradle task that produces release APKs (e.g. `assembleRelease`)
- An Android signing keystore (`.jks` file)

## Required GitHub Secrets

| Secret | Description | How to generate |
|--------|-------------|-----------------|
| `PAT` | GitHub PAT with `repo` scope (for tag push to trigger downstream workflows) | `gh auth token` or GitHub Settings > Developer settings > Personal access tokens |
| `GPG_PRIVATE_KEY` | GPG private key for signing tags (full armored export including private + public blocks) | `gpg --armor --export-secret-keys <KEY_ID> && gpg --armor --export <KEY_ID>` |
| `KEYSTORE_BASE64` | Base64-encoded `.jks` keystore | `base64 -w0 keystore.jks` |
| `KEYSTORE_PASSWORD` | Keystore store password (also used as key password if same) | From your `keystore.properties` |
| `KEY_ALIAS` | Key alias within the keystore | From your `keystore.properties` |

## Workflow

### Step 1: Create auto-tag workflow

Create `.github/workflows/auto-tag.yml`. This workflow:
- Triggers on push to the main branch when the version file changes
- Reads the version from the version file
- Only proceeds if version has no `-SNAPSHOT` or pre-release suffix
- Checks if the tag already exists
- Imports GPG key and creates a signed tag

### Step 2: Create release workflow

Create `.github/workflows/release.yml`. This workflow:
- Triggers on tag push matching `v*`
- Decodes keystore from base64 secret
- Writes `keystore.properties` from secrets
- Builds the release APK
- Creates a GitHub Release with the APK attached

### Step 3: Set GitHub secrets

Use `gh secret set` for each secret. For secrets stored in `pass`:

```bash
pass <path/to/secret> | gh secret set SECRET_NAME --repo <owner/repo>
```

For the keystore:

```bash
base64 -w0 keystore.jks | gh secret set KEYSTORE_BASE64 --repo <owner/repo>
```

### Step 4: Test the pipeline

1. Ensure version has `-SNAPSHOT` suffix (auto-tag won't fire)
2. Remove snapshot: `./gradlew clearPreRelease` (or edit version file manually)
3. Commit and push
4. Verify auto-tag creates the tag
5. Verify release workflow builds and publishes

## Version file patterns

The auto-tag workflow needs to read the version. Adapt the grep command to your project:

### Gradle version.properties (APS pattern)

```bash
VERSION=$(grep 'versioning-plugin.versionName' app/version.properties | cut -d= -f2 | tr -d '[:space:]')
```

### Cargo.toml (Rust pattern)

```bash
VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
```

### package.json (Node pattern)

```bash
VERSION=$(jq -r '.version' package.json)
```

## Template: auto-tag.yml

```yaml
name: Auto tag

on:
  push:
    branches:
      - main  # or develop
    paths:
      - app/version.properties  # adapt to your version file

jobs:
  tag:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          token: ${{ secrets.PAT }}
          fetch-depth: 0

      - name: Read version
        id: version
        run: |
          VERSION=$(grep 'versionName' app/version.properties | cut -d= -f2 | tr -d '[:space:]')
          echo "version=$VERSION" >> $GITHUB_OUTPUT
          if [[ "$VERSION" == *"SNAPSHOT"* || "$VERSION" == *"-"* ]]; then
            echo "is_release=false" >> $GITHUB_OUTPUT
          else
            echo "is_release=true" >> $GITHUB_OUTPUT
          fi

      - name: Check if tag exists
        if: steps.version.outputs.is_release == 'true'
        id: check_tag
        run: |
          TAG="v${{ steps.version.outputs.version }}"
          if git ls-remote --tags origin | grep -q "refs/tags/$TAG"; then
            echo "exists=true" >> $GITHUB_OUTPUT
          else
            echo "exists=false" >> $GITHUB_OUTPUT
          fi

      - name: Import GPG key
        if: steps.version.outputs.is_release == 'true' && steps.check_tag.outputs.exists == 'false'
        env:
          GPG_PRIVATE_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
        run: echo "$GPG_PRIVATE_KEY" | gpg --batch --import

      - name: Create signed tag
        if: steps.version.outputs.is_release == 'true' && steps.check_tag.outputs.exists == 'false'
        run: |
          TAG="v${{ steps.version.outputs.version }}"
          git config --global user.name "${{ github.repository_owner }}"
          git config --global user.email "${{ github.repository_owner }}@users.noreply.github.com"
          GPG_KEY_ID=$(gpg --list-secret-keys --with-colons | grep '^sec' | cut -d':' -f5 | head -1)
          git tag -s "$TAG" -m "Release $TAG" --local-user "$GPG_KEY_ID"
          git push origin "$TAG"
```

## Template: release.yml

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v7

      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '21'

      - uses: gradle/actions/setup-gradle@v4

      - name: Decode signing keystore
        run: echo "${{ secrets.KEYSTORE_BASE64 }}" | base64 -d > keystore.jks

      - name: Write keystore.properties
        env:
          KEYSTORE_PASSWORD: ${{ secrets.KEYSTORE_PASSWORD }}
          KEY_ALIAS: ${{ secrets.KEY_ALIAS }}
        run: |
          {
            echo "storeFile=keystore.jks"
            echo "storePassword=${KEYSTORE_PASSWORD}"
            echo "keyAlias=${KEY_ALIAS}"
            echo "keyPassword=${KEYSTORE_PASSWORD}"
          } > keystore.properties

      - name: Build release APK
        run: ./gradlew :app:assembleRelease :app:collectReleaseApks --no-daemon

      - name: Read version
        id: version
        run: |
          VERSION=$(grep 'versionName' app/version.properties | cut -d= -f2 | tr -d '[:space:]')
          echo "version=$VERSION" >> $GITHUB_OUTPUT

      - name: Read changelog entry
        id: changelog
        uses: mindsers/changelog-reader-action@v2
        with:
          path: ./CHANGELOG.md
          version: ${{ steps.version.outputs.version }}

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ github.ref_name }}
          name: ${{ github.ref_name }}
          body: ${{ steps.changelog.outputs.changes }}
          files: app/outputs/*.apk
          fail_on_unmatched_files: true
```

## Signing config integration

The Android Gradle signing config reads `keystore.properties` from the project root. The convention plugin pattern:

```kotlin
// build-logic: AppSigning.kt
private const val KEYSTORE_CONFIG_PATH = "keystore.properties"

internal fun Project.configureBuildSigning() {
  val keystoreConfigFile = rootProject.layout.projectDirectory.file(KEYSTORE_CONFIG_PATH)
  if (keystoreConfigFile.asFile.exists()) {
    extensions.configure<ApplicationExtension> {
      val contents = providers.fileContents(keystoreConfigFile).asText
      val props = Properties().also { it.load(contents.get().byteInputStream()) }
      signingConfigs {
        register("release") {
          keyAlias = props["keyAlias"] as String
          keyPassword = props["keyPassword"] as String
          storeFile = rootProject.file(props["storeFile"] as String)
          storePassword = props["storePassword"] as String
        }
      }
      buildTypes.all { signingConfig = signingConfigs.getByName("release") }
    }
  }
}
```

The CI workflow recreates both `keystore.jks` and `keystore.properties` from secrets at runtime.

## GPG key setup

If the user doesn't have a GPG key for signing:

```bash
# Generate a key (no passphrase for CI usage)
gpg --batch --quick-generate-key "username <email>" rsa3072 sign 0

# Export for GitHub secret (both private and public)
gpg --armor --export-secret-keys <KEY_ID> > gpg-private.txt
gpg --armor --export <KEY_ID> >> gpg-private.txt
cat gpg-private.txt | gh secret set GPG_PRIVATE_KEY --repo <owner/repo>
```

## Release lifecycle

After initial setup, the day-to-day release flow is:

```bash
# 1. Update CHANGELOG.md: rename [Unreleased] to [version] with date
#    Example: ## [1.17.1] - 2026-06-30

# 2. Prepare release version (removes -SNAPSHOT suffix)
./gradlew :app:clearPreRelease

# 3. Commit and push
git add app/version.properties CHANGELOG.md
git commit -m "release: <version>"
git push origin main

# 4. Auto-tag fires → creates GPG-signed tag → release.yml builds APK
#    Release notes are extracted from CHANGELOG.md entry matching the version
#    (wait ~8 minutes for CI)

# 5. Start next development cycle
./gradlew :app:bumpSnapshot
# Add a new [Unreleased] section to CHANGELOG.md
git add app/version.properties CHANGELOG.md
git commit -m "chore: start <next-version>-SNAPSHOT"
git push origin main
```

The auto-tag workflow only fires when:
- `app/version.properties` changes on the default branch
- The version has NO `-SNAPSHOT` suffix (or any `-` pre-release marker)
- The tag doesn't already exist

Snapshot pushes are silently skipped.

## CHANGELOG.md integration

The release workflow reads release notes from `CHANGELOG.md` using
`mindsers/changelog-reader-action`. The changelog must have an entry
matching the released version:

```markdown
## [1.17.1] - 2026-06-30

### Added
- Feature description

### Fixed
- Fix description
```

If no entry is found, the release fails. This ensures every release
has curated, human-readable notes.

### When merging upstream

After merging upstream changes, consolidate the upstream's `[Unreleased]`
entries into the version section being released. Keep fork-specific
changes (CI, signing, etc.) in a separate `### Fork infrastructure`
subsection.

## Fork cleanup

When forking an Android project with existing CI, the upstream workflows often reference the original repo and use secrets you don't have. Steps:

1. **List existing workflows**: `git ls-tree -r --name-only HEAD .github/workflows/`
2. **Delete workflows** that reference the upstream repo or need unavailable secrets:
   ```bash
   git rm .github/workflows/deploy_github_releases.yml .github/workflows/deploy_snapshot.yml ...
   ```
3. **Fix remaining workflows** to point to your fork:
   ```bash
   sed -i 's|original-owner/repo|your-username/repo|g' .github/workflows/*.yml
   ```
4. **Fix issue templates and other references**:
   ```bash
   sed -i 's|original-owner/repo|your-username/repo|g' .github/ISSUE_TEMPLATE/*.yaml
   sed -i 's|/blob/develop/|/blob/main/|g' .github/ISSUE_TEMPLATE/*.yaml
   ```
5. **Rename default branch** if needed:
   ```bash
   git branch -m develop main
   git push -u origin main
   gh repo edit <owner/repo> --default-branch main
   git push origin --delete develop
   ```

## Troubleshooting

### Auto-tag didn't fire
- Check `app/version.properties` doesn't have `-SNAPSHOT` in the version
- Check the `paths:` filter in auto-tag.yml matches the version file path
- Check the push went to the correct branch (must match `branches:` in workflow)

### Auto-tag fired but tag wasn't created
- Check `PAT` secret has `repo` scope (needed to push tags that trigger downstream workflows)
- Check GPG key import worked: view workflow logs for "Import GPG key" step
- Check the tag doesn't already exist

### Release build failed: signing
- Check `KEYSTORE_BASE64` decodes to a valid `.jks` file
- Check `KEYSTORE_PASSWORD` matches both store and key password
- Check `KEY_ALIAS` exists in the keystore

### Release published but no APK attached
- Check `collectReleaseApks` task exists and produces files in `app/outputs/`
- Check `files:` glob in release.yml matches the output filename pattern

### Upstream workflows failing alongside new ones
- Delete them: see [Fork cleanup](#fork-cleanup) section

## Output

After setup, report:
1. Which workflow files were created
2. Which secrets were set (names only, never values)
3. The release URL if a release was triggered
4. How to cut the next release (clearPreRelease → push → bumpSnapshot cycle)

When cutting a release, report:
1. The CHANGELOG.md changes (what was moved from [Unreleased] to [version])
2. Whether any git log commits were missing from the changelog
3. The version being released and confirmation it matches in both files
4. The release URL once published
