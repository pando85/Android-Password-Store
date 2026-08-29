#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

UPSTREAM_URL="https://github.com/agrahn/Android-Password-Store.git"
UPSTREAM_BRANCH="develop"

if git remote get-url upstream >/dev/null 2>&1; then
  git remote set-url upstream "$UPSTREAM_URL"
else
  git remote add upstream "$UPSTREAM_URL"
fi

git fetch --quiet --no-tags upstream "$UPSTREAM_BRANCH"

find_pr_commit() {
  local pr="$1"
  local sha
  sha="$(git log "upstream/$UPSTREAM_BRANCH" --format='%H' --grep="#${pr}" -n 1)"
  if [[ -z "$sha" ]]; then
    echo "Unable to locate upstream PR #$pr on upstream/$UPSTREAM_BRANCH" >&2
    exit 10
  fi
  printf '%s' "$sha"
}

apply_pr_paths() {
  local pr="$1"
  shift
  local sha
  sha="$(find_pr_commit "$pr")"
  echo "Applying upstream #$pr from $sha"

  local path patch
  for path in "$@"; do
    patch="$(mktemp)"
    git diff --binary "${sha}^" "$sha" -- "$path" > "$patch"
    if [[ ! -s "$patch" ]]; then
      echo "Expected $path to change in upstream #$pr, but it did not." >&2
      rm -f "$patch"
      exit 11
    fi
    if ! git apply --3way --index --whitespace=nowarn "$patch"; then
      echo "Failed to three-way apply upstream #$pr path: $path" >&2
      rm -f "$patch"
      git status --short >&2 || true
      exit 12
    fi
    rm -f "$patch"
  done

  if ! git diff --cached --quiet; then
    git commit -m "chore(upstream): port upstream #$pr" -m "Selective port from agrahn/Android-Password-Store PR #$pr. Fork-owned passkey implementation is intentionally excluded unless explicitly listed."
  fi
}

# Small classic-app fixes and complete recent-password timestamp lifecycle.
apply_pr_paths 936 \
  app/src/main/java/app/passwordstore/util/git/sshj/SshKey.kt

# #938 overlaps fork-specific password creation work. Apply only its timestamp-cache invariant.
python3 <<'PY'
from pathlib import Path
path = Path("app/src/main/java/app/passwordstore/ui/crypto/PasswordCreationActivity.kt")
text = path.read_text()
old = '''          // associate the new password name with the last name's timestamp in history
          val preference = getSharedPreferences("recent_password_history", Context.MODE_PRIVATE)
          val oldFilePathHash = "${fullPath.trimEnd('/')}/$suggestedName.gpg".base64()
          val timestamp = preference.getString(oldFilePathHash)
          if (timestamp != null) {
            preference.edit {
              remove(oldFilePathHash)
              putString(passwordFile.absolutePathString().base64(), timestamp)
            }
          }
'''
new = '''          // create/update timestamp on the current password file
          val preference = getSharedPreferences("recent_password_history", Context.MODE_PRIVATE)
          preference.edit {
            suggestedName?.let { oldFile ->
              val oldFilePathHash = "${fullPath.trimEnd('/')}/$oldFile.gpg".base64()
              remove(oldFilePathHash)
            }
            putString(
              passwordFile.absolutePathString().base64(),
              System.currentTimeMillis().toString(),
            )
          }
'''
if old not in text:
    raise SystemExit("Unable to locate fork timestamp block for upstream #938")
path.write_text(text.replace(old, new, 1))
PY
git add app/src/main/java/app/passwordstore/ui/crypto/PasswordCreationActivity.kt
git commit -m "chore(upstream): adapt upstream #938 timestamp lifecycle" -m "Preserve fork-specific password creation logic while updating recent-password timestamps on every create/edit."

apply_pr_paths 939 \
  app/src/main/java/app/passwordstore/ui/passwords/PasswordStore.kt
apply_pr_paths 941 \
  app/src/main/java/app/passwordstore/ui/passwords/PasswordStore.kt
apply_pr_paths 942 \
  app/src/main/java/app/passwordstore/ui/settings/RepositorySettings.kt \
  app/src/main/java/app/passwordstore/util/extensions/AndroidExtensions.kt

# Contextual fast-unlock wording. Deliberately omit upstream's ui/credman passkey activity.
apply_pr_paths 1000 \
  app/src/main/java/app/passwordstore/ui/autofill/AutofillDecryptActivity.kt \
  app/src/main/java/app/passwordstore/ui/crypto/BasePGPActivity.kt \
  app/src/main/res/values/strings.xml \
  app/src/main/res/values-de/strings.xml

apply_pr_paths 1007 \
  app/src/main/java/app/passwordstore/util/shortcuts/ShortcutHandler.kt

# Fast-unlock state is isolated per PGP identity. This is a security invariant, not a passkey port.
apply_pr_paths 1011 \
  app/src/main/java/app/passwordstore/Application.kt \
  app/src/main/java/app/passwordstore/injection/prefs/PreferenceModule.kt \
  app/src/main/java/app/passwordstore/injection/prefs/UnlockPins.kt \
  app/src/main/java/app/passwordstore/ui/crypto/BasePGPActivity.kt \
  app/src/main/java/app/passwordstore/ui/crypto/PinDialog.kt \
  app/src/main/java/app/passwordstore/ui/settings/PasswordSettings.kt \
  app/src/main/java/app/passwordstore/util/extensions/AndroidExtensions.kt \
  app/src/main/java/app/passwordstore/util/settings/Migrations.kt \
  app/src/test/java/app/passwordstore/util/settings/MigrationsTest.kt

apply_pr_paths 1014 \
  app/src/main/java/app/passwordstore/ui/crypto/DecryptActivity.kt \
  app/src/main/java/app/passwordstore/ui/settings/PasswordSettings.kt \
  app/src/main/java/app/passwordstore/util/settings/PreferenceKeys.kt \
  app/src/main/res/values/strings.xml \
  app/src/main/res/values-de/strings.xml
apply_pr_paths 1016 \
  app/src/main/java/app/passwordstore/util/autofill/Api30AutofillResponseBuilder.kt
apply_pr_paths 1022 \
  app/src/main/AndroidManifest.xml
apply_pr_paths 1026 \
  autofill-parser/src/main/java/com/github/androidpasswordstore/autofillparser/FeatureAndTrustDetection.kt
apply_pr_paths 1043 \
  app/src/main/java/app/passwordstore/ui/pgp/PGPKeyListActivity.kt

# Generated data is adopted as one current snapshot rather than replaying update commits.
git checkout "upstream/$UPSTREAM_BRANCH" -- autofill-parser/src/main/assets/publicsuffixes
if ! git diff --cached --quiet; then
  git commit -m "chore(autofill): refresh Public Suffix List from upstream"
fi

# Keep the recurring tools executable in normal clones.
chmod +x scripts/upstream-audit.sh scripts/adopt-upstream-pr.sh scripts/mark-upstream-reviewed.sh

# One-time bootstrap machinery must not remain in the resulting PR.
rm -f scripts/bootstrap-upstream-sync.sh .github/workflows/bootstrap-upstream-sync.yml

git add -A
if ! git diff --cached --quiet; then
  git commit -m "chore(upstream): finalize recurring reconciliation tooling"
fi

# Normalize Kotlin/XML formatting after the selective ports.
./gradlew spotlessApply
git add -A
if ! git diff --cached --quiet; then
  git commit -m "style: format selective upstream ports"
fi

git push origin "HEAD:${GITHUB_REF_NAME}"
