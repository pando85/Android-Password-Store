#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/agrahn/Android-Password-Store.git}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-develop}"
BASELINE_FILE="${UPSTREAM_BASELINE_FILE:-.github/upstream-sync-baseline}"
OUTPUT="${1:-upstream-audit.md}"

if [[ ! -f "$BASELINE_FILE" ]]; then
  echo "Missing upstream baseline: $BASELINE_FILE" >&2
  exit 2
fi

BASELINE="$(tr -d '[:space:]' < "$BASELINE_FILE")"
if ! [[ "$BASELINE" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Invalid upstream baseline SHA in $BASELINE_FILE: $BASELINE" >&2
  exit 2
fi

if git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
  git remote set-url "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
else
  git remote add "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
fi

git fetch --quiet --no-tags "$UPSTREAM_REMOTE" "$UPSTREAM_BRANCH"
UPSTREAM_REF="$UPSTREAM_REMOTE/$UPSTREAM_BRANCH"
UPSTREAM_HEAD="$(git rev-parse "$UPSTREAM_REF")"

if ! git cat-file -e "${BASELINE}^{commit}" 2>/dev/null; then
  echo "Baseline $BASELINE is not available after fetching $UPSTREAM_REF" >&2
  exit 2
fi
if ! git merge-base --is-ancestor "$BASELINE" "$UPSTREAM_HEAD"; then
  echo "Baseline $BASELINE is not an ancestor of $UPSTREAM_REF ($UPSTREAM_HEAD)." >&2
  echo "Upstream may have been rebased; review manually before moving the baseline." >&2
  exit 3
fi

COUNT="$(git rev-list --count "$BASELINE..$UPSTREAM_HEAD")"

classify_path() {
  local path="$1"
  case "$path" in
    passkeys/*|PASSKEYS.md|PasskeyStorage.md|app/src/main/java/app/passwordstore/passkeys/*|app/src/main/java/app/passwordstore/injection/passkeys/*|app/src/main/res/xml/passkey_provider.xml|app/src/main/res/values-v34/bools.xml)
      printf 'PASSKEY-PROTECTED'
      ;;
    autofill-parser/*|app/src/main/java/app/passwordstore/util/autofill/*|app/src/main/java/app/passwordstore/ui/autofill/*)
      printf 'AUTOFILL'
      ;;
    app/src/main/java/app/passwordstore/ui/crypto/*|app/src/main/java/app/passwordstore/ui/pgp/*|crypto/*)
      printf 'PGP/CRYPTO'
      ;;
    gradle/*|gradlew|gradlew.bat|renovate.json|*/build.gradle.kts|build.gradle.kts|settings.gradle.kts)
      printf 'DEPENDENCY/BUILD'
      ;;
    .github/*)
      printf 'CI/REPOSITORY'
      ;;
    *publicsuffix*)
      printf 'GENERATED-DATA'
      ;;
    *)
      printf 'CLASSIC-APP'
      ;;
  esac
}

{
  echo "# Upstream reconciliation report"
  echo
  echo "- Fork: \`$(git rev-parse --short=12 HEAD)\`"
  echo "- Last reviewed upstream: \`$BASELINE\`"
  echo "- Current upstream \`$UPSTREAM_BRANCH\`: \`$UPSTREAM_HEAD\`"
  echo "- New upstream commits: **$COUNT**"
  echo

  if [[ "$COUNT" == "0" ]]; then
    echo "No upstream changes require review."
  else
    echo "## Commits"
    echo
    git log --reverse --format='- `%h` %s' "$BASELINE..$UPSTREAM_HEAD"
    echo
    echo "## Changed files"
    echo
    echo "| Area | Path |"
    echo "| --- | --- |"
    while IFS= read -r path; do
      [[ -z "$path" ]] && continue
      printf '| %s | `%s` |\n' "$(classify_path "$path")" "$path"
    done < <(git diff --name-only "$BASELINE..$UPSTREAM_HEAD")
    echo
    echo "## Review policy"
    echo
    echo "- **PASSKEY-PROTECTED** changes are never adopted mechanically. Review their behavioural/security invariant and reimplement only when it applies to this fork."
    echo "- Classic app, Autofill, PGP and crypto fixes can normally be selectively cherry-picked or semantically ported."
    echo "- Dependency/build updates stay under Renovate unless an upstream change carries behaviour not represented by a version bump."
    echo "- Generated public-suffix data should be refreshed as one current snapshot rather than replaying historical update commits."
    echo
    echo "After every commit in this report has a disposition (adopted, adapted, already solved, or intentionally skipped), run \`scripts/mark-upstream-reviewed.sh\` and commit the baseline change."
  fi
} > "$OUTPUT"

HAS_CHANGES=false
if [[ "$COUNT" != "0" ]]; then
  HAS_CHANGES=true
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "has_changes=$HAS_CHANGES"
    echo "commit_count=$COUNT"
    echo "upstream_head=$UPSTREAM_HEAD"
  } >> "$GITHUB_OUTPUT"
fi

cat "$OUTPUT"
