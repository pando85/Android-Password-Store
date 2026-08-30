#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/adopt-upstream-pr.sh [--allow-passkeys] <upstream-pr-number>

Find the squash/merge commit for an upstream PR on agrahn/Android-Password-Store:develop,
refuse protected passkey changes by default, then cherry-pick it with provenance.
EOF
}

ALLOW_PASSKEYS=false
if [[ "${1:-}" == "--allow-passkeys" ]]; then
  ALLOW_PASSKEYS=true
  shift
fi

PR="${1:-}"
if ! [[ "$PR" =~ ^[0-9]+$ ]]; then
  usage >&2
  exit 2
fi

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Working tree must be clean before adopting an upstream PR." >&2
  exit 2
fi

UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/agrahn/Android-Password-Store.git}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-develop}"

if git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
  git remote set-url "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
else
  git remote add "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
fi

git fetch --quiet --no-tags "$UPSTREAM_REMOTE" "$UPSTREAM_BRANCH"
UPSTREAM_REF="$UPSTREAM_REMOTE/$UPSTREAM_BRANCH"

COMMIT="$(git log "$UPSTREAM_REF" --format='%H' --grep="#${PR}" -n 1)"
if [[ -z "$COMMIT" ]]; then
  echo "Could not find a commit for upstream PR #$PR on $UPSTREAM_REF." >&2
  exit 3
fi

mapfile -t FILES < <(git diff-tree --no-commit-id --name-only -r "$COMMIT")
PROTECTED=()
for path in "${FILES[@]}"; do
  case "$path" in
    passkeys/*|PASSKEYS.md|PasskeyStorage.md|app/src/main/java/app/passwordstore/passkeys/*|app/src/main/java/app/passwordstore/injection/passkeys/*|app/src/main/res/xml/passkey_provider.xml|app/src/main/res/values-v34/bools.xml)
      PROTECTED+=("$path")
      ;;
  esac
done

if (( ${#PROTECTED[@]} > 0 )) && [[ "$ALLOW_PASSKEYS" != true ]]; then
  echo "Refusing to cherry-pick upstream PR #$PR because it touches fork-owned passkey code:" >&2
  printf '  - %s\n' "${PROTECTED[@]}" >&2
  echo "Review the behavioural invariant and port it manually. Use --allow-passkeys only after an explicit review." >&2
  exit 4
fi

echo "Upstream PR #$PR -> $COMMIT"
printf '  %s\n' "${FILES[@]}"
git cherry-pick -x "$COMMIT"
