#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/agrahn/Android-Password-Store.git}"
UPSTREAM_BRANCH="${UPSTREAM_BRANCH:-develop}"
BASELINE_FILE="${UPSTREAM_BASELINE_FILE:-.github/upstream-sync-baseline}"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Working tree must be clean before moving the upstream review baseline." >&2
  exit 2
fi

if git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
  git remote set-url "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
else
  git remote add "$UPSTREAM_REMOTE" "$UPSTREAM_URL"
fi

git fetch --quiet --no-tags "$UPSTREAM_REMOTE" "$UPSTREAM_BRANCH"
UPSTREAM_HEAD="$(git rev-parse "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH")"
printf '%s\n' "$UPSTREAM_HEAD" > "$BASELINE_FILE"

echo "Updated $BASELINE_FILE to $UPSTREAM_HEAD"
echo "Commit this only after every upstream change up to that SHA has an explicit disposition."
