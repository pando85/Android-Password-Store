---
name: pre-merge-ci
description: Run CI checks locally before merging a PR. Covers build verification (assembleDebug) and optionally the full CI suite.
---

## When to use

- User asks to "run CI locally", "pre-merge check", "verify before merge"
- User is about to merge a PR and wants to confirm the build compiles
- User wants to run `assembleDebug` locally (the CI job not covered by the pre-push hook)

## Cheat sheet

| Step | Command | What it does | Est. time |
|------|---------|-------------|-----------|
| Build APKs | `./gradlew assembleDebug` | Verify compilation produces debug APKs | ~2 min |
| Full CI suite | `CI=true ./gradlew lint spotlessCheck test -PslimTests` | Same as the PR workflow | ~5 min |
| Everything | Both of the above | Full pre-merge gate | ~7 min |

## Pre-merge checklist

When the user asks to verify before merging:

1. **Build verification** (`assembleDebug`): Always run this — it's the CI job the pre-push hook doesn't cover
2. **Full suite** (optional): Run if there are significant or risky changes

The pre-push hook (`git push`) already covers `lint + spotlessCheck + test -PslimTests`, so `assembleDebug` is the only gap.

## Running

```bash
# Quick build check (recommended before every merge)
./gradlew assembleDebug

# Full suite (for risky changes or before merging to main)
CI=true ./gradlew lint spotlessCheck test -PslimTests

# Everything (full CI equivalent)
CI=true ./gradlew lint spotlessCheck test -PslimTests assembleDebug
```
