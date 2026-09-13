# Secret and runtime-data handling

## Version-control boundary

Version source code, redacted configuration examples, and documentation. Keep environment
files, sessions, QR artifacts, backups, persistent runtime data, diagnostic dumps, and
generated logs outside the repository.

The ignore rules intentionally allow `.env.example` and `.env.*.example` so required variable
names can be documented without versioning values.

## Before staging

1. Run `pwsh -File scripts/verify-repository-hygiene.ps1 -IncludeStaged` after staging explicit paths.
2. Review `git diff --name-status` and `git diff --cached --name-status`.
3. Stage explicit paths only. Never use a bulk add command when a worktree contains runtime or
   recovery material.

## If a secret was tracked

Removing the file prevents future commits from carrying it, but does not invalidate previously
exposed values. Rotate the credential first, then decide whether history rewriting is justified
under the repository owner's incident process.

## Historical artifact debt

See [Historical tracked artifact debt](HISTORICAL_TRACKED_ARTIFACT_DEBT.md). The pre-commit
gate checks staged additions and modifications only so that historical debt does not block a
safe incremental cleanup. It is not a waiver to add another artifact of the same kind.
