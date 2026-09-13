# Historical tracked artifact debt

## Scope

The baseline contains historical diagnostic artifacts that predate the hygiene gate. They remain
tracked until a dedicated, reviewed cleanup commit removes them; this document does not authorize
their deletion and no files are removed by it.

## Recorded categories

- `AchadinhosBot.Next/build_errors*.txt` and `AchadinhosBot.Next/out_*.json`: build diagnostics
  and generated output snapshots.
- Root-level `build_errors*.txt`, `logs*.txt`, `test_*.txt`, `tmp-*`, `diff.txt`, and `out.json`:
  local diagnostics and temporary results.

`AchadinhosBot.Next/Domain/Logs/*.cs` is deliberately excluded from this debt: it is application
source code whose directory name does not make it a generated log artifact.

## Cleanup acceptance criteria

1. Confirm that no listed file is a required import/export or release input.
2. Remove only explicitly approved paths in a dedicated hygiene commit.
3. Preserve source files under `AchadinhosBot.Next/Domain/Logs/`.
4. Run `pwsh -File scripts/verify-repository-hygiene.ps1` after the cleanup and the staged-mode
   gate before committing future changes.
