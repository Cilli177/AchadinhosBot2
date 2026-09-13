[CmdletBinding()]
param(
    [switch]$IncludeStaged
)

$ErrorActionPreference = "Stop"

function Get-TrackedPaths {
    param([switch]$Staged)

    if ($Staged) {
        return @(& git diff --cached --name-only --diff-filter=ACMR)
    }

    return @(& git ls-files)
}

$forbiddenPatterns = @(
    '(^|/).*\.session(\.|$)',
    '(^|/).*-qr\.(png|jpe?g)$',
    '(^|/)(backups|restore-stage-data-current|hotfix-build)(/|$)',
    '(^|/)(build_errors[^/]*\.txt|logs[^/]*\.(txt|err|out)|test_(error|failure|results)[^/]*\.txt|out(_final[^/]*|_ml|_v[0-9][^/]*)?\.json|tmp[-_][^/]*|diff\.txt)$',
    '(^|/)_probe_.*\.bin$'
)

if ($IncludeStaged) {
    # This mode is the pre-commit gate: inspect only paths being introduced or
    # modified in the index. Deletions cannot introduce a forbidden artifact.
    $paths = Get-TrackedPaths -Staged
}
else {
    $paths = Get-TrackedPaths
}

$violations = foreach ($path in ($paths | Sort-Object -Unique)) {
    if ($path -match '(^|/)\.env($|\.)' -and $path -notmatch '\.example$') {
        $path
        continue
    }

    foreach ($pattern in $forbiddenPatterns) {
        if ($path -match $pattern) {
            $path
            break
        }
    }
}

if ($violations) {
    Write-Error ("Repository hygiene check failed. Forbidden tracked paths:`n{0}" -f ($violations -join "`n"))
    exit 1
}

$scope = if ($IncludeStaged) { "staged additions/modifications" } else { "all tracked paths" }
Write-Host "Repository hygiene check passed for ${scope}: no forbidden paths found."
