Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$composeArgs = @(
    "compose",
    "-p", "achadinhos-dev",
    "-f", "docker-compose.yml",
    "-f", "docker-compose.dev.override.yml",
    "ps"
)

Push-Location $repoRoot
try {
    docker @composeArgs
}
finally {
    Pop-Location
}
