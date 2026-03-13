Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$envFile = Join-Path $repoRoot ".env.prod"

$composeArgs = @(
    "compose",
    "--env-file", $envFile,
    "-p", "achadinhos-prod",
    "-f", "docker-compose.prod.yml",
    "down"
)

Push-Location $repoRoot
try {
    docker @composeArgs
}
finally {
    Pop-Location
}
