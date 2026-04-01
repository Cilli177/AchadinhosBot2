Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$envFile = Join-Path $repoRoot ".env.prod"
$composeFile = Join-Path $repoRoot "docker-compose.tunnels.yml"
$expectedTunnelId = "97a029fe-3c66-446c-b727-d016928cbcb8"

function Assert-PathExists {
    param([Parameter(Mandatory = $true)][string]$PathValue)
    if (-not (Test-Path $PathValue)) {
        throw "Arquivo nao encontrado: $PathValue"
    }
}

function Get-EnvValue {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$Key
    )

    $line = Get-Content $FilePath | Where-Object { $_.StartsWith("$Key=") } | Select-Object -First 1
    if (-not $line) {
        return $null
    }

    return ($line -split "=", 2)[1].Trim()
}

Assert-PathExists -PathValue $envFile
Assert-PathExists -PathValue $composeFile

$credDir = Get-EnvValue -FilePath $envFile -Key "CLOUDFLARED_CRED_DIR"
if ([string]::IsNullOrWhiteSpace($credDir)) {
    throw "CLOUDFLARED_CRED_DIR nao definido em .env.prod"
}

if (-not (Test-Path $credDir)) {
    throw "Diretorio de credenciais nao encontrado: $credDir"
}

$expectedCredFile = Join-Path $credDir "$expectedTunnelId.json"
if (-not (Test-Path $expectedCredFile)) {
    throw "Credencial do tunnel nao encontrada: $expectedCredFile"
}

$composeArgs = @(
    "compose",
    "--env-file", $envFile,
    "-p", "achadinhos-tunnels",
    "-f", $composeFile,
    "up",
    "-d",
    "--force-recreate",
    "cloudflared-prod"
)

Push-Location $repoRoot
try {
    docker @composeArgs
}
finally {
    Pop-Location
}
