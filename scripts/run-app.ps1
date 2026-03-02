param(
    [switch]$Once,
    [int]$RestartDelaySeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$appDir = Join-Path $repoRoot "AchadinhosBot.Next"
$logDir = Join-Path $repoRoot "logs"
$outLog = Join-Path $logDir "app-host.out.log"
$errLog = Join-Path $logDir "app-host.err.log"

New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$dotnetCmd = Get-Command dotnet -ErrorAction SilentlyContinue
$exe = if ($dotnetCmd -and $dotnetCmd.Source) { $dotnetCmd.Source } else { "dotnet" }
$dll = Join-Path $appDir "bin/Release/net8.0/AchadinhosBot.Next.dll"
$appArgs = @($dll, "--urls", "http://0.0.0.0:5000")

if (-not (Test-Path $dll)) {
    throw "DLL nao encontrada: $dll"
}

function Run-AppOnce {
    Push-Location $appDir
    try {
        & $exe @appArgs 1>>$outLog 2>>$errLog
    }
    finally {
        Pop-Location
    }
}

if ($Once) {
    Run-AppOnce
    exit 0
}

while ($true) {
    Run-AppOnce
    Start-Sleep -Seconds $RestartDelaySeconds
}
