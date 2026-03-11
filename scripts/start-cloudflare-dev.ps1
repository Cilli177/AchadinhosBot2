param(
    [string]$AppUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-HealthyDevAppUrl {
    param(
        [string]$CandidateUrl
    )

    if (-not [string]::IsNullOrWhiteSpace($CandidateUrl)) {
        return $CandidateUrl
    }

    foreach ($url in @("http://127.0.0.1:8081", "http://127.0.0.1:5000")) {
        try {
            $response = Invoke-WebRequest "$url/health" -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                return $url
            }
        }
        catch {
        }
    }

    return "http://127.0.0.1:8081"
}

$resolvedAppUrl = Resolve-HealthyDevAppUrl -CandidateUrl $AppUrl

& (Join-Path $PSScriptRoot "start-cloudflare-tunnel.ps1") `
    -TunnelName "achadinhos-dev" `
    -Hostname "achadinhos-dev.reidasofertas.ia.br" `
    -AppUrl $resolvedAppUrl `
    -NoConfigUpdate `
    -ConfigFileName "config.dev.yml" `
    -LogPrefix "dev"
