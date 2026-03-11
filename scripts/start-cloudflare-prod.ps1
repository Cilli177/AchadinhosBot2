param(
    [string]$AppUrl = "http://127.0.0.1:5005",
    [string]$TunnelName = "achadinhos-fixed",
    [string]$Hostname = "achadinhos.reidasofertas.ia.br",
    [string]$BioHostname = "bio.reidasofertas.ia.br"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot "start-cloudflare-tunnel.ps1") `
    -TunnelName $TunnelName `
    -Hostname $Hostname `
    -AppUrl $AppUrl `
    -ConfigFileName "config.prod.yml" `
    -LogPrefix "prod" `
    -ConfigUpdateScope "Production"

if (-not [string]::IsNullOrWhiteSpace($BioHostname)) {
    $cloudflared = (Get-Command "cloudflared" -ErrorAction Stop).Source
    & $cloudflared tunnel route dns $TunnelName $BioHostname 2>$null
}
