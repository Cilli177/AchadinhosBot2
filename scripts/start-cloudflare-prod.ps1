param(
    [string]$AppUrl = "http://127.0.0.1:5005"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot "start-cloudflare-tunnel.ps1") `
    -TunnelName "achadinhos-fixed" `
    -Hostname "achadinhos.reidasofertas.ia.br" `
    -AppUrl $AppUrl `
    -ConfigFileName "config.prod.yml" `
    -LogPrefix "prod" `
    -ConfigUpdateScope "Production"
