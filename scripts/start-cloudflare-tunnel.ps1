param(
    [string]$AppUrl = "http://localhost:5000",
    [switch]$NoConfigUpdate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-CloudflaredPath {
    $candidates = @(
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Cloudflare.cloudflared_Microsoft.Winget.Source_8wekyb3d8bbwe\cloudflared.exe",
        "$env:LOCALAPPDATA\Microsoft\WindowsApps\cloudflared.exe"
    )

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        if (Test-Path $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }

    $cmd = Get-Command cloudflared -ErrorAction SilentlyContinue
    if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source)) {
        return $cmd.Source
    }

    throw "cloudflared nao encontrado. Instale com: winget install --id Cloudflare.cloudflared -e --source winget"
}

function Extract-TunnelUrlFromLogs {
    param([string[]]$Paths)

    $pattern = "https://[a-z0-9-]+\.trycloudflare\.com"
    foreach ($path in $Paths) {
        if (-not (Test-Path $path)) {
            continue
        }

        $content = Get-Content -Path $path -Raw -ErrorAction SilentlyContinue
        if ([string]::IsNullOrWhiteSpace($content)) {
            continue
        }

        $match = [regex]::Match($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($match.Success) {
            return $match.Value.Trim().TrimEnd("/")
        }
    }

    return $null
}

function Update-PublicBaseUrl {
    param(
        [string]$FilePath,
        [string]$NewUrl
    )

    if (-not (Test-Path $FilePath)) {
        return
    }

    $raw = Get-Content -Path $FilePath -Raw
    $updated = [regex]::Replace(
        $raw,
        '("PublicBaseUrl"\s*:\s*")[^"]+(")',
        ('$1' + $NewUrl + '$2'),
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if ($updated -ne $raw) {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($FilePath, $updated, $encoding)
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$outLog = Join-Path $repoRoot "cloudflared.out.log"
$errLog = Join-Path $repoRoot "cloudflared.err.log"

foreach ($log in @($outLog, $errLog)) {
    if (Test-Path $log) {
        Remove-Item $log -Force
    }
}

# Garante apenas um tunnel local ativo.
Get-Process cloudflared -ErrorAction SilentlyContinue | Stop-Process -Force

$cloudflaredPath = Resolve-CloudflaredPath
$process = Start-Process `
    -FilePath $cloudflaredPath `
    -ArgumentList @("tunnel", "--url", $AppUrl, "--no-autoupdate") `
    -WorkingDirectory $repoRoot `
    -WindowStyle Minimized `
    -RedirectStandardOutput $outLog `
    -RedirectStandardError $errLog `
    -PassThru

$tunnelUrl = $null
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 1
    $tunnelUrl = Extract-TunnelUrlFromLogs -Paths @($outLog, $errLog)
    if (-not [string]::IsNullOrWhiteSpace($tunnelUrl)) {
        break
    }

    if ($process.HasExited) {
        break
    }
}

if ([string]::IsNullOrWhiteSpace($tunnelUrl)) {
    Write-Host "Falha ao obter URL do Cloudflare Tunnel."
    if (Test-Path $errLog) {
        Write-Host "Ultimas linhas de erro:"
        Get-Content -Path $errLog -Tail 40
    }
    exit 1
}

if (-not $NoConfigUpdate) {
    Update-PublicBaseUrl -FilePath (Join-Path $repoRoot "AchadinhosBot.Next\appsettings.json") -NewUrl $tunnelUrl
    Update-PublicBaseUrl -FilePath (Join-Path $repoRoot "AchadinhosBot.Next\appsettings.Development.json") -NewUrl $tunnelUrl
}

Write-Host "Cloudflare Tunnel ativo."
Write-Host "URL: $tunnelUrl"
Write-Host "PID: $($process.Id)"
Write-Host "Logs: $outLog / $errLog"
