param(
    [string]$TunnelName = "achadinhos-fixed",
    [string]$Hostname = "achadinhos.reidasofertas.ia.br",
    [string[]]$AdditionalHostnames = @(),
    [string]$AppUrl = "http://127.0.0.1:5000",
    [switch]$NoConfigUpdate,
    [string]$ConfigFileName,
    [string]$LogPrefix,
    [ValidateSet("Production", "Development", "Both")]
    [string]$ConfigUpdateScope = "Production"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

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

function Ensure-CertFile {
    $certPath = Join-Path $env:USERPROFILE ".cloudflared\cert.pem"
    if (Test-Path $certPath) {
        return $certPath
    }

    throw "cert.pem nao encontrado. Execute: cloudflared tunnel login"
}

function Resolve-TunnelId {
    param(
        [string]$CloudflaredPath,
        [string]$Name
    )

    $uuidPattern = "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    $info = & $CloudflaredPath --loglevel error tunnel info $Name 2>$null
    if ($LASTEXITCODE -eq 0 -and $info) {
        $infoText = ($info | Out-String)
        if ($infoText -match $uuidPattern) {
            return $matches[1]
        }
    }

    $createOutput = & $CloudflaredPath --loglevel error tunnel create $Name 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Falha ao criar tunnel '$Name'."
    }

    $allText = ($createOutput | Out-String)
    if ($allText -match "id $uuidPattern") {
        return $matches[1]
    }

    $infoRetry = & $CloudflaredPath --loglevel error tunnel info $Name
    $infoRetryText = ($infoRetry | Out-String)
    if ($infoRetryText -match $uuidPattern) {
        return $matches[1]
    }

    throw "Nao foi possivel identificar o ID do tunnel '$Name'."
}

function Ensure-DnsRoute {
    param(
        [string]$CloudflaredPath,
        [string]$Name,
        [string]$HostnameValue
    )

    $routeOutput = & $CloudflaredPath --loglevel error tunnel route dns $Name $HostnameValue 2>&1
    if ($LASTEXITCODE -eq 0) {
        return
    }

    $text = ($routeOutput | Out-String)
    if ($text -match "already exists|CNAME .* already exists|code: 1003") {
        return
    }

    throw "Falha ao configurar rota DNS para '$HostnameValue'."
}

function Write-TunnelConfig {
    param(
        [string]$TunnelId,
        [string]$HostnameValue,
        [string[]]$ExtraHostnames,
        [string]$OriginUrl,
        [string]$ConfigPath
    )

    $credPath = Join-Path (Join-Path $env:USERPROFILE ".cloudflared") "$TunnelId.json"
    if (-not (Test-Path $credPath)) {
        throw "Arquivo de credenciais nao encontrado: $credPath"
    }

    $hostnames = @($HostnameValue) + @($ExtraHostnames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $lines = @(
        "tunnel: $TunnelId",
        "credentials-file: $credPath",
        "ingress:"
    )

    foreach ($entryHostname in $hostnames | Select-Object -Unique) {
        $lines += "  - hostname: $entryHostname"
        $lines += "    service: $OriginUrl"
    }

    $lines += "  - service: http_status:404"
    $yaml = ($lines -join [Environment]::NewLine)

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ConfigPath, $yaml, $encoding)
    return $ConfigPath
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

function Get-TargetConfigFiles {
    param(
        [string]$RootPath,
        [string]$Scope
    )

    $configDir = Join-Path $RootPath "AchadinhosBot.Next"
    switch ($Scope) {
        "Production" { return @(Join-Path $configDir "appsettings.json") }
        "Development" { return @(Join-Path $configDir "appsettings.Development.json") }
        "Both" { return @(Join-Path $configDir "appsettings.json"), (Join-Path $configDir "appsettings.Development.json") }
        default { return @() }
    }
}

function Stop-TunnelProcesses {
    param(
        [string]$TunnelNameValue,
        [string]$ConfigPath
    )

    $tunnelPattern = [regex]::Escape("run $TunnelNameValue")
    $configPattern = [regex]::Escape($ConfigPath)

    $targets = Get-CimInstance Win32_Process -Filter "Name = 'cloudflared.exe'" -ErrorAction SilentlyContinue |
        Where-Object {
            $_.CommandLine -and (
                $_.CommandLine -match $tunnelPattern -or
                $_.CommandLine -match $configPattern
            )
        }

    foreach ($target in $targets) {
        Stop-Process -Id $target.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$publicBaseUrl = "https://$Hostname"
$cfgDir = Join-Path $env:USERPROFILE ".cloudflared"

if ([string]::IsNullOrWhiteSpace($ConfigFileName)) {
    $ConfigFileName = "config.$TunnelName.yml"
}

if ([string]::IsNullOrWhiteSpace($LogPrefix)) {
    $LogPrefix = $TunnelName
}

$configPath = Join-Path $cfgDir $ConfigFileName

# Evita resolver localhost para IPv6 (::1), que pode falhar no origin
if ($AppUrl -match "localhost") {
    $AppUrl = $AppUrl -replace "localhost", "127.0.0.1"
}

$cloudflaredPath = Resolve-CloudflaredPath
Ensure-CertFile | Out-Null

$tunnelId = Resolve-TunnelId -CloudflaredPath $cloudflaredPath -Name $TunnelName
Ensure-DnsRoute -CloudflaredPath $cloudflaredPath -Name $TunnelName -HostnameValue $Hostname
foreach ($extraHostname in $AdditionalHostnames) {
    if (-not [string]::IsNullOrWhiteSpace($extraHostname)) {
        Ensure-DnsRoute -CloudflaredPath $cloudflaredPath -Name $TunnelName -HostnameValue $extraHostname
    }
}
$configPath = Write-TunnelConfig -TunnelId $tunnelId -HostnameValue $Hostname -ExtraHostnames $AdditionalHostnames -OriginUrl $AppUrl -ConfigPath $configPath

if (-not $NoConfigUpdate) {
    foreach ($filePath in Get-TargetConfigFiles -RootPath $repoRoot -Scope $ConfigUpdateScope) {
        Update-PublicBaseUrl -FilePath $filePath -NewUrl $publicBaseUrl
    }
}

$outLog = Join-Path $repoRoot "cloudflared.$LogPrefix.out.log"
$errLog = Join-Path $repoRoot "cloudflared.$LogPrefix.err.log"
Stop-TunnelProcesses -TunnelNameValue $TunnelName -ConfigPath $configPath
foreach ($log in @($outLog, $errLog)) {
    if (Test-Path $log) {
        Remove-Item $log -Force -ErrorAction SilentlyContinue
    }
}

$proc = Start-Process `
    -FilePath $cloudflaredPath `
    -ArgumentList @("tunnel", "--config", $configPath, "run", $TunnelName) `
    -WorkingDirectory $repoRoot `
    -WindowStyle Minimized `
    -RedirectStandardOutput $outLog `
    -RedirectStandardError $errLog `
    -PassThru

Start-Sleep -Seconds 3
if ($proc.HasExited) {
    throw "cloudflared encerrou apos iniciar. Veja: $errLog"
}

Write-Host "Cloudflare Named Tunnel ativo."
Write-Host "Tunnel: $TunnelName ($tunnelId)"
Write-Host "Hostname fixo: $publicBaseUrl"
Write-Host "Origem local: $AppUrl"
Write-Host "PID: $($proc.Id)"
Write-Host "Logs: $outLog / $errLog"
