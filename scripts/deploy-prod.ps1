param(
    [switch]$SkipBackup,
    [switch]$BackupLogs,
    [switch]$NoBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$composeFile = Join-Path $repoRoot "docker-compose.prod.yml"
$envFile = Join-Path $repoRoot ".env.prod"
$composeProject = "achadinhos-prod"
$dataVolume = "achadinhos-prod_achadinhos_data"
$logsVolume = "achadinhos-prod_achadinhos_logs"
$rabbitMqVolume = "achadinhos-prod_achadinhos_rabbitmq_data"

function Assert-CommandExists {
    param([Parameter(Mandatory = $true)][string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Comando nao encontrado: $Name"
    }
}

function Assert-PathExists {
    param([Parameter(Mandatory = $true)][string]$PathValue)
    if (-not (Test-Path $PathValue)) {
        throw "Arquivo nao encontrado: $PathValue"
    }
}

function Assert-VolumeExists {
    param([Parameter(Mandatory = $true)][string]$VolumeName)
    $existing = docker volume ls --format "{{.Name}}" | Where-Object { $_ -eq $VolumeName }
    if (-not $existing) {
        throw "Volume nao encontrado: $VolumeName"
    }
}

function Backup-Volume {
    param(
        [Parameter(Mandatory = $true)][string]$SourceVolume,
        [Parameter(Mandatory = $true)][string]$BackupName
    )

    Write-Host "Criando volume de backup: $BackupName"
    docker volume create $BackupName | Out-Null

    Write-Host "Copiando dados: $SourceVolume -> $BackupName"
    docker run --rm -v "${SourceVolume}:/from" -v "${BackupName}:/to" busybox sh -c "cp -a /from/. /to/"
}

Assert-CommandExists -Name "docker"
Assert-PathExists -PathValue $composeFile
Assert-PathExists -PathValue $envFile

Assert-VolumeExists -VolumeName $dataVolume
Assert-VolumeExists -VolumeName $rabbitMqVolume
if ($BackupLogs) {
    Assert-VolumeExists -VolumeName $logsVolume
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$dataBackup = "${dataVolume}_backup_${timestamp}"
$logsBackup = "${logsVolume}_backup_${timestamp}"
$rabbitMqBackup = "${rabbitMqVolume}_backup_${timestamp}"

if (-not $SkipBackup) {
    Backup-Volume -SourceVolume $dataVolume -BackupName $dataBackup
    Backup-Volume -SourceVolume $rabbitMqVolume -BackupName $rabbitMqBackup
    if ($BackupLogs) {
        Backup-Volume -SourceVolume $logsVolume -BackupName $logsBackup
    }
} else {
    Write-Warning "Backup ignorado por parametro -SkipBackup."
}

$composeArgs = @(
    "compose",
    "--env-file", $envFile,
    "-p", $composeProject,
    "-f", $composeFile,
    "up",
    "-d"
)

if ($NoBuild) {
    $composeArgs += "--no-build"
}

Write-Host "Subindo producao com docker compose..."
docker @composeArgs

Write-Host ""
Write-Host "Deploy finalizado."
if (-not $SkipBackup) {
    Write-Host "Backup de dados: $dataBackup"
    Write-Host "Backup de RabbitMQ: $rabbitMqBackup"
    if ($BackupLogs) {
        Write-Host "Backup de logs: $logsBackup"
    }
}
Write-Host "Healthcheck local: http://127.0.0.1:5005/health"
