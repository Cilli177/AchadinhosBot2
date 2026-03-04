param(
    [switch]$Apply,
    [int]$KeepRecent = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Get-TargetFiles {
    param([Parameter(Mandatory = $true)][string]$Root)

    $patterns = @("*.log", "*.out", "*.err", "*.jsonl")
    $all = Get-ChildItem -Path $Root -File -Recurse -Include $patterns -ErrorAction SilentlyContinue

    $safeRoots = @(
        (Join-Path $Root "logs"),
        (Join-Path $Root "AchadinhosBot.Next/logs"),
        (Join-Path $Root "AchadinhosBot.Next/bin"),
        (Join-Path $Root "AchadinhosBot.Next/obj"),
        (Join-Path $Root "_build_check"),
        $Root
    )

    $all | Where-Object {
        $full = $_.FullName
        $match = $false
        foreach ($base in $safeRoots) {
            if ($full.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) {
                $match = $true
                break
            }
        }

        $match
    }
}

function Keep-NewestByDirectory {
    param(
        [Parameter(Mandatory = $true)]$Files,
        [int]$Keep = 5
    )

    $toDelete = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $groups = $Files | Group-Object DirectoryName
    foreach ($group in $groups) {
        $ordered = $group.Group | Sort-Object LastWriteTimeUtc -Descending
        $remove = $ordered | Select-Object -Skip $Keep
        foreach ($item in $remove) {
            $toDelete.Add($item)
        }
    }

    return $toDelete
}

$targets = Get-TargetFiles -Root $repoRoot
if (-not $targets -or $targets.Count -eq 0) {
    Write-Host "Nenhum arquivo de log temporario encontrado."
    exit 0
}

$toDelete = Keep-NewestByDirectory -Files $targets -Keep $KeepRecent
$count = $toDelete.Count
$sizeBytes = ($toDelete | Measure-Object -Property Length -Sum).Sum
$sizeMB = [math]::Round($sizeBytes / 1MB, 2)

Write-Host "Arquivos elegiveis para limpeza: $count"
Write-Host "Espaco estimado para liberar: $sizeMB MB"

if (-not $Apply) {
    Write-Host "Modo simulacao. Use -Apply para remover."
    $toDelete | Sort-Object Length -Descending | Select-Object -First 20 FullName, Length | Format-Table -AutoSize
    exit 0
}

foreach ($file in $toDelete) {
    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
}

Write-Host "Limpeza concluida. Arquivos removidos: $count"
