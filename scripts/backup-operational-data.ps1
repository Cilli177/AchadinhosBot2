[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Source,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Destination,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,80}$')]
    [string]$Label = 'achadinhos'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sourceRoot = [IO.Path]::GetFullPath($Source)
$destinationParent = [IO.Path]::GetFullPath($Destination)
if (-not (Test-Path -LiteralPath $sourceRoot -PathType Container)) { throw 'Source directory does not exist.' }
if ($sourceRoot.TrimEnd('\') -eq $destinationParent.TrimEnd('\')) { throw 'Destination must differ from source.' }
if ($destinationParent.StartsWith($sourceRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Destination cannot be inside source.' }

$runId = '{0}-{1:yyyyMMdd-HHmmss}-{2}' -f $Label, (Get-Date).ToUniversalTime(), ([Guid]::NewGuid().ToString('N').Substring(0, 8))
$destinationRoot = Join-Path $destinationParent $runId
New-Item -ItemType Directory -Force -Path $destinationRoot | Out-Null
robocopy $sourceRoot $destinationRoot /E /COPY:DAT /DCOPY:DAT /R:2 /W:2 /XJ /NFL /NDL /NP
if ($LASTEXITCODE -gt 7) { throw "Backup copy failed with robocopy exit code $LASTEXITCODE." }

function Get-FileInventory([string]$Root) {
    @(Get-ChildItem -LiteralPath $Root -File -Recurse -Force | ForEach-Object {
        $relative = $_.FullName.Substring($Root.TrimEnd('\').Length).TrimStart('\')
        [pscustomobject]@{
            Path = $relative.Replace('\', '/')
            Bytes = $_.Length
            Sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    } | Sort-Object Path)
}

$sourceInventory = Get-FileInventory $sourceRoot
$destinationInventory = Get-FileInventory $destinationRoot
$sourceJson = $sourceInventory | ConvertTo-Json -Depth 3 -Compress
$destinationJson = $destinationInventory | ConvertTo-Json -Depth 3 -Compress
if ($sourceJson -ne $destinationJson) {
    throw 'Backup verification failed: file paths, sizes, or SHA-256 hashes differ from the source.'
}

$manifest = [pscustomobject]@{
    SchemaVersion = 1
    BackupId = $runId
    CreatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    SourceFileCount = $sourceInventory.Count
    SourceBytes = [Int64](($sourceInventory | Measure-Object -Property Bytes -Sum).Sum)
    Files = $sourceInventory
}
$manifestPath = Join-Path $destinationRoot 'backup-manifest.json'
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
Write-Output "Backup verified: $destinationRoot ($($sourceInventory.Count) file(s))"
