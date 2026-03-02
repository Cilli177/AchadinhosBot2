$path = Join-Path $PSScriptRoot "bin\Debug\net8.0\data\link-tracking.json"

if (-not (Test-Path $path)) {
    Write-Host "File not found: $path"
    exit 1
}

$raw = Get-Content $path -Raw
$data = $raw | ConvertFrom-Json

$staleKeys = @()
foreach ($prop in $data.PSObject.Properties) {
    $targetUrl = $prop.Value.TargetUrl
    # Find entries that point to the Grego Bar tinyurl or grego product URL
    if ($targetUrl -like "*2bj4nztb*" -or $targetUrl -like "*grego*" -or $targetUrl -like "*MLB95052496314*") {
        Write-Host "Stale entry found: $($prop.Name) -> $targetUrl"
        $staleKeys += $prop.Name
    }
}

if ($staleKeys.Count -eq 0) {
    Write-Host "No stale entries found. Listing all tracked URLs:"
    foreach ($prop in $data.PSObject.Properties) {
        Write-Host " - $($prop.Name): $($prop.Value.TargetUrl)"
    }
} else {
    Write-Host "Removing $($staleKeys.Count) stale entries..."
    foreach ($key in $staleKeys) {
        $data.PSObject.Properties.Remove($key)
    }
    $data | ConvertTo-Json -Depth 10 | Set-Content $path -Encoding UTF8
    Write-Host "Done. Removed stale entries."
}
