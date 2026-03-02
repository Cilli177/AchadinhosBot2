$links = @(
    "https://meli.la/2mrFTYt",
    "https://meli.la/2BAJkfi"
)

foreach ($link in $links) {
    Write-Host "`n=== TESTING: $link ===" -ForegroundColor Cyan
    try {
        $body = "{`"url`":`"$link`"}"
        $res = Invoke-RestMethod -Uri "http://localhost:5000/api/conversor" -Method POST -ContentType "application/json" -Body $body -TimeoutSec 90
        Write-Host "title:        " $res.title
        Write-Host "price:        " $res.price
        Write-Host "previousPrice:" $res.previousPrice
        Write-Host "imageUrl:     " $res.imageUrl
        Write-Host "convertedUrl: " $res.convertedUrl
        Write-Host "trackedUrl:   " $res.trackedUrl
        Write-Host "dataSource:   " $res.dataSource
        Write-Host "store:        " $res.store
        Write-Host "isAffiliated: " $res.isAffiliated
        Write-Host "success:      " $res.success
        Write-Host "error:        " $res.error
    } catch {
        Write-Host "ERROR:" $_.Exception.Message -ForegroundColor Red
    }
}
