$body = '{"url":"https://meli.la/2mrFTYt"}'
$res = Invoke-RestMethod -Uri "http://localhost:5000/api/conversor" -Method POST -ContentType "application/json" -Body $body
Write-Host "=== METADATA ==="
Write-Host "title:         $($res.title)"
Write-Host "price:         $($res.price)"
Write-Host "previousPrice: $($res.previousPrice)"
Write-Host "imageUrl:      $($res.imageUrl)"
Write-Host "convertedUrl:  $($res.convertedUrl)"
Write-Host "trackedUrl:    $($res.trackedUrl)"
Write-Host "dataSource:    $($res.dataSource)"
Write-Host "store:         $($res.store)"
Write-Host "isAffiliated:  $($res.isAffiliated)"
Write-Host "validationError: $($res.validationError)"
