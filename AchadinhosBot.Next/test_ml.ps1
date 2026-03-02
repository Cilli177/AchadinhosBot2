$body = @{ url = 'https://meli.la/15qbwtu' } | ConvertTo-Json
$response = Invoke-RestMethod -Uri 'http://localhost:5000/api/conversor' -Method POST -ContentType 'application/json' -Body $body -TimeoutSec 30
$response | ConvertTo-Json -Depth 3
