Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$exe = "C:\Users\overl\AppData\Local\Microsoft\WinGet\Packages\Cloudflare.cloudflared_Microsoft.Winget.Source_8wekyb3d8bbwe\cloudflared.exe"
$out = "cloudflared.quick.out.log"
$err = "cloudflared.quick.err.log"

if (Test-Path $out) { Remove-Item $out -Force }
if (Test-Path $err) { Remove-Item $err -Force }

Start-Process `
  -FilePath $exe `
  -ArgumentList @("tunnel", "--url", "http://127.0.0.1:8081", "--no-autoupdate") `
  -RedirectStandardOutput $out `
  -RedirectStandardError $err `
  -WindowStyle Hidden

Start-Sleep -Seconds 8

if (Test-Path $out) {
  Get-Content $out -Tail 80
}
if (Test-Path $err) {
  Get-Content $err -Tail 80
}
