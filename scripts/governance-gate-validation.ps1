param(
    [Parameter(Mandatory = $true)]
    [string]$BaseUrl,

    [Parameter(Mandatory = $true)]
    [string]$Username,

    [Parameter(Mandatory = $true)]
    [string]$Password,

    [ValidateSet('dev','shadow','prod')]
    [string]$Stage = 'dev',

    [int]$MaxOpenCriticalIncidents = 2,
    [int]$MaxFailedActions24h = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportDir = Join-Path $PSScriptRoot '..\docs\reports'
$reportDir = [System.IO.Path]::GetFullPath($reportDir)
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
$reportPath = Join-Path $reportDir "gate-validation-$Stage-$timestamp.md"

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Check,
        [bool]$Success,
        [string]$Details
    )

    $results.Add([pscustomobject]@{
        Check = $Check
        Success = $Success
        Details = $Details
    })
}

function Invoke-JsonGet {
    param([string]$Path)

    $uri = "$BaseUrl$Path"
    $resp = Invoke-RestMethod -Method Get -Uri $uri -WebSession $session
    return $resp
}

function Invoke-JsonPost {
    param(
        [string]$Path,
        [object]$Body
    )

    $uri = "$BaseUrl$Path"
    $json = $Body | ConvertTo-Json -Depth 8
    $resp = Invoke-RestMethod -Method Post -Uri $uri -WebSession $session -ContentType 'application/json' -Body $json
    return $resp
}

try {
    $health = Invoke-RestMethod -Method Get -Uri "$BaseUrl/health" -WebSession $session
    $healthOk = $health.status -eq 'ok'
    Add-Result -Check 'Health endpoint' -Success $healthOk -Details ("status={0}" -f $health.status)
}
catch {
    Add-Result -Check 'Health endpoint' -Success $false -Details $_.Exception.Message
}

try {
    $login = Invoke-JsonPost -Path '/auth/login' -Body @{ username = $Username; password = $Password; rememberMe = $false }
    $loginOk = $login.success -eq $true
    Add-Result -Check 'Admin login' -Success $loginOk -Details ("username={0} role={1}" -f $login.username, $login.role)
}
catch {
    Add-Result -Check 'Admin login' -Success $false -Details $_.Exception.Message
}

$status = $null
$incidents = $null
$actions = $null
$tuning = $null
$canaryRules = $null

try {
    $status = Invoke-JsonGet -Path '/api/admin/governance/status'
    Add-Result -Check 'Governance status endpoint' -Success $true -Details 'ok'
}
catch {
    Add-Result -Check 'Governance status endpoint' -Success $false -Details $_.Exception.Message
}

try {
    $incidents = Invoke-JsonGet -Path '/api/admin/governance/incidents?onlyOpen=true&limit=200'
    Add-Result -Check 'Governance incidents endpoint' -Success $true -Details ("count={0}" -f @($incidents).Count)
}
catch {
    Add-Result -Check 'Governance incidents endpoint' -Success $false -Details $_.Exception.Message
}

try {
    $actions = Invoke-JsonGet -Path '/api/admin/governance/actions?limit=200'
    Add-Result -Check 'Governance actions endpoint' -Success $true -Details ("count={0}" -f @($actions).Count)
}
catch {
    Add-Result -Check 'Governance actions endpoint' -Success $false -Details $_.Exception.Message
}

try {
    $tuning = Invoke-JsonGet -Path '/api/admin/governance/tuning?limit=200'
    Add-Result -Check 'Governance tuning endpoint' -Success $true -Details ("count={0}" -f @($tuning).Count)
}
catch {
    Add-Result -Check 'Governance tuning endpoint' -Success $false -Details $_.Exception.Message
}

try {
    $canaryRules = Invoke-JsonGet -Path '/api/admin/canary/rules'
    Add-Result -Check 'Canary rules endpoint' -Success $true -Details ("count={0}" -f @($canaryRules).Count)
}
catch {
    Add-Result -Check 'Canary rules endpoint' -Success $false -Details $_.Exception.Message
}

if ($null -ne $status -and $null -ne $status.snapshot) {
    $criticalOpen = [int]$status.snapshot.criticalIncidents
    $failedActions24h = [int]$status.snapshot.failedActions24h

    $criticalOk = $criticalOpen -le $MaxOpenCriticalIncidents
    $failedOk = $failedActions24h -le $MaxFailedActions24h

    Add-Result -Check 'Critical incidents threshold' -Success $criticalOk -Details ("criticalOpen={0} limit={1}" -f $criticalOpen, $MaxOpenCriticalIncidents)
    Add-Result -Check 'Failed actions threshold' -Success $failedOk -Details ("failedActions24h={0} limit={1}" -f $failedActions24h, $MaxFailedActions24h)
}

if ($null -ne $actions) {
    $actionList = @($actions)
    $hasShadowSummary = $actionList | Where-Object { $_.summary -like '*Shadow mode*' } | Select-Object -First 1

    if ($Stage -eq 'shadow') {
        Add-Result -Check 'Shadow mode evidence' -Success ($null -ne $hasShadowSummary) -Details 'expected at least one simulated shadow action'
    }

    if ($Stage -eq 'prod') {
        Add-Result -Check 'No shadow action in PROD gate' -Success ($null -eq $hasShadowSummary) -Details 'expected no simulated shadow action in recent window'
    }
}

if ($null -ne $canaryRules -and $Stage -eq 'prod') {
    $activeCanary = @($canaryRules) | Where-Object { $_.enabled -eq $true -and [int]$_.canaryPercent -gt 0 }
    Add-Result -Check 'Canary stabilization for PROD' -Success ($activeCanary.Count -eq 0) -Details ("activeCanaryRules={0}" -f $activeCanary.Count)
}

$failed = @($results | Where-Object { -not $_.Success })
$passed = @($results | Where-Object { $_.Success })

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# Gate Validation Report ($Stage)")
$lines.Add("")
$lines.Add("- BaseUrl: $BaseUrl")
$lines.Add("- GeneratedAt: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
$lines.Add("- Passed: $($passed.Count)")
$lines.Add("- Failed: $($failed.Count)")
$lines.Add("")
$lines.Add("## Checks")
$lines.Add("")
$lines.Add("| Check | Result | Details |")
$lines.Add("| --- | --- | --- |")
foreach ($r in $results) {
    $symbol = if ($r.Success) { 'PASS' } else { 'FAIL' }
    $safeDetails = ($r.Details -replace "\|", "\\|")
    $lines.Add("| $($r.Check) | $symbol | $safeDetails |")
}

$lines | Set-Content -Path $reportPath -Encoding UTF8

Write-Host "Report generated: $reportPath"
if ($failed.Count -gt 0) {
    Write-Host "Gate result: FAILED ($($failed.Count) checks)."
    exit 2
}

Write-Host "Gate result: PASSED."
exit 0
