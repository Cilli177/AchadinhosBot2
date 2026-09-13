[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$containers = @(
    'achadinhos-next-dev-e',
    'achadinhos-calendar-worker-dev-e',
    'achadinhos-mercadolivre-affiliate-scraper-dev-e',
    'achadinhos-rabbitmq-dev-e'
)
$expectedProject = 'achadinhos-dev-e'
$expectedNetwork = 'achadinhos-dev-e_network'

function Assert-Condition {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-DockerReadOnly {
    param([string[]]$Arguments)

    $output = & docker @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed: docker $($Arguments -join ' ')"
    }

    return @($output)
}

function Wait-ContainerHealthy {
    param(
        [string]$Container,
        [int]$TimeoutSeconds = 90
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastState = 'unknown'
    $lastHealth = 'unknown'
    do {
        $lastState = (Invoke-DockerReadOnly @('inspect', '--format', '{{.State.Status}}', $Container)).Trim()
        $lastHealth = (Invoke-DockerReadOnly @('inspect', '--format', '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}', $Container)).Trim()
        if ($lastState -eq 'running' -and $lastHealth -eq 'healthy') {
            return
        }

        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "$Container did not become healthy within $TimeoutSeconds seconds. Last state=$lastState health=$lastHealth."
}

foreach ($container in $containers) {
    Wait-ContainerHealthy -Container $container

    # Parse labels from JSON: PowerShell/Windows argument parsing strips the quotes required by Docker's Go template index syntax.
    $inspection = (Invoke-DockerReadOnly @('inspect', $container) | Out-String | ConvertFrom-Json)
    $project = $inspection.Config.Labels.'com.docker.compose.project'
    Assert-Condition ($project -eq $expectedProject) "$container does not belong to $expectedProject."

    $networks = @($inspection.NetworkSettings.Networks.psobject.Properties.Name)
    Assert-Condition ($networks -contains $expectedNetwork) "$container is not connected to $expectedNetwork."

    if ($container -eq 'achadinhos-calendar-worker-dev-e') {
        Assert-Condition (-not ($networks -contains 'achadinhos-dev-e_access')) 'Calendar worker must not have the DEV host-access network.'
        $portBindings = $inspection.HostConfig.PortBindings
        Assert-Condition ($null -eq $portBindings -or @($portBindings.psobject.Properties).Count -eq 0) 'Calendar worker must not publish host ports.'
    }
}

# These are local container requests only. They do not call a delivery endpoint.
Invoke-DockerReadOnly @('exec', 'achadinhos-next-dev-e', 'curl', '-fsS', 'http://127.0.0.1:8081/health/live', '-o', '/dev/null') | Out-Null
Invoke-DockerReadOnly @('exec', 'achadinhos-next-dev-e', 'curl', '-fsS', 'http://127.0.0.1:8081/health/ready', '-o', '/dev/null') | Out-Null
Invoke-DockerReadOnly @('exec', 'achadinhos-calendar-worker-dev-e', 'curl', '-fsS', 'http://127.0.0.1:8081/health/live', '-o', '/dev/null') | Out-Null
Invoke-DockerReadOnly @('exec', 'achadinhos-mercadolivre-affiliate-scraper-dev-e', 'curl', '-fsS', 'http://127.0.0.1:3002/health', '-o', '/dev/null') | Out-Null
# RabbitMQ CLIs can wait indefinitely during broker startup. Enforce a container-local timeout;
# this remains read-only and never consumes or requeues messages.
Invoke-DockerReadOnly @('exec', 'achadinhos-rabbitmq-dev-e', 'sh', '-c', 'timeout 20 rabbitmq-diagnostics -q ping') | Out-Null

# Inspect queue counters only. Queue names and message content are neither emitted nor consumed.
$queueCounters = Invoke-DockerReadOnly @('exec', 'achadinhos-rabbitmq-dev-e', 'sh', '-c', 'timeout 20 rabbitmqctl list_queues -q messages messages_ready messages_unacknowledged')
$nonEmptyQueueRows = 0
foreach ($row in $queueCounters) {
    $values = @($row -split '\s+' | Where-Object { $_ -ne '' })
    $hasNonNumericValue = @($values | Where-Object { $_ -notmatch '^\d+$' }).Count -gt 0
    if ($values.Count -ne 3 -or $hasNonNumericValue) {
        continue
    }

    if (([long]$values[0] + [long]$values[1] + [long]$values[2]) -ne 0) {
        $nonEmptyQueueRows++
    }
}

Assert-Condition ($nonEmptyQueueRows -eq 0) 'The isolated RabbitMQ contains non-empty queues; do not replay, requeue, or consume them.'

Write-Output 'DEV isolated smoke passed: provenance, narrow calendar-worker isolation, health, readiness, RabbitMQ reachability, and empty queue counters verified.'
