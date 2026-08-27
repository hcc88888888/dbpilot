[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$GoBinary,
    [Parameter(Mandatory = $true)]
    [string]$DockerBinary,
    [Parameter(Mandatory = $true)]
    [string]$KylinImage,
    [int]$HealthTimeoutSeconds = 120,
    [int]$TestTimeoutSeconds = 240
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 7) { $PSNativeCommandUseErrorActionPreference = $false }
if ($HealthTimeoutSeconds -lt 1 -or $TestTimeoutSeconds -lt 90) { throw 'HealthTimeoutSeconds must be positive and TestTimeoutSeconds must be at least 90.' }

function Resolve-RequiredBinary {
    param([string]$Path, [string]$Name)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Name binary path is required." }
    $candidate = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path (Get-Location).Path $Path }
    $resolved = [IO.Path]::GetFullPath($candidate)
    if (-not [IO.Path]::IsPathRooted($resolved) -or -not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Name binary must resolve to an existing absolute file."
    }
    return (Resolve-Path -LiteralPath $resolved).Path
}

$GoBinary = Resolve-RequiredBinary $GoBinary 'Go'
$DockerBinary = Resolve-RequiredBinary $DockerBinary 'Docker'
if ([string]::IsNullOrWhiteSpace($KylinImage)) { throw 'An approved Kylin image is required.' }

function Invoke-Docker {
    param([string[]]$Arguments)
    & $DockerBinary @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed with exit code $LASTEXITCODE." }
}

function Invoke-Go {
    param([string[]]$Arguments)
    & $GoBinary @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Go command failed with exit code $LASTEXITCODE." }
}

function Get-ComposeContainer {
    param([string]$Service)
    $container = (& $DockerBinary compose --project-name $projectName --file $composeFile ps -aq $Service).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($container)) { throw "Compose service '$Service' was not created." }
    return $container
}

function Wait-Healthy {
    param([string]$Service)
    $container = Get-ComposeContainer $Service
    $deadline = [DateTime]::UtcNow.AddSeconds($HealthTimeoutSeconds)
    do {
        $status = (& $DockerBinary inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $container).Trim()
        if ($LASTEXITCODE -ne 0) { throw "Unable to inspect '$Service'." }
        if ($status -eq 'healthy') { return }
        if ($status -in @('unhealthy', 'exited', 'dead')) { throw "Service '$Service' failed health verification ($status)." }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Service '$Service' was not healthy within $HealthTimeoutSeconds seconds."
}

function Assert-NoPublishedPorts {
    $rendered = & $DockerBinary compose --project-name $projectName --file $composeFile config --format json
    if ($LASTEXITCODE -ne 0) { throw 'Unable to render Compose configuration.' }
    $configuration = ($rendered | Out-String) | ConvertFrom-Json
    if (-not $configuration.networks.alert_internal.internal) { throw 'Compose alert_internal network must be internal.' }
    foreach ($serviceProperty in $configuration.services.PSObject.Properties) {
        $ports = $serviceProperty.Value.ports
        if ($null -ne $ports -and @($ports).Count -gt 0) { throw "Published host ports are forbidden ($($serviceProperty.Name))." }
    }
}

function Assert-RunningContainersHaveNoPublishedPorts {
    foreach ($service in @('postgres', 'smtp-sink', 'webhook-sink', 'controlplane')) {
        $container = Get-ComposeContainer $service
        $bindings = (& $DockerBinary inspect --format '{{json .HostConfig.PortBindings}}' $container).Trim()
        if ($LASTEXITCODE -ne 0) { throw "Unable to inspect port bindings for '$Service'." }
        if ($bindings -ne '{}' -and $bindings -ne 'null') { throw "Published host ports are forbidden ($service)." }
    }
}

function Get-ServiceLogs {
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = & $DockerBinary compose --project-name $projectName --file $composeFile logs --no-color --timestamps 2>&1
    $composeExit = $LASTEXITCODE
    $existingAgent = (& $DockerBinary ps -aq --filter "name=^/${agentContainer}$" 2>$null).Trim()
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($existingAgent)) {
        $output += & $DockerBinary logs --timestamps $agentContainer 2>&1
    }
    $ErrorActionPreference = $savedPreference
    if ($composeExit -ne 0) { return 'Sanitized service logs were unavailable.' }
    return ($output | Out-String)
}

function Assert-NoSecretEcho {
    param([string]$Logs)
    foreach ($secret in @($postgresPassword, $smtpPassword, $webhookSecret)) {
        if (-not [string]::IsNullOrEmpty($secret) -and $Logs.Contains($secret)) { throw 'Secret echo detected in service logs.' }
    }
}

function Write-SanitizedFailureLogs {
    $logs = Get-ServiceLogs
    Assert-NoSecretEcho $logs
    $sanitized = $logs.Replace($runtimeDirectory, '<temporary-runtime>')
    if ($sanitized.Length -gt 16000) { $sanitized = $sanitized.Substring($sanitized.Length - 16000) }
    Write-Warning "Sanitized service logs:`n$sanitized"
}

$backendRoot = Split-Path -Parent $PSScriptRoot
$composeFile = (Resolve-Path -LiteralPath (Join-Path $backendRoot 'deploy\compose\alert-control-plane.compose.yaml')).Path
$projectName = "dbpilot-alert-e2e-$PID"
$networkName = "${projectName}_alert_internal"
$agentContainer = "${projectName}-agent"
$agentVolume = "${projectName}_agent_runtime"
$runtimeDirectory = Join-Path ([IO.Path]::GetTempPath()) ("dbpilot-alert-e2e-" + [Guid]::NewGuid().ToString('N'))
$runtimeDirectory = [IO.Path]::GetFullPath($runtimeDirectory)
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
if (-not $runtimeDirectory.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($runtimeDirectory) -notlike 'dbpilot-alert-e2e-*') {
    throw 'Temporary runtime path failed safety validation.'
}
[IO.Directory]::CreateDirectory($runtimeDirectory) | Out-Null

$postgresPassword = 'pg-' + [Guid]::NewGuid().ToString('N')
$smtpPassword = 'smtp-' + [Guid]::NewGuid().ToString('N')
$webhookSecret = 'hook-' + [Guid]::NewGuid().ToString('N')
$storageHasher = [Security.Cryptography.SHA256]::Create()
try {
    $agentStorageDirectory = [BitConverter]::ToString($storageHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes('agent-t1-p1'))).Replace('-', '').ToLowerInvariant()
} finally {
    $storageHasher.Dispose()
}
$passwordFile = Join-Path $runtimeDirectory 'postgres-password'
[IO.File]::WriteAllText($passwordFile, $postgresPassword, [Text.UTF8Encoding]::new($false))

$priorEnvironment = @{}
foreach ($name in @('DBPILOT_ALERT_COMPOSE_PROJECT', 'DBPILOT_KYLIN_IMAGE', 'DBPILOT_ALERT_RUNTIME_DIR', 'DBPILOT_ALERT_POSTGRES_PASSWORD_FILE', 'DBPILOT_ALERT_SMTP_PASSWORD', 'DBPILOT_ALERT_WEBHOOK_SECRET', 'DBPILOT_ALERT_PREPARE_DIR', 'DBPILOT_ALERT_POSTGRES_PASSWORD', 'GOOS', 'GOARCH', 'CGO_ENABLED')) {
    $priorEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

$primaryFailure = $null
$completed = $false
try {
    Invoke-Docker @('version', '--format', '{{.Server.Version}}')
    $imageID = (& $DockerBinary image inspect --format '{{.Id}}' $KylinImage 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($imageID)) { throw "Approved Kylin image '$KylinImage' is not available locally." }
    & $DockerBinary run --rm --entrypoint /bin/sh $KylinImage -c '. /etc/os-release; case "${ID:-}" in kylin|kylin-server|neokylin|kylinsec) ;; *) exit 41 ;; esac; case "${VERSION_ID:-}" in V10|v10|10*) ;; *) exit 42 ;; esac'
    if ($LASTEXITCODE -ne 0) { throw 'The requested image is not an approved Kylin V10 runtime.' }

    [Environment]::SetEnvironmentVariable('DBPILOT_ALERT_PREPARE_DIR', $runtimeDirectory, 'Process')
    [Environment]::SetEnvironmentVariable('DBPILOT_ALERT_POSTGRES_PASSWORD', $postgresPassword, 'Process')
    Invoke-Go @('test', './test/e2e', '-run', '^TestPrepareAlertControlPlaneFixture$', '-count=1')

    [Environment]::SetEnvironmentVariable('GOOS', 'linux', 'Process')
    [Environment]::SetEnvironmentVariable('GOARCH', 'amd64', 'Process')
    [Environment]::SetEnvironmentVariable('CGO_ENABLED', '0', 'Process')
    Invoke-Go @('build', '-trimpath', '-o', (Join-Path $runtimeDirectory 'dbpilot-controlplane'), './cmd/controlplane')
    Invoke-Go @('build', '-trimpath', '-o', (Join-Path $runtimeDirectory 'dbpilot-agent'), './cmd/agent')
    Invoke-Go @('build', '-trimpath', '-tags', 'smtp_sink', '-o', (Join-Path $runtimeDirectory 'smtp-sink'), './deploy/compose/fixtures')
    Invoke-Go @('build', '-trimpath', '-tags', 'webhook_sink', '-o', (Join-Path $runtimeDirectory 'webhook-sink'), './deploy/compose/fixtures')
    Invoke-Go @('test', '-c', '-o', (Join-Path $runtimeDirectory 'alert-e2e.test'), './test/e2e')

    [Environment]::SetEnvironmentVariable('DBPILOT_ALERT_COMPOSE_PROJECT', $projectName, 'Process')
    [Environment]::SetEnvironmentVariable('DBPILOT_KYLIN_IMAGE', $KylinImage, 'Process')
    [Environment]::SetEnvironmentVariable('DBPILOT_ALERT_RUNTIME_DIR', ($runtimeDirectory -replace '\\', '/'), 'Process')
    [Environment]::SetEnvironmentVariable('DBPILOT_ALERT_POSTGRES_PASSWORD_FILE', ($passwordFile -replace '\\', '/'), 'Process')
    [Environment]::SetEnvironmentVariable('DBPILOT_ALERT_SMTP_PASSWORD', $smtpPassword, 'Process')
    [Environment]::SetEnvironmentVariable('DBPILOT_ALERT_WEBHOOK_SECRET', $webhookSecret, 'Process')
    Assert-NoPublishedPorts

    Invoke-Docker @('compose', '--project-name', $projectName, '--file', $composeFile, 'up', '--detach')
    foreach ($service in @('postgres', 'smtp-sink', 'webhook-sink', 'controlplane')) { Wait-Healthy $service }
    Assert-RunningContainersHaveNoPublishedPorts

    Invoke-Docker @('volume', 'create', $agentVolume)
    $runtimeMount = "type=bind,source=$runtimeDirectory,target=/input,readonly"
    $agentMount = "type=volume,source=$agentVolume,target=/agent-runtime"
    $populateCommand = "cp /input/dbpilot-agent /input/alert-e2e.test /input/agent.yaml /input/ca.pem /input/agent.pem /input/agent-key.pem /input/admin.pem /input/admin-key.pem /input/member.pem /input/member-key.pem /input/policy-public.pem /input/policy.json /agent-runtime/; mkdir -p /agent-runtime/spool /agent-runtime/diagnostic-spool /agent-runtime/dbpilot-spool/$agentStorageDirectory; chmod 0700 /agent-runtime /agent-runtime/spool /agent-runtime/diagnostic-spool /agent-runtime/dbpilot-spool /agent-runtime/dbpilot-spool/$agentStorageDirectory; chmod 0755 /agent-runtime/dbpilot-agent /agent-runtime/alert-e2e.test; chmod 0600 /agent-runtime/*.pem /agent-runtime/*.json /agent-runtime/*.yaml; chown -R 65532:65532 /agent-runtime"
    Invoke-Docker @('run', '--rm', '--user', '0:0', '--mount', $runtimeMount, '--mount', $agentMount, $KylinImage, '/bin/sh', '-c', $populateCommand)
    $agentRunMount = "type=volume,source=$agentVolume,target=/runtime"
    Invoke-Docker @('run', '--rm', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m,mode=1777', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--network', $networkName, '--user', '65532:65532', '--workdir', '/runtime', '--mount', $agentRunMount, '-e', 'DBPILOT_ALERT_KYLIN_POLICY_CHECK=1', $KylinImage, '/runtime/alert-e2e.test', '-test.v', '-test.run', '^TestKylinAgentPolicyApply$', '-test.timeout', '45s')
    $agentID = (& $DockerBinary run --detach --read-only --tmpfs '/tmp:rw,noexec,nosuid,size=16m,mode=1777' --cap-drop ALL --security-opt no-new-privileges --name $agentContainer --network $networkName --user 65532:65532 --workdir /runtime --mount $agentRunMount $KylinImage /runtime/dbpilot-agent --config /runtime/agent.yaml).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($agentID)) { throw 'Unable to start the production Agent in Kylin.' }
    Start-Sleep -Seconds 3
    $agentState = (& $DockerBinary inspect --format '{{.State.Status}}' $agentContainer).Trim()
    if ($LASTEXITCODE -ne 0 -or $agentState -ne 'running') { throw 'The production Agent did not remain running in Kylin.' }
    Write-Host 'EVIDENCE agent runtime=kylin-v10 identity=agent-t1-p1 mtls=enabled'

    $testArguments = @(
        'run', '--rm', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m,mode=1777', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--network', $networkName, '--user', '65532:65532', '--workdir', '/runtime', '--mount', $agentRunMount,
        '-e', 'DBPILOT_ALERT_E2E=1',
        '-e', 'DBPILOT_ALERT_HTTP_BASE=https://controlplane:8443',
        '-e', 'DBPILOT_ALERT_GRPC_ADDRESS=controlplane:9443',
        '-e', 'DBPILOT_ALERT_FIXTURE_BASE=https://webhook-sink:8443',
        '-e', 'DBPILOT_ALERT_CA=/runtime/ca.pem',
        '-e', 'DBPILOT_ALERT_AGENT_CERT=/runtime/agent.pem', '-e', 'DBPILOT_ALERT_AGENT_KEY=/runtime/agent-key.pem',
        '-e', 'DBPILOT_ALERT_ADMIN_CERT=/runtime/admin.pem', '-e', 'DBPILOT_ALERT_ADMIN_KEY=/runtime/admin-key.pem',
        '-e', 'DBPILOT_ALERT_MEMBER_CERT=/runtime/member.pem', '-e', 'DBPILOT_ALERT_MEMBER_KEY=/runtime/member-key.pem',
        $KylinImage, '/runtime/alert-e2e.test', '-test.v', '-test.run', '^TestAlertControlPlaneLifecycle$', '-test.timeout', "${TestTimeoutSeconds}s"
    )
    Invoke-Docker $testArguments

    $logs = Get-ServiceLogs
    Assert-NoSecretEcho $logs
    $completed = $true
}
catch {
    $primaryFailure = $_
    try { Write-SanitizedFailureLogs } catch { Write-Warning $_.Exception.Message }
    throw
}
finally {
    $cleanupFailures = @()
    & $DockerBinary rm --force $agentContainer 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $existingAgent = (& $DockerBinary ps -aq --filter "name=^/${agentContainer}$" 2>$null).Trim()
        if (-not [string]::IsNullOrWhiteSpace($existingAgent)) { $cleanupFailures += 'Agent container cleanup failed.' }
    }
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $cleanupOutput = & $DockerBinary compose --project-name $projectName --file $composeFile down --volumes --remove-orphans 2>&1
    $composeCleanupExit = $LASTEXITCODE
    & $DockerBinary volume rm --force $agentVolume 2>$null | Out-Null
    $volumeCleanupExit = $LASTEXITCODE
    $ErrorActionPreference = $savedPreference
    if ($composeCleanupExit -ne 0) { $cleanupFailures += 'Compose container/network/volume cleanup failed.' }
    if ($volumeCleanupExit -ne 0) {
        $remainingVolume = (& $DockerBinary volume ls -q --filter "name=^${agentVolume}$" 2>$null).Trim()
        if (-not [string]::IsNullOrWhiteSpace($remainingVolume)) { $cleanupFailures += 'Agent runtime volume cleanup failed.' }
    }
    if (Test-Path -LiteralPath $runtimeDirectory) {
        $resolvedRuntime = [IO.Path]::GetFullPath($runtimeDirectory)
        if (-not $resolvedRuntime.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolvedRuntime) -notlike 'dbpilot-alert-e2e-*') {
            $cleanupFailures += 'Temporary runtime path refused cleanup safety validation.'
        } else {
            Remove-Item -LiteralPath $resolvedRuntime -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $resolvedRuntime) { $cleanupFailures += 'Temporary runtime cleanup failed.' }
        }
    }
    foreach ($entry in $priorEnvironment.GetEnumerator()) { [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process') }
    if ($cleanupFailures.Count -gt 0) {
        $message = $cleanupFailures -join ' '
        if ($null -ne $primaryFailure) { Write-Error $message -ErrorAction Continue } else { throw $message }
    } elseif ($completed) {
        Write-Host 'EVIDENCE cleanup containers=removed networks=removed volumes=removed temp=removed'
    }
}
