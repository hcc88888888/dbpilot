param(
    [string]$DockerBinary = 'docker',
    [string]$GoBinary = 'go',
    [ValidatePattern('^[a-f0-9]{32}$')][string]$RunId = ([guid]::NewGuid().ToString('N')),
    [switch]$ContractOnly
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$systemdRoot = Join-Path $repoRoot 'backend\packaging\systemd'
$helperUnit = Join-Path $systemdRoot 'dbpilot-docker-discovery.service'

function Assert-RestrictedDockerContract {
    $unit = Get-Content -Raw $helperUnit
    foreach ($required in @('User=dbpilot', 'Group=dbpilot', 'SupplementaryGroups=docker', 'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'AmbientCapabilities=', 'PrivateNetwork=yes', 'ProtectSystem=strict', 'ProtectHome=yes', 'RestrictAddressFamilies=AF_UNIX', '--docker-socket ${DBPILOT_DOCKER_SOCKET}')) {
        if (-not $unit.Contains($required)) { throw "Docker helper unit is missing required hardening: $required" }
    }
    $otherUnits = @(Get-ChildItem $systemdRoot -Filter '*.service' | Where-Object FullName -ne $helperUnit)
    foreach ($service in $otherUnits) {
        if ((Get-Content -Raw $service.FullName) -match '(docker\.sock|DOCKER_HOST)') {
            throw "Only dbpilot-docker-discovery.service may reference the Docker Socket: $($service.Name)"
        }
    }
    $productionGo = @(Get-ChildItem (Join-Path $repoRoot 'backend\internal'), (Join-Path $repoRoot 'backend\cmd') -Filter '*.go' -Recurse | Where-Object Name -notlike '*_test.go')
    foreach ($source in $productionGo) {
        $relative = $source.FullName.Substring($repoRoot.Length + 1).Replace('\', '/')
        if ((Get-Content -Raw $source.FullName) -match '(/var/run/docker\.sock|DOCKER_HOST)' -and
            $relative -notin @('backend/internal/dockerdiscovery/client.go', 'backend/cmd/dbpilot-docker-discovery/main.go')) {
            throw "Only the Docker discovery helper may open/configure the Docker Socket: $relative"
        }
    }
    [pscustomobject]@{ Contract = 'restricted-docker-discovery-v1'; Status = 'pass'; SocketOwner = 'dbpilot-docker-discovery' } | ConvertTo-Json -Compress
}

Assert-RestrictedDockerContract
if ($ContractOnly) { exit 0 }

$docker = (Get-Command $DockerBinary -ErrorAction Stop).Source
$go = (Get-Command $GoBinary -ErrorAction Stop).Source
& $docker version | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Engine is unavailable.' }

. (Join-Path $PSScriptRoot 'container-safety.ps1')
$runLabel = "dbpilot-docker-discovery-$RunId"
$mysqlNames = @("$runLabel-mysql-a", "$runLabel-mysql-b")
$helperName = "$runLabel-helper"
$probeName = "$runLabel-agent-probe"
$initName = "$runLabel-runtime-init"
$volumeName = "$runLabel-runtime"
$containerIds = [Collections.Generic.List[string]]::new()
$volumeCreated = $false
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) $runLabel

try {
    New-Item -ItemType Directory -Path $tempRoot -ErrorAction Stop | Out-Null
    $helperBinary = Join-Path $tempRoot 'dbpilot-docker-discovery'
    $probeBinary = Join-Path $tempRoot 'docker-discovery-probe.test'
    Push-Location (Join-Path $repoRoot 'backend')
    & $go test ./internal/dockerdiscovery -run 'TestDocker(EndpointGuard|ClientDoesNotFollow|ClientRejects)' -count=1
    if ($LASTEXITCODE -ne 0) { throw 'Docker forbidden endpoint/redirect/query checks failed.' }
    Pop-Location
    $oldGoos, $oldGoarch, $oldCgo = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
    try {
        $env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
        Push-Location (Join-Path $repoRoot 'backend')
        & $go build -trimpath -o $helperBinary ./cmd/dbpilot-docker-discovery
        if ($LASTEXITCODE -ne 0) { throw 'Unable to build Linux Docker discovery helper.' }
        & $go test -c -o $probeBinary ./internal/agent/discovery
        if ($LASTEXITCODE -ne 0) { throw 'Unable to build Linux Agent Docker discovery probe.' }
        Pop-Location
    } finally {
        $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $oldGoos, $oldGoarch, $oldCgo
        if ((Get-Location).Path -eq (Join-Path $repoRoot 'backend')) { Pop-Location }
    }

    & $docker image inspect mysql:8.4 | Out-Null
    if ($LASTEXITCODE -ne 0) { & $docker pull mysql:8.4 | Out-Null }
    if ($LASTEXITCODE -ne 0) { throw 'The exact mysql:8.4 image is required.' }
    & $docker image inspect debian:bookworm-slim | Out-Null
    if ($LASTEXITCODE -ne 0) { & $docker pull debian:bookworm-slim | Out-Null }
    if ($LASTEXITCODE -ne 0) { throw 'The exact debian:bookworm-slim image is required.' }

    & $docker volume create --label dbpilot.verifier=docker-discovery --label "dbpilot.run=$runLabel" $volumeName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to create the exact verifier runtime volume.' }
    $volumeCreated = $true

    $initId = New-DBPilotOwnedContainer -DockerBinary $docker -Name $initName -CreateArguments @(
        '--label', 'dbpilot.verifier=docker-discovery', '--label', "dbpilot.run=$runLabel",
        '--read-only', '--network', 'none', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--security-opt', 'no-new-privileges:true',
        '--mount', "type=volume,source=$volumeName,target=/run/dbpilot",
        'debian:bookworm-slim', 'chown', '1001:1001', '/run/dbpilot'
    )
    $containerIds.Add($initId)
    & $docker start -a $initId | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to assign the private runtime volume to the Agent identity.' }

    foreach ($name in $mysqlNames) {
        $id = New-DBPilotOwnedContainer -DockerBinary $docker -Name $name -CreateArguments @(
            '--label', 'dbpilot.verifier=docker-discovery', '--label', "dbpilot.run=$runLabel", '--label', 'dbpilot.discovery.family=mysql',
            '--env', 'MYSQL_ALLOW_EMPTY_PASSWORD=yes', '--publish', '127.0.0.1::3306', 'mysql:8.4', '--skip-grant-tables'
        )
        $containerIds.Add($id)
        & $docker start $id | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Unable to start recorded MySQL container $id." }
    }

    $helperId = New-DBPilotOwnedContainer -DockerBinary $docker -Name $helperName -CreateArguments @(
        '--label', 'dbpilot.verifier=docker-discovery', '--label', "dbpilot.run=$runLabel",
        '--read-only', '--network', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--user', '1001:1001', '--group-add', '0',
        '--mount', "type=bind,source=$helperBinary,target=/usr/bin/dbpilot-docker-discovery,readonly",
        '--mount', 'type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock',
        '--mount', "type=volume,source=$volumeName,target=/run/dbpilot",
        'debian:bookworm-slim', '/usr/bin/dbpilot-docker-discovery', '--docker-socket', '/var/run/docker.sock', '--agent-socket', '/run/dbpilot/docker-discovery.sock', '--allowed-uid', '1001', '--allowed-gid', '1001', '--allowed-labels', 'dbpilot.discovery.family,dbpilot.run'
    )
    $containerIds.Add($helperId)
    & $docker start $helperId | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to start the restricted helper.' }

    $helperReady = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $helperState = (& $docker inspect --format '{{.State.Status}}' $helperId | Out-String).Trim()
        if ($helperState -in @('exited', 'dead')) {
            $helperOutput = (& $docker logs $helperId 2>&1 | Out-String)
            throw "Restricted helper exited before its socket was ready:`n$helperOutput"
        }
        $savedPreference = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        & $docker exec $helperId test -S /run/dbpilot/docker-discovery.sock 2>$null
        $socketCheckExit = $LASTEXITCODE; $ErrorActionPreference = $savedPreference
        if ($socketCheckExit -eq 0) { $helperReady = $true; break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $helperReady) { throw 'Restricted helper socket was not ready in time.' }

    $probeId = New-DBPilotOwnedContainer -DockerBinary $docker -Name $probeName -CreateArguments @(
        '--label', 'dbpilot.verifier=docker-discovery', '--label', "dbpilot.run=$runLabel",
        '--read-only', '--network', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--user', '1001:1001',
        '--mount', "type=bind,source=$probeBinary,target=/usr/bin/docker-discovery-probe.test,readonly",
        '--mount', "type=volume,source=$volumeName,target=/run/dbpilot",
        '--env', 'DBPILOT_DOCKER_HELPER_SOCKET=/run/dbpilot/docker-discovery.sock', '--env', "DBPILOT_DOCKER_TEST_RUN=$runLabel", '--env', 'DBPILOT_DOCKER_TEST_READY_FILE=/run/dbpilot/probe.ready', '--env', "DBPILOT_DOCKER_TEST_RESTART_ID=$($containerIds[1])",
        'debian:bookworm-slim', '/usr/bin/docker-discovery-probe.test', '-test.run', '^TestDockerHelperTwoMySQLContainersAndEventReconciliation$', '-test.v'
    )
    $containerIds.Add($probeId)
    & $docker start $probeId | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to start Agent probe without Docker Socket.' }

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $savedPreference = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        & $docker exec $helperId test -f /run/dbpilot/probe.ready 2>$null
        $readyCheckExit = $LASTEXITCODE; $ErrorActionPreference = $savedPreference
        if ($readyCheckExit -eq 0) { $ready = $true; break }
        $probeState = (& $docker inspect --format '{{.State.Status}}' $probeId | Out-String).Trim()
        if ($probeState -in @('exited', 'dead')) {
            $probeOutput = (& $docker logs $probeId 2>&1 | Out-String)
            throw "Agent probe exited before event readiness:`n$probeOutput"
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) { throw 'Agent probe did not establish the helper event stream.' }
    & $docker restart $containerIds[1] | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to generate the exact container restart event.' }
    & $docker wait $probeId | Out-Null
    $probeExit = [int]((& $docker inspect --format '{{.State.ExitCode}}' $probeId | Out-String).Trim())
    $probeOutput = (& $docker logs $probeId 2>&1 | Out-String)
    if ($probeExit -ne 0) { throw "Agent probe failed without Docker Socket:`n$probeOutput" }

    $probeInspect = @(& $docker inspect $probeId | ConvertFrom-Json)[0]
    foreach ($mount in @($probeInspect.Mounts)) {
        if ($mount.Source -eq '/var/run/docker.sock' -or $mount.Destination -eq '/var/run/docker.sock') { throw 'Agent probe unexpectedly received the Docker Socket.' }
    }
    Write-Output 'PASS: two MySQL candidates, redaction, restricted endpoint guard, and event reconciliation verified; Agent probe has no Docker Socket.'
} finally {
    for ($index = $containerIds.Count - 1; $index -ge 0; $index--) {
        Remove-DBPilotRecordedContainer -DockerBinary $docker -ContainerID $containerIds[$index] -Verifier 'docker-discovery' -RunLabel $runLabel
    }
    if ($volumeCreated) { Remove-DBPilotRecordedVolume -DockerBinary $docker -VolumeName $volumeName -Verifier 'docker-discovery' -RunLabel $runLabel }
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}
