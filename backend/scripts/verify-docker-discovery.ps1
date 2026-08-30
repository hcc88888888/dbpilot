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
$helperSocketUnit = Join-Path $systemdRoot 'dbpilot-docker-discovery.socket'
$agentUnit = Join-Path $systemdRoot 'dbpilot-agent.service'
$procUnit = Join-Path $systemdRoot 'dbpilot-agent-proc-helper.service'
$procSocketUnit = Join-Path $systemdRoot 'dbpilot-agent-proc-helper.socket'
$centosProcDropIn = Join-Path $systemdRoot 'dbpilot-agent-proc-helper.service.d\centos7.conf'

function Assert-UnitLine {
    param([string]$Body, [string]$Line, [string]$UnitName)
    $present = @($Body -split "`r?`n" | Where-Object { $_ -ceq $Line }).Count -eq 1
    if (-not $present) { throw "$UnitName must contain exactly one '$Line' directive." }
}

function Assert-RestrictedDockerContract {
    $unit = Get-Content -Raw $helperUnit
    foreach ($required in @('User=dbpilot-docker', 'Group=dbpilot-docker', 'SupplementaryGroups=docker', 'NoNewPrivileges=yes', 'PrivateNetwork=yes', 'ProtectSystem=strict', 'ProtectHome=yes', 'RestrictAddressFamilies=AF_UNIX', '--docker-socket ${DBPILOT_DOCKER_SOCKET}', 'Requires=docker.service dbpilot-docker-discovery.socket')) {
        if (-not $unit.Contains($required)) { throw "Docker helper unit is missing required hardening: $required" }
    }
    Assert-UnitLine $unit 'CapabilityBoundingSet=' 'dbpilot-docker-discovery.service'
    Assert-UnitLine $unit 'AmbientCapabilities=' 'dbpilot-docker-discovery.service'
    if ($unit -match '(?m)^(User|Group)=dbpilot$') { throw 'Docker helper must not share the main Agent identity.' }

    $dockerSocketUnit = Get-Content -Raw $helperSocketUnit
    foreach ($line in @('ListenStream=/run/dbpilot-agent/docker-discovery.sock', 'SocketUser=dbpilot', 'SocketGroup=dbpilot', 'SocketMode=0600')) {
        Assert-UnitLine $dockerSocketUnit $line 'dbpilot-docker-discovery.socket'
    }

    $agent = Get-Content -Raw $agentUnit
    Assert-UnitLine $agent 'User=dbpilot' 'dbpilot-agent.service'
    Assert-UnitLine $agent 'Group=dbpilot' 'dbpilot-agent.service'
    Assert-UnitLine $agent 'CapabilityBoundingSet=' 'dbpilot-agent.service'
    Assert-UnitLine $agent 'AmbientCapabilities=' 'dbpilot-agent.service'
    if ($agent -match '(?im)(CAP_SYS_PTRACE|docker\.sock|SupplementaryGroups=.*docker)') { throw 'Main Agent must have no ptrace capability or Docker Socket group/path.' }

    $proc = Get-Content -Raw $procUnit
    foreach ($line in @('User=dbpilot-proc', 'Group=dbpilot-proc', 'CapabilityBoundingSet=CAP_SYS_PTRACE', 'AmbientCapabilities=CAP_SYS_PTRACE', 'RestrictAddressFamilies=AF_UNIX', 'SystemCallFilter=~ptrace process_vm_readv process_vm_writev pidfd_getfd kcmp mount umount2 reboot')) {
        Assert-UnitLine $proc $line 'dbpilot-agent-proc-helper.service'
    }
    foreach ($required in @('--allowed-process-names=${DBPILOT_PROC_ALLOWED_PROCESS_NAMES}', 'NoNewPrivileges=true')) {
        if (-not $proc.Contains($required)) { throw "Proc helper unit is missing required boundary: $required" }
    }
    if ($proc -match '(?im)(docker\.sock|SupplementaryGroups=.*docker|CAP_DAC_READ_SEARCH)') { throw 'Modern proc helper must not hold Docker access or legacy-only capability.' }
    $procSocket = Get-Content -Raw $procSocketUnit
    foreach ($line in @('ListenStream=/run/dbpilot-agent/proc-helper.sock', 'SocketUser=dbpilot', 'SocketGroup=dbpilot', 'SocketMode=0600')) {
        Assert-UnitLine $procSocket $line 'dbpilot-agent-proc-helper.socket'
    }
    $legacyProc = Get-Content -Raw $centosProcDropIn
    foreach ($line in @('User=root', 'Group=root', 'AmbientCapabilities=', 'CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH')) {
        Assert-UnitLine $legacyProc $line 'centos7 proc-helper drop-in'
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
    [pscustomobject]@{ Contract = 'dbpilot-local-helper-boundary-v2'; Status = 'pass'; AgentUser = 'dbpilot'; ProcHelperUser = 'dbpilot-proc'; DockerHelperUser = 'dbpilot-docker'; AgentCapabilities = 'none'; DockerSocketOwner = 'dbpilot-docker-discovery' } | ConvertTo-Json -Compress
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
$procHelperName = "$runLabel-proc-helper"
$probeName = "$runLabel-agent-probe"
$initName = "$runLabel-runtime-init"
$volumeName = "$runLabel-runtime"
$containerIds = [Collections.Generic.List[string]]::new()
$volumeCreated = $false
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) $runLabel

try {
    New-Item -ItemType Directory -Path $tempRoot -ErrorAction Stop | Out-Null
    $helperBinary = Join-Path $tempRoot 'dbpilot-docker-discovery'
	$agentBinary = Join-Path $tempRoot 'dbpilot-agent'
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
		& $go build -trimpath -o $agentBinary ./cmd/agent
		if ($LASTEXITCODE -ne 0) { throw 'Unable to build Linux Agent/proc-helper binary.' }
        & $go test -c -o $probeBinary ./internal/agent/discovery
        if ($LASTEXITCODE -ne 0) { throw 'Unable to build Linux Agent Docker discovery probe.' }
        Pop-Location
    } finally {
        $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $oldGoos, $oldGoarch, $oldCgo
        if ((Get-Location).Path -eq (Join-Path $repoRoot 'backend')) { Pop-Location }
    }

	$kylinImage = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1'
	& $docker image inspect $kylinImage | Out-Null
	if ($LASTEXITCODE -ne 0) { throw "Approved Kylin systemd verification image is unavailable: $kylinImage" }
	$systemdValidationRoot = Join-Path $tempRoot 'systemd-validation'
	New-Item -ItemType Directory -Path $systemdValidationRoot -ErrorAction Stop | Out-Null
	Copy-Item -Path (Join-Path $systemdRoot '*') -Destination $systemdValidationRoot -Recurse -Force
	[IO.File]::WriteAllText((Join-Path $systemdValidationRoot 'docker.service'), "[Unit]`nDescription=Verifier Docker service`n[Service]`nType=oneshot`nExecStart=/bin/true`nRemainAfterExit=yes`n", [Text.UTF8Encoding]::new($false))
	& $docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges:true `
		'--mount' "type=bind,source=$systemdValidationRoot,target=/source-units,readonly" `
		'--mount' "type=bind,source=$agentBinary,target=/usr/local/bin/dbpilot-agent,readonly" `
		'--mount' "type=bind,source=$helperBinary,target=/usr/bin/dbpilot-docker-discovery,readonly" `
		$kylinImage /bin/sh -c 'cp -a /source-units /tmp/units && find /tmp/units -type d -exec chmod 0755 {} \; && find /tmp/units -type f -exec chmod 0644 {} \; && SYSTEMD_UNIT_PATH=/tmp/units:/usr/lib/systemd/system:/lib/systemd/system systemd-analyze verify dbpilot-agent.service dbpilot-agent-proc-helper.socket dbpilot-agent-proc-helper.service dbpilot-docker-discovery.socket dbpilot-docker-discovery.service'
	if ($LASTEXITCODE -ne 0) { throw 'Kylin V10 systemd-analyze rejected a production Agent/helper unit.' }

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
        '--mount', "type=volume,source=$volumeName,target=/run/dbpilot-agent",
        'debian:bookworm-slim', '/bin/sh', '-c', 'chmod 0770 /run/dbpilot-agent && chown 1001:1001 /run/dbpilot-agent'
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
        '--read-only', '--network', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--user', '1002:1002', '--group-add', '0', '--group-add', '1001',
        '--mount', "type=bind,source=$helperBinary,target=/usr/bin/dbpilot-docker-discovery,readonly",
        '--mount', 'type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock',
        '--mount', "type=volume,source=$volumeName,target=/run/dbpilot-agent",
        'debian:bookworm-slim', '/usr/bin/dbpilot-docker-discovery', '--docker-socket', '/var/run/docker.sock', '--agent-socket', '/run/dbpilot-agent/docker-discovery.sock', '--allowed-uid', '1001', '--allowed-gid', '1001', '--allowed-labels', 'dbpilot.discovery.family,dbpilot.run'
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
        & $docker exec $helperId test -S /run/dbpilot-agent/docker-discovery.sock 2>$null
        $socketCheckExit = $LASTEXITCODE; $ErrorActionPreference = $savedPreference
        if ($socketCheckExit -eq 0) { $helperReady = $true; break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $helperReady) { throw 'Restricted helper socket was not ready in time.' }

	$procHelperId = New-DBPilotOwnedContainer -DockerBinary $docker -Name $procHelperName -CreateArguments @(
		'--label', 'dbpilot.verifier=docker-discovery', '--label', "dbpilot.run=$runLabel",
		'--read-only', '--network', 'none', '--cap-drop', 'ALL', '--cap-add', 'SYS_PTRACE', '--security-opt', 'no-new-privileges:true', '--user', '1003:1003', '--group-add', '1001', '--pid', "container:$helperId",
		'--mount', "type=bind,source=$agentBinary,target=/usr/bin/dbpilot-agent,readonly",
		'--mount', "type=volume,source=$volumeName,target=/run/dbpilot-agent",
		'debian:bookworm-slim', '/usr/bin/dbpilot-agent', 'proc-helper', '--allowed-uid', '1001', '--allowed-gid', '1001', '--allowed-process-names', 'mysqld'
	)
	$containerIds.Add($procHelperId)
	& $docker start $procHelperId | Out-Null
	if ($LASTEXITCODE -ne 0) { throw 'Unable to start the bounded proc helper.' }
	$procReady = $false
	for ($attempt = 0; $attempt -lt 40; $attempt++) {
		$procState = (& $docker inspect --format '{{.State.Status}}' $procHelperId | Out-String).Trim()
		if ($procState -in @('exited', 'dead')) { throw "Proc helper exited before readiness: $(& $docker logs $procHelperId 2>&1 | Out-String)" }
		$savedPreference = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
		& $docker exec $procHelperId test -S /run/dbpilot-agent/proc-helper.sock 2>$null
		$procSocketExit = $LASTEXITCODE; $ErrorActionPreference = $savedPreference
		if ($procSocketExit -eq 0) { $procReady = $true; break }
		Start-Sleep -Milliseconds 250
	}
	if (-not $procReady) { throw 'Bounded proc helper socket was not ready in time.' }

    $probeId = New-DBPilotOwnedContainer -DockerBinary $docker -Name $probeName -CreateArguments @(
        '--label', 'dbpilot.verifier=docker-discovery', '--label', "dbpilot.run=$runLabel",
        '--read-only', '--network', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--user', '1001:1001', '--pid', "container:$helperId",
        '--mount', "type=bind,source=$probeBinary,target=/usr/bin/docker-discovery-probe.test,readonly",
        '--mount', "type=volume,source=$volumeName,target=/run/dbpilot-agent",
        '--env', 'DBPILOT_DOCKER_HELPER_SOCKET=/run/dbpilot-agent/docker-discovery.sock', '--env', 'DBPILOT_PROC_HELPER_SOCKET=/run/dbpilot-agent/proc-helper.sock', '--env', 'DBPILOT_BOUNDARY_DOCKER_HELPER_PID=1', '--env', "DBPILOT_DOCKER_TEST_RUN=$runLabel", '--env', 'DBPILOT_DOCKER_TEST_READY_FILE=/run/dbpilot-agent/probe.ready', '--env', "DBPILOT_DOCKER_TEST_RESTART_ID=$($containerIds[1])",
        'debian:bookworm-slim', '/usr/bin/docker-discovery-probe.test', '-test.run', '^(TestLocalHelperBoundaryDeniesAgentProcessAndDockerSocketEscalation|TestDockerHelperTwoMySQLContainersAndEventReconciliation)$', '-test.v'
    )
    $containerIds.Add($probeId)
    & $docker start $probeId | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to start Agent probe without Docker Socket.' }

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $savedPreference = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        & $docker exec $helperId test -f /run/dbpilot-agent/probe.ready 2>$null
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
	$helperInspect = @(& $docker inspect $helperId | ConvertFrom-Json)[0]
	$procInspect = @(& $docker inspect $procHelperId | ConvertFrom-Json)[0]
	if ($probeInspect.Config.User -cne '1001:1001' -or $helperInspect.Config.User -cne '1002:1002' -or $procInspect.Config.User -cne '1003:1003') { throw 'Agent, Docker helper, and proc helper must use distinct UIDs.' }
    foreach ($mount in @($probeInspect.Mounts)) {
        if ($mount.Source -eq '/var/run/docker.sock' -or $mount.Destination -eq '/var/run/docker.sock') { throw 'Agent probe unexpectedly received the Docker Socket.' }
    }
    Write-Output 'PASS: distinct Agent/proc/Docker identities, zero Agent capabilities, process isolation, fixed helper DTO, two MySQL candidates, and event reconciliation verified.'
} finally {
    for ($index = $containerIds.Count - 1; $index -ge 0; $index--) {
        Remove-DBPilotRecordedContainer -DockerBinary $docker -ContainerID $containerIds[$index] -Verifier 'docker-discovery' -RunLabel $runLabel
    }
    if ($volumeCreated) { Remove-DBPilotRecordedVolume -DockerBinary $docker -VolumeName $volumeName -Verifier 'docker-discovery' -RunLabel $runLabel }
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}

$remainingContainers = @(& $docker ps -a --filter 'label=dbpilot.verifier=docker-discovery' --filter "label=dbpilot.run=$runLabel" --format '{{.ID}}')
$remainingVolumes = @(& $docker volume ls --filter 'label=dbpilot.verifier=docker-discovery' --filter "label=dbpilot.run=$runLabel" --format '{{.Name}}')
if (@($remainingContainers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -ne 0 -or @($remainingVolumes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -ne 0) {
    throw 'Docker discovery verifier left labelled resources after cleanup.'
}
