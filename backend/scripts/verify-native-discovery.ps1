param(
    [string]$Image = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1',
    [string]$GoBinary = 'go',
    [string]$DockerBinary = 'docker'
)

$ErrorActionPreference = 'Stop'
$backendRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$probeId = [Guid]::NewGuid().ToString('N')
$outputRoot = Join-Path $backendRoot ".tmp\native-discovery-$probeId"
$containerName = "dbpilot-native-discovery-$probeId"
$probePort = 43307
$oldGOOS = $env:GOOS
$oldGOARCH = $env:GOARCH
$oldCGO = $env:CGO_ENABLED
$oldGoCache = $env:GOCACHE
$dockerAvailable = $false

try {
	$unitPath = Join-Path $backendRoot 'packaging\systemd\dbpilot-agent.service'
	$unit = Get-Content -LiteralPath $unitPath
	$directives = @{}
	foreach ($line in $unit) {
		if ($line -match '^([A-Za-z][A-Za-z0-9]+)=(.*)$') {
			$key = $Matches[1]
			if ($directives.ContainsKey($key)) { throw "duplicate systemd directive: $key" }
			$directives[$key] = $Matches[2]
		}
	}
	if ($directives['User'] -ne 'dbpilot' -or $directives['Group'] -ne 'dbpilot') { throw 'Agent systemd unit must run as dbpilot:dbpilot' }
	if ($directives['CapabilityBoundingSet'] -ne 'CAP_SYS_PTRACE') { throw 'Agent capability bounding set must contain only CAP_SYS_PTRACE' }
	if ($directives['AmbientCapabilities'] -ne 'CAP_SYS_PTRACE') { throw 'Agent ambient capabilities must contain only CAP_SYS_PTRACE' }
	if ($directives['NoNewPrivileges'] -ne 'true') { throw 'Agent systemd unit must retain NoNewPrivileges=true' }

    New-Item -ItemType Directory -Path $outputRoot | Out-Null
    $env:GOOS = 'linux'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    $env:GOCACHE = Join-Path $outputRoot 'go-build'
    New-Item -ItemType Directory -Path $env:GOCACHE | Out-Null
    $null = Get-Command $DockerBinary -ErrorAction Stop
    $dockerAvailable = $true
    & $GoBinary build -trimpath -o (Join-Path $outputRoot 'dbpilot-agent') ./cmd/agent
    if ($LASTEXITCODE -ne 0) { throw 'Agent cross-build failed' }
    & $GoBinary build -trimpath -o (Join-Path $outputRoot 'mysqld-dbp') ./test/fixtures/native-discovery-mysqld
    if ($LASTEXITCODE -ne 0) { throw 'fixture cross-build failed' }
	Copy-Item -LiteralPath (Join-Path $outputRoot 'mysqld-dbp') -Destination (Join-Path $outputRoot 'not-a-database')
	& $GoBinary build -trimpath -o (Join-Path $outputRoot 'native-discovery-probe') ./test/fixtures/native-discovery-mysqld/probe
	if ($LASTEXITCODE -ne 0) { throw 'discovery probe cross-build failed' }

    $mount = "${outputRoot}:/probe:ro"
	$spoofPort = $probePort + 1
	$command = "set -euo pipefail; grep -Fxq 'VERSION=`"V10 (Tercel)`"' /etc/os-release; setpriv --reuid=19002 --regid=19002 --clear-groups /probe/mysqld-dbp --port=$probePort --password=dbpilot-probe-secret >/tmp/dbpilot-fixture.log 2>&1 & fixture_pid=`$!; setpriv --reuid=19002 --regid=19002 --clear-groups /bin/bash -c 'exec -a mysqld-dbp /probe/not-a-database --comm=mysqld-dbp --port=$spoofPort --password=dbpilot-spoof-secret' >/tmp/dbpilot-spoof.log 2>&1 & spoof_pid=`$!; trap 'kill `$fixture_pid `$spoof_pid 2>/dev/null || true; wait `$fixture_pid `$spoof_pid 2>/dev/null || true' EXIT; ready=0; for i in {1..20}; do if grep -qi ':A92B' /proc/net/tcp && grep -qi ':A92C' /proc/net/tcp; then ready=1; break; fi; sleep 0.25; done; test `$ready -eq 1; capsh --keep=1 --gid=19001 --groups= --uid=19001 --caps=cap_sys_ptrace,cap_setpcap+eip --inh=cap_sys_ptrace --addamb=cap_sys_ptrace --drop=cap_setuid,cap_setgid,cap_setpcap --caps=cap_sys_ptrace+eip -- -c '/probe/native-discovery-probe --mode=positive --port=$probePort'; capsh --keep=1 --gid=19001 --groups= --uid=19001 --caps=cap_setpcap+eip --drop=cap_setuid,cap_setgid,cap_setpcap,cap_sys_ptrace --caps= --noamb -- -c '/probe/native-discovery-probe --mode=permission'"
	$output = & $DockerBinary run --name $containerName --rm --cap-drop ALL --cap-add SYS_PTRACE --cap-add SETUID --cap-add SETGID --cap-add SETPCAP --security-opt no-new-privileges:true -v $mount $Image /bin/bash -lc $command 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Kylin native discovery probe failed: $output" }
    $text = $output -join "`n"
	if ([regex]::Matches($text, '(?m)^PASS POSITIVE ').Count -ne 1 -or [regex]::Matches($text, '(?m)^PASS NEGATIVE ').Count -ne 1) { throw 'Kylin native discovery positive and negative probes did not both pass' }
    if ($text -match 'dbpilot-probe-secret') { throw 'Kylin native discovery output leaked the fixture secret' }
	if ($text -match 'dbpilot-spoof-secret') { throw 'Kylin native discovery output leaked the spoof fixture secret' }
	if ($text -notmatch 'CAP_BND=0000000000080000 CAP_AMB=0000000000080000 CAP_EFF=0000000000080000') { throw 'Kylin positive probe did not run with exactly CAP_SYS_PTRACE bounded, ambient and effective' }
	if ($text -notmatch 'CAP_BND=0000000000000000 CAP_AMB=0000000000000000 CAP_EFF=0000000000000000 CAPABILITY_STATE=unavailable REASON=permission_denied') { throw 'Kylin negative probe did not report explicit permission_denied capability state' }
    if ([regex]::Matches($text, '"database_family":"mysql"').Count -ne 1) { throw 'Kylin native discovery did not emit exactly one MySQL candidate' }
	if ($text -match 'not-a-database') { throw 'spoofed argv0/comm process was accepted as a database' }
	Write-Host 'PASS: Kylin V10 SP1 dbpilot UID used only CAP_SYS_PTRACE, discovered one redacted cross-UID MySQL process, rejected spoofing, and reported the no-capability state.'
}
finally {
    $env:GOOS = $oldGOOS
    $env:GOARCH = $oldGOARCH
    $env:CGO_ENABLED = $oldCGO
    $env:GOCACHE = $oldGoCache
    if ($dockerAvailable) {
        & $DockerBinary rm -f $containerName 2>$null | Out-Null
    }
    if (Test-Path -LiteralPath $outputRoot) {
        $resolved = (Resolve-Path -LiteralPath $outputRoot).Path
        $expectedParent = (Resolve-Path -LiteralPath (Join-Path $backendRoot '.tmp')).Path
        if ((Split-Path -Parent $resolved) -ne $expectedParent -or (Split-Path -Leaf $resolved) -ne "native-discovery-$probeId") {
            throw 'refusing to clean an unexpected native discovery path'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
