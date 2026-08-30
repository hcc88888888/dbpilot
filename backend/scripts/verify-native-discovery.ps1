param(
    [string]$Image = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1',
    [string]$GoImage = 'golang:1.27.0-bookworm',
    [string]$GoBinary = 'go',
    [string]$DockerBinary = 'docker'
)

$ErrorActionPreference = 'Stop'
$backendRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$probeId = [Guid]::NewGuid().ToString('N')
$relativeOutput = ".tmp/native-discovery-$probeId"
$outputRoot = Join-Path $backendRoot ".tmp\native-discovery-$probeId"
$buildName = "dbpilot-native-build-$probeId"
$modernName = "dbpilot-native-modern-$probeId"
$legacyName = "dbpilot-native-legacy-$probeId"
$probePort = 43307
$spoofPort = $probePort + 1
$dockerAvailable = $false

function Assert-Directive([string]$Path, [string]$Name, [string]$Expected) {
    $matches = @(Get-Content -LiteralPath $Path | Where-Object { $_ -match "^$Name=(.*)$" })
    if ($matches.Count -ne 1 -or $matches[0].Substring($Name.Length + 1) -ne $Expected) {
        throw "$Path must contain exactly $Name=$Expected"
    }
}

function Invoke-DockerChecked([string[]]$Arguments, [string]$Failure) {
    $output = & $DockerBinary @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "$Failure`: $($output -join "`n")" }
    return $output
}

try {
    $null = Get-Command $DockerBinary -ErrorAction Stop
    $null = Get-Command $GoBinary -ErrorAction Stop
    $dockerAvailable = $true

    $baseUnit = Join-Path $backendRoot 'packaging\systemd\dbpilot-agent.service'
    Assert-Directive $baseUnit 'User' 'dbpilot'
    Assert-Directive $baseUnit 'Group' 'dbpilot'
    Assert-Directive $baseUnit 'CapabilityBoundingSet' 'CAP_SYS_PTRACE'
    Assert-Directive $baseUnit 'AmbientCapabilities' 'CAP_SYS_PTRACE'
    Assert-Directive $baseUnit 'NoNewPrivileges' 'true'

    $helperUnit = Join-Path $backendRoot 'packaging\systemd\dbpilot-agent-proc-helper.service'
    Assert-Directive $helperUnit 'User' 'root'
    Assert-Directive $helperUnit 'CapabilityBoundingSet' 'CAP_SYS_PTRACE CAP_DAC_READ_SEARCH'
    Assert-Directive $helperUnit 'NoNewPrivileges' 'true'
    Assert-Directive $helperUnit 'RestrictAddressFamilies' 'AF_UNIX'
    Assert-Directive $helperUnit 'PrivateNetwork' 'true'

    $socketUnit = Join-Path $backendRoot 'packaging\systemd\dbpilot-agent-proc-helper.socket'
    Assert-Directive $socketUnit 'SocketUser' 'dbpilot'
    Assert-Directive $socketUnit 'SocketGroup' 'dbpilot'
    Assert-Directive $socketUnit 'SocketMode' '0600'

    $legacyDropIn = Get-Content -Raw (Join-Path $backendRoot 'packaging\systemd\dbpilot-agent.service.d\centos7-proc-helper.conf')
    if ($legacyDropIn -notmatch '(?m)^CapabilityBoundingSet=$' -or $legacyDropIn -notmatch '(?m)^AmbientCapabilities=$') {
        throw 'CentOS 7 Agent drop-in must clear Agent bounding and ambient capabilities'
    }

    New-Item -ItemType Directory -Path $outputRoot | Out-Null
    $goModuleCache = (& $GoBinary env GOMODCACHE).Trim()
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $goModuleCache)) { throw 'Go module cache is unavailable' }
    $sourceMount = "${backendRoot}:/src"
    $moduleMount = "${goModuleCache}:/go/pkg/mod:ro"
    $buildCommand = "/usr/local/go/bin/go build -trimpath -o $relativeOutput/dbpilot-agent ./cmd/agent && /usr/local/go/bin/go build -trimpath -o $relativeOutput/mysqld-dbp ./test/fixtures/native-discovery-mysqld && cp $relativeOutput/mysqld-dbp $relativeOutput/not-a-database && /usr/local/go/bin/go build -trimpath -o $relativeOutput/native-discovery-probe ./test/fixtures/native-discovery-mysqld/probe"
    $null = Invoke-DockerChecked -Arguments @('run', '--rm', '--name', $buildName, '--label', 'dbpilot.verifier=native-build', '-v', $sourceMount, '-v', $moduleMount, '-w', '/src', '-e', 'CGO_ENABLED=0', $GoImage, '/bin/bash', '-lc', $buildCommand) -Failure 'native Linux verifier build failed'

    $probeMount = "${outputRoot}:/probe:ro"
    $modernCommand = "set -euo pipefail; grep -q '^VERSION_ID=.*V10' /etc/os-release; setpriv --reuid=19002 --regid=19002 --clear-groups /probe/mysqld-dbp --port=$probePort --password=dbpilot-probe-secret >/tmp/dbpilot-fixture.log 2>&1 & fixture=`$!; setpriv --reuid=19002 --regid=19002 --clear-groups /bin/bash -c 'exec -a mysqld-dbp /probe/not-a-database --comm=mysqld-dbp --port=$spoofPort --password=dbpilot-spoof-secret' >/tmp/dbpilot-spoof.log 2>&1 & spoof=`$!; trap 'kill `$fixture `$spoof 2>/dev/null || true; wait `$fixture `$spoof 2>/dev/null || true' EXIT; sleep 1; timeout 15 capsh --keep=1 --gid=19001 --groups= --uid=19001 --caps=cap_sys_ptrace,cap_setpcap+eip --inh=cap_sys_ptrace --addamb=cap_sys_ptrace --drop=cap_setuid,cap_setgid,cap_setpcap,cap_kill --caps=cap_sys_ptrace+eip -- -c '/probe/native-discovery-probe --mode=positive --port=$probePort'; timeout 15 capsh --keep=1 --gid=19001 --groups= --uid=19001 --caps=cap_setpcap+eip --drop=cap_setuid,cap_setgid,cap_setpcap,cap_kill,cap_sys_ptrace --caps= --noamb -- -c '/probe/native-discovery-probe --mode=permission'"
    $modernOutput = Invoke-DockerChecked -Arguments @('run', '--rm', '--name', $modernName, '--label', 'dbpilot.verifier=native-modern', '--stop-timeout', '3', '--cap-drop', 'ALL', '--cap-add', 'SYS_PTRACE', '--cap-add', 'SETUID', '--cap-add', 'SETGID', '--cap-add', 'SETPCAP', '--cap-add', 'KILL', '--security-opt', 'no-new-privileges:true', '-v', $probeMount, $Image, '/bin/bash', '-lc', $modernCommand) -Failure 'modern Kylin probe failed'
    $modernText = $modernOutput -join "`n"
    if ([regex]::Matches($modernText, '(?m)^PASS POSITIVE PATH=modern ').Count -ne 1) { throw 'modern positive probe did not execute exactly once' }
    if ([regex]::Matches($modernText, '(?m)^PASS NEGATIVE ').Count -ne 1) { throw 'modern no-capability probe did not execute exactly once' }
    if ($modernText -notmatch 'CAP_BND=0000000000080000 CAP_AMB=0000000000080000 CAP_EFF=0000000000080000') { throw 'modern Agent did not retain exactly CAP_SYS_PTRACE' }
    if ($modernText -notmatch 'CAPABILITY_STATE=unavailable REASON=permission_denied') { throw 'modern no-capability probe did not report permission_denied' }
    if ([regex]::Matches($modernText, '"database_family":"mysql"').Count -ne 1) { throw 'modern probe did not emit exactly one MySQL candidate' }

    $null = Invoke-DockerChecked -Arguments @('run', '-d', '--name', $legacyName, '--label', 'dbpilot.verifier=native-legacy', '--stop-timeout', '3', '--cap-drop', 'ALL', '--cap-add', 'SYS_PTRACE', '--cap-add', 'DAC_READ_SEARCH', '--cap-add', 'CHOWN', '--cap-add', 'SETPCAP', '--cap-add', 'SETUID', '--cap-add', 'SETGID', '--security-opt', 'no-new-privileges:true', '-v', $probeMount, $Image, 'sleep', '60') -Failure 'legacy Kylin container failed to start'
    $null = Invoke-DockerChecked -Arguments @('exec', '-d', '--user', '19002:19002', $legacyName, '/probe/mysqld-dbp', "--port=$probePort", '--password=dbpilot-probe-secret') -Failure 'legacy fixture failed to start'
    $null = Invoke-DockerChecked -Arguments @('exec', '-d', '--user', '19002:19002', $legacyName, '/bin/bash', '-c', "exec -a mysqld-dbp /probe/not-a-database --comm=mysqld-dbp --port=$spoofPort --password=dbpilot-spoof-secret") -Failure 'legacy spoof fixture failed to start'
    $null = Invoke-DockerChecked -Arguments @('exec', '-d', $legacyName, '/bin/bash', '-c', '/probe/native-discovery-probe --mode=activate-helper >/tmp/helper.log 2>&1') -Failure 'legacy helper activator failed to start'
    $helperReady = $false
    for ($index = 0; $index -lt 30; $index++) {
        & $DockerBinary exec $legacyName grep -q HELPER_READY /tmp/helper.log 2>$null
        if ($LASTEXITCODE -eq 0) { $helperReady = $true; break }
        Start-Sleep -Milliseconds 200
    }
    if (-not $helperReady) {
        $helperLog = & $DockerBinary exec $legacyName cat /tmp/helper.log 2>&1
        throw "legacy helper readiness timeout: $($helperLog -join "`n")"
    }
    $helperOutput = (Invoke-DockerChecked -Arguments @('exec', $legacyName, 'cat', '/tmp/helper.log') -Failure 'read helper evidence failed') -join "`n"
    $legacyPositive = (Invoke-DockerChecked -Arguments @('exec', '--user', '19001:19001', $legacyName, '/probe/native-discovery-probe', '--mode=positive', '--legacy', "--port=$probePort") -Failure 'legacy positive probe failed') -join "`n"
    $protocolNegative = (Invoke-DockerChecked -Arguments @('exec', '--user', '19001:19001', $legacyName, '/probe/native-discovery-probe', '--mode=protocol-negative') -Failure 'legacy protocol negative failed') -join "`n"
    $wrongUID = (Invoke-DockerChecked -Arguments @('exec', '--user', '19003:19003', $legacyName, '/probe/native-discovery-probe', '--mode=wrong-peer') -Failure 'legacy wrong UID negative failed') -join "`n"
    $wrongGID = (Invoke-DockerChecked -Arguments @('exec', '--user', '19001:19004', $legacyName, '/probe/native-discovery-probe', '--mode=wrong-gid') -Failure 'legacy wrong GID negative failed') -join "`n"
    $legacyText = "$helperOutput`n$legacyPositive`n$protocolNegative`n$wrongUID`n$wrongGID"
    if ($helperOutput -notmatch 'HELPER_READY CAP_BND=0000000000080004 CAP_EFF=0000000000080004 NO_NEW_PRIVS=1') { throw 'legacy helper capability evidence is invalid' }
    if ($legacyPositive -notmatch '^PASS POSITIVE PATH=legacy_helper UID=19001 ' -or $legacyPositive -notmatch 'CAP_AMB=0000000000000000 CAP_EFF=0000000000000000') { throw 'legacy Agent was not unprivileged or did not use helper path' }
    if ([regex]::Matches($legacyPositive, '"database_family":"mysql"').Count -ne 1) { throw 'legacy probe did not emit exactly one MySQL candidate' }
    foreach ($required in @('PASS MALFORMED_OVERSIZE_FORBIDDEN_PATH_REJECTED', 'PASS WRONG_PEER_REJECTED', 'PASS WRONG_GID_REJECTED')) {
        if ($legacyText -notmatch [regex]::Escape($required)) { throw "legacy negative did not execute: $required" }
    }

    $allOutput = "$modernText`n$legacyText"
    if ($allOutput -match 'dbpilot-probe-secret|dbpilot-spoof-secret|not-a-database') { throw 'native discovery verification leaked a secret or accepted the spoof executable' }
    Write-Host 'PASS: modern and CentOS 7 helper Kylin native discovery paths completed with exact capability, redaction, peer and protocol evidence.'
}
finally {
    if ($dockerAvailable) {
        foreach ($name in @($buildName, $modernName, $legacyName)) {
            try {
                & $DockerBinary rm -f $name 2>$null | Out-Null
            }
            catch {
                # --rm containers can still be in the daemon's removal window.
            }
        }
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
