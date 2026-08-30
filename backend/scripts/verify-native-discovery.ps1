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
    & $GoBinary test -c -trimpath -o (Join-Path $outputRoot 'native-discovery.test') ./internal/agent/discovery
    if ($LASTEXITCODE -ne 0) { throw 'discovery test cross-build failed' }

    $mount = "${outputRoot}:/probe:ro"
    $command = "/probe/mysqld-dbp --port=$probePort --password=dbpilot-probe-secret >/tmp/dbpilot-fixture.log 2>&1 & fixture_pid=`$!; trap 'kill `$fixture_pid 2>/dev/null || true' EXIT; for i in 1 2 3 4 5 6 7 8 9 10; do grep -qi ':A92B' /proc/net/tcp && break; sleep 1; done; DBPILOT_KYLIN_DISCOVERY_PROBE=1 DBPILOT_KYLIN_DISCOVERY_PORT=$probePort /probe/native-discovery.test -test.run '^TestKylinNativeDiscoveryProbe$' -test.v"
    $output = & $DockerBinary run --name $containerName --rm -v $mount $Image /bin/bash -lc $command 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Kylin native discovery probe failed: $output" }
    $text = $output -join "`n"
    if ($text -notmatch 'PASS') { throw 'Kylin native discovery probe did not pass' }
    if ($text -match 'dbpilot-probe-secret') { throw 'Kylin native discovery output leaked the fixture secret' }
    if ([regex]::Matches($text, '"database_family":"mysql"').Count -ne 1) { throw 'Kylin native discovery did not emit exactly one MySQL candidate' }
    Write-Host 'PASS: Kylin native discovery found exactly one redacted MySQL candidate.'
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
