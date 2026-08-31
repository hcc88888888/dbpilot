param(
    [Parameter(Mandatory = $true)][string]$GoBinary,
    [Parameter(Mandatory = $true)][string]$DockerBinary,
    [string]$KylinImage = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1'
)

$ErrorActionPreference = 'Stop'
$backendRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$temporaryRoot = [IO.Path]::GetFullPath((Join-Path $backendRoot ('.tmp\plugin-supervisor-' + [Guid]::NewGuid().ToString('N'))))
$allowedTemporaryRoot = [IO.Path]::GetFullPath((Join-Path $backendRoot '.tmp')) + [IO.Path]::DirectorySeparatorChar
if (-not $temporaryRoot.StartsWith($allowedTemporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'temporary verifier path escaped backend/.tmp'
}
$containerName = 'dbpilot-plugin-supervisor-' + [Guid]::NewGuid().ToString('N')

try {
    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    $fixturePath = Join-Path $temporaryRoot 'dbpilot-plugin-fixture'
    $testPath = Join-Path $temporaryRoot 'pluginsupervisor.test'

    $previousGOOS = $env:GOOS
    $previousGOARCH = $env:GOARCH
    $previousCGO = $env:CGO_ENABLED
    try {
        $env:GOOS = 'linux'
        $env:GOARCH = 'amd64'
        $env:CGO_ENABLED = '0'
        & $GoBinary build -trimpath -ldflags '-s -w' -o $fixturePath ./test/fixtures/plugin-supervisor
        if ($LASTEXITCODE -ne 0) { throw 'fixture cross-build failed' }
        & $GoBinary test -c -o $testPath ./internal/agent/pluginsupervisor
        if ($LASTEXITCODE -ne 0) { throw 'supervisor test cross-build failed' }
    }
    finally {
        $env:GOOS = $previousGOOS
        $env:GOARCH = $previousGOARCH
        $env:CGO_ENABLED = $previousCGO
    }

    $mount = $temporaryRoot.Replace('\', '/')
    $probeScript = @'
set -eu
grep -E '^(ID|VERSION_ID|NAME)=' /etc/os-release
test "$(id -u)" = "19001"
test "$(id -g)" = "19001"
grep '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status
grep '^CapAmb:[[:space:]]*0000000000000000$' /proc/self/status
DBPILOT_KYLIN_SUPERVISOR_PROBE=1 DBPILOT_PLUGIN_PROCESS_FIXTURE=/probe/dbpilot-plugin-fixture DBPILOT_SECRET_SENTINEL=must-not-leak /probe/pluginsupervisor.test -test.v -test.run 'Test(LinuxProcessRunnerDirectExecUsesFixedArgvCleanEnvironmentAndBoundedOutput|GRPCHealthCheckerRequiresExactPrivateHandshakeAndAssignmentHealth|KylinPluginSupervisorLifecycleProbe|InstallerRejectsSignedCaseCollisionAndInstalledHardlinkMutation|InstallerReauthenticatesRetainedPackageAndRejectsSameUIDTamper)$'
'@
    & $DockerBinary run --rm --name $containerName --network none --user '19001:19001' --cap-drop ALL --security-opt 'no-new-privileges:true' --read-only --tmpfs '/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777' -v "${mount}:/probe:ro" $KylinImage /bin/sh -c $probeScript
    if ($LASTEXITCODE -ne 0) { throw 'Kylin plugin supervisor probe failed' }

    $residue = & $DockerBinary ps -a --filter "name=^/${containerName}$" --format '{{.ID}}'
    if ($LASTEXITCODE -ne 0) { throw 'Docker residue check failed' }
    if ($residue) { throw 'Kylin verifier container residue remains' }
    Write-Host 'PASS: Kylin V10 non-root zero-cap plugin install/start/two-instance/rollback/restart/stop/absent lifecycle.'
}
finally {
    & $DockerBinary rm -f $containerName 2>$null | Out-Null
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolved = [IO.Path]::GetFullPath($temporaryRoot)
        if (-not $resolved.StartsWith($allowedTemporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'refusing to remove verifier path outside backend/.tmp'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
