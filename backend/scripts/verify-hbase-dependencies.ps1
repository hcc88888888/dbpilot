[CmdletBinding()]
param(
    [string]$DockerBinary,
    [string]$GoBinary,
    [string]$KylinImage = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1',
    [ValidateSet('amd64', 'arm64')]
    [string]$Architecture = 'amd64',
    [int]$HealthTimeoutSeconds = 90,
    [int]$TestTimeoutSeconds = 120,
    [switch]$SkipKylin
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 7) { $PSNativeCommandUseErrorActionPreference = $false }
if ($HealthTimeoutSeconds -lt 1 -or $TestTimeoutSeconds -lt 1) { throw 'Timeout values must be positive.' }

if ([string]::IsNullOrWhiteSpace($DockerBinary)) {
    $dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
    if ($dockerCommand) {
        $DockerBinary = $dockerCommand.Source
    } else {
        $dockerCandidates = @(
            (Join-Path ${env:ProgramFiles} 'Docker\Docker\resources\bin\docker.exe'),
            (Join-Path ${env:LOCALAPPDATA} 'Programs\DockerDesktop\resources\bin\docker.exe')
        )
        $DockerBinary = $dockerCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    }
}
if ([string]::IsNullOrWhiteSpace($DockerBinary) -or -not (Test-Path -LiteralPath $DockerBinary -PathType Leaf)) {
    throw 'Docker CLI is required. Start Docker Desktop or pass -DockerBinary with an absolute docker.exe path.'
}

function Invoke-Docker {
    param([string[]]$Arguments)
    & $DockerBinary @Arguments
    if ($LASTEXITCODE -ne 0) { throw "docker $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
}

function Get-ComposeContainer {
    param([string]$Service)
    $containerID = (& $DockerBinary compose --project-name $projectName --file $composeFile ps -aq $Service).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerID)) { throw "Compose service '$Service' was not created." }
    return $containerID
}

function Wait-Healthy {
    param([string]$Service)
    $containerID = Get-ComposeContainer $Service
    $deadline = [DateTime]::UtcNow.AddSeconds($HealthTimeoutSeconds)
    do {
        $status = (& $DockerBinary inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $containerID).Trim()
        if ($LASTEXITCODE -ne 0) { throw "Unable to inspect '$Service'." }
        if ($status -eq 'healthy') { return }
        if ($status -in @('unhealthy', 'exited', 'dead')) {
            Invoke-Docker @('compose', '--project-name', $projectName, '--file', $composeFile, 'logs', '--no-color', $Service)
            throw "Service '$Service' failed health verification with status '$status'."
        }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    Invoke-Docker @('compose', '--project-name', $projectName, '--file', $composeFile, 'logs', '--no-color', $Service)
    throw "Service '$Service' was not healthy within $HealthTimeoutSeconds seconds."
}

function Resolve-GoBinary {
    if (-not [string]::IsNullOrWhiteSpace($GoBinary)) { return $GoBinary }
    $worktreeRoot = Split-Path -Parent $backendRoot
    $repositoryRoot = Split-Path -Parent (Split-Path -Parent $worktreeRoot)
    $candidate = Join-Path $repositoryRoot '.tooling\go\bin\go.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    $goCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($goCommand) { return $goCommand.Source }
    return $null
}

$backendRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $backendRoot 'deploy\compose\hbase-dependencies.compose.yaml'
if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) { throw "Compose file not found: $composeFile" }
$composeFile = (Resolve-Path -LiteralPath $composeFile).Path
$projectName = "dbpilot-hbase-dependencies-$PID"
$networkName = "${projectName}_hbase-dependencies"
$kylinContainer = $null
$agentBinary = $null
$fixtureBinary = $null
$primaryFailure = $null

try {
    Invoke-Docker @('version', '--format', '{{.Server.Version}}')
    Invoke-Docker @('compose', '--project-name', $projectName, '--file', $composeFile, 'config', '--quiet')
    Invoke-Docker @('compose', '--project-name', $projectName, '--file', $composeFile, 'up', '--detach', 'hbase-jmx', 'hbase-failing-jmx', 'hdfs-jmx', 'zookeeper-jmx')
    foreach ($service in @('hbase-jmx', 'hbase-failing-jmx', 'hdfs-jmx', 'zookeeper-jmx')) { Wait-Healthy $service }
    Invoke-Docker @('compose', '--project-name', $projectName, '--file', $composeFile, 'run', '--rm', '--no-deps', '--env', "DBPILOT_TEST_TIMEOUT_SECONDS=$TestTimeoutSeconds", 'collector-tests')
    Write-Host 'Docker fixture runtime-path validation passed (fixture JMX, not full distribution E2E).'

    if (-not $SkipKylin) {
        $resolvedGoBinary = Resolve-GoBinary
        if ([string]::IsNullOrWhiteSpace($resolvedGoBinary) -or -not (Test-Path -LiteralPath $resolvedGoBinary -PathType Leaf)) {
            throw 'Kylin validation requires an absolute Go executable path via -GoBinary.'
        }
        $imageID = (& $DockerBinary image inspect --format '{{.Id}}' $KylinImage 2>$null).Trim()
        if ([string]::IsNullOrWhiteSpace($imageID)) { throw "Approved Kylin image '$KylinImage' is not available locally." }

        $agentBinary = Join-Path ([IO.Path]::GetTempPath()) "dbpilot-agent-$PID"
        $fixtureBinary = Join-Path ([IO.Path]::GetTempPath()) "dbpilot-hbase-agent-fixture-$PID"
        $priorGOOS, $priorGOARCH, $priorCGO = ${env:GOOS}, ${env:GOARCH}, ${env:CGO_ENABLED}
        try {
            ${env:GOOS} = 'linux'; ${env:GOARCH} = $Architecture; ${env:CGO_ENABLED} = '0'
            & $resolvedGoBinary build -o $agentBinary ./cmd/agent
            if ($LASTEXITCODE -ne 0) { throw "Build Kylin Agent failed with exit code $LASTEXITCODE." }
            & $resolvedGoBinary build -o $fixtureBinary ./test/fixtures/hbase-agent
            if ($LASTEXITCODE -ne 0) { throw "Build Kylin fixture inspector failed with exit code $LASTEXITCODE." }
        } finally {
            ${env:GOOS}, ${env:GOARCH}, ${env:CGO_ENABLED} = $priorGOOS, $priorGOARCH, $priorCGO
        }

        $platform = if ($Architecture -eq 'amd64') { 'linux/amd64' } else { 'linux/arm64' }
        $kylinContainer = (& $DockerBinary create --platform $platform --network $networkName --tmpfs '/tmp:rw,nosuid,size=256m' $KylinImage /bin/sh -c 'sleep 300').Trim()
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($kylinContainer)) { throw 'Unable to create Kylin validation container.' }
        Invoke-Docker @('cp', $agentBinary, "${kylinContainer}:/opt/dbpilot-agent")
        Invoke-Docker @('cp', $fixtureBinary, "${kylinContainer}:/opt/hbase-agent-fixture")
        Invoke-Docker @('start', $kylinContainer)
        $kylinScript = @'
set -eu
. /etc/os-release
case "${ID:-}" in kylin|kylin-server|neokylin|kylinsec) ;; *) exit 41 ;; esac
case "${VERSION_ID:-}" in V10|v10|10*) ;; *) exit 42 ;; esac
case "${DBPILOT_EXPECTED_ARCH}" in amd64) test "$(uname -m)" = x86_64 ;; arm64) test "$(uname -m)" = aarch64 ;; esac
chmod 0755 /opt/dbpilot-agent /opt/hbase-agent-fixture
mkdir -m 0700 /opt/agent-fixture
/opt/hbase-agent-fixture -mode prepare -dir /opt/agent-fixture -hbase http://hbase-jmx:8000/jmx -hbase-failing http://hbase-failing-jmx:8000/jmx -hdfs http://hdfs-jmx:8000/jmx -zookeeper http://zookeeper-jmx:8000/jmx
DBPILOT_SECRET_FIXTURE_READER=dbpilot-fixture-read-only /opt/dbpilot-agent --config /opt/agent-fixture/agent.yaml >/tmp/dbpilot-agent.log 2>&1 &
agent_pid=$!
iterations=0
while [ "$iterations" -lt 8 ]; do
  kill -0 "$agent_pid" || { cat /tmp/dbpilot-agent.log; exit 43; }
  sleep 1
  iterations=$((iterations + 1))
done
kill -TERM "$agent_pid"
wait "$agent_pid" || { cat /tmp/dbpilot-agent.log; exit 44; }
/opt/hbase-agent-fixture -mode inspect -dir /opt/agent-fixture
printf 'Kylin HBase dependency validation passed: ID=%s VERSION=%s ARCH=%s\n' "$ID" "${VERSION_ID:-unknown}" "$(uname -m)"
'@
        $encodedScript = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($kylinScript))
        Invoke-Docker @('exec',
            '-e', "DBPILOT_EXPECTED_ARCH=$Architecture",
            $kylinContainer, '/bin/sh', '-c', "echo $encodedScript | base64 -d | /bin/sh")
    }
}
catch {
    $primaryFailure = $_
    throw
}
finally {
    $cleanupFailures = @()
    if (-not [string]::IsNullOrWhiteSpace($kylinContainer)) {
        & $DockerBinary rm -f $kylinContainer 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { $cleanupFailures += 'Kylin container cleanup failed.' }
    }
    foreach ($temporaryBinary in @($agentBinary, $fixtureBinary)) {
        if (-not [string]::IsNullOrWhiteSpace($temporaryBinary) -and (Test-Path -LiteralPath $temporaryBinary)) {
            Remove-Item -LiteralPath $temporaryBinary -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $temporaryBinary) { $cleanupFailures += "Temporary binary cleanup failed: $temporaryBinary" }
        }
    }
    $cleanupPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $cleanupOutput = & $DockerBinary compose --project-name $projectName --file $composeFile down --volumes --remove-orphans 2>&1
    $cleanupExitCode = $LASTEXITCODE
    $ErrorActionPreference = $cleanupPreference
    if ($cleanupExitCode -ne 0) { $cleanupFailures += "Compose cleanup failed: $(($cleanupOutput | Out-String).Trim())" }
    if ($cleanupFailures.Count -gt 0) {
        $cleanupMessage = $cleanupFailures -join ' '
        if ($null -ne $primaryFailure) { Write-Error $cleanupMessage -ErrorAction Continue } else { throw $cleanupMessage }
    }
}
