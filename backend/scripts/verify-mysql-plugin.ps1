param(
    [string]$GoBinary = '',
    [string]$DockerBinary = "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe",
    [string]$MySQLImage = 'mysql:8.4',
    [string]$KylinImage = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1'
)

$ErrorActionPreference = 'Stop'
$backendRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$repositoryRoot = (Resolve-Path (Join-Path $backendRoot '..')).Path
$runID = "task13-$PID-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
$network = "dbpilot-$runID"
$mysqlA = "dbpilot-$runID-mysql-a"
$mysqlB = "dbpilot-$runID-mysql-b"
$verifier = "dbpilot-$runID-verifier"
$artifactRoot = Join-Path $backendRoot ".tmp-$runID"
$testPassword = "task13-$([Guid]::NewGuid().ToString('N'))"

if ([string]::IsNullOrWhiteSpace($GoBinary)) {
    $cursor = $repositoryRoot
    while ($cursor) {
        $candidate = Join-Path $cursor '.tooling\go\bin\go.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $GoBinary = $candidate; break }
        $parent = Split-Path $cursor -Parent
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Invoke-Docker {
    param([string[]]$DockerArgs)
    & $DockerBinary @DockerArgs
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed" }
}

function Wait-MySQL {
    param([string]$Container)
    $deadline = [DateTime]::UtcNow.AddMinutes(3)
    while ([DateTime]::UtcNow -lt $deadline) {
        & $DockerBinary exec -e "MYSQL_PWD=$testPassword" $Container mysqladmin ping '-h127.0.0.1' '-uroot' '--silent' *> $null
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Seconds 2
    }
    throw "MySQL container did not become ready"
}

try {
    if (-not (Test-Path -LiteralPath $GoBinary -PathType Leaf)) { throw "Go binary not found" }
    if (-not (Test-Path -LiteralPath $DockerBinary -PathType Leaf)) { throw "Docker binary not found" }
    New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
    $resolvedArtifactRoot = (Resolve-Path -LiteralPath $artifactRoot).Path
    if (-not $resolvedArtifactRoot.StartsWith($backendRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw "Artifact path escaped backend worktree" }

    Push-Location $backendRoot
    try {
        $oldCGO = $env:CGO_ENABLED; $oldGOOS = $env:GOOS; $oldGOARCH = $env:GOARCH
        $env:CGO_ENABLED = '0'; $env:GOOS = 'linux'; $env:GOARCH = 'amd64'
        & $GoBinary build -trimpath -o (Join-Path $artifactRoot 'dbpilot-plugin-mysql') ./cmd/dbpilot-plugin-mysql
        if ($LASTEXITCODE -ne 0) { throw "MySQL plugin build failed" }
        & $GoBinary build -trimpath -o (Join-Path $artifactRoot 'mysql-plugin-verifier') ./test/fixtures/mysql-plugin
        if ($LASTEXITCODE -ne 0) { throw "MySQL verifier build failed" }
    } finally {
        $env:CGO_ENABLED = $oldCGO; $env:GOOS = $oldGOOS; $env:GOARCH = $oldGOARCH
        Pop-Location
    }

    Invoke-Docker -DockerArgs @('network', 'create', '--internal', $network) | Out-Null
    Invoke-Docker -DockerArgs @('run', '-d', '--name', $mysqlA, '--network', $network, '--network-alias', 'mysql-a', '-e', "MYSQL_ROOT_PASSWORD=$testPassword", '-e', 'MYSQL_ROOT_HOST=%', $MySQLImage, '--skip-name-resolve') | Out-Null
    Invoke-Docker -DockerArgs @('run', '-d', '--name', $mysqlB, '--network', $network, '--network-alias', 'mysql-b', '-e', "MYSQL_ROOT_PASSWORD=$testPassword", '-e', 'MYSQL_ROOT_HOST=%', $MySQLImage, '--skip-name-resolve') | Out-Null
    Wait-MySQL $mysqlA
    Wait-MySQL $mysqlB

    Invoke-Docker -DockerArgs @('run', '-d', '--name', $verifier, '--network', $network, '--entrypoint', '/bin/sh', $KylinImage, '-c', 'sleep 600') | Out-Null
    Invoke-Docker -DockerArgs @('cp', (Join-Path $artifactRoot 'dbpilot-plugin-mysql'), "${verifier}:/opt/dbpilot-plugin-mysql")
    Invoke-Docker -DockerArgs @('cp', (Join-Path $artifactRoot 'mysql-plugin-verifier'), "${verifier}:/opt/mysql-plugin-verifier")
    Invoke-Docker -DockerArgs @('exec', $verifier, '/bin/sh', '-c', 'groupadd -g 65532 dbpilot && useradd -u 65532 -g 65532 -M -d /tmp -s /sbin/nologin dbpilot && chown 65532:65532 /opt/dbpilot-plugin-mysql /opt/mysql-plugin-verifier && chmod 0500 /opt/dbpilot-plugin-mysql /opt/mysql-plugin-verifier')
    Invoke-Docker -DockerArgs @('exec', '--user', '65532:65532', '-e', 'DBPILOT_MYSQL_PLUGIN=/opt/dbpilot-plugin-mysql', '-e', "DBPILOT_MYSQL_TEST_PASSWORD=$testPassword", $verifier, '/opt/mysql-plugin-verifier')

    Write-Output 'PASS: one non-root Linux MySQL plugin process managed two MySQL 8 instances, collected five canonical metrics, observed connection-count change, isolated a bad credential, drained its active stream, and then exited cleanly on SIGTERM.'
} finally {
    $previousErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    & $DockerBinary rm -f $verifier $mysqlA $mysqlB 2>$null | Out-Null
    & $DockerBinary network rm $network 2>$null | Out-Null
    $ErrorActionPreference = $previousErrorPreference
    if (Test-Path -LiteralPath $artifactRoot) {
        $cleanupPath = (Resolve-Path -LiteralPath $artifactRoot).Path
        if ($cleanupPath.StartsWith($backendRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $cleanupPath -Recurse -Force
        }
    }
}
