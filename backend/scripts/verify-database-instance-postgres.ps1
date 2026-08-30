param(
    [string]$Image = 'postgres:16-alpine',
    [string]$GoBinary = 'go',
    [string]$DockerBinary = 'docker'
)

$ErrorActionPreference = 'Stop'
$backendRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$probeId = [Guid]::NewGuid().ToString('N')
$containerName = "dbpilot-database-instance-pg-$probeId"
$password = 'dbpilot-database-instance-test-only'
$oldIntegration = $env:DBPILOT_DATABASE_INSTANCE_POSTGRES_INTEGRATION
$oldDSN = $env:DBPILOT_DATABASE_INSTANCE_POSTGRES_DSN
$oldGoCache = $env:GOCACHE
$started = $false

try {
    & $DockerBinary run --detach --name $containerName --label "dbpilot.test.owner=$probeId" --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=512m -e "POSTGRES_PASSWORD=$password" -e POSTGRES_DB=dbpilot -p 127.0.0.1::5432 $Image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'start PostgreSQL 16 database-instance verification container failed' }
    $started = $true
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        & $DockerBinary exec $containerName pg_isready -U postgres -d dbpilot 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'PostgreSQL 16 database-instance verification container did not become ready' }
    $mapping = (& $DockerBinary port $containerName 5432/tcp).Trim()
    if ($mapping -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'PostgreSQL loopback port mapping is invalid' }
    $port = $Matches[1]
    $env:DBPILOT_DATABASE_INSTANCE_POSTGRES_INTEGRATION = '1'
    $env:DBPILOT_DATABASE_INSTANCE_POSTGRES_DSN = "postgres://postgres:$password@127.0.0.1:$port/dbpilot?sslmode=disable"
    $cache = Join-Path $backendRoot '.tmp\database-instance-pg-go-build'
    New-Item -ItemType Directory -Force -Path $cache | Out-Null
    $env:GOCACHE = (Resolve-Path -LiteralPath $cache).Path
    Push-Location $backendRoot
    try {
        & $GoBinary test ./internal/databaseinstance -run '^TestDatabaseInstancePostgres' -count=1 -v
        if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL 16 database-instance integration failed' }
    }
    finally {
        Pop-Location
    }
    Write-Host 'PASS: PostgreSQL 16 database-instance concurrency, CAS, replay, rollback and pagination verification passed.'
}
finally {
    $env:DBPILOT_DATABASE_INSTANCE_POSTGRES_INTEGRATION = $oldIntegration
    $env:DBPILOT_DATABASE_INSTANCE_POSTGRES_DSN = $oldDSN
    $env:GOCACHE = $oldGoCache
    if ($started) { & $DockerBinary rm -f $containerName 2>$null | Out-Null }
}
