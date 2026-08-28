[CmdletBinding()]
param(
    [string]$GoBinary,
    [string]$DockerBinary,
    [ValidatePattern('^[0-9a-f]{32}$')]
    [string]$RunId
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 7) { $PSNativeCommandUseErrorActionPreference = $false }

$backendRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$null = . (Join-Path $PSScriptRoot 'container-safety.ps1')
if ([string]::IsNullOrWhiteSpace($RunId)) { $RunId = [guid]::NewGuid().ToString('N') }
$containerName = "dbpilot-host-inspection-postgres-$RunId"
$containerID = $null
$anonymousVolumes = @()
$primaryFailure = $null

if ([string]::IsNullOrWhiteSpace($DockerBinary)) {
    $dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
    if ($dockerCommand) { $DockerBinary = $dockerCommand.Source }
    if ([string]::IsNullOrWhiteSpace($DockerBinary)) {
        foreach ($candidate in @(
            (Join-Path ${env:ProgramFiles} 'Docker\Docker\resources\bin\docker.exe'),
            (Join-Path ${env:LOCALAPPDATA} 'Programs\DockerDesktop\resources\bin\docker.exe')
        )) {
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $DockerBinary = $candidate; break }
        }
    }
}
if ([string]::IsNullOrWhiteSpace($DockerBinary) -or -not [IO.Path]::IsPathRooted($DockerBinary) -or -not (Test-Path -LiteralPath $DockerBinary -PathType Leaf)) {
    throw 'Docker CLI is required. Install/start Docker Desktop or pass -DockerBinary with an absolute executable path.'
}

if ([string]::IsNullOrWhiteSpace($GoBinary)) {
    $goCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($goCommand) { $GoBinary = $goCommand.Source }
    if ([string]::IsNullOrWhiteSpace($GoBinary)) {
        $cursor = $backendRoot
        while (-not [string]::IsNullOrWhiteSpace($cursor)) {
            $candidate = Join-Path $cursor '.tooling\go\bin\go.exe'
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $GoBinary = $candidate; break }
            $parent = Split-Path -Parent $cursor
            if ($parent -eq $cursor) { break }
            $cursor = $parent
        }
    }
}
if ([string]::IsNullOrWhiteSpace($GoBinary) -or -not [IO.Path]::IsPathRooted($GoBinary) -or -not (Test-Path -LiteralPath $GoBinary -PathType Leaf)) {
    throw 'An absolute Go executable path is required. Pass -GoBinary when Go is not on PATH.'
}

function Invoke-Checked {
    param([Parameter(Mandatory = $true)][string]$Command, [string[]]$Arguments = @())
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE" }
}

$hadE2E = Test-Path Env:DBPILOT_CONTRACT_E2E
$previousE2E = $env:DBPILOT_CONTRACT_E2E
$hadDSN = Test-Path Env:DBPILOT_CONTRACT_POSTGRES_DSN
$previousDSN = $env:DBPILOT_CONTRACT_POSTGRES_DSN

try {
    $containerID = New-DBPilotOwnedContainer -DockerBinary $DockerBinary -Name $containerName -CreateArguments @(
        '--label', 'dbpilot.verifier=host-inspection',
        '--label', "dbpilot.run=$containerName",
        '--publish', '127.0.0.1::5432',
        '--env', 'POSTGRES_DB=dbpilot_inspection',
        '--env', 'POSTGRES_USER=dbpilot_inspection',
        '--env', 'POSTGRES_PASSWORD=dbpilot_inspection',
        'postgres:16-alpine'
    )
    $inspectionJSON = (& $DockerBinary inspect $containerID | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect the host inspection PostgreSQL container.' }
    $inspection = @($inspectionJSON | ConvertFrom-Json)
    if ($inspection.Count -ne 1 -or
        $inspection[0].Id -cne $containerID -or
        $inspection[0].Config.Labels.'dbpilot.verifier' -cne 'host-inspection' -or
        $inspection[0].Config.Labels.'dbpilot.run' -cne $containerName) {
        throw 'Host inspection PostgreSQL ownership metadata is missing or incorrect.'
    }
    $anonymousVolumes = @($inspection[0].Mounts | Where-Object Type -eq 'volume' | ForEach-Object Name)
    Invoke-Checked $DockerBinary @('start', $containerID)

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        & $DockerBinary exec $containerID pg_isready -U dbpilot_inspection -d dbpilot_inspection *> $null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'Host inspection PostgreSQL did not become ready.' }

    $binding = (& $DockerBinary port $containerID '5432/tcp' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $binding -notmatch '^127\.0\.0\.1:(\d+)$') {
        throw 'Unable to resolve the ephemeral PostgreSQL loopback port.'
    }
    $port = $Matches[1]
    $env:DBPILOT_CONTRACT_E2E = '1'
    $env:DBPILOT_CONTRACT_POSTGRES_DSN = "postgres://dbpilot_inspection:dbpilot_inspection@127.0.0.1:$port/dbpilot_inspection?sslmode=disable"
    Push-Location $backendRoot
    try {
        Invoke-Checked $GoBinary @('test', './test/e2e', '-run', '^TestHostInspectionLifecycle$', '-count=1', '-v')
    }
    finally { Pop-Location }
    Write-Host "Host inspection PostgreSQL lifecycle verification passed: run=$RunId port=ephemeral."
}
catch {
    $primaryFailure = $_
    throw
}
finally {
    if ($hadE2E) { $env:DBPILOT_CONTRACT_E2E = $previousE2E } else { Remove-Item Env:DBPILOT_CONTRACT_E2E -ErrorAction SilentlyContinue }
    if ($hadDSN) { $env:DBPILOT_CONTRACT_POSTGRES_DSN = $previousDSN } else { Remove-Item Env:DBPILOT_CONTRACT_POSTGRES_DSN -ErrorAction SilentlyContinue }

    $cleanupFailures = @()
    try {
        Remove-DBPilotOwnedContainer -DockerBinary $DockerBinary -ContainerID $containerID
        if (-not [string]::IsNullOrWhiteSpace($containerID)) {
            $remainingByID = @(& $DockerBinary ps -a --no-trunc --filter "id=$containerID" --format '{{.ID}}')
            if ($LASTEXITCODE -ne 0) { throw 'Unable to audit host inspection container cleanup by ID.' }
            if ($remainingByID -contains $containerID) { throw "Host inspection verifier left container '$containerID' behind." }
        }
        $remainingByRun = @(& $DockerBinary ps -a --filter "label=dbpilot.run=$containerName" --format '{{.ID}}')
        if ($LASTEXITCODE -ne 0) { throw 'Unable to audit host inspection container cleanup by ownership label.' }
        if (($remainingByRun | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
            throw "Host inspection verifier left a run-labelled container for '$containerName' behind."
        }
        foreach ($volume in $anonymousVolumes) {
            $remainingVolume = @(& $DockerBinary volume ls --filter "name=^$volume$" --format '{{.Name}}')
            if ($LASTEXITCODE -ne 0) { throw "Unable to audit anonymous volume cleanup for '$volume'." }
            if ($remainingVolume -contains $volume) { throw "Host inspection verifier left anonymous volume '$volume' behind." }
        }
        Write-Host "Host inspection cleanup audit passed: container=$containerID anonymous_volumes=$($anonymousVolumes.Count)."
    }
    catch { $cleanupFailures += $_ }
    if ($cleanupFailures.Count -gt 0) {
        if ($null -eq $primaryFailure) { throw $cleanupFailures[0] }
        foreach ($failure in $cleanupFailures) { Write-Error $failure -ErrorAction Continue }
    }
}
