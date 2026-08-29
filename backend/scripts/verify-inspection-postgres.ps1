[CmdletBinding()]
param(
    [string]$GoBinary,
    [string]$DockerBinary
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 7) { $PSNativeCommandUseErrorActionPreference = $false }

$backendRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$null = . (Join-Path $PSScriptRoot 'container-safety.ps1')
$containerName = New-DBPilotOwnedContainerName -Prefix 'dbpilot-inspection-postgres'
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
if ([string]::IsNullOrWhiteSpace($DockerBinary) -or -not (Test-Path -LiteralPath $DockerBinary -PathType Leaf)) {
    throw 'Docker CLI is required. Install/start Docker Desktop or pass -DockerBinary.'
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
$hadDSN = Test-Path Env:DBPILOT_INSPECTION_POSTGRES_DSN
$previousDSN = $env:DBPILOT_INSPECTION_POSTGRES_DSN
$hadPlatformIntegration = Test-Path Env:DBPILOT_PLATFORM_POSTGRES_INTEGRATION
$previousPlatformIntegration = $env:DBPILOT_PLATFORM_POSTGRES_INTEGRATION
$hadPlatformDSN = Test-Path Env:DBPILOT_PLATFORM_POSTGRES_DSN
$previousPlatformDSN = $env:DBPILOT_PLATFORM_POSTGRES_DSN
$hadJobIntegration = Test-Path Env:DBPILOT_JOB_POSTGRES_INTEGRATION
$previousJobIntegration = $env:DBPILOT_JOB_POSTGRES_INTEGRATION
$hadJobDSN = Test-Path Env:DBPILOT_JOB_POSTGRES_DSN
$previousJobDSN = $env:DBPILOT_JOB_POSTGRES_DSN

try {
    $containerID = New-DBPilotOwnedContainer -DockerBinary $DockerBinary -Name $containerName -CreateArguments @(
        '--label', 'dbpilot.verifier=inspection-postgres',
        '--label', "dbpilot.run=$containerName",
        '--publish', '127.0.0.1::5432',
        '--env', 'POSTGRES_DB=dbpilot_inspection',
        '--env', 'POSTGRES_USER=dbpilot_inspection',
        '--env', 'POSTGRES_PASSWORD=dbpilot_inspection',
        'postgres:16-alpine'
    )
    $inspectionJSON = (& $DockerBinary inspect $containerID | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect inspection PostgreSQL container.' }
    $inspection = @($inspectionJSON | ConvertFrom-Json)
    if ($inspection.Count -ne 1 -or $inspection[0].Config.Labels.'dbpilot.run' -cne $containerName) { throw 'Inspection PostgreSQL ownership label is missing.' }
    $anonymousVolumes = @($inspection[0].Mounts | Where-Object Type -eq 'volume' | ForEach-Object Name)
    Invoke-Checked $DockerBinary @('start', $containerID)
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        & $DockerBinary exec $containerID pg_isready -U dbpilot_inspection -d dbpilot_inspection *> $null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'Inspection PostgreSQL did not become ready.' }
    $binding = (& $DockerBinary port $containerID '5432/tcp' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'Unable to resolve the ephemeral PostgreSQL loopback port.' }
    $port = $Matches[1]
    $env:DBPILOT_CONTRACT_E2E = '1'
    $env:DBPILOT_INSPECTION_POSTGRES_DSN = "postgres://dbpilot_inspection:dbpilot_inspection@127.0.0.1:$port/dbpilot_inspection?sslmode=disable"
    $env:DBPILOT_PLATFORM_POSTGRES_INTEGRATION = '1'
    $env:DBPILOT_PLATFORM_POSTGRES_DSN = $env:DBPILOT_INSPECTION_POSTGRES_DSN
	$env:DBPILOT_JOB_POSTGRES_INTEGRATION = '1'
	$env:DBPILOT_JOB_POSTGRES_DSN = $env:DBPILOT_INSPECTION_POSTGRES_DSN
    Push-Location $backendRoot
    try {
        Invoke-Checked $GoBinary @('test', './internal/inspection', '-run', 'Test(PostgresIntegration|Scheduler|InspectionReportRows)', '-count=1', '-v')
		Invoke-Checked $GoBinary @('test', './internal/job', '-run', 'TestPostgresIntegrationPrepareSlotsSurviveConcurrentDispatchersRestartAndRelease', '-count=1', '-v')
        Invoke-Checked $GoBinary @('test', './internal/platformdb', '-run', 'TestPlatformPostgresIntegration', '-count=1', '-v')
    }
    finally { Pop-Location }
}
catch {
    $primaryFailure = $_
    throw
}
finally {
    if ($hadE2E) { $env:DBPILOT_CONTRACT_E2E = $previousE2E } else { Remove-Item Env:DBPILOT_CONTRACT_E2E -ErrorAction SilentlyContinue }
    if ($hadDSN) { $env:DBPILOT_INSPECTION_POSTGRES_DSN = $previousDSN } else { Remove-Item Env:DBPILOT_INSPECTION_POSTGRES_DSN -ErrorAction SilentlyContinue }
    if ($hadPlatformIntegration) { $env:DBPILOT_PLATFORM_POSTGRES_INTEGRATION = $previousPlatformIntegration } else { Remove-Item Env:DBPILOT_PLATFORM_POSTGRES_INTEGRATION -ErrorAction SilentlyContinue }
    if ($hadPlatformDSN) { $env:DBPILOT_PLATFORM_POSTGRES_DSN = $previousPlatformDSN } else { Remove-Item Env:DBPILOT_PLATFORM_POSTGRES_DSN -ErrorAction SilentlyContinue }
	if ($hadJobIntegration) { $env:DBPILOT_JOB_POSTGRES_INTEGRATION = $previousJobIntegration } else { Remove-Item Env:DBPILOT_JOB_POSTGRES_INTEGRATION -ErrorAction SilentlyContinue }
	if ($hadJobDSN) { $env:DBPILOT_JOB_POSTGRES_DSN = $previousJobDSN } else { Remove-Item Env:DBPILOT_JOB_POSTGRES_DSN -ErrorAction SilentlyContinue }
    $cleanupFailures = @()
    try {
        Remove-DBPilotOwnedContainer -DockerBinary $DockerBinary -ContainerID $containerID
        $remaining = @(& $DockerBinary ps -a --filter "label=dbpilot.run=$containerName" --format '{{.ID}}')
        if ($LASTEXITCODE -ne 0 -or ($remaining | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) { throw 'Inspection verifier left its container behind.' }
        foreach ($volume in $anonymousVolumes) {
            $remainingVolume = @(& $DockerBinary volume ls --filter "name=^$volume$" --format '{{.Name}}')
            if ($LASTEXITCODE -ne 0 -or $remainingVolume -contains $volume) { throw "Inspection verifier left anonymous volume '$volume' behind." }
        }
    }
    catch { $cleanupFailures += $_ }
    if ($cleanupFailures.Count -gt 0) {
        if ($null -eq $primaryFailure) { throw $cleanupFailures[0] }
        foreach ($failure in $cleanupFailures) { Write-Error $failure -ErrorAction Continue }
    }
}
