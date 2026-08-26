[CmdletBinding()]
param(
    [string]$DockerBinary,
    [int]$HealthTimeoutSeconds = 120,
    [int]$TestTimeoutSeconds = 75
)

$ErrorActionPreference = 'Stop'
# Docker Compose writes progress updates to stderr even for successful commands.
# Keep those updates from being converted into terminating PowerShell errors;
# Invoke-Docker below still turns every non-zero Docker exit status into a clear
# failure.
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

if ($HealthTimeoutSeconds -lt 1) { throw 'HealthTimeoutSeconds must be at least one second.' }
if ($TestTimeoutSeconds -lt 1) { throw 'TestTimeoutSeconds must be at least one second.' }

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
    throw 'Docker CLI is required. Install/start Docker Desktop or pass -DockerBinary with the absolute docker.exe path.'
}

function Invoke-Docker {
    param([string[]]$Arguments)
    & $DockerBinary @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Invoke-DockerCapture {
    param([string[]]$Arguments)
    $output = & $DockerBinary @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "docker $($Arguments -join ' ') failed with exit code $exitCode"
    }
    return ($output | Out-String).Trim()
}

function Get-ComposeContainer {
    param([string]$Service)
    $container = (& $DockerBinary compose --project-name $projectName --file $composeFile ps -aq $Service).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($container)) {
        throw "Docker Compose did not create the $Service service."
    }
    return $container
}

function Wait-ForHealthyService {
    param([string]$Service)
    $container = Get-ComposeContainer $Service
    $deadline = [DateTime]::UtcNow.AddSeconds($HealthTimeoutSeconds)
    do {
        $status = (& $DockerBinary inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' $container).Trim()
        if ($LASTEXITCODE -ne 0) { throw "Unable to inspect $Service container health." }
        if ($status -eq 'healthy') { return }
        if ($status -eq 'unhealthy' -or $status -eq 'exited' -or $status -eq 'dead') {
            Invoke-Docker @('compose', '--project-name', $projectName, '--file', $composeFile, 'logs', '--no-color', $Service)
            throw "$Service did not become healthy (status: $status)."
        }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    Invoke-Docker @('compose', '--project-name', $projectName, '--file', $composeFile, 'logs', '--no-color', $Service)
    throw "$Service did not become healthy within $HealthTimeoutSeconds seconds."
}

function Wait-ForCompletedService {
    param([string]$Service)
    $container = Get-ComposeContainer $Service
    $deadline = [DateTime]::UtcNow.AddSeconds($HealthTimeoutSeconds)
    do {
        $state = (& $DockerBinary inspect --format '{{.State.Status}}/{{.State.ExitCode}}' $container).Trim()
        if ($LASTEXITCODE -ne 0) { throw "Unable to inspect $Service container state." }
        if ($state -eq 'exited/0') { return }
        if ($state -match '^exited/') {
            Invoke-Docker @('compose', '--project-name', $projectName, '--file', $composeFile, 'logs', '--no-color', $Service)
            throw "$Service failed ($state)."
        }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    Invoke-Docker @('compose', '--project-name', $projectName, '--file', $composeFile, 'logs', '--no-color', $Service)
    throw "$Service did not complete within $HealthTimeoutSeconds seconds."
}

$backendRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $backendRoot 'docker\database-adapters\docker-compose.yml'
if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) { throw "Compose file not found: $composeFile" }
$composeFile = (Resolve-Path -LiteralPath $composeFile).Path
$projectName = "dbpilot-adapters-$PID"

try {
    Invoke-Docker @('version', '--format', '{{.Server.Version}}')
    Invoke-Docker @('compose', '--project-name', $projectName, '--file', $composeFile, 'up', '--detach', 'mysql', 'postgres', 'mysql-bootstrap', 'postgres-bootstrap')
    Wait-ForHealthyService 'mysql'
    Wait-ForHealthyService 'postgres'
    Wait-ForCompletedService 'mysql-bootstrap'
    Wait-ForCompletedService 'postgres-bootstrap'

    $mysqlVersion = Invoke-DockerCapture @('compose', '--project-name', $projectName, '--file', $composeFile, 'exec', '-T', '-e', 'MYSQL_PWD=dbpilot-integration-root', 'mysql', 'mysql', '-uroot', '-Nse', 'SELECT VERSION()')
    $postgresVersion = Invoke-DockerCapture @('compose', '--project-name', $projectName, '--file', $composeFile, 'exec', '-T', '-e', 'PGPASSWORD=dbpilot-integration-root', 'postgres', 'psql', '-U', 'postgres', '-d', 'dbpilot_integration', '-Atc', 'SHOW server_version')
    Write-Host "MySQL version: $mysqlVersion"
    Write-Host "PostgreSQL version: $postgresVersion"
    Invoke-Docker @('compose', '--project-name', $projectName, '--file', $composeFile, 'run', '--rm', '--no-deps', '--env', "DBPILOT_DB_TEST_TIMEOUT_SECONDS=$TestTimeoutSeconds", 'adapter-tests')
}
finally {
    if (-not [string]::IsNullOrWhiteSpace($DockerBinary) -and (Test-Path -LiteralPath $DockerBinary -PathType Leaf)) {
        $cleanupErrorPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & $DockerBinary compose --project-name $projectName --file $composeFile down --volumes --remove-orphans 2>$null | Out-Null
        $ErrorActionPreference = $cleanupErrorPreference
    }
}
