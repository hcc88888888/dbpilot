[CmdletBinding()]
param(
    [string]$GoBinary,
    [string]$DockerBinary
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$backendRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$repoRoot = (Resolve-Path (Join-Path $backendRoot '..')).Path
$null = . (Join-Path $PSScriptRoot 'container-safety.ps1')
$postgresContainer = New-DBPilotOwnedContainerName -Prefix 'dbpilot-contract-postgres'
$postgresContainerID = $null
$temporaryRoot = Join-Path $backendRoot ('.tmp-contract-foundation-' + [guid]::NewGuid().ToString('N'))
$primaryFailure = $null

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
if ([string]::IsNullOrWhiteSpace($DockerBinary) -or -not [System.IO.Path]::IsPathRooted($DockerBinary) -or -not (Test-Path -LiteralPath $DockerBinary -PathType Leaf)) {
    throw 'Docker CLI is required. Install/start Docker Desktop or pass -DockerBinary.'
}

if ([string]::IsNullOrWhiteSpace($GoBinary)) {
    $goCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($goCommand) {
        $GoBinary = $goCommand.Source
    } else {
        $workspaceRoot = Split-Path -Parent (Split-Path -Parent $repoRoot)
        $workspaceGo = Join-Path $workspaceRoot '.tooling\go\bin\go.exe'
        if (Test-Path -LiteralPath $workspaceGo -PathType Leaf) {
            $GoBinary = $workspaceGo
        }
    }
}
if ([string]::IsNullOrWhiteSpace($GoBinary) -or -not [System.IO.Path]::IsPathRooted($GoBinary) -or -not (Test-Path -LiteralPath $GoBinary -PathType Leaf)) {
    throw 'An absolute Go executable path is required. Pass -GoBinary when Go is not on PATH.'
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)] [string]$Command,
        [string[]]$Arguments = @()
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Remove-SafeTemporaryDirectory {
    if (-not (Test-Path -LiteralPath $temporaryRoot)) { return }
    $resolved = (Resolve-Path -LiteralPath $temporaryRoot).Path
	$separators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
	$parent = [System.IO.Path]::GetFullPath($backendRoot).TrimEnd($separators) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase) -or -not (Split-Path -Leaf $resolved).StartsWith('.tmp-contract-foundation-', [StringComparison]::Ordinal)) {
        throw "Refusing unsafe foundation verifier cleanup: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

$hadE2E = Test-Path Env:DBPILOT_CONTRACT_E2E
$previousE2E = $env:DBPILOT_CONTRACT_E2E
$hadDSN = Test-Path Env:DBPILOT_CONTRACT_POSTGRES_DSN
$previousDSN = $env:DBPILOT_CONTRACT_POSTGRES_DSN
$previousPath = $env:PATH
$env:PATH = (Split-Path -Parent $GoBinary) + [System.IO.Path]::PathSeparator + $env:PATH

try {
    Push-Location $repoRoot
    try {
        Invoke-Checked 'npm' @('ci')
        Invoke-Checked 'npm' @('run', 'contracts:lint')
        Invoke-Checked 'npm' @('run', 'contracts:breaking')
        Invoke-Checked 'npm' @('run', 'contracts:verify')
        Invoke-Checked 'node' @('--test')
        Invoke-Checked 'npm' @('run', 'contracts:mock:test')
    }
    finally {
        Pop-Location
    }

    Push-Location $backendRoot
    try {
		Invoke-Checked $GoBinary @('test', './...', '-count=1')
		Invoke-Checked $GoBinary @('vet', './...')
    }
    finally {
        Pop-Location
    }

	$postgresContainerID = New-DBPilotOwnedContainer -DockerBinary $DockerBinary -Name $postgresContainer -CreateArguments @(
        '--publish', '127.0.0.1:55432:5432',
        '--env', 'POSTGRES_DB=dbpilot_contract',
        '--env', 'POSTGRES_USER=dbpilot_contract',
        '--env', 'POSTGRES_PASSWORD=dbpilot_contract',
        'postgres:16-alpine'
    )
	Invoke-Checked $DockerBinary @('start', $postgresContainerID)
    $ready = $false
    for ($attempt = 1; $attempt -le 60; $attempt++) {
		& $DockerBinary exec $postgresContainerID pg_isready -U dbpilot_contract -d dbpilot_contract *> $null
        if ($LASTEXITCODE -eq 0) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'Contract PostgreSQL did not become ready.' }

    $env:DBPILOT_CONTRACT_E2E = '1'
    $env:DBPILOT_CONTRACT_POSTGRES_DSN = 'postgres://dbpilot_contract:dbpilot_contract@127.0.0.1:55432/dbpilot_contract?sslmode=disable'
    Push-Location $backendRoot
    try {
		Invoke-Checked $GoBinary @('test', './test/e2e', '-run', 'Test(JobCommandLifecycle|TwoPhaseCommandLifecycle)', '-v', '-count=1')
    }
    finally {
        Pop-Location
    }

    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    & (Join-Path $PSScriptRoot 'build-linux.ps1') -OutputDirectory $temporaryRoot -Version '0.1.0-contract-foundation' -GoBinary $GoBinary
    if ($LASTEXITCODE -ne 0) { throw 'Linux foundation build failed.' }
    foreach ($name in @(
        'dbpilot-controlplane-linux-amd64', 'dbpilot-controlplane-linux-arm64',
        'dbpilot-agent-linux-amd64', 'dbpilot-agent-linux-arm64'
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $temporaryRoot $name) -PathType Leaf)) {
            throw "Linux foundation build is missing $name"
        }
    }

    Write-Host 'DBPilot contract foundation verification passed.'
}
catch {
    $primaryFailure = $_
    throw
}
finally {
	$env:PATH = $previousPath
    if ($hadE2E) { $env:DBPILOT_CONTRACT_E2E = $previousE2E } else { Remove-Item Env:DBPILOT_CONTRACT_E2E -ErrorAction SilentlyContinue }
    if ($hadDSN) { $env:DBPILOT_CONTRACT_POSTGRES_DSN = $previousDSN } else { Remove-Item Env:DBPILOT_CONTRACT_POSTGRES_DSN -ErrorAction SilentlyContinue }

	$cleanupFailures = @()
	try {
		Remove-DBPilotOwnedContainer -DockerBinary $DockerBinary -ContainerID $postgresContainerID
		if (-not [string]::IsNullOrWhiteSpace($postgresContainerID)) {
			$remaining = @(& $DockerBinary ps -a --no-trunc --filter "id=$postgresContainerID" --format '{{.ID}}')
			if ($LASTEXITCODE -ne 0) { throw 'Unable to verify foundation container cleanup.' }
			if ($remaining -contains $postgresContainerID) { throw "Foundation verifier left container '$postgresContainerID' behind." }
		}
	}
	catch {
		$cleanupFailures += $_
	}
	try {
		Remove-SafeTemporaryDirectory
		if (Test-Path -LiteralPath $temporaryRoot) {
			throw "Foundation verifier left temporary directory '$temporaryRoot' behind."
		}
	}
	catch {
		$cleanupFailures += $_
	}
	if ($cleanupFailures.Count -gt 0) {
		if ($null -eq $primaryFailure) { throw $cleanupFailures[0] }
		foreach ($cleanupFailure in $cleanupFailures) { Write-Error $cleanupFailure -ErrorAction Continue }
	}
}
