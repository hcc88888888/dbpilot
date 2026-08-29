[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Image,
    [ValidateSet('amd64')][string]$Architecture = 'amd64',
    [string]$GoBinary,
    [string]$DockerBinary,
    [ValidatePattern('^[0-9a-f]{32}$')][string]$RunId,
    [ValidateRange(0, 120)][int]$OutageSeconds = 12,
    [string]$FailureArtifactRoot = [IO.Path]::GetTempPath()
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 7) { $PSNativeCommandUseErrorActionPreference = $false }

$approvedImage = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1'
if ($Image -cne $approvedImage) {
    throw "Full-stack verification requires the approved image reference '$approvedImage'."
}
if ($OutageSeconds -eq 0 -and $env:DBPILOT_FULL_STACK_TEST_MODE -cne '1') {
    throw 'A zero-second outage is allowed only by the fake-Docker contract tests.'
}
if (-not [IO.Path]::IsPathRooted($FailureArtifactRoot) -or -not (Test-Path -LiteralPath $FailureArtifactRoot -PathType Container)) {
    throw 'The failure artifact root must be an existing absolute directory.'
}

$backendRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$repoRoot = (Resolve-Path (Join-Path $backendRoot '..')).Path
$composeFile = Join-Path $backendRoot 'docker\full-stack\docker-compose.yml'
$null = . (Join-Path $PSScriptRoot 'container-safety.ps1')

function Resolve-RequiredExecutable {
    param([string]$Value, [string]$CommandName, [string[]]$Candidates, [string]$Failure)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        $command = Get-Command $CommandName -ErrorAction SilentlyContinue
        if ($command) { $Value = $command.Source }
    }
    if ([string]::IsNullOrWhiteSpace($Value)) {
        $Value = $Candidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
    }
    if ([string]::IsNullOrWhiteSpace($Value) -or -not [IO.Path]::IsPathRooted($Value) -or -not (Test-Path -LiteralPath $Value -PathType Leaf)) {
        throw $Failure
    }
    return (Resolve-Path -LiteralPath $Value).Path
}

$DockerBinary = Resolve-RequiredExecutable $DockerBinary 'docker' @(
    (Join-Path ${env:ProgramFiles} 'Docker\Docker\resources\bin\docker.exe'),
    (Join-Path ${env:LOCALAPPDATA} 'Programs\DockerDesktop\resources\bin\docker.exe')
) 'Docker CLI is required. Install/start Docker Desktop or pass -DockerBinary with an absolute executable path.'

$goCandidates = @()
$cursor = $repoRoot
while (-not [string]::IsNullOrWhiteSpace($cursor)) {
    $goCandidates += Join-Path $cursor '.tooling\go\bin\go.exe'
    $parent = Split-Path -Parent $cursor
    if ($parent -eq $cursor) { break }
    $cursor = $parent
}
$GoBinary = Resolve-RequiredExecutable $GoBinary 'go' $goCandidates 'Go 1.27.0 is required. Pass -GoBinary with an absolute executable path.'

if ([string]::IsNullOrWhiteSpace($RunId)) { $RunId = [guid]::NewGuid().ToString('N') }
$projectName = "dbpilot-full-stack-$RunId"
$verifierLabel = 'full-stack-compose'
$temporaryRoot = Join-Path $backendRoot ".tmp-full-stack-$RunId"
$ledgerPath = Join-Path $temporaryRoot 'resource-ledger.json'
$failureArtifactPath = $null
$frontendPort = $null
$containerIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$runnerContainerIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$networkIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$volumeNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$primaryFailure = $null
$cleanupFailures = [Collections.Generic.List[object]]::new()

$savedEnvironment = @{}
foreach ($name in @('DBPILOT_ACCEPTANCE_PROJECT', 'DBPILOT_ACCEPTANCE_RUN_ID')) {
    $savedEnvironment[$name] = if (Test-Path "Env:$name") { [pscustomobject]@{ Exists = $true; Value = [Environment]::GetEnvironmentVariable($name) } } else { [pscustomobject]@{ Exists = $false; Value = $null } }
}
$env:DBPILOT_ACCEPTANCE_PROJECT = $projectName
$env:DBPILOT_ACCEPTANCE_RUN_ID = $RunId

function Get-UTCInstant {
    return (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
}

function Invoke-DockerChecked {
    param([string[]]$Arguments)
    & $DockerBinary @Arguments *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Docker operation failed.' }
}

function Invoke-DockerCapture {
    param([string[]]$Arguments, [string]$Failure = 'Docker operation failed.')
    $output = (& $DockerBinary @Arguments 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw $Failure }
    return $output
}

function Get-ComposeArguments {
    param([string[]]$Arguments)
    return @('compose', '-f', $composeFile, '--project-name', $projectName) + $Arguments
}

function Invoke-ComposeChecked {
    param([string[]]$Arguments)
    Invoke-DockerChecked (Get-ComposeArguments $Arguments)
}

function Write-ResourceLedger {
    if (-not (Test-Path -LiteralPath $temporaryRoot -PathType Container)) { return }
    $ledger = [ordered]@{
        version = 1
        project_name = $projectName
        verifier = $verifierLabel
        run_label = $RunId
        temporary_directory = $temporaryRoot
        frontend_port = $frontendPort
        container_ids = @($containerIDs | Sort-Object)
        network_ids = @($networkIDs | Sort-Object)
        volume_ids = @($volumeNames | Sort-Object)
    }
    [IO.File]::WriteAllText($ledgerPath, (($ledger | ConvertTo-Json -Depth 4) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
}

function Register-OwnedVolume {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $volumeNames.Contains($Name)) { return }
    $null = Get-DBPilotOwnedVolumeRecord -DockerBinary $DockerBinary -VolumeName $Name -Verifier $verifierLabel -RunLabel $RunId
    $null = $volumeNames.Add($Name)
}

function Register-OwnedResources {
    $containers = @(& $DockerBinary ps -a --no-trunc --filter "label=dbpilot.verifier=$verifierLabel" --filter "label=dbpilot.run=$RunId" --format '{{.ID}}')
    if ($LASTEXITCODE -ne 0) { throw 'Unable to discover owned Compose containers.' }
    foreach ($id in $containers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
        $record = Get-DBPilotOwnedContainerRecord -DockerBinary $DockerBinary -ContainerID $id -Verifier $verifierLabel -RunLabel $RunId
        $null = $containerIDs.Add($record.ID)
        foreach ($name in $record.VolumeNames) { Register-OwnedVolume $name }
    }
    $networks = @(& $DockerBinary network ls --no-trunc --filter "label=dbpilot.verifier=$verifierLabel" --filter "label=dbpilot.run=$RunId" --format '{{.ID}}')
    if ($LASTEXITCODE -ne 0) { throw 'Unable to discover owned Compose networks.' }
    foreach ($id in $networks | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
        $record = Get-DBPilotOwnedNetworkRecord -DockerBinary $DockerBinary -NetworkID $id -Verifier $verifierLabel -RunLabel $RunId
        $null = $networkIDs.Add($record.ID)
    }
    $volumes = @(& $DockerBinary volume ls --filter "label=dbpilot.verifier=$verifierLabel" --filter "label=dbpilot.run=$RunId" --format '{{.Name}}')
    if ($LASTEXITCODE -ne 0) { throw 'Unable to discover owned Compose volumes.' }
    foreach ($name in $volumes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) { Register-OwnedVolume $name }
    Write-ResourceLedger
}

function Get-ServiceContainerID {
    param([string]$Service)
    $id = Invoke-DockerCapture (Get-ComposeArguments @('ps', '-aq', $Service)) "Unable to resolve the '$Service' container ID."
    if ($id -notmatch '^[a-zA-Z0-9_.-]+$' -or $id -match '[\r\n]') { throw "The '$Service' container ID is invalid." }
    $null = Get-DBPilotOwnedContainerRecord -DockerBinary $DockerBinary -ContainerID $id -Verifier $verifierLabel -RunLabel $RunId
    $null = $containerIDs.Add($id)
    Write-ResourceLedger
    return $id
}

function Wait-ContainerExit {
    param([string]$ContainerID)
    $text = Invoke-DockerCapture @('wait', $ContainerID) 'Unable to wait for a Compose job.'
    $code = 0
    if (-not [int]::TryParse($text, [ref]$code)) { throw 'Compose job returned an invalid exit status.' }
    return $code
}

function Wait-Healthy {
    param([string]$ContainerID, [string]$Service, [int]$Attempts = 120)
    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        $status = (& $DockerBinary inspect --format '{{.State.Health.Status}}' $ContainerID 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $status -ceq 'healthy') { return }
        if ($status -ceq 'unhealthy') { throw "The '$Service' service became unhealthy." }
        if ($attempt + 1 -lt $Attempts) { Start-Sleep -Seconds 1 }
    }
    throw "The '$Service' service did not become healthy before the deadline."
}

function Redact-Text {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $value = $Text
    $value = [regex]::Replace($value, '(?is)-----BEGIN [^-\r\n]+PRIVATE KEY-----.*?-----END [^-\r\n]+PRIVATE KEY-----', '[REDACTED PRIVATE KEY]')
    $value = [regex]::Replace($value, '(?i)Bearer\s+\S+', 'Bearer [REDACTED]')
    $value = [regex]::Replace($value, '(?i)eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED JWT]')
    $value = [regex]::Replace($value, '(?i)postgres(?:ql)?://[^\s]+', 'postgres://[REDACTED]')
    $value = [regex]::Replace($value, '(?i)(password|credential|token|secret)\s*[=:]\s*[^\s]+', '$1=[REDACTED]')
    return $value
}

function Save-BoundedContainerLog {
    param([string]$ContainerID, [string]$Path)
    $body = (& $DockerBinary logs --tail 500 $ContainerID 2>&1 | Out-String)
    if ($body.Length -gt 1000000) { $body = $body.Substring($body.Length - 1000000) }
    [IO.File]::WriteAllText($Path, (Redact-Text $body), [Text.UTF8Encoding]::new($false))
}

function Invoke-ComposeJob {
    param([string]$Service, [string[]]$Command = @(), [hashtable]$Environment = @{}, [switch]$ExpectedFailure)
    $arguments = @('run', '-d', '--no-deps')
    foreach ($name in $Environment.Keys | Sort-Object) { $arguments += @('--env', "$name=$($Environment[$name])") }
    $arguments += $Service
    $arguments += $Command
    $id = Invoke-DockerCapture (Get-ComposeArguments $arguments) "Unable to create the '$Service' phase container."
    if ($id -notmatch '^[a-zA-Z0-9_.-]+$' -or $id -match '[\r\n]') { throw "The '$Service' phase container ID is invalid." }
    $null = Get-DBPilotOwnedContainerRecord -DockerBinary $DockerBinary -ContainerID $id -Verifier $verifierLabel -RunLabel $RunId
    $null = $containerIDs.Add($id)
    if ($Service -ceq 'acceptance-runner') { $null = $runnerContainerIDs.Add($id) }
    Register-OwnedResources
    Write-ResourceLedger
    $code = Wait-ContainerExit $id
    $logPath = Join-Path $temporaryRoot "$id.log"
    Save-BoundedContainerLog $id $logPath
    if (-not $ExpectedFailure -and $code -ne 0) { throw "The '$Service' phase failed with exit code $code." }
    if ($ExpectedFailure -and $code -eq 0) { throw "The '$Service' negative phase unexpectedly succeeded." }
    return [pscustomobject]@{ ContainerID = $id; ExitCode = $code; TimedOut = ($code -eq 124); LogPath = $logPath }
}

function Invoke-AssertionPhase {
    param([ValidateSet('database', 'replay', 'journal')][string]$Phase)
    return Invoke-ComposeJob -Service 'assertions' -Environment @{ DBPILOT_ASSERTION_PHASE = $Phase }
}

function Wait-OutageBoundary {
    param([datetime]$StoppedAt)
    $requiredUntil = $StoppedAt.AddSeconds($OutageSeconds)
    $deadline = $requiredUntil.AddSeconds(15)
    while ((Get-Date).ToUniversalTime() -lt $requiredUntil) {
        if ((Get-Date).ToUniversalTime() -ge $deadline) { throw 'The bounded control-plane outage window timed out.' }
        Start-Sleep -Milliseconds 250
    }
}

function Copy-RogueEvidence {
    param([string]$ControlplaneID, [string]$Kind, [string]$Source)
    $name = "rogue-$Kind.log"
    Invoke-DockerChecked @('cp', $Source, "${ControlplaneID}:/acceptance/state/artifacts/$name")
    return "/acceptance/artifacts/$name"
}

function Remove-SafeVerifierDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $prefix = [IO.Path]::GetFullPath($backendRoot).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or -not (Split-Path -Leaf $resolved).StartsWith('.tmp-full-stack-', [StringComparison]::Ordinal)) {
        throw "Refusing unsafe full-stack verifier directory cleanup: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Collect-FailureArtifacts {
    $destination = Join-Path $FailureArtifactRoot "dbpilot-full-stack-failure-$RunId"
    if (Test-Path -LiteralPath $destination) { throw 'The failure artifact directory already exists.' }
    New-Item -ItemType Directory -Path $destination | Out-Null
    foreach ($id in $containerIDs) {
        try { Save-BoundedContainerLog $id (Join-Path $destination "$id.log") } catch { }
    }
    if (Test-Path -LiteralPath $ledgerPath -PathType Leaf) { Copy-Item -LiteralPath $ledgerPath -Destination (Join-Path $destination 'resource-ledger.json') }
    foreach ($id in $runnerContainerIDs) {
        $playwright = Join-Path $destination "playwright-$id"
        New-Item -ItemType Directory -Path $playwright | Out-Null
        & $DockerBinary cp "${id}:/acceptance/artifacts/playwright/." $playwright 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { Remove-Item -LiteralPath $playwright -Recurse -Force -ErrorAction SilentlyContinue }
    }
    foreach ($file in Get-ChildItem -LiteralPath $destination -Recurse -File -ErrorAction SilentlyContinue) {
        if ($file.Extension -notin @('.log', '.txt', '.html', '.json', '.png')) { Remove-Item -LiteralPath $file.FullName -Force; continue }
        if ($file.Extension -ne '.png') {
            $body = [IO.File]::ReadAllText($file.FullName)
            [IO.File]::WriteAllText($file.FullName, (Redact-Text $body), [Text.UTF8Encoding]::new($false))
        }
    }
    return $destination
}

function Assert-ZeroResidualResources {
    $remainingContainers = @(& $DockerBinary ps -a --no-trunc --filter "label=dbpilot.verifier=$verifierLabel" --filter "label=dbpilot.run=$RunId" --format '{{.ID}}')
    $containerAuditExit = $LASTEXITCODE
    $remainingContainers = @($remainingContainers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($containerAuditExit -ne 0 -or $remainingContainers.Count -ne 0) { throw 'Full-stack cleanup left an owned container behind.' }
    $remainingNetworks = @(& $DockerBinary network ls --no-trunc --filter "label=dbpilot.verifier=$verifierLabel" --filter "label=dbpilot.run=$RunId" --format '{{.ID}}')
    $networkAuditExit = $LASTEXITCODE
    $remainingNetworks = @($remainingNetworks | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($networkAuditExit -ne 0 -or $remainingNetworks.Count -ne 0) { throw 'Full-stack cleanup left an owned network behind.' }
    $remainingVolumes = @(& $DockerBinary volume ls --filter "label=dbpilot.verifier=$verifierLabel" --filter "label=dbpilot.run=$RunId" --format '{{.Name}}')
    $volumeAuditExit = $LASTEXITCODE
    $remainingVolumes = @($remainingVolumes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($volumeAuditExit -ne 0 -or $remainingVolumes.Count -ne 0) { throw 'Full-stack cleanup left an owned volume behind.' }
    foreach ($id in $containerIDs) { & $DockerBinary inspect $id *> $null; if ($LASTEXITCODE -eq 0) { throw "Recorded container '$id' remains after cleanup." } }
    foreach ($id in $networkIDs) { & $DockerBinary network inspect $id *> $null; if ($LASTEXITCODE -eq 0) { throw "Recorded network '$id' remains after cleanup." } }
    foreach ($name in $volumeNames) { & $DockerBinary volume inspect $name *> $null; if ($LASTEXITCODE -eq 0) { throw "Recorded volume '$name' remains after cleanup." } }
}

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    Write-ResourceLedger

    $dockerVersion = Invoke-DockerCapture @('version', '--format', '{{.Server.Version}}') 'Docker Engine is unavailable.'
    if ([string]::IsNullOrWhiteSpace($dockerVersion)) { throw 'Docker Engine is unavailable.' }
    $composeVersion = Invoke-DockerCapture @('compose', 'version', '--short') 'Docker Compose v2 is unavailable.'
    if ([string]::IsNullOrWhiteSpace($composeVersion)) { throw 'Docker Compose v2 is unavailable.' }
    $dockerArchitecture = Invoke-DockerCapture @('info', '--format', '{{.Architecture}}') 'Docker architecture is unavailable.'
    if ($dockerArchitecture -notin @('amd64', 'x86_64')) { throw 'Full-stack acceptance requires an amd64 Docker host/runtime.' }
    $goVersion = (& $GoBinary version 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $goVersion -notmatch '\bgo1\.27\.0\b') { throw 'Go 1.27.0 is required.' }
    $imageID = Invoke-DockerCapture @('image', 'inspect', '--format', '{{.Id}}', $Image) 'The approved Kylin image is not available locally.'
    if ($imageID -notmatch '^sha256:[a-zA-Z0-9]+$') { throw 'The approved Kylin image identity is invalid.' }
    $worktreeRoot = (& git -C $repoRoot rev-parse --show-toplevel | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [IO.Path]::GetFullPath($worktreeRoot) -ne [IO.Path]::GetFullPath($repoRoot)) { throw 'The verifier must run from a DBPilot Git worktree.' }

    Invoke-ComposeChecked @('--profile', '*', 'config', '--quiet')
    Invoke-ComposeChecked @('build', 'acceptance-runner')
    Register-OwnedResources

    Invoke-ComposeChecked @('up', '-d', '--no-deps', 'asset-builder')
    Register-OwnedResources
    $builderID = Get-ServiceContainerID 'asset-builder'
    if ((Wait-ContainerExit $builderID) -ne 0) { throw 'The asset-builder service failed.' }

    Invoke-ComposeChecked @('up', '-d', '--no-deps', 'bootstrap')
    Register-OwnedResources
    $bootstrapID = Get-ServiceContainerID 'bootstrap'
    if ((Wait-ContainerExit $bootstrapID) -ne 0) { throw 'The bootstrap service failed.' }

    Invoke-ComposeChecked @('up', '-d', '--no-deps', 'postgres', 'oidc')
    Register-OwnedResources
    $postgresID = Get-ServiceContainerID 'postgres'
    $oidcID = Get-ServiceContainerID 'oidc'
    Wait-Healthy $postgresID 'postgres'
    Wait-Healthy $oidcID 'oidc'

    Invoke-ComposeChecked @('up', '-d', '--no-deps', 'controlplane')
    Register-OwnedResources
    $controlplaneID = Get-ServiceContainerID 'controlplane'
    Wait-Healthy $controlplaneID 'controlplane'

    Invoke-ComposeChecked @('up', '-d', '--no-deps', 'agent')
    Register-OwnedResources
    $agentID = Get-ServiceContainerID 'agent'

    Invoke-ComposeChecked @('up', '-d', '--no-deps', 'frontend')
    Register-OwnedResources
    $frontendID = Get-ServiceContainerID 'frontend'
    Wait-Healthy $frontendID 'frontend'
    $binding = Invoke-DockerCapture @('port', $frontendID, '8443/tcp') 'Unable to discover the frontend ephemeral port.'
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'The frontend port is not an ephemeral loopback binding.' }
    $frontendPort = [int]$Matches[1]
    if ($frontendPort -lt 1 -or $frontendPort -gt 65535) { throw 'The frontend ephemeral port is invalid.' }
    Write-ResourceLedger
    Write-Host "Full-stack runtime ready: frontend_port=$frontendPort."

    $null = Invoke-ComposeJob -Service 'acceptance-runner' -Command @('normal')
    $null = Invoke-ComposeJob -Service 'acceptance-runner' -Command @('unauthorized')
    Write-Host 'OIDC acceptance passed'
    Write-Host 'Agent mTLS communication passed'
    Write-Host 'Host inspection browser acceptance passed'
    $null = Invoke-AssertionPhase 'database'

    Invoke-DockerChecked @('stop', '--time', '20', $controlplaneID)
    $stoppedAtValue = (Get-Date).ToUniversalTime()
    $stoppedAt = $stoppedAtValue.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
    Wait-OutageBoundary $stoppedAtValue
    Invoke-DockerChecked @('start', $controlplaneID)
    $restartedAt = Get-UTCInstant
    Wait-Healthy $controlplaneID 'controlplane'
    $null = Invoke-ComposeJob -Service 'acceptance-runner' -Command @('post-restart') -Environment @{
        CONTROLPLANE_STOPPED_AT = $stoppedAt
        CONTROLPLANE_RESTARTED_AT = $restartedAt
    }

    foreach ($rogue in @(
        [pscustomobject]@{ Service = 'rogue-untrusted'; Kind = 'untrusted' },
        [pscustomobject]@{ Service = 'rogue-mismatch'; Kind = 'mismatch' }
    )) {
        $result = Invoke-ComposeJob -Service $rogue.Service -ExpectedFailure
        $containerLog = Copy-RogueEvidence $controlplaneID $rogue.Kind $result.LogPath
        $null = Invoke-ComposeJob -Service 'acceptance-runner' -Command @('rogue') -Environment @{
            ROGUE_KIND = $rogue.Kind
            ROGUE_EXIT_CODE = [string]$result.ExitCode
            ROGUE_TIMED_OUT = ([string]$result.TimedOut).ToLowerInvariant()
            ROGUE_LOG_FILE = $containerLog
            ROGUE_OBSERVED_AT = Get-UTCInstant
        }
    }
    Invoke-DockerChecked @('stop', '--time', '20', $agentID)
    $null = Invoke-AssertionPhase 'replay'
    Write-Host 'Control-plane restart and spool recovery passed'
    $null = Invoke-AssertionPhase 'journal'
    $null = Invoke-AssertionPhase 'database'
    Write-Host 'Rogue Agent rejection passed'
    Write-Host 'Database and journal assertions passed'
}
catch {
    $primaryFailure = $_
}
finally {
    try { Register-OwnedResources } catch { $cleanupFailures.Add($_) }
    if ($null -ne $primaryFailure) {
        try {
            $failureArtifactPath = Collect-FailureArtifacts
            Write-Host "Full-stack failure artifacts: $failureArtifactPath"
        } catch { $cleanupFailures.Add($_) }
    }
    foreach ($id in @($containerIDs) | Sort-Object -Descending) {
        try { Remove-DBPilotRecordedContainer -DockerBinary $DockerBinary -ContainerID $id -Verifier $verifierLabel -RunLabel $RunId } catch { $cleanupFailures.Add($_) }
    }
    foreach ($id in @($networkIDs) | Sort-Object -Descending) {
        try { Remove-DBPilotRecordedNetwork -DockerBinary $DockerBinary -NetworkID $id -Verifier $verifierLabel -RunLabel $RunId } catch { $cleanupFailures.Add($_) }
    }
    foreach ($name in @($volumeNames) | Sort-Object -Descending) {
        try { Remove-DBPilotRecordedVolume -DockerBinary $DockerBinary -VolumeName $name -Verifier $verifierLabel -RunLabel $RunId } catch { $cleanupFailures.Add($_) }
    }
    try { Assert-ZeroResidualResources } catch { $cleanupFailures.Add($_) }
    try {
        Remove-SafeVerifierDirectory $temporaryRoot
        if (Test-Path -LiteralPath $temporaryRoot) { throw 'Full-stack verifier temporary directory remains after cleanup.' }
    } catch { $cleanupFailures.Add($_) }

    foreach ($name in $savedEnvironment.Keys) {
        if ($savedEnvironment[$name].Exists) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name].Value) }
        else { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
    }

    if ($cleanupFailures.Count -eq 0) {
        Write-Host "Full-stack cleanup audit passed: containers=$($containerIDs.Count) networks=$($networkIDs.Count) volumes=$($volumeNames.Count) temporary_directory=removed."
    } else {
        foreach ($failure in $cleanupFailures) { Write-Error (Redact-Text $failure.Exception.Message) -ErrorAction Continue }
    }
}

if ($null -ne $primaryFailure) { throw (Redact-Text $primaryFailure.Exception.Message) }
if ($cleanupFailures.Count -gt 0) { throw 'Full-stack cleanup audit failed.' }
