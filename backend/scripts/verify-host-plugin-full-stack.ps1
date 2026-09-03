[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$KylinImage,
    [ValidateSet('amd64')][string]$Architecture = 'amd64',
    [string]$GoBinary,
    [string]$DockerBinary,
    [ValidateRange(0, 120)][int]$OutageSeconds = 12,
    [string]$FailureArtifactRoot = [IO.Path]::GetTempPath(),
    [ValidateRange(1, 300)][int]$DockerCommandTimeoutSeconds = 30,
    [ValidateRange(1, 7200)][int]$MaterializeTimeoutSeconds = 1800,
    [ValidateRange(1, 7200)][int]$BuildTimeoutSeconds = 1800,
    [ValidateRange(1, 7200)][int]$AssetBuildTimeoutSeconds = 1800,
    [ValidateRange(1, 900)][int]$JobTimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 7) { $PSNativeCommandUseErrorActionPreference = $false }

$approvedImage = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1'
if ($KylinImage -cne $approvedImage) {
    throw "Host-plugin full-stack verification requires the approved image reference '$approvedImage'."
}
if ($OutageSeconds -eq 0 -and $env:DBPILOT_HOST_PLUGIN_TEST_MODE -cne '1') {
    throw 'A zero-second outage is allowed only by the fake-Docker contract tests.'
}
if (-not [IO.Path]::IsPathRooted($FailureArtifactRoot) -or -not (Test-Path -LiteralPath $FailureArtifactRoot -PathType Container)) {
    throw 'The failure artifact root must be an existing absolute directory.'
}

$backendRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$repoRoot = (Resolve-Path (Join-Path $backendRoot '..')).Path
$composeFile = Join-Path $backendRoot 'docker\host-plugin-full-stack\docker-compose.yml'
$null = . (Join-Path $PSScriptRoot 'container-safety.ps1')
$null = . (Join-Path $PSScriptRoot 'bounded-process.ps1')

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

$RunId = [guid]::NewGuid().ToString('N')
$projectName = "dbpilot-host-plugin-$RunId"
$runnerImageReference = "dbpilot-host-plugin-runner:$RunId"
$verifierLabel = 'host-plugin-full-stack'
$verifierOwnershipFilter = 'dbpilot.verifier=host-plugin-full-stack'
if ($verifierOwnershipFilter -cne "dbpilot.verifier=$verifierLabel") { throw 'Verifier ownership filter is inconsistent.' }
$temporaryRoot = Join-Path $backendRoot ".tmp-host-plugin-$RunId"
$ledgerPath = Join-Path $temporaryRoot 'resource-ledger.json'
$failureArtifactPath = $null
$frontendPort = $null
$containerIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$runnerContainerIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$networkIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$volumeNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$imageIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$ownedContainerIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$ownedNetworkIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$ownedVolumeNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$ownedImageIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$primaryFailure = $null
$cleanupFailures = [Collections.Generic.List[object]]::new()
$temporaryCreated = $false
$ownershipStarted = $false

$savedEnvironment = @{}
foreach ($name in @('DBPILOT_ACCEPTANCE_PROJECT', 'DBPILOT_HOST_PLUGIN_RUN_ID', 'DBPILOT_HOST_PLUGIN_RUNNER_IMAGE', 'DBPILOT_KYLIN_IMAGE')) {
    $savedEnvironment[$name] = if (Test-Path "Env:$name") { [pscustomobject]@{ Exists = $true; Value = [Environment]::GetEnvironmentVariable($name) } } else { [pscustomobject]@{ Exists = $false; Value = $null } }
}
$env:DBPILOT_ACCEPTANCE_PROJECT = $projectName
$env:DBPILOT_HOST_PLUGIN_RUN_ID = $RunId
$env:DBPILOT_HOST_PLUGIN_RUNNER_IMAGE = $runnerImageReference
$env:DBPILOT_KYLIN_IMAGE = $KylinImage

function Get-UTCInstant {
    return (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
}

function Invoke-DockerProcess {
    param(
        [string[]]$Arguments,
        [int]$TimeoutSeconds = $DockerCommandTimeoutSeconds,
        [string]$Failure = 'Docker operation failed.',
        [string]$TimeoutFailure = 'Docker operation timed out.'
    )
    return Invoke-BoundedProcess -Command $DockerBinary -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds -StartFailure $Failure -TimeoutFailure $TimeoutFailure
}

$boundedDockerInvoker = { param([string[]]$Arguments) Invoke-DockerProcess -Arguments $Arguments }

function Get-DockerFailureMessage {
    param([string]$Failure, [object]$Result)
    $detail = @($Result.Stdout, $Result.Stderr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $detail = $detail -join [Environment]::NewLine
    if ($detail.Length -gt 4096) { $detail = $detail.Substring($detail.Length - 4096) }
    $detail = Redact-Text $detail
    if ([string]::IsNullOrWhiteSpace($detail)) { return $Failure }
    return "$Failure $detail"
}

function Invoke-DockerChecked {
    param(
        [string[]]$Arguments,
        [int]$TimeoutSeconds = $DockerCommandTimeoutSeconds,
        [string]$Failure = 'Docker operation failed.',
        [string]$TimeoutFailure = 'Docker operation timed out.'
    )
    $result = Invoke-DockerProcess $Arguments $TimeoutSeconds $Failure $TimeoutFailure
    if ($result.ExitCode -ne 0) { throw (Get-DockerFailureMessage $Failure $result) }
}

function Invoke-DockerCapture {
    param(
        [string[]]$Arguments,
        [string]$Failure = 'Docker operation failed.',
        [int]$TimeoutSeconds = $DockerCommandTimeoutSeconds,
        [string]$TimeoutFailure = 'Docker operation timed out.'
    )
    $result = Invoke-DockerProcess $Arguments $TimeoutSeconds $Failure $TimeoutFailure
    if ($result.ExitCode -ne 0) { throw (Get-DockerFailureMessage $Failure $result) }
    return $result.Stdout
}

function ConvertTo-OutputLines {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    return @($Text -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Get-ComposeArguments {
    param([string[]]$Arguments)
    return @('compose', '-f', $composeFile, '--project-name', $projectName) + $Arguments
}

function Invoke-ComposeChecked {
    param(
        [string[]]$Arguments,
        [int]$TimeoutSeconds = $DockerCommandTimeoutSeconds,
        [string]$Failure = 'Docker Compose operation failed.',
        [string]$TimeoutFailure = 'Docker Compose operation timed out.'
    )
    Invoke-DockerChecked (Get-ComposeArguments $Arguments) $TimeoutSeconds $Failure $TimeoutFailure
}

function Invoke-PublicImageMaterialization {
    foreach ($image in @('golang:1.27.0-bookworm', 'postgres:16-alpine', 'nginx:1.29.1-alpine', 'mysql:8.4')) {
        $identity = Invoke-DockerCapture @('image', 'inspect', '--format', '{{.Id}}', $image) "Required local image '$image' is unavailable."
        if ($identity -notmatch '^sha256:[a-zA-Z0-9]+$') { throw "Required local image '$image' has an invalid identity." }
    }
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
        image_ids = @($imageIDs | Sort-Object)
        owned_container_ids = @($ownedContainerIDs | Sort-Object)
        owned_network_ids = @($ownedNetworkIDs | Sort-Object)
        owned_volume_ids = @($ownedVolumeNames | Sort-Object)
        owned_image_ids = @($ownedImageIDs | Sort-Object)
    }
    [IO.File]::WriteAllText($ledgerPath, (($ledger | ConvertTo-Json -Depth 4) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
}

function Register-OwnedVolume {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $ownedVolumeNames.Contains($Name)) { return }
    if ($volumeNames.Add($Name)) { Write-ResourceLedger }
    $null = Get-DBPilotOwnedVolumeRecord -DockerBinary $DockerBinary -VolumeName $Name -Verifier $verifierLabel -RunLabel $RunId -InvokeDocker $boundedDockerInvoker
    $null = $ownedVolumeNames.Add($Name)
}

function Register-OwnedResources {
	param([ValidateRange(0, 30)][int]$RunnerImageRetrySeconds = 0)
	$containers = ConvertTo-OutputLines (Invoke-DockerCapture @('ps', '-a', '--no-trunc', '--filter', "label=dbpilot.verifier=$verifierLabel", '--filter', "label=dbpilot.run=$RunId", '--format', '{{.ID}}') 'Unable to discover owned Compose containers.')
    foreach ($id in $containers | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
        if ($containerIDs.Add($id)) { Write-ResourceLedger }
        if ($ownedContainerIDs.Contains($id)) { continue }
        $record = Get-DBPilotOwnedContainerRecord -DockerBinary $DockerBinary -ContainerID $id -Verifier $verifierLabel -RunLabel $RunId -InvokeDocker $boundedDockerInvoker
        $null = $ownedContainerIDs.Add($record.ID)
        foreach ($name in $record.VolumeNames) { Register-OwnedVolume $name }
    }
    $networks = ConvertTo-OutputLines (Invoke-DockerCapture @('network', 'ls', '--no-trunc', '--filter', "label=dbpilot.verifier=$verifierLabel", '--filter', "label=dbpilot.run=$RunId", '--format', '{{.ID}}') 'Unable to discover owned Compose networks.')
    foreach ($id in $networks | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
        if ($networkIDs.Add($id)) { Write-ResourceLedger }
        if ($ownedNetworkIDs.Contains($id)) { continue }
        $record = Get-DBPilotOwnedNetworkRecord -DockerBinary $DockerBinary -NetworkID $id -Verifier $verifierLabel -RunLabel $RunId -InvokeDocker $boundedDockerInvoker
        $null = $ownedNetworkIDs.Add($record.ID)
    }
    $volumes = ConvertTo-OutputLines (Invoke-DockerCapture @('volume', 'ls', '--filter', "label=dbpilot.verifier=$verifierLabel", '--filter', "label=dbpilot.run=$RunId", '--format', '{{.Name}}') 'Unable to discover owned Compose volumes.')
    foreach ($name in $volumes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) { Register-OwnedVolume $name }
	Register-OwnedRunnerImages -RetrySeconds $RunnerImageRetrySeconds
    Write-ResourceLedger
}

function Register-OwnedRunnerImageID {
    param([string]$Candidate)
    $id = (Invoke-DockerCapture @('image', 'inspect', '--format', '{{.Id}}', $Candidate) 'Unable to canonicalize the acceptance-runner image ID.').Trim()
    if ($id -notmatch '^sha256:[0-9a-f]{64}$') { throw 'The acceptance-runner image ID is invalid.' }
    $labels = (Invoke-DockerCapture @('image', 'inspect', '--format', '{{ index .Config.Labels "dbpilot.verifier" }}|{{ index .Config.Labels "dbpilot.run" }}', $id) 'Unable to inspect acceptance-runner image ownership.').Trim()
    if ($labels -cne "$verifierLabel|$RunId") { throw 'The acceptance-runner image ownership labels do not match.' }
    $null = $imageIDs.Add($id)
    $null = $ownedImageIDs.Add($id)
    Write-ResourceLedger
}

function Register-OwnedRunnerImages {
	param([ValidateRange(0, 30)][int]$RetrySeconds = 0)
	$deadline = [DateTime]::UtcNow.AddSeconds($RetrySeconds)
	do {
		try {
			$candidates = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
			$reference = Invoke-DockerProcess @('image', 'inspect', '--format', '{{.Id}}', $runnerImageReference)
			if ($reference.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($reference.Stdout)) { $null = $candidates.Add($reference.Stdout.Trim()) }
			$labelMatches = @(ConvertTo-OutputLines (Invoke-DockerCapture @('image', 'ls', '--no-trunc', '--filter', "label=dbpilot.verifier=$verifierLabel", '--filter', "label=dbpilot.run=$RunId", '--format', '{{.ID}}') 'Unable to discover labelled acceptance-runner images.'))
			foreach ($candidate in $labelMatches) { $null = $candidates.Add($candidate) }
			foreach ($candidate in $candidates) { Register-OwnedRunnerImageID $candidate }
		} catch {
			if ([DateTime]::UtcNow -ge $deadline) { throw }
		}
		if ([DateTime]::UtcNow -ge $deadline) { return }
		Start-Sleep -Seconds 1
	} while ($true)
}

function Remove-OwnedRunnerImage {
    param([string]$ImageID)
    if (-not $ownedImageIDs.Contains($ImageID) -or $ImageID -notmatch '^sha256:[0-9a-f]{64}$') { throw 'Refusing unrecorded acceptance-runner image cleanup.' }
    $labels = (Invoke-DockerCapture @('image', 'inspect', '--format', '{{ index .Config.Labels "dbpilot.verifier" }}|{{ index .Config.Labels "dbpilot.run" }}', $ImageID) 'Unable to revalidate acceptance-runner image ownership.').Trim()
    if ($labels -cne "$verifierLabel|$RunId") { throw 'Refusing mismatched acceptance-runner image cleanup.' }
    Invoke-DockerChecked @('image', 'rm', $ImageID) -Failure 'Unable to remove the exact acceptance-runner image.'
}

function Assert-NoRunOwnershipCollision {
    $queries = @(
        @('ps', '-a', '--no-trunc', '--filter', "label=dbpilot.run=$RunId", '--format', '{{.ID}}'),
        @('ps', '-a', '--no-trunc', '--filter', "label=com.docker.compose.project=$projectName", '--format', '{{.ID}}'),
        @('network', 'ls', '--no-trunc', '--filter', "label=dbpilot.run=$RunId", '--format', '{{.ID}}'),
        @('network', 'ls', '--no-trunc', '--filter', "label=com.docker.compose.project=$projectName", '--format', '{{.ID}}'),
        @('volume', 'ls', '--filter', "label=dbpilot.run=$RunId", '--format', '{{.Name}}'),
        @('volume', 'ls', '--filter', "label=com.docker.compose.project=$projectName", '--format', '{{.Name}}'),
        @('image', 'ls', '--filter', "label=dbpilot.run=$RunId", '--format', '{{.ID}}')
    )
    foreach ($arguments in $queries) {
        $matches = ConvertTo-OutputLines (Invoke-DockerCapture $arguments 'Unable to audit host-plugin full-stack run ownership before creation.')
        if ($matches.Count -ne 0) { throw 'Host-plugin host-plugin full-stack run ownership collision detected before creation.' }
    }
    $tagMatches = ConvertTo-OutputLines (Invoke-DockerCapture @('image', 'ls', '--no-trunc', '--filter', "reference=$runnerImageReference", '--format', '{{.ID}}') 'Unable to audit the acceptance-runner image reference before build.')
    if ($tagMatches.Count -ne 0) { throw 'The acceptance-runner image reference already exists.' }
}

function Get-ServiceContainerID {
    param([string]$Service)
    $id = Invoke-DockerCapture (Get-ComposeArguments @('ps', '-aq', $Service)) "Unable to resolve the '$Service' container ID."
    if ($id -notmatch '^[a-zA-Z0-9_.-]+$' -or $id -match '[\r\n]') { throw "The '$Service' container ID is invalid." }
    $null = $containerIDs.Add($id)
    Write-ResourceLedger
    $null = Get-DBPilotOwnedContainerRecord -DockerBinary $DockerBinary -ContainerID $id -Verifier $verifierLabel -RunLabel $RunId -InvokeDocker $boundedDockerInvoker
    $null = $ownedContainerIDs.Add($id)
    Write-ResourceLedger
    return $id
}

function Wait-ContainerExit {
    param([string]$ContainerID, [string]$Service, [int]$TimeoutSeconds = $JobTimeoutSeconds)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $body = Invoke-DockerCapture @('inspect', '--format', '{{json .State}}', $ContainerID) 'Unable to inspect a Compose job.'
        try { $state = $body | ConvertFrom-Json } catch { throw 'Compose job state was invalid.' }
        if ($state.Status -ceq 'exited' -or $state.Status -ceq 'dead') { return [int]$state.ExitCode }
        if ($state.Status -notin @('created', 'running', 'restarting', 'paused')) { throw "The '$Service' job entered an invalid state." }
        if ([DateTime]::UtcNow -ge $deadline) { throw "$Service did not exit before the deadline." }
        Start-Sleep -Milliseconds 250
    } while ($true)
}

function Wait-Healthy {
    param([string]$ContainerID, [string]$Service, [int]$Attempts = 120)
    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        $status = Invoke-DockerCapture @('inspect', '--format', '{{.State.Health.Status}}', $ContainerID) "Unable to inspect the '$Service' health state."
        if ($status -ceq 'healthy') { return }
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
    $value = [regex]::Replace($value, '(?i)(signature=)[^&\s"''<>#;]+', '$1[REDACTED]')
    $value = [regex]::Replace($value, '(?i)(password|credential|token|secret)\s*[=:]\s*[^\s]+', '$1=[REDACTED]')
    return $value
}

function Save-BoundedContainerLog {
    param([string]$ContainerID, [string]$Path)
    $result = Invoke-DockerProcess @('logs', '--tail', '500', $ContainerID)
    if ($result.ExitCode -ne 0) { throw 'Unable to collect a bounded container log.' }
    $body = @($result.Stdout, $result.Stderr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $body = $body -join [Environment]::NewLine
    if ($body.Length -gt 1000000) { $body = $body.Substring($body.Length - 1000000) }
    [IO.File]::WriteAllText($Path, (Redact-Text $body), [Text.UTF8Encoding]::new($false))
}

function Get-AcceptanceFailureStage {
    param([string]$ContainerID)
    $stagePath = Join-Path $temporaryRoot "$ContainerID-stage.json"
    try {
        Invoke-DockerChecked @('cp', "${ContainerID}:/acceptance/state/host-plugin-phase.json", $stagePath) -Failure 'Unable to copy bounded acceptance failure state.'
        if (-not (Test-Path -LiteralPath $stagePath -PathType Leaf) -or (Get-Item -LiteralPath $stagePath).Length -gt 65536) { return 'unknown' }
        try { $state = [IO.File]::ReadAllText($stagePath) | ConvertFrom-Json } catch { return 'unknown' }
        if ($state.diagnostic_stage -is [string] -and $state.diagnostic_stage -match '^[a-z][a-z0-9-]{0,63}$') { return $state.diagnostic_stage }
        return 'unknown'
    } catch {
        return 'unknown'
    } finally {
        Remove-Item -LiteralPath $stagePath -Force -ErrorAction SilentlyContinue
    }
}

function Get-AssertionFailureStage {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'unknown' }
    $body = [IO.File]::ReadAllText($Path)
    $stateMatch = [regex]::Match($body, 'host plugin phase state invalid: (enrollment|version|assignment|assignment-pid|instances|template|high-cardinality|high-cardinality-job|restart-boundaries)')
    if ($stateMatch.Success) { return ('state-' + $stateMatch.Groups[1].Value) }
    $fixed = [ordered]@{
        'host plugin assertion arguments are invalid' = 'arguments'
        'host plugin database credential is unavailable' = 'database-credential'
        'host plugin phase state is unavailable or invalid' = 'state'
        'host plugin assertion connection failed' = 'database-connection'
        'Agent command journal diagnostic is unavailable' = 'journal-open'
        'Agent spool retains pending metric batches' = 'spool-pending'
    }
    foreach ($message in $fixed.Keys) {
        if ($body.Contains($message)) { return $fixed[$message] }
    }
    return 'assertion'
}

function Invoke-ComposeJob {
    param([string]$Service, [string[]]$Command = @(), [hashtable]$Environment = @{}, [switch]$ExpectedFailure)
    $arguments = @('run', '-d', '--no-deps')
    foreach ($name in $Environment.Keys | Sort-Object) { $arguments += @('--env', "$name=$($Environment[$name])") }
    $arguments += $Service
    $arguments += $Command
    $id = Invoke-DockerCapture (Get-ComposeArguments $arguments) "Unable to create the '$Service' phase container."
    if ($id -notmatch '^[a-zA-Z0-9_.-]+$' -or $id -match '[\r\n]') { throw "The '$Service' phase container ID is invalid." }
    $null = $containerIDs.Add($id)
    Write-ResourceLedger
    $null = Get-DBPilotOwnedContainerRecord -DockerBinary $DockerBinary -ContainerID $id -Verifier $verifierLabel -RunLabel $RunId -InvokeDocker $boundedDockerInvoker
    $null = $ownedContainerIDs.Add($id)
    if ($Service -ceq 'acceptance-runner') { $null = $runnerContainerIDs.Add($id) }
    Register-OwnedResources
    Write-ResourceLedger
    $code = Wait-ContainerExit $id $Service
    $logPath = Join-Path $temporaryRoot "$id.log"
    Save-BoundedContainerLog $id $logPath
    if (-not $ExpectedFailure -and $code -ne 0) {
        $stage = if ($Service -ceq 'acceptance-runner') { Get-AcceptanceFailureStage $id } elseif ($Service -ceq 'assertions') { Get-AssertionFailureStage $logPath } else { 'unknown' }
        throw "The '$Service' phase failed with exit code $code at stage '$stage'."
    }
    if ($ExpectedFailure -and $code -eq 0) { throw "The '$Service' negative phase unexpectedly succeeded." }
    return [pscustomobject]@{ ContainerID = $id; ExitCode = $code; TimedOut = ($code -eq 124); LogPath = $logPath }
}

function Invoke-AssertionPhase {
    param([ValidateSet('host-plugin', 'trial-diagnostic')][string]$Phase)
    return Invoke-ComposeJob -Service 'assertions' -Environment @{ DBPILOT_ASSERTION_PHASE = $Phase }
}

function Invoke-AssertionExport {
    Invoke-ComposeChecked @('--profile', 'assertions', 'up', '--pull', 'never', '-d', '--no-deps', 'assertion-exporter')
    Register-OwnedResources
    $exporterID = Get-ServiceContainerID 'assertion-exporter'
    if ((Wait-ContainerExit $exporterID 'assertion-exporter') -ne 0) { throw 'The assertion-exporter service failed.' }
}

function Write-TrialFailureDiagnostic {
    param([Parameter(Mandatory = $true)]$Result)
    if ([string]::IsNullOrWhiteSpace($Result.LogPath) -or -not (Test-Path -LiteralPath $Result.LogPath -PathType Leaf)) { return }
    $body = [IO.File]::ReadAllText($Result.LogPath).Trim()
    if ($body.Length -eq 0 -or $body.Length -gt 2048) { return }
    try { $value = $body | ConvertFrom-Json } catch { return }
    $allowed = @('job_status', 'command_status', 'command_phase', 'journal_state', 'result_state', 'trial_code', 'reported')
    $actual = @($value.PSObject.Properties.Name)
    if ($actual.Count -ne $allowed.Count -or @($actual | Where-Object { $_ -cnotin $allowed }).Count -ne 0) { return }
    foreach ($name in @('job_status', 'command_status', 'command_phase', 'journal_state', 'result_state', 'trial_code')) {
        if ($value.$name -isnot [string] -or $value.$name -notmatch '^[a-z_]+$') { return }
    }
    if ($value.reported -isnot [bool]) { return }
    Write-Host ('Host-plugin bounded trial diagnostic: ' + ($value | ConvertTo-Json -Compress))
}

function Invoke-AcceptancePhase {
    param(
        [ValidateSet('enrollment', 'platform', 'template', 'stop', 'restart', 'rollback', 'capture-agent-restart', 'capture-agent-stopped', 'convergence-agent', 'capture-server-restart', 'capture-server-stopped', 'convergence-server', 'browser', 'failure-canary')][string]$Phase,
        [string]$RestartBoundaryUTC,
        [switch]$ExpectedFailure
    )
    $environment = @{ DBPILOT_ACCEPTANCE_PHASE = $Phase }
    if (-not [string]::IsNullOrWhiteSpace($RestartBoundaryUTC)) {
        if ($RestartBoundaryUTC -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$') { throw 'The restart boundary is invalid.' }
        $environment.RESTART_BOUNDARY_UTC = $RestartBoundaryUTC
    }
    return Invoke-ComposeJob -Service 'acceptance-runner' -Environment $environment -ExpectedFailure:$ExpectedFailure
}

function Write-SuccessSummary {
    param([Parameter(Mandatory = $true)]$Result)
    if ([string]::IsNullOrWhiteSpace($Result.LogPath) -or -not (Test-Path -LiteralPath $Result.LogPath -PathType Leaf)) {
        throw 'Host-plugin host-plugin full-stack success summary is unavailable.'
    }
    $body = [IO.File]::ReadAllText($Result.LogPath).Trim()
    if ($body.Length -eq 0 -or $body.Length -gt 8192) { throw 'Host-plugin host-plugin full-stack success summary is invalid.' }
    try { $value = $body | ConvertFrom-Json } catch { throw 'Host-plugin host-plugin full-stack success summary is invalid.' }
    $allowed = @(
        'run_id', 'job_id', 'online_command_id', 'offline_command_id', 'report_id',
        'target_count', 'finding_count', 'report_count', 'artifact_count', 'audit_count',
        'controlplane_stopped_at', 'controlplane_restarted_at'
    )
    $actual = @($value.PSObject.Properties.Name)
    if ($actual.Count -ne $allowed.Count -or @($actual | Where-Object { $_ -cnotin $allowed }).Count -ne 0) {
        throw 'Host-plugin host-plugin full-stack success summary contains an unapproved field.'
    }
    foreach ($name in @('run_id', 'job_id', 'online_command_id', 'offline_command_id', 'report_id')) {
        if ($value.$name -isnot [string] -or $value.$name -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
            throw 'Host-plugin host-plugin full-stack success summary contains an invalid identifier.'
        }
    }
    $expectedCounts = @{ target_count = 2; finding_count = 13; report_count = 1; artifact_count = 2 }
    foreach ($name in @('target_count', 'finding_count', 'report_count', 'artifact_count', 'audit_count')) {
        if ($value.$name -is [bool] -or $value.$name -isnot [ValueType]) { throw 'Host-plugin host-plugin full-stack success summary contains an invalid count.' }
        try { $count = [int64]$value.$name } catch { throw 'Host-plugin host-plugin full-stack success summary contains an invalid count.' }
        if (($expectedCounts.ContainsKey($name) -and $count -ne $expectedCounts[$name]) -or ($name -ceq 'audit_count' -and $count -lt 4)) {
            throw 'Host-plugin host-plugin full-stack success summary contains an invalid count.'
        }
    }
    $instants = @{}
    foreach ($name in @('controlplane_stopped_at', 'controlplane_restarted_at')) {
        $rawTimestamp = $value.$name
        if ($rawTimestamp -is [DateTimeOffset]) {
            $parsed = $rawTimestamp
        } elseif ($rawTimestamp -is [DateTime]) {
            $parsed = [DateTimeOffset]::new($rawTimestamp.ToUniversalTime())
        } elseif ($rawTimestamp -is [string] -and $rawTimestamp -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$') {
            $parsed = [DateTimeOffset]::MinValue
            if (-not [DateTimeOffset]::TryParse($rawTimestamp, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
                throw 'Host-plugin host-plugin full-stack success summary contains an invalid timestamp.'
            }
        } else {
            throw 'Host-plugin host-plugin full-stack success summary contains an invalid timestamp.'
        }
        $instants[$name] = $parsed
    }
    if ($instants.controlplane_restarted_at -le $instants.controlplane_stopped_at) {
        throw 'Host-plugin host-plugin full-stack success summary contains an invalid outage boundary.'
    }
    $safe = [ordered]@{}
    foreach ($name in $allowed) {
        $safe[$name] = if ($instants.ContainsKey($name)) {
            $instants[$name].UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
        } else {
            $value.$name
        }
    }
    Write-Host ('Host-plugin host-plugin full-stack success summary: ' + ($safe | ConvertTo-Json -Compress))
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
    param([string]$ArtifactCarrierID, [string]$Kind, [string]$Source)
    $name = "rogue-$Kind.log"
    Invoke-DockerChecked @('cp', $Source, "${ArtifactCarrierID}:/acceptance/artifacts/$name")
    return "/acceptance/artifacts/$name"
}

function Remove-SafeVerifierDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $prefix = [IO.Path]::GetFullPath($backendRoot).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or -not (Split-Path -Leaf $resolved).StartsWith('.tmp-host-plugin-', [StringComparison]::Ordinal)) {
        throw "Refusing unsafe host-plugin full-stack verifier directory cleanup: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Collect-FailureArtifacts {
    $destination = Join-Path $FailureArtifactRoot "dbpilot-host-plugin-failure-$RunId"
    if (Test-Path -LiteralPath $destination) { throw 'The failure artifact directory already exists.' }
    New-Item -ItemType Directory -Path $destination | Out-Null
    $diagnostic = [ordered]@{
        version = 1
        run_id = $RunId
        failure_code = 'host_plugin_acceptance_failed'
        recorded_container_count = $containerIDs.Count
        recorded_network_count = $networkIDs.Count
        recorded_volume_count = $volumeNames.Count
    }
    [IO.File]::WriteAllText((Join-Path $destination 'diagnostic.json'), ($diagnostic | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    return $destination
}

function Assert-FailureCanariesAbsent {
    param([string]$ArtifactPath)
    $canaries = @(
        'DBPILOT_CANARY_SQL_7f30e2',
        'DBPILOT_CANARY_PACKAGE_BYTES_7f30e2',
        'DBPILOT_CANARY_TRIAL_ROW_7f30e2',
        'DBPILOT_CANARY_RAW_INSPECT_7f30e2',
        'DBPILOT_CANARY_NON_PEM_PRIVATE_KEY_7f30e2'
    )
    foreach ($id in $ownedContainerIDs) {
        $result = Invoke-DockerProcess @('logs', $id)
        if ($result.ExitCode -ne 0) { throw 'An owned container log could not be read.' }
        if ($result.StdoutTruncated) { throw 'An owned container stdout log exceeded the audit bound.' }
        if ($result.StderrTruncated) { throw 'An owned container stderr log exceeded the audit bound.' }
        $body = @($result.Stdout, $result.Stderr) -join [Environment]::NewLine
        foreach ($canary in $canaries) {
            if ($body.Contains($canary)) { throw 'A prohibited failure canary entered a container log.' }
        }
    }
    $files = @(Get-ChildItem -LiteralPath $ArtifactPath -Recurse -File -ErrorAction Stop)
    if ($files.Count -ne 1 -or $files[0].Extension -cne '.json' -or $files[0].Length -gt 65536) {
        throw 'Failure artifacts contain a non-auditable file.'
    }
    $retained = [IO.File]::ReadAllText($files[0].FullName)
    foreach ($canary in $canaries) {
        if ($retained.Contains($canary)) { throw 'A prohibited failure canary entered a retained artifact.' }
    }
}

function Remove-SafeFailureArtifactDirectory {
    param([string]$Path)
    $expected = [IO.Path]::GetFullPath((Join-Path $FailureArtifactRoot "dbpilot-host-plugin-failure-$RunId"))
    if ([IO.Path]::GetFullPath($Path) -cne $expected -or -not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw 'Refusing unsafe failure artifact cleanup.'
    }
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Assert-ZeroResidualResources {
    $auditFailures = [Collections.Generic.List[string]]::new()
    try {
        $remainingContainers = ConvertTo-OutputLines (Invoke-DockerCapture @('ps', '-a', '--no-trunc', '--filter', "label=dbpilot.verifier=$verifierLabel", '--filter', "label=dbpilot.run=$RunId", '--format', '{{.ID}}') 'Unable to audit host-plugin full-stack containers by ownership label.')
        if ($remainingContainers.Count -ne 0) { $auditFailures.Add('Host-plugin host-plugin full-stack cleanup left an owned container behind.') }
    } catch { $auditFailures.Add('Unable to audit host-plugin full-stack containers by ownership label.') }
    try {
        $remainingNetworks = ConvertTo-OutputLines (Invoke-DockerCapture @('network', 'ls', '--no-trunc', '--filter', "label=dbpilot.verifier=$verifierLabel", '--filter', "label=dbpilot.run=$RunId", '--format', '{{.ID}}') 'Unable to audit host-plugin full-stack networks by ownership label.')
        if ($remainingNetworks.Count -ne 0) { $auditFailures.Add('Host-plugin host-plugin full-stack cleanup left an owned network behind.') }
    } catch { $auditFailures.Add('Unable to audit host-plugin full-stack networks by ownership label.') }
    try {
        $remainingVolumes = ConvertTo-OutputLines (Invoke-DockerCapture @('volume', 'ls', '--filter', "label=dbpilot.verifier=$verifierLabel", '--filter', "label=dbpilot.run=$RunId", '--format', '{{.Name}}') 'Unable to audit host-plugin full-stack volumes by ownership label.')
        if ($remainingVolumes.Count -ne 0) { $auditFailures.Add('Host-plugin host-plugin full-stack cleanup left an owned volume behind.') }
    } catch { $auditFailures.Add('Unable to audit host-plugin full-stack volumes by ownership label.') }
    try {
        $remainingImages = ConvertTo-OutputLines (Invoke-DockerCapture @('image', 'ls', '--filter', "label=dbpilot.verifier=$verifierLabel", '--filter', "label=dbpilot.run=$RunId", '--format', '{{.ID}}') 'Unable to audit host-plugin full-stack images by ownership label.')
        if ($remainingImages.Count -ne 0) { $auditFailures.Add('Host-plugin host-plugin full-stack cleanup left an owned image behind.') }
    } catch { $auditFailures.Add('Unable to audit host-plugin full-stack images by ownership label.') }
    foreach ($id in $containerIDs) { try { $result = Invoke-DockerProcess @('inspect', $id); if ($result.ExitCode -eq 0) { $auditFailures.Add("Recorded container '$id' remains after cleanup.") } } catch { $auditFailures.Add("Unable to audit recorded container '$id'.") } }
    foreach ($id in $networkIDs) { try { $result = Invoke-DockerProcess @('network', 'inspect', $id); if ($result.ExitCode -eq 0) { $auditFailures.Add("Recorded network '$id' remains after cleanup.") } } catch { $auditFailures.Add("Unable to audit recorded network '$id'.") } }
    foreach ($name in $volumeNames) { try { $result = Invoke-DockerProcess @('volume', 'inspect', $name); if ($result.ExitCode -eq 0) { $auditFailures.Add("Recorded volume '$name' remains after cleanup.") } } catch { $auditFailures.Add("Unable to audit recorded volume '$name'.") } }
    foreach ($id in $imageIDs) { try { $result = Invoke-DockerProcess @('image', 'inspect', $id); if ($result.ExitCode -eq 0) { $auditFailures.Add("Recorded image '$id' remains after cleanup.") } } catch { $auditFailures.Add("Unable to audit recorded image '$id'.") } }
    if ($auditFailures.Count -ne 0) { throw ($auditFailures -join ' ') }
}

try {
    $dockerVersion = Invoke-DockerCapture @('version', '--format', '{{.Server.Version}}') 'Docker Engine is unavailable.'
    if ([string]::IsNullOrWhiteSpace($dockerVersion)) { throw 'Docker Engine is unavailable.' }
    $composeVersion = Invoke-DockerCapture @('compose', 'version', '--short') 'Docker Compose v2 is unavailable.'
    if ([string]::IsNullOrWhiteSpace($composeVersion)) { throw 'Docker Compose v2 is unavailable.' }
    $dockerArchitecture = Invoke-DockerCapture @('info', '--format', '{{.Architecture}}') 'Docker architecture is unavailable.'
    if ($dockerArchitecture -notin @('amd64', 'x86_64')) { throw 'Host-plugin full-stack acceptance requires an amd64 Docker host/runtime.' }
    $goVersion = (& $GoBinary version 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $goVersion -notmatch '\bgo1\.27\.0\b') { throw 'Go 1.27.0 is required.' }
    $imageID = Invoke-DockerCapture @('image', 'inspect', '--format', '{{.Id}}', $KylinImage) 'The approved Kylin image is not available locally.'
    if ($imageID -notmatch '^sha256:[a-zA-Z0-9]+$') { throw 'The approved Kylin image identity is invalid.' }
    $worktreeRoot = (& git -C $repoRoot rev-parse --show-toplevel | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [IO.Path]::GetFullPath($worktreeRoot) -ne [IO.Path]::GetFullPath($repoRoot)) { throw 'The verifier must run from a DBPilot Git worktree.' }

    Assert-NoRunOwnershipCollision
    New-Item -ItemType Directory -Path $temporaryRoot -ErrorAction Stop | Out-Null
    $temporaryCreated = $true
    $ownershipStarted = $true
    Write-ResourceLedger

    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if ($null -eq $npm -or [string]::IsNullOrWhiteSpace($npm.Source)) { throw 'Node.js npm is required for the production React build.' }
    $savedAcceptanceBuild = [Environment]::GetEnvironmentVariable('VITE_DBPILOT_ACCEPTANCE')
    [Environment]::SetEnvironmentVariable('VITE_DBPILOT_ACCEPTANCE', '1')
    try {
        $frontendBuild = Invoke-BoundedProcess -Command $npm.Source -Arguments @('--prefix', (Join-Path $repoRoot 'frontend/app'), 'run', 'build') -TimeoutSeconds 600 -StartFailure 'The production React build could not start.' -TimeoutFailure 'The production React build timed out.'
    } finally {
        [Environment]::SetEnvironmentVariable('VITE_DBPILOT_ACCEPTANCE', $savedAcceptanceBuild)
    }
    if ($frontendBuild.ExitCode -ne 0) { throw 'The production React build failed.' }

    $binaryRoot = Join-Path $temporaryRoot 'bin'
    New-Item -ItemType Directory -Path $binaryRoot -ErrorAction Stop | Out-Null
    $savedBuildEnvironment = @{}
    foreach ($name in @('CGO_ENABLED', 'GOOS', 'GOARCH', 'GOAMD64')) { $savedBuildEnvironment[$name] = [Environment]::GetEnvironmentVariable($name) }
    [Environment]::SetEnvironmentVariable('CGO_ENABLED', '0')
    [Environment]::SetEnvironmentVariable('GOOS', 'linux')
    [Environment]::SetEnvironmentVariable('GOARCH', 'amd64')
    [Environment]::SetEnvironmentVariable('GOAMD64', 'v1')
    try {
        foreach ($target in @(
            [pscustomobject]@{ Name = 'dbpilot-controlplane'; Package = './cmd/controlplane' },
            [pscustomobject]@{ Name = 'dbpilot-agent'; Package = './cmd/agent' },
            [pscustomobject]@{ Name = 'dbpilot-docker-discovery'; Package = './cmd/dbpilot-docker-discovery' },
            [pscustomobject]@{ Name = 'dbpilot-plugin-mysql'; Package = './cmd/dbpilot-plugin-mysql' },
            [pscustomobject]@{ Name = 'dbpilot-fullstack-fixture'; Package = './test/fixtures/fullstack' }
        )) {
            $output = Join-Path $binaryRoot $target.Name
            $build = Invoke-BoundedProcess -Command $GoBinary -Arguments @('-C', $backendRoot, 'build', '-trimpath', '-o', $output, $target.Package) -TimeoutSeconds $BuildTimeoutSeconds -StartFailure "The $($target.Name) static build could not start." -TimeoutFailure "The $($target.Name) static build timed out."
            if ($build.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $output -PathType Leaf)) { throw "The $($target.Name) static build failed." }
        }
        [Environment]::SetEnvironmentVariable('GOARCH', 'arm64')
        [Environment]::SetEnvironmentVariable('GOAMD64', $null)
        $arm64Output = Join-Path $binaryRoot 'dbpilot-plugin-mysql-arm64'
        $arm64Build = Invoke-BoundedProcess -Command $GoBinary -Arguments @('-C', $backendRoot, 'build', '-trimpath', '-o', $arm64Output, './cmd/dbpilot-plugin-mysql') -TimeoutSeconds $BuildTimeoutSeconds -StartFailure 'The dbpilot-plugin-mysql arm64 static build could not start.' -TimeoutFailure 'The dbpilot-plugin-mysql arm64 static build timed out.'
        if ($arm64Build.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $arm64Output -PathType Leaf)) { throw 'The dbpilot-plugin-mysql arm64 static build failed.' }
    } finally {
        foreach ($name in $savedBuildEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedBuildEnvironment[$name]) }
    }

    Invoke-ComposeChecked @('--profile', '*', 'config', '--quiet')
    Invoke-PublicImageMaterialization
    Invoke-ComposeChecked -Arguments @('build', 'acceptance-runner') -TimeoutSeconds $BuildTimeoutSeconds -Failure 'The acceptance-runner image build failed.' -TimeoutFailure 'The acceptance-runner image build timed out.'
    Register-OwnedRunnerImages
    Register-OwnedResources

    Invoke-ComposeChecked @('up', '--pull', 'never', '-d', '--no-deps', 'asset-builder')
    Register-OwnedResources
    $builderID = Get-ServiceContainerID 'asset-builder'
    if ((Wait-ContainerExit $builderID 'asset-builder' $AssetBuildTimeoutSeconds) -ne 0) { throw 'The asset-builder service failed.' }

    Invoke-ComposeChecked @('up', '--pull', 'never', '-d', '--no-deps', 'bootstrap')
    Register-OwnedResources
    $bootstrapID = Get-ServiceContainerID 'bootstrap'
    if ((Wait-ContainerExit $bootstrapID 'bootstrap') -ne 0) { throw 'The bootstrap service failed.' }

    Invoke-ComposeChecked @('up', '--pull', 'never', '-d', '--no-deps', 'postgres', 'oidc')
    Register-OwnedResources
    $postgresID = Get-ServiceContainerID 'postgres'
    $oidcID = Get-ServiceContainerID 'oidc'
    Wait-Healthy $postgresID 'postgres'
    Wait-Healthy $oidcID 'oidc'

    Invoke-ComposeChecked @('up', '--pull', 'never', '-d', '--no-deps', 'controlplane')
    Register-OwnedResources
    $controlplaneID = Get-ServiceContainerID 'controlplane'
    Wait-Healthy $controlplaneID 'controlplane'

    Invoke-ComposeChecked @('up', '--pull', 'never', '-d', '--no-deps', 'frontend')
    Register-OwnedResources
    $frontendID = Get-ServiceContainerID 'frontend'
    Wait-Healthy $frontendID 'frontend'
    $binding = Invoke-DockerCapture @('port', $frontendID, '8443/tcp') 'Unable to discover the frontend ephemeral port.'
    if ($binding -notmatch '^127\.0\.0\.1:(\d+)$') { throw 'The frontend port is not an ephemeral loopback binding.' }
    $frontendPort = [int]$Matches[1]
    Write-ResourceLedger

    $null = Invoke-AcceptancePhase 'enrollment'

    Invoke-ComposeChecked @('up', '--pull', 'never', '-d', '--no-deps', 'docker-discovery', 'mysql-primary', 'mysql-secondary')
    Register-OwnedResources
    $helperID = Get-ServiceContainerID 'docker-discovery'
    $mysqlPrimaryID = Get-ServiceContainerID 'mysql-primary'
    $mysqlSecondaryID = Get-ServiceContainerID 'mysql-secondary'
    Wait-Healthy $helperID 'docker-discovery'
    Wait-Healthy $mysqlPrimaryID 'mysql-primary'
    Wait-Healthy $mysqlSecondaryID 'mysql-secondary'

    Invoke-ComposeChecked @('up', '--pull', 'never', '-d', '--no-deps', 'agent')
    Register-OwnedResources
    $agentID = Get-ServiceContainerID 'agent'
    Invoke-ComposeChecked @('up', '--pull', 'never', '-d', '--no-deps', 'proc-helper')
    Register-OwnedResources
    $procHelperID = Get-ServiceContainerID 'proc-helper'
    Wait-Healthy $procHelperID 'proc-helper'

    $null = Invoke-AcceptancePhase 'platform'
    Invoke-ComposeChecked @('--profile', 'plugin-probe', 'up', '--pull', 'never', '-d', '--no-deps', 'mysql-plugin')
    Register-OwnedResources
    $null = Invoke-AcceptancePhase 'template'
    $null = Invoke-AcceptancePhase 'stop'
    $null = Invoke-AcceptancePhase 'restart'
    $null = Invoke-AcceptancePhase 'rollback'

    $null = Invoke-AcceptancePhase 'capture-agent-restart'
    Invoke-DockerChecked @('stop', '--time', '20', $procHelperID)
    Invoke-DockerChecked @('stop', '--time', '20', $agentID)
    $agentStoppedAt = Get-UTCInstant
    Invoke-DockerChecked @('start', $agentID)
    Invoke-DockerChecked @('start', $procHelperID)
    Wait-Healthy $procHelperID 'proc-helper'
    $null = Invoke-AcceptancePhase 'capture-agent-stopped' -RestartBoundaryUTC $agentStoppedAt
    $null = Invoke-AcceptancePhase 'convergence-agent'

    $null = Invoke-AcceptancePhase 'capture-server-restart'
    Invoke-DockerChecked @('stop', '--time', '20', $controlplaneID)
    $serverStoppedAt = Get-UTCInstant
    Invoke-DockerChecked @('start', $controlplaneID)
    Wait-Healthy $controlplaneID 'controlplane'
    $null = Invoke-AcceptancePhase 'capture-server-stopped' -RestartBoundaryUTC $serverStoppedAt
    $null = Invoke-AcceptancePhase 'convergence-server'
    $null = Invoke-AcceptancePhase 'browser'
    $null = Invoke-AcceptancePhase 'failure-canary' -ExpectedFailure
    $canaryArtifacts = Collect-FailureArtifacts
    Assert-FailureCanariesAbsent $canaryArtifacts
    Remove-SafeFailureArtifactDirectory $canaryArtifacts
    Invoke-DockerChecked @('stop', '--time', '20', $procHelperID)
    Invoke-DockerChecked @('stop', '--time', '20', $agentID)
    Invoke-AssertionExport
    $null = Invoke-AssertionPhase 'host-plugin'

    Write-Host "Host-plugin full-stack acceptance passed: frontend_port=$frontendPort."
}
catch {
    $primaryFailure = $_
	if ($primaryFailure.Exception.Message -match "stage 'job-status-running'" -and -not [string]::IsNullOrWhiteSpace($agentID) -and -not [string]::IsNullOrWhiteSpace($procHelperID)) {
		try {
			Invoke-DockerChecked @('stop', '--time', '20', $procHelperID)
			Invoke-DockerChecked @('stop', '--time', '20', $agentID)
			Invoke-AssertionExport
			Write-TrialFailureDiagnostic (Invoke-AssertionPhase 'trial-diagnostic')
		} catch { Write-Warning 'The bounded trial diagnostic could not be collected.' }
	}
}
finally {
    if ($ownershipStarted) {
		try { Register-OwnedResources -RunnerImageRetrySeconds 5 } catch { $cleanupFailures.Add($_) }
    }
    if ($null -ne $primaryFailure -and $ownershipStarted) {
        try {
            $failureArtifactPath = Collect-FailureArtifacts
            Assert-FailureCanariesAbsent $failureArtifactPath
            Write-Host "Host-plugin host-plugin full-stack failure artifacts: $failureArtifactPath"
        } catch { $cleanupFailures.Add($_) }
    }
    if ($ownershipStarted) {
        foreach ($id in @($ownedContainerIDs) | Sort-Object -Descending) {
            try { Remove-DBPilotRecordedContainer -DockerBinary $DockerBinary -ContainerID $id -Verifier $verifierLabel -RunLabel $RunId -InvokeDocker $boundedDockerInvoker } catch { $cleanupFailures.Add($_) }
        }
        foreach ($id in @($ownedImageIDs) | Sort-Object -Descending) {
            try { Remove-OwnedRunnerImage $id } catch { $cleanupFailures.Add($_) }
        }
        foreach ($id in @($ownedNetworkIDs) | Sort-Object -Descending) {
            try { Remove-DBPilotRecordedNetwork -DockerBinary $DockerBinary -NetworkID $id -Verifier $verifierLabel -RunLabel $RunId -InvokeDocker $boundedDockerInvoker } catch { $cleanupFailures.Add($_) }
        }
        foreach ($name in @($ownedVolumeNames) | Sort-Object -Descending) {
            try { Remove-DBPilotRecordedVolume -DockerBinary $DockerBinary -VolumeName $name -Verifier $verifierLabel -RunLabel $RunId -InvokeDocker $boundedDockerInvoker } catch { $cleanupFailures.Add($_) }
        }
        try { Assert-ZeroResidualResources } catch { $cleanupFailures.Add($_) }
    }
    if ($temporaryCreated) {
        try {
            Remove-SafeVerifierDirectory $temporaryRoot
            if (Test-Path -LiteralPath $temporaryRoot) { throw 'Host-plugin host-plugin full-stack verifier temporary directory remains after cleanup.' }
        } catch { $cleanupFailures.Add($_) }
    }

    foreach ($name in $savedEnvironment.Keys) {
        if ($savedEnvironment[$name].Exists) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name].Value) }
        else { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
    }

    if ($cleanupFailures.Count -eq 0 -and $ownershipStarted) {
        Write-Host "Host-plugin host-plugin full-stack cleanup audit passed: containers=$($containerIDs.Count) networks=$($networkIDs.Count) volumes=$($volumeNames.Count) images=$($imageIDs.Count) temporary_directory=removed."
    } else {
        foreach ($failure in $cleanupFailures) { Write-Error (Redact-Text $failure.Exception.Message) -ErrorAction Continue }
    }
}

if ($null -ne $primaryFailure) { throw (Redact-Text $primaryFailure.Exception.Message) }
if ($cleanupFailures.Count -gt 0) { throw 'Host-plugin host-plugin full-stack cleanup audit failed.' }
