$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$bufConfig = Join-Path $repoRoot 'buf.yaml'
$agentContractPath = 'contracts/protobuf/dbpilot'
$baselineRoot = Join-Path ([IO.Path]::GetTempPath()) ('dbpilot-breaking-' + [guid]::NewGuid().ToString('N'))
$archivePath = Join-Path $baselineRoot 'baseline.tar'

Push-Location $repoRoot
try {
  $null = git rev-parse --verify --quiet refs/remotes/origin/main
  $remoteRefExitCode = $LASTEXITCODE
  if ($remoteRefExitCode -ne 0) {
    Write-Error 'Unable to resolve refs/remotes/origin/main for contract breaking checks.'
    exit $remoteRefExitCode
  }

  $baselineContract = @(git ls-tree -r --name-only refs/remotes/origin/main -- $agentContractPath)
  $baselineLookupExitCode = $LASTEXITCODE
  if ($baselineLookupExitCode -ne 0) {
    Write-Error "Unable to inspect $agentContractPath on refs/remotes/origin/main."
    exit $baselineLookupExitCode
  }

  if ($baselineContract.Count -eq 0) {
    exit 0
  }

  if (-not (Test-Path $bufConfig)) {
    Write-Error 'Missing root buf.yaml required for contract breaking checks.'
    exit 1
  }

  New-Item -ItemType Directory -Path $baselineRoot -Force | Out-Null
  & git archive --format=tar --output=$archivePath refs/remotes/origin/main -- buf.yaml contracts/protobuf/dbpilot
  if ($LASTEXITCODE -ne 0) {
    Write-Error 'Unable to materialize the origin/main contract baseline.'
    exit $LASTEXITCODE
  }
  & tar -xf $archivePath -C $baselineRoot
  if ($LASTEXITCODE -ne 0) {
    Write-Error 'Unable to extract the origin/main contract baseline.'
    exit $LASTEXITCODE
  }
  Remove-Item -LiteralPath $archivePath -Force

  & docker run --rm `
    -v "${repoRoot}:/workspace:ro" `
    -v "${baselineRoot}:/baseline:ro" `
    -w /workspace `
    bufbuild/buf:1.57.2 breaking /workspace --against /baseline
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
}
finally {
  Pop-Location
  if (Test-Path -LiteralPath $baselineRoot) {
    $resolved = (Resolve-Path -LiteralPath $baselineRoot).Path
    $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or -not (Split-Path -Leaf $resolved).StartsWith('dbpilot-breaking-', [StringComparison]::Ordinal)) {
      throw "Refusing unsafe breaking-check cleanup: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
  }
}
