$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$bufConfig = Join-Path $repoRoot 'buf.yaml'
$agentContractPath = 'contracts/protobuf/dbpilot/agent/v1/command.proto'

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

  & buf breaking $repoRoot --path $agentContractPath --against '.git#branch=origin/main'
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
}
finally {
  Pop-Location
}
