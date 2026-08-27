$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$agentContractDirectory = Join-Path $repoRoot 'contracts/agent'
$agentBufConfig = Join-Path $agentContractDirectory 'buf.yaml'

Push-Location $repoRoot
try {
  if (-not (Test-Path $agentBufConfig)) {
    exit 0
  }

  git cat-file -e 'origin/main:contracts/agent/buf.yaml' 2>$null
  if ($LASTEXITCODE -ne 0) {
    exit 0
  }

  & buf breaking $agentContractDirectory --against '.git#branch=origin/main,subdir=contracts/agent'
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
}
finally {
  Pop-Location
}
