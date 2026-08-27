$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path

Push-Location $repoRoot
try {
  & (Join-Path $PSScriptRoot 'generate.ps1')

  & git diff --quiet -- contracts backend/gen frontend/generated
  $trackedDrift = $LASTEXITCODE
  $untracked = @(git ls-files --others --exclude-standard -- contracts backend/gen frontend/generated)
  if ($trackedDrift -ne 0 -or $untracked.Count -gt 0) {
    git diff --name-only -- contracts backend/gen frontend/generated | Write-Error
    $untracked | Write-Error
    exit 1
  }
}
finally {
  Pop-Location
}
