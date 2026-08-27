$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path

Push-Location $repoRoot
try {
  & (Join-Path $PSScriptRoot 'generate.ps1')

  $changed = git status --short -- contracts backend/gen frontend/generated
  if ($changed) {
    $changed | Write-Error
    exit 1
  }
}
finally {
  Pop-Location
}
