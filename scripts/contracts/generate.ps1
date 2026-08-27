$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$componentScripts = @(
  (Join-Path $PSScriptRoot 'generate-rest.ps1'),
  (Join-Path $PSScriptRoot 'generate-agent.ps1')
)

Push-Location $repoRoot
try {
  foreach ($componentScript in $componentScripts) {
    if (Test-Path $componentScript) {
      $LASTEXITCODE = 0
      & $componentScript
      if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
      }
    }
  }
}
finally {
  Pop-Location
}
