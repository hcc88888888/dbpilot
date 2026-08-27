$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path

Push-Location $repoRoot
try {
  & docker run --rm -v "${repoRoot}:/workspace" -w /workspace bufbuild/buf:1.57.2 generate
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
}
finally {
  Pop-Location
}
