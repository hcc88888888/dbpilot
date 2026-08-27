$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$openApiDocument = Join-Path $repoRoot 'contracts/openapi.yaml'
$bufConfig = Join-Path $repoRoot 'buf.yaml'

Push-Location $repoRoot
try {
  if (Test-Path $openApiDocument) {
    & npx --no-install redocly lint $openApiDocument
    if ($LASTEXITCODE -ne 0) {
      exit $LASTEXITCODE
    }
  }

  if (Test-Path $bufConfig) {
    & buf lint
    if ($LASTEXITCODE -ne 0) {
      exit $LASTEXITCODE
    }
  }
}
finally {
  Pop-Location
}
