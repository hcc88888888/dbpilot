$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$openApiDocument = Join-Path $repoRoot 'contracts/openapi.yaml'
$bufConfig = Join-Path $repoRoot 'buf.yaml'

Push-Location $repoRoot
try {
  if (-not (Test-Path $openApiDocument)) {
    Write-Error "Missing required OpenAPI contract: $openApiDocument"
    exit 1
  }
  if (-not (Test-Path $bufConfig)) {
    Write-Error "Missing required Protobuf contract configuration: $bufConfig"
    exit 1
  }

  & npx --no-install redocly lint $openApiDocument
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }

  & docker run --rm -v "${repoRoot}:/workspace" -w /workspace bufbuild/buf:1.57.2 lint
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
}
finally {
  Pop-Location
}
