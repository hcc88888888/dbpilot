$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$composeFile = Join-Path $repoRoot 'deploy/contracts/prism.compose.yaml'
$projectName = 'dbpilot-contracts'
$baseUrl = 'http://localhost:4010'
$readinessUrl = "$baseUrl/api/v1/tenants/demo/projects/demo/capabilities"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw 'Docker Desktop is required to start the contract mock.'
}
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
  throw 'curl.exe is required to check contract mock readiness.'
}

& docker info *> $null
if ($LASTEXITCODE -ne 0) {
  throw 'Docker Desktop is not running or is not ready.'
}

try {
  & docker compose -p $projectName -f $composeFile up -d | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to start the $projectName compose project."
  }

  for ($attempt = 1; $attempt -le 60; $attempt++) {
    try {
      & curl.exe --fail --silent --show-error --max-time 2 --header 'Authorization: Bearer prism-readiness-token' $readinessUrl 2>$null | Out-Null
      if ($LASTEXITCODE -eq 0) {
        Write-Output $baseUrl
        return
      }
    }
    catch {
      # Prism may still be loading the OpenAPI document.
    }
    Start-Sleep -Seconds 1
  }

  throw "Prism did not become ready at $readinessUrl."
}
catch {
  & docker compose -p $projectName -f $composeFile down --volumes --remove-orphans | Out-Null
  throw
}
