param(
  [switch] $Test
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$composeFile = Join-Path $repoRoot 'deploy/contracts/prism.compose.yaml'
$projectName = if ($Test) { 'dbpilot-contracts-' + $PID + '-' + [guid]::NewGuid().ToString('N') } else { 'dbpilot-contracts' }
$baseUrl = 'http://localhost:4010'
$readinessUrl = "$baseUrl/api/v1/tenants/demo/projects/demo/capabilities"
$prismTest = Join-Path $repoRoot 'tests/contracts/prism.test.mjs'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw 'Docker Desktop is required to start the contract mock.'
}
& docker info *> $null
if ($LASTEXITCODE -ne 0) {
  throw 'Docker Desktop is not running or is not ready.'
}

$cleanupRequired = $Test
try {
  & docker compose -p $projectName -f $composeFile up -d | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Unable to start the $projectName compose project."
  }

  for ($attempt = 1; $attempt -le 60; $attempt++) {
    try {
      $response = Invoke-WebRequest -UseBasicParsing -Uri $readinessUrl -Headers @{ Authorization = 'Bearer prism-readiness-token' } -TimeoutSec 2
      if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
        if (-not $Test) {
          Write-Output $baseUrl
          return
        }

        $hadIntegrationFlag = Test-Path Env:DBPILOT_PRISM_INTEGRATION
        $previousIntegrationFlag = $env:DBPILOT_PRISM_INTEGRATION
		$hadProjectFlag = Test-Path Env:DBPILOT_PRISM_COMPOSE_PROJECT
		$previousProjectFlag = $env:DBPILOT_PRISM_COMPOSE_PROJECT
        try {
          $env:DBPILOT_PRISM_INTEGRATION = '1'
		  $env:DBPILOT_PRISM_COMPOSE_PROJECT = $projectName
          & node --test $prismTest
          if ($LASTEXITCODE -ne 0) {
            throw 'Prism integration test failed.'
          }
        }
        finally {
          if ($hadIntegrationFlag) {
            $env:DBPILOT_PRISM_INTEGRATION = $previousIntegrationFlag
          }
          else {
            Remove-Item Env:DBPILOT_PRISM_INTEGRATION -ErrorAction SilentlyContinue
          }
		  if ($hadProjectFlag) {
			$env:DBPILOT_PRISM_COMPOSE_PROJECT = $previousProjectFlag
		  }
		  else {
			Remove-Item Env:DBPILOT_PRISM_COMPOSE_PROJECT -ErrorAction SilentlyContinue
		  }
        }
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
  $cleanupRequired = $true
  throw
}
finally {
  if ($cleanupRequired) {
    & docker compose -p $projectName -f $composeFile down --volumes --remove-orphans | Out-Null
  }
}
