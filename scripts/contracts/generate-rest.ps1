$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$generatedApiRoot = Join-Path $repoRoot 'frontend/generated/api'
$openApiDocument = Join-Path $repoRoot 'contracts/openapi/dbpilot-api.yaml'
$permissionGenerator = Join-Path $repoRoot 'scripts/contracts/generate-permissions.mjs'
$permissionOutput = Join-Path $repoRoot 'backend/gen/openapi/permissions.gen.go'
$bundlePath = Join-Path ([IO.Path]::GetTempPath()) ("dbpilot-openapi-{0}.json" -f [guid]::NewGuid())

function Get-SafeGeneratedDirectory {
  param(
    [Parameter(Mandatory)] [string] $RelativePath,
    [Parameter(Mandatory)] [string] $ResolvedRoot
  )

  $candidate = Join-Path $ResolvedRoot $RelativePath
  $resolvedCandidate = if (Test-Path -LiteralPath $candidate) {
    (Resolve-Path -LiteralPath $candidate).Path
  }
  else {
    [IO.Path]::GetFullPath($candidate)
  }

  $rootPrefix = $ResolvedRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not $resolvedCandidate.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove generated directory outside ${ResolvedRoot}: $resolvedCandidate"
  }

  return $resolvedCandidate
}

New-Item -ItemType Directory -Force $generatedApiRoot | Out-Null
$resolvedGeneratedApiRoot = (Resolve-Path -LiteralPath $generatedApiRoot).Path
$sourceDirectory = Get-SafeGeneratedDirectory -RelativePath 'src' -ResolvedRoot $resolvedGeneratedApiRoot
$distDirectory = Get-SafeGeneratedDirectory -RelativePath 'dist' -ResolvedRoot $resolvedGeneratedApiRoot

foreach ($generatedDirectory in @($sourceDirectory, $distDirectory)) {
  if (Test-Path -LiteralPath $generatedDirectory) {
    Remove-Item -LiteralPath $generatedDirectory -Recurse -Force
  }
}

Push-Location $repoRoot
try {
  & npx --no-install redocly bundle $openApiDocument --output $bundlePath
  if ($LASTEXITCODE -ne 0) {
    throw "Redocly bundle failed with exit code $LASTEXITCODE"
  }

  $bundledDocument = Get-Content -LiteralPath $bundlePath -Raw | ConvertFrom-Json -Depth 100
  $closedSchemaNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($schemaProperty in $bundledDocument.components.schemas.PSObject.Properties) {
    if ($schemaProperty.Value.additionalProperties -eq $false) {
      $null = $closedSchemaNames.Add($schemaProperty.Name)
    }
  }

  & node $permissionGenerator $bundlePath $permissionOutput
  if ($LASTEXITCODE -ne 0) {
    throw "Permission generation failed with exit code $LASTEXITCODE"
  }

  Push-Location (Join-Path $repoRoot 'backend')
  try {
    & go tool oapi-codegen -config api/openapi/oapi-codegen.yaml $bundlePath
    if ($LASTEXITCODE -ne 0) {
      throw "oapi-codegen failed with exit code $LASTEXITCODE"
    }

    & gofmt -w gen/openapi/dbpilot.gen.go gen/openapi/permissions.gen.go
    if ($LASTEXITCODE -ne 0) {
      throw "gofmt failed with exit code $LASTEXITCODE"
    }
  }
  finally {
    Pop-Location
  }

  & docker run --rm -v "${repoRoot}:/workspace" -v "${bundlePath}:/tmp/dbpilot-api.json:ro" -w /workspace openapitools/openapi-generator-cli:v7.15.0 generate `
    -i /tmp/dbpilot-api.json `
    -g typescript-fetch `
    -o /workspace/frontend/generated/api/src `
    -c /workspace/frontend/generated/api/openapi-generator-config.json
  if ($LASTEXITCODE -ne 0) {
    throw "OpenAPI Generator failed with exit code $LASTEXITCODE"
  }

  $apiIndex = Join-Path $sourceDirectory 'apis/index.ts'
  if (-not (Test-Path -LiteralPath $apiIndex)) {
    throw "OpenAPI Generator did not produce the expected API index: $apiIndex"
  }
  [IO.File]::AppendAllText(
    $apiIndex,
    "export { DefaultApi as PlatformApi } from './DefaultApi.js';`n",
    [Text.UTF8Encoding]::new($false)
  )

  foreach ($typescriptFile in Get-ChildItem -LiteralPath $sourceDirectory -Recurse -Filter '*.ts' -File) {
    $source = [IO.File]::ReadAllText($typescriptFile.FullName)

    $openEnumMatches = [Text.RegularExpressions.Regex]::Matches(
      $source,
      "export const (?<name>[A-Za-z0-9_]+) = \{[\s\S]*?UnknownDefaultOpenApi: '11184809'[\s\S]*?\} as const;"
    )
    foreach ($openEnumMatch in $openEnumMatches) {
      $enumName = $openEnumMatch.Groups['name'].Value
      $escapedEnumName = [Text.RegularExpressions.Regex]::Escape($enumName)
      $fromJSONPattern = [Text.RegularExpressions.Regex]::new(
        "export function ${escapedEnumName}FromJSONTyped\(json: any, ignoreDiscriminator: boolean\): ${escapedEnumName} \{\r?\n    return json as ${escapedEnumName};\r?\n\}"
      )
      $replacement = @"
export function ${enumName}FromJSONTyped(json: any, ignoreDiscriminator: boolean): ${enumName} {
    if (instanceOf${enumName}(json)) {
        return json as ${enumName};
    }
    return ${enumName}.UnknownDefaultOpenApi;
}
"@.TrimEnd()
      $updated = $fromJSONPattern.Replace($source, $replacement, 1)
      if ($updated -eq $source) {
        throw "Open enum post-processing could not update ${enumName} in $($typescriptFile.FullName)"
      }
      $source = $updated
    }

    $modelName = [IO.Path]::GetFileNameWithoutExtension($typescriptFile.Name)
    if ($closedSchemaNames.Contains($modelName)) {
      $source = [Text.RegularExpressions.Regex]::Replace(
        $source,
        '^\s*\[key: string\]: any \| any;\r?\n',
        '',
        [Text.RegularExpressions.RegexOptions]::Multiline
      )
      $source = [Text.RegularExpressions.Regex]::Replace(
        $source,
        '^\s*\.\.\.(?:json|value),\r?\n',
        '',
        [Text.RegularExpressions.RegexOptions]::Multiline
      )
    }

    $source = [Text.RegularExpressions.Regex]::Replace(
      $source,
      '[ \t]+(?=\r?$)',
      '',
      [Text.RegularExpressions.RegexOptions]::Multiline
    )
    $source = $source.TrimEnd([char[]] @("`r", "`n")) + "`n"
    [IO.File]::WriteAllText($typescriptFile.FullName, $source, [Text.UTF8Encoding]::new($false))
  }

  & npx --no-install tsc -p frontend/generated/api/tsconfig.json
  if ($LASTEXITCODE -ne 0) {
    throw "TypeScript compilation failed with exit code $LASTEXITCODE"
  }
}
finally {
  if (Test-Path -LiteralPath $bundlePath) {
    Remove-Item -LiteralPath $bundlePath -Force
  }
  Pop-Location
}
