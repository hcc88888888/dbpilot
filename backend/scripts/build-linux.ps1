[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [string]$GoBinary
)

$ErrorActionPreference = 'Stop'

if (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
    throw 'OutputDirectory must be an absolute path.'
}
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
$root = [System.IO.Path]::GetPathRoot($output)
if ([string]::IsNullOrWhiteSpace($output) -or $output -eq $root) {
    throw 'OutputDirectory must not be a filesystem root.'
}

if ([string]::IsNullOrWhiteSpace($GoBinary)) {
    $command = Get-Command go -ErrorAction Stop
    $GoBinary = $command.Source
}
if (-not [System.IO.Path]::IsPathRooted($GoBinary) -or -not (Test-Path -LiteralPath $GoBinary -PathType Leaf)) {
    throw 'GoBinary must be an absolute path to a Go executable.'
}
$go = [System.IO.Path]::GetFullPath($GoBinary)
$goVersion = (& $go version).Trim()
if ($goVersion -notmatch '^go version go1\.27\.0 ') {
    throw "Go 1.27.0 is required; found: $goVersion"
}

$scriptRoot = Split-Path -Parent $PSScriptRoot
Push-Location $scriptRoot
try {
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    $commit = (& git rev-parse --short HEAD).Trim()
    if ([string]::IsNullOrWhiteSpace($commit)) { $commit = 'unknown' }
    $ldflags = "-s -w -X main.version=$Version -X main.commit=$commit"

    $oldCGO = $env:CGO_ENABLED
    $oldOS = $env:GOOS
    $oldArch = $env:GOARCH
    $oldAMD64 = $env:GOAMD64
    try {
        $env:CGO_ENABLED = '0'
        $env:GOOS = 'linux'
        $env:GOARCH = 'amd64'
        $env:GOAMD64 = 'v1'
        $amd64 = Join-Path $output 'dbpilot-agent-linux-amd64'
        & $go build -trimpath -ldflags $ldflags -o $amd64 ./cmd/agent
        if ($LASTEXITCODE -ne 0) { throw 'amd64 build failed.' }
        "$((Get-FileHash -Algorithm SHA256 -LiteralPath $amd64).Hash.ToLowerInvariant())  $(Split-Path -Leaf $amd64)" | Set-Content -NoNewline -Encoding ascii "$amd64.sha256"

        $env:GOARCH = 'arm64'
        Remove-Item Env:GOAMD64 -ErrorAction SilentlyContinue
        $arm64 = Join-Path $output 'dbpilot-agent-linux-arm64'
        & $go build -trimpath -ldflags $ldflags -o $arm64 ./cmd/agent
        if ($LASTEXITCODE -ne 0) { throw 'arm64 build failed.' }
        "$((Get-FileHash -Algorithm SHA256 -LiteralPath $arm64).Hash.ToLowerInvariant())  $(Split-Path -Leaf $arm64)" | Set-Content -NoNewline -Encoding ascii "$arm64.sha256"
    }
    finally {
        $env:CGO_ENABLED = $oldCGO
        $env:GOOS = $oldOS
        $env:GOARCH = $oldArch
        $env:GOAMD64 = $oldAMD64
    }
}
finally {
    Pop-Location
}
