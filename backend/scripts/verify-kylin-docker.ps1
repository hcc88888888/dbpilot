[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Image,
    [Parameter(Mandatory = $true)]
    [string]$Binary,
    [ValidateSet('amd64', 'arm64')]
    [string]$Architecture = 'amd64',
    [string]$DockerBinary,
    [switch]$Pull
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($DockerBinary)) {
    $dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
    if ($dockerCommand) {
        $DockerBinary = $dockerCommand.Source
    } else {
        $dockerCandidates = @(
            (Join-Path ${env:ProgramFiles} 'Docker\Docker\resources\bin\docker.exe'),
            (Join-Path ${env:LOCALAPPDATA} 'Programs\DockerDesktop\resources\bin\docker.exe')
        )
        $DockerBinary = $dockerCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    }
}
if ([string]::IsNullOrWhiteSpace($DockerBinary) -or -not (Test-Path -LiteralPath $DockerBinary -PathType Leaf)) {
    throw 'Docker CLI is required. Install/start Docker Desktop or pass -DockerBinary with the absolute docker.exe path.'
}

function Invoke-Docker {
    param([string[]]$Arguments)
    & $DockerBinary @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

if (-not [System.IO.Path]::IsPathRooted($Binary) -or -not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw 'Binary must be an existing absolute path.'
}

if ($Pull) {
    Invoke-Docker @('pull', $Image)
}
$imageId = (& $DockerBinary image inspect --format '{{.Id}}' $Image 2>$null).Trim()
if ([string]::IsNullOrWhiteSpace($imageId)) {
    throw "Kylin image '$Image' is not available locally. Pull it from the approved enterprise registry or configure a Docker context with access."
}

$platform = if ($Architecture -eq 'amd64') { 'linux/amd64' } else { 'linux/arm64' }
$container = (& $DockerBinary create --platform $platform $Image /bin/sh -c 'sleep 300').Trim()
if ([string]::IsNullOrWhiteSpace($container)) { throw 'Unable to create Kylin validation container.' }
try {
    Invoke-Docker @('cp', $Binary, "${container}:/opt/dbpilot-agent")
    Invoke-Docker @('start', $container)
    $script = @'
set -eu
test -f /etc/os-release
. /etc/os-release
case "${ID:-}" in
  kylin|kylin-server|neokylin|kylinsec) ;;
  *) echo "unexpected OS ID: ${ID:-unknown}" >&2; exit 41 ;;
esac
chmod 0755 /opt/dbpilot-agent
arch="$(uname -m)"
case "${DBPILOT_EXPECTED_ARCH}" in
  amd64) test "$arch" = x86_64 ;;
  arm64) test "$arch" = aarch64 ;;
esac
/opt/dbpilot-agent --version
printf 'Kylin validation passed: ID=%s VERSION=%s ARCH=%s\n' "${ID}" "${VERSION_ID:-unknown}" "$arch"
'@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script))
    Invoke-Docker @('exec', '-e', "DBPILOT_EXPECTED_ARCH=$Architecture", $container, '/bin/sh', '-c', "echo $encoded | base64 -d | /bin/sh")
}
finally {
    & $DockerBinary rm -f $container 2>$null | Out-Null
}
