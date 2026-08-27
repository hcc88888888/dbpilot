[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Image,
    [ValidateSet('amd64', 'arm64')]
    [string]$Architecture = 'amd64',
    [string]$Version = '0.1.0-kylin-smoke',
    [string]$GoBinary,
    [string]$DockerBinary,
    [switch]$Pull
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$backendRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$repoRoot = (Resolve-Path (Join-Path $backendRoot '..')).Path
$null = . (Join-Path $PSScriptRoot 'container-safety.ps1')
$approvedImage = 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1'
if ($Image -cne $approvedImage) {
    throw "Kylin verification requires the approved image reference '$approvedImage'."
}

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
if ([string]::IsNullOrWhiteSpace($DockerBinary) -or -not [System.IO.Path]::IsPathRooted($DockerBinary) -or -not (Test-Path -LiteralPath $DockerBinary -PathType Leaf)) {
    throw 'Docker CLI is required. Install/start Docker Desktop or pass -DockerBinary with the absolute docker executable path.'
}

if ([string]::IsNullOrWhiteSpace($GoBinary)) {
    $goCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($goCommand) {
        $GoBinary = $goCommand.Source
    } else {
        $workspaceRoot = Split-Path -Parent (Split-Path -Parent $repoRoot)
        $workspaceGo = Join-Path $workspaceRoot '.tooling\go\bin\go.exe'
        if (Test-Path -LiteralPath $workspaceGo -PathType Leaf) {
            $GoBinary = $workspaceGo
        }
    }
}
if ([string]::IsNullOrWhiteSpace($GoBinary) -or -not [System.IO.Path]::IsPathRooted($GoBinary) -or -not (Test-Path -LiteralPath $GoBinary -PathType Leaf)) {
    throw 'An absolute Go executable path is required. Pass -GoBinary when Go is not on PATH.'
}

function Invoke-Docker {
    param([string[]]$Arguments)
    & $DockerBinary @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Remove-SafeTemporaryDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
	$separators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
	$parent = [System.IO.Path]::GetFullPath($backendRoot).TrimEnd($separators) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase) -or -not (Split-Path -Leaf $resolved).StartsWith('.tmp-kylin-', [StringComparison]::Ordinal)) {
        throw "Refusing unsafe Kylin verifier cleanup: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

if ($Pull) {
    Invoke-Docker @('pull', $Image)
}
$imageID = (& $DockerBinary image inspect --format '{{.Id}}' $Image 2>$null | Out-String).Trim()
if ([string]::IsNullOrWhiteSpace($imageID)) {
    throw "Kylin image '$Image' is not available locally. Pull it from the approved enterprise registry or pass -Pull."
}
if ($Architecture -eq 'arm64') {
    $dockerArchitecture = (& $DockerBinary info --format '{{.Architecture}}' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $dockerArchitecture -notin @('aarch64', 'arm64')) {
        throw 'Kylin arm64 runtime verification requires a native arm64 Docker host; emulation is not accepted as evidence.'
    }
}

$temporaryRoot = Join-Path $backendRoot ('.tmp-kylin-' + [guid]::NewGuid().ToString('N'))
$fixtureDirectory = Join-Path $temporaryRoot 'runtime'
$binaryDirectory = Join-Path $temporaryRoot 'bin'
$fixtureSource = Join-Path $temporaryRoot 'main.go'
$container = $null
$containerName = New-DBPilotOwnedContainerName -Prefix 'dbpilot-kylin-smoke'
$primaryFailure = $null

try {
    New-Item -ItemType Directory -Path $fixtureDirectory, $binaryDirectory -Force | Out-Null
    $fixtureProgram = @'
package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/json"
    "encoding/pem"
    "math/big"
    "net"
    "os"
    "path/filepath"
    "time"

    "dbpilot.local/platform/internal/policy"
)

func must(err error) { if err != nil { panic(err) } }
func write(path string, body []byte, mode os.FileMode) { must(os.WriteFile(path, body, mode)) }
func keyPair(directory, prefix string) (ed25519.PublicKey, ed25519.PrivateKey) {
    publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader); must(err)
    publicDER, err := x509.MarshalPKIXPublicKey(publicKey); must(err)
    privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey); must(err)
    write(filepath.Join(directory, prefix+"-public.pem"), pem.EncodeToMemory(&pem.Block{Type:"PUBLIC KEY", Bytes:publicDER}), 0600)
    write(filepath.Join(directory, prefix+"-private.pem"), pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY", Bytes:privateDER}), 0600)
    return publicKey, privateKey
}
func main() {
    directory := os.Args[1]
    must(os.MkdirAll(directory, 0700))
    _, policyPrivate := keyPair(directory, "policy")
    keyPair(directory, "command")
    caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader); must(err)
    now := time.Now().UTC()
    ca := &x509.Certificate{SerialNumber:big.NewInt(1), Subject:pkix.Name{CommonName:"DBPilot Kylin smoke CA"}, NotBefore:now.Add(-time.Hour), NotAfter:now.Add(time.Hour), IsCA:true, BasicConstraintsValid:true, KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature}
    caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate); must(err)
    write(filepath.Join(directory, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:caDER}), 0600)
    serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader); must(err)
    server := &x509.Certificate{SerialNumber:big.NewInt(2), Subject:pkix.Name{CommonName:"localhost"}, DNSNames:[]string{"localhost"}, IPAddresses:[]net.IP{net.ParseIP("127.0.0.1")}, NotBefore:now.Add(-time.Hour), NotAfter:now.Add(time.Hour), KeyUsage:x509.KeyUsageDigitalSignature, ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth,x509.ExtKeyUsageClientAuth}}
    serverDER, err := x509.CreateCertificate(rand.Reader, server, ca, serverPublic, caPrivate); must(err)
    serverKey, err := x509.MarshalPKCS8PrivateKey(serverPrivate); must(err)
    write(filepath.Join(directory, "endpoint.pem"), pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:serverDER}), 0600)
    write(filepath.Join(directory, "endpoint-key.pem"), pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY", Bytes:serverKey}), 0600)
    value := policy.Policy{AgentID:"kylin-smoke-agent", Version:1, IssuedAt:now.Add(-time.Minute), ExpiresAt:now.Add(time.Hour), Sources:[]policy.Source{{ID:"host",Kind:policy.SourceHostMetrics,Interval:5*time.Second}}, Limits:policy.Limits{MaxSpoolBytes:1048576,MaxBatchBytes:65536,MaxEventsPerSec:100}}
    envelope, err := policy.Sign(policyPrivate, value); must(err)
    encoded, err := json.Marshal(envelope); must(err)
    write(filepath.Join(directory, "policy.json"), encoded, 0600)
}
'@
    [System.IO.File]::WriteAllText($fixtureSource, $fixtureProgram, [Text.UTF8Encoding]::new($false))

    Push-Location $backendRoot
    try {
        & $GoBinary run $fixtureSource $fixtureDirectory
        if ($LASTEXITCODE -ne 0) { throw 'Unable to create signed Kylin smoke fixtures.' }
    }
    finally {
        Pop-Location
    }

    $agentConfig = @'
agent_id: kylin-smoke-agent
server_address: 127.0.0.1:1
ca_file: /runtime/ca.pem
cert_file: /runtime/endpoint.pem
key_file: /runtime/endpoint-key.pem
policy_public_key_file: /runtime/policy-public.pem
policy_file: /runtime/policy.json
data_directory: /runtime/data
file_collection_enabled: false
control:
  public_key_file: /runtime/command-public.pem
  journal_path: /runtime/data/command-journal.db
  heartbeat_interval: 1s
  reconnect_backoff: 100ms
'@
    [System.IO.File]::WriteAllText((Join-Path $fixtureDirectory 'agent.yaml'), $agentConfig, [Text.UTF8Encoding]::new($false))
    $controlplaneConfig = @'
database_url: "postgres://dbpilot:smoke@127.0.0.1:1/dbpilot?sslmode=disable&connect_timeout=1"
http:
  address: "127.0.0.1:18443"
  tls:
    cert_file: "/runtime/endpoint.pem"
    key_file: "/runtime/endpoint-key.pem"
identity:
  mode: "local_headers"
grpc:
  address: "127.0.0.1:19443"
  tls:
    cert_file: "/runtime/endpoint.pem"
    key_file: "/runtime/endpoint-key.pem"
    client_ca_file: "/runtime/ca.pem"
webhook_allowlist: ["hooks.example.com"]
event_url_base: "https://127.0.0.1:18443"
evaluation_scopes:
  - tenant_id: "tenant-smoke"
    project_id: "project-smoke"
command:
  signing_private_key_ref: "env://DBPILOT_COMMAND_SIGNING_PRIVATE_KEY"
'@
    [System.IO.File]::WriteAllText((Join-Path $fixtureDirectory 'controlplane.yaml'), $controlplaneConfig, [Text.UTF8Encoding]::new($false))

    & (Join-Path $PSScriptRoot 'build-linux.ps1') -OutputDirectory $binaryDirectory -Version $Version -GoBinary $GoBinary
    if ($LASTEXITCODE -ne 0) { throw 'Linux binary build failed.' }

    $agentBinary = Join-Path $binaryDirectory "dbpilot-agent-linux-$Architecture"
    $controlplaneBinary = Join-Path $binaryDirectory "dbpilot-controlplane-linux-$Architecture"
    foreach ($binary in @($agentBinary, $controlplaneBinary)) {
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "Expected Linux binary is missing: $binary" }
    }

    $platform = if ($Architecture -eq 'amd64') { 'linux/amd64' } else { 'linux/arm64' }
	$container = New-DBPilotOwnedContainer -DockerBinary $DockerBinary -Name $containerName -CreateArguments @('--platform', $platform, $Image, '/bin/sh', '-c', 'sleep 300')
    Invoke-Docker @('cp', $agentBinary, "${container}:/opt/dbpilot-agent")
    Invoke-Docker @('cp', $controlplaneBinary, "${container}:/opt/dbpilot-controlplane")
    Invoke-Docker @('cp', (Join-Path $fixtureDirectory '.'), "${container}:/runtime")
    Invoke-Docker @('start', $container)

    $smoke = @'
set -eu
. /etc/os-release
test "${ID:-}" = kylin
test "${VERSION_ID:-}" = V10
test "${VERSION:-}" = 'V10 (Tercel)'
arch="$(uname -m)"
case "${DBPILOT_EXPECTED_ARCH}" in
  amd64) test "$arch" = x86_64 ;;
  arm64) test "$arch" = aarch64 ;;
esac
chmod 0755 /opt/dbpilot-agent /opt/dbpilot-controlplane
chmod 0600 /runtime/*.pem /runtime/*.json /runtime/*.yaml
mkdir -p /runtime/data
chmod 0700 /runtime/data
/opt/dbpilot-agent --version
/opt/dbpilot-controlplane --version

set +e
timeout 8 /opt/dbpilot-agent --config /runtime/agent.yaml >/runtime/agent-startup.log 2>&1
agent_status=$?
set -e
case "$agent_status" in
  0|124|143) ;;
  *) cat /runtime/agent-startup.log >&2; exit 42 ;;
esac
test -s /runtime/data/command-journal.db
if grep -E 'parse configuration|load control-plane command public key|no usable signed policy' /runtime/agent-startup.log >/dev/null; then
  cat /runtime/agent-startup.log >&2
  exit 43
fi

export DBPILOT_COMMAND_SIGNING_PRIVATE_KEY="$(cat /runtime/command-private.pem)"
set +e
/opt/dbpilot-controlplane --config /runtime/controlplane.yaml >/runtime/controlplane-startup.log 2>&1
controlplane_status=$?
set -e
test "$controlplane_status" -ne 0
grep 'database readiness' /runtime/controlplane-startup.log >/dev/null
printf 'Kylin validation passed: ID=%s VERSION=%s ARCH=%s journal=opened policy=parsed\n' "${ID}" "${VERSION_ID:-unknown}" "$arch"
'@
    $encodedSmoke = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($smoke))
    Invoke-Docker @('exec', '-e', "DBPILOT_EXPECTED_ARCH=$Architecture", $container, '/bin/sh', '-c', "echo $encodedSmoke | base64 -d | /bin/sh")
}
catch {
    $primaryFailure = $_
    throw
}
finally {
	try {
		Remove-DBPilotOwnedContainer -DockerBinary $DockerBinary -ContainerID $container
	}
	catch {
		if ($null -eq $primaryFailure) { throw }
		Write-Error $_ -ErrorAction Continue
	}
    Remove-SafeTemporaryDirectory $temporaryRoot
}
