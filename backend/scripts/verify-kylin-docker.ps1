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
$protocolProbeSource = Join-Path $temporaryRoot 'protocol-probe.go'
$probeGatewaySource = Join-Path $temporaryRoot 'probe-gateway.go'
$spoolProbeSource = Join-Path $temporaryRoot 'spool-probe.go'
$container = $null
$containerName = New-DBPilotOwnedContainerName -Prefix 'dbpilot-kylin-smoke'
$anonymousVolumes = @()
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
	"net/url"
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
	dataDirectory := filepath.Join(directory, "data")
	must(os.MkdirAll(dataDirectory, 0700))
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
	agentPublic, agentPrivate, err := ed25519.GenerateKey(rand.Reader); must(err)
	agentIdentity, err := url.Parse("spiffe://dbpilot.local/agent/kylin-smoke-agent"); must(err)
	agent := &x509.Certificate{SerialNumber:big.NewInt(3), Subject:pkix.Name{CommonName:"kylin-smoke-agent"}, URIs:[]*url.URL{agentIdentity}, NotBefore:now.Add(-time.Hour), NotAfter:now.Add(time.Hour), KeyUsage:x509.KeyUsageDigitalSignature, ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	agentDER, err := x509.CreateCertificate(rand.Reader, agent, ca, agentPublic, caPrivate); must(err)
	agentKey, err := x509.MarshalPKCS8PrivateKey(agentPrivate); must(err)
	write(filepath.Join(directory, "agent.pem"), pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:agentDER}), 0600)
	write(filepath.Join(directory, "agent-key.pem"), pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY", Bytes:agentKey}), 0600)
    value := policy.Policy{AgentID:"kylin-smoke-agent", Version:1, IssuedAt:now.Add(-time.Minute), ExpiresAt:now.Add(time.Hour), Sources:[]policy.Source{{ID:"host",Kind:policy.SourceHostMetrics,Interval:5*time.Second}}, Limits:policy.Limits{MaxSpoolBytes:1048576,MaxBatchBytes:65536,MaxEventsPerSec:100}}
    envelope, err := policy.Sign(policyPrivate, value); must(err)
    encoded, err := json.Marshal(envelope); must(err)
    write(filepath.Join(directory, "policy.json"), encoded, 0600)
}
'@
    [System.IO.File]::WriteAllText($fixtureSource, $fixtureProgram, [Text.UTF8Encoding]::new($false))
	$protocolProbe = @'
package main

import (
	"context"
	"fmt"
	"os"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/commandjournal"
)

func main() {
	if len(os.Args) != 2 { panic("journal path is required") }
	journal, err := commandjournal.Open(os.Args[1]); if err != nil { panic(err) }
	defer journal.Close()
	for _, commandID := range []string{"kylin-dependency-command", "kylin-protocol-command"} {
		entry, err := journal.Get(context.Background(), commandID); if err != nil { panic(err) }
		if entry.State != commandjournal.StateCompleted { panic(fmt.Sprintf("command %s state is not completed: %s", commandID, entry.State)) }
		if entry.Result == nil || entry.Result.GetState() != agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED { panic(fmt.Sprintf("command %s result is not succeeded", commandID)) }
		if entry.ReportedAt.IsZero() { panic(fmt.Sprintf("command %s ResultAck was not persisted in the Agent journal", commandID)) }
	}
	pending, err := journal.PendingResults(context.Background()); if err != nil { panic(err) }
	if len(pending) != 0 { panic("acknowledged command result remains pending") }
	fmt.Println("Kylin protocol smoke passed: production_agent=true collect_now_dependencies=true collect_now_host=true result_ack=true")
}
'@
	[System.IO.File]::WriteAllText($protocolProbeSource, $protocolProbe, [Text.UTF8Encoding]::new($false))
	$spoolProbe = @'
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"dbpilot.local/platform/internal/spool"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func must(err error) { if err != nil { panic(err) } }
func main() {
	if len(os.Args) != 2 { panic("spool directory is required") }
	store, err := spool.Open(os.Args[1], spool.Limits{MaxBytes:1<<30, SegmentBytes:16<<20}); must(err)
	defer store.Close()
	batches, err := store.Pending(context.Background(), spool.Metric, 100); must(err)
	var hostBatches []spool.Batch
	for _, batch := range batches { if batch.SourceID == "inspection-host-snapshot" { hostBatches = append(hostBatches, batch) } }
	if len(hostBatches) != 1 { panic(fmt.Sprintf("expected exactly one retained inspection-host-snapshot batch, got %d", len(hostBatches))) }
	metrics, err := (&pmetric.ProtoUnmarshaler{}).UnmarshalMetrics(hostBatches[0].Payload); must(err)
	counts := map[string]int{}
	snapshotAt := ""
	metricCount := 0
	for resourceIndex := 0; resourceIndex < metrics.ResourceMetrics().Len(); resourceIndex++ {
		resourceMetrics := metrics.ResourceMetrics().At(resourceIndex)
		if value, ok := resourceMetrics.Resource().Attributes().Get("inspection.snapshot_at"); ok { snapshotAt = value.Str() }
		for scopeIndex := 0; scopeIndex < resourceMetrics.ScopeMetrics().Len(); scopeIndex++ {
			metricSlice := resourceMetrics.ScopeMetrics().At(scopeIndex).Metrics()
			for metricIndex := 0; metricIndex < metricSlice.Len(); metricIndex++ {
				metric := metricSlice.At(metricIndex)
				points := 0
				switch metric.Type() {
				case pmetric.MetricTypeGauge: points = metric.Gauge().DataPoints().Len()
				case pmetric.MetricTypeSum: points = metric.Sum().DataPoints().Len()
				default: panic(fmt.Sprintf("unsupported host metric type for %s", metric.Name()))
				}
				if points == 0 { panic(fmt.Sprintf("host metric %s has no data points", metric.Name())) }
				counts[metric.Name()] += points
				metricCount++
			}
		}
	}
	for _, name := range []string{"system.cpu.utilization", "system.memory.utilization", "system.filesystem.utilization", "system.cpu.load_average.1m_per_cpu"} {
		if counts[name] == 0 { panic(fmt.Sprintf("canonical host metric %s is missing", name)) }
	}
	if parsed, err := time.Parse(time.RFC3339Nano, snapshotAt); err != nil || parsed.IsZero() { panic("inspection.snapshot_at is missing or invalid") }
	fmt.Printf("Kylin host snapshot evidence: source=%s batch=%s metrics=%d cpu=%d memory=%d filesystem=%d load=%d snapshot_at=%s\n", hostBatches[0].SourceID, hostBatches[0].ID, metricCount, counts["system.cpu.utilization"], counts["system.memory.utilization"], counts["system.filesystem.utilization"], counts["system.cpu.load_average.1m_per_cpu"], snapshotAt)
}
'@
	[System.IO.File]::WriteAllText($spoolProbeSource, $spoolProbe, [Text.UTF8Encoding]::new($false))
	$probeGateway = @'
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agentcontrol"
	"dbpilot.local/platform/internal/job"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const commandID = "kylin-protocol-command"
const dependencyCommandID = "kylin-dependency-command"

type controlProbe struct {
	agentv1.UnimplementedAgentControlServer
	signer *job.Ed25519CommandSigner
	completePath string
	jmxCalls *atomic.Int32
}

func contains(values []string, want string) bool {
	for _, value := range values { if value == want { return true } }
	return false
}

func (probe *controlProbe) execute(stream grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ServerMessage], id string, kinds []string, requireJMX bool) error {
	now := time.Now().UTC()
	initialJMXCalls := probe.jmxCalls.Load()
	envelope := &agentv1.CommandEnvelope{
		CommandId:id, JobId:"kylin-protocol-job", AgentId:"kylin-smoke-agent", Nonce:[]byte("kylin-protocol-nonce-"+id), LeaseSeconds:30,
		IssuedAt:timestamppb.New(now), ExpiresAt:timestamppb.New(now.Add(time.Minute)),
		Command:&agentv1.CommandEnvelope_CollectNow{CollectNow:&agentv1.CollectNow{CollectionKinds:kinds}},
	}
	if err := probe.signer.Sign(stream.Context(), envelope); err != nil { return err }
	encodedEnvelope, err := proto.MarshalOptions{Deterministic:true}.Marshal(envelope); if err != nil { return err }
	envelopeDigest := sha256.Sum256(encodedEnvelope)
	if err := stream.Send(&agentv1.ServerMessage{MessageId:id, SentAt:timestamppb.New(now), Message:&agentv1.ServerMessage_Command{Command:envelope}}); err != nil { return err }
	for {
		message, receiveErr := stream.Recv(); if receiveErr != nil { return receiveErr }
		prepared := message.GetCommandPrepared()
		if prepared == nil { continue }
		if prepared.GetCommandId() != id || !bytes.Equal(prepared.GetEnvelopeDigest(), envelopeDigest[:]) { return status.Error(codes.FailedPrecondition, "Prepared digest mismatch") }
		break
	}
	token := make([]byte, sha256.Size); if _, err := rand.Read(token); err != nil { return err }
	start := &agentv1.CommandStart{CommandId:id, ExecutionToken:token, LeaseRevision:1, LeaseSeconds:30, StartDeadline:timestamppb.New(time.Now().UTC().Add(20*time.Second))}
	if err := stream.Send(&agentv1.ServerMessage{MessageId:"start-"+id, Message:&agentv1.ServerMessage_CommandStart{CommandStart:start}}); err != nil { return err }
	var resultDigest [sha256.Size]byte
	for {
		message, receiveErr := stream.Recv(); if receiveErr != nil { return receiveErr }
		result := message.GetCommandResult()
		if result == nil { continue }
		if result.GetCommandId() != id || result.GetState() != agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED || result.GetSummary() != "dependency telemetry collection completed" || len(result.GetArtifacts()) != 0 || !bytes.Equal(result.GetExecutionToken(), token) || result.GetLeaseRevision() != 1 {
			return status.Error(codes.FailedPrecondition, "CollectNow result is invalid")
		}
		if requireJMX && probe.jmxCalls.Load() <= initialJMXCalls { return status.Error(codes.FailedPrecondition, "dependency CollectNow did not reach the JMX fixture") }
		encodedResult, marshalErr := proto.MarshalOptions{Deterministic:true}.Marshal(result); if marshalErr != nil { return marshalErr }
		resultDigest = sha256.Sum256(encodedResult)
		break
	}
	ack := &agentv1.CommandResultAcknowledgement{CommandId:id, Persisted:true, ReasonCode:"PERSISTED", ResultDigest:resultDigest[:]}
	return stream.Send(&agentv1.ServerMessage{MessageId:"result-ack-"+id, Message:&agentv1.ServerMessage_CommandResultAcknowledgement{CommandResultAcknowledgement:ack}})
}

func (probe *controlProbe) Connect(stream grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	first, err := stream.Recv(); if err != nil { return err }
	hello := first.GetHello()
	if hello == nil || hello.GetAgentId() != "kylin-smoke-agent" || hello.GetProtocolVersion() != agentcontrol.ProtocolVersion || !contains(hello.GetCapabilities(), "collect_now") {
		return status.Error(codes.FailedPrecondition, "production Agent did not advertise collect_now")
	}
	initialDeadline := time.Now().Add(5*time.Second)
	for probe.jmxCalls.Load() == 0 {
		if time.Now().After(initialDeadline) { return status.Error(codes.FailedPrecondition, "periodic DependencyCollector did not reach the JMX fixture") }
		select { case <-stream.Context().Done(): return stream.Context().Err(); case <-time.After(10*time.Millisecond): }
	}
	now := time.Now().UTC()
	if err := stream.Send(&agentv1.ServerMessage{MessageId:"hello-ack", SentAt:timestamppb.New(now), Message:&agentv1.ServerMessage_HelloAck{HelloAck:&agentv1.HelloAck{ProtocolVersion:agentcontrol.ProtocolVersion, ServerTime:timestamppb.New(now)}}}); err != nil { return err }
	if err := probe.execute(stream, dependencyCommandID, []string{"dependencies"}, true); err != nil { return err }
	if err := probe.execute(stream, commandID, []string{"host"}, false); err != nil { return err }
	for {
		message, receiveErr := stream.Recv(); if receiveErr != nil { return receiveErr }
		if message.GetHeartbeat() != nil {
			if err := os.WriteFile(probe.completePath, []byte("complete\n"), 0600); err != nil { return err }
			return nil
		}
	}
}

type ingestProbe struct{ agentv1.UnimplementedTelemetryIngestServer }
func (ingestProbe) PushLogBatch(_ context.Context, batch *agentv1.LogBatch) (*agentv1.BatchAck, error) { return &agentv1.BatchAck{BatchId:batch.GetBatchId(), Accepted:true}, nil }
func (ingestProbe) PushMetricBatch(_ context.Context, batch *agentv1.MetricBatch) (*agentv1.BatchAck, error) { return &agentv1.BatchAck{BatchId:batch.GetBatchId(), Accepted:false, Retryable:true, ErrorCode:"SMOKE_RETAIN"}, nil }
func (ingestProbe) ReportPolicyStatus(context.Context, *agentv1.PolicyStatus) (*agentv1.PolicyStatusAck, error) { return &agentv1.PolicyStatusAck{Accepted:true}, nil }

func must(err error) { if err != nil { panic(err) } }
func main() {
	if len(os.Args) != 2 { panic("runtime directory is required") }
	directory := os.Args[1]
	privateKey, err := os.ReadFile(directory+"/command-private.pem"); must(err)
	signer, err := job.NewEd25519CommandSignerPEM(privateKey); must(err)
	caPEM, err := os.ReadFile(directory+"/ca.pem"); must(err)
	pool := x509.NewCertPool(); if !pool.AppendCertsFromPEM(caPEM) { panic("invalid CA") }
	certificate, err := tls.LoadX509KeyPair(directory+"/endpoint.pem", directory+"/endpoint-key.pem"); must(err)
	tlsConfig := &tls.Config{Certificates:[]tls.Certificate{certificate}, ClientAuth:tls.RequireAndVerifyClientCert, ClientCAs:pool, MinVersion:tls.VersionTLS12}
	grpcListener, err := net.Listen("tcp", "127.0.0.1:19444"); must(err)
	httpListener, err := net.Listen("tcp", "127.0.0.1:18080"); must(err)
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	var jmxCalls atomic.Int32
	agentv1.RegisterAgentControlServer(grpcServer, &controlProbe{signer:signer, completePath:directory+"/protocol-complete", jmxCalls:&jmxCalls})
	agentv1.RegisterTelemetryIngestServer(grpcServer, ingestProbe{})
	jmx := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		jmxCalls.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"beans":[{"name":"Hadoop:service=DataNode,name=FSDatasetState","Capacity":1000,"DfsUsed":950,"Remaining":50,"NumFailedVolumes":0,"NumBlocks":80},{"name":"Hadoop:service=DataNode,name=DataNodeInfo","xceiverCount":4}]}`))
	})
	httpServer := &http.Server{Handler:jmx, ReadHeaderTimeout:time.Second}
	go func() { if serveErr := httpServer.Serve(httpListener); serveErr != nil && serveErr != http.ErrServerClosed { panic(serveErr) } }()
	must(os.WriteFile(directory+"/gateway-ready", []byte("ready\n"), 0600))
	fmt.Println("Kylin AgentControl probe ready")
	must(grpcServer.Serve(grpcListener))
}
'@
	[System.IO.File]::WriteAllText($probeGatewaySource, $probeGateway, [Text.UTF8Encoding]::new($false))

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
server_address: 127.0.0.1:19444
ca_file: /runtime/ca.pem
cert_file: /runtime/agent.pem
key_file: /runtime/agent-key.pem
policy_public_key_file: /runtime/policy-public.pem
policy_file: /runtime/policy.json
data_directory: /runtime/data
file_collection_enabled: false
control:
  public_key_file: /runtime/command-public.pem
  journal_path: /runtime/data/command-journal.db
  heartbeat_interval: 100ms
  reconnect_backoff: 100ms
component_secrets:
  provider: environment
component_collection:
  interval_seconds: 3600
  request_timeout_seconds: 2
  max_attempts: 1
  initial_backoff_milliseconds: 10
  max_backoff_milliseconds: 10
components:
  - id: hdfs-smoke
    kind: hdfs
    endpoints:
      - url: http://127.0.0.1:18080/jmx
        role: datanode
    secret_ref: secret://hdfs/reader
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
  execution_token_key_ref: "env://DBPILOT_COMMAND_EXECUTION_TOKEN_KEY"
artifact:
  storage_root: "/runtime/data/artifacts"
  signing_key_ref: "secret://controlplane/artifact-download"
'@
    [System.IO.File]::WriteAllText((Join-Path $fixtureDirectory 'controlplane.yaml'), $controlplaneConfig, [Text.UTF8Encoding]::new($false))

    & (Join-Path $PSScriptRoot 'build-linux.ps1') -OutputDirectory $binaryDirectory -Version $Version -GoBinary $GoBinary
    if ($LASTEXITCODE -ne 0) { throw 'Linux binary build failed.' }
	$protocolProbeBinary = Join-Path $binaryDirectory "dbpilot-protocol-smoke-linux-$Architecture"
	$probeGatewayBinary = Join-Path $binaryDirectory "dbpilot-probe-gateway-linux-$Architecture"
	$spoolProbeBinary = Join-Path $binaryDirectory "dbpilot-spool-probe-linux-$Architecture"
	$hadCGOEnabled = Test-Path Env:CGO_ENABLED
	$previousCGOEnabled = $env:CGO_ENABLED
	$hadGOOS = Test-Path Env:GOOS
	$previousGOOS = $env:GOOS
	$hadGOARCH = Test-Path Env:GOARCH
	$previousGOARCH = $env:GOARCH
	try {
		$env:CGO_ENABLED = '0'
		$env:GOOS = 'linux'
		$env:GOARCH = $Architecture
		Push-Location $backendRoot
		try {
			foreach ($helper in @(
				@{ Source = $protocolProbeSource; Output = $protocolProbeBinary; Name = 'protocol journal probe' },
				@{ Source = $probeGatewaySource; Output = $probeGatewayBinary; Name = 'AgentControl probe gateway' },
				@{ Source = $spoolProbeSource; Output = $spoolProbeBinary; Name = 'host metric spool probe' }
			)) {
				& $GoBinary build -trimpath -o $helper.Output $helper.Source
				if ($LASTEXITCODE -ne 0) { throw "Kylin $($helper.Name) build failed." }
			}
		}
		finally { Pop-Location }
	}
	finally {
		if ($hadCGOEnabled) { $env:CGO_ENABLED = $previousCGOEnabled } else { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue }
		if ($hadGOOS) { $env:GOOS = $previousGOOS } else { Remove-Item Env:GOOS -ErrorAction SilentlyContinue }
		if ($hadGOARCH) { $env:GOARCH = $previousGOARCH } else { Remove-Item Env:GOARCH -ErrorAction SilentlyContinue }
	}

    $agentBinary = Join-Path $binaryDirectory "dbpilot-agent-linux-$Architecture"
    $controlplaneBinary = Join-Path $binaryDirectory "dbpilot-controlplane-linux-$Architecture"
    foreach ($binary in @($agentBinary, $controlplaneBinary)) {
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "Expected Linux binary is missing: $binary" }
    }

    $platform = if ($Architecture -eq 'amd64') { 'linux/amd64' } else { 'linux/arm64' }
	$container = New-DBPilotOwnedContainer -DockerBinary $DockerBinary -Name $containerName -CreateArguments @('--platform', $platform, '--label', 'dbpilot.verifier=kylin-production-agent', '--label', "dbpilot.run=$containerName", $Image, '/bin/sh', '-c', 'sleep 300')
	$containerInspectionJSON = (& $DockerBinary inspect $container | Out-String)
	if ($LASTEXITCODE -ne 0) { throw 'Unable to inspect Kylin smoke ownership metadata.' }
	$containerInspection = @($containerInspectionJSON | ConvertFrom-Json)
	if ($containerInspection.Count -ne 1 -or $containerInspection[0].Id -cne $container -or $containerInspection[0].Config.Labels.'dbpilot.verifier' -cne 'kylin-production-agent' -or $containerInspection[0].Config.Labels.'dbpilot.run' -cne $containerName) {
		throw 'Kylin smoke ownership metadata is missing or incorrect.'
	}
	$anonymousVolumes = @($containerInspection[0].Mounts | Where-Object Type -eq 'volume' | ForEach-Object Name)
    Invoke-Docker @('cp', $agentBinary, "${container}:/opt/dbpilot-agent")
    Invoke-Docker @('cp', $controlplaneBinary, "${container}:/opt/dbpilot-controlplane")
	Invoke-Docker @('cp', $protocolProbeBinary, "${container}:/opt/dbpilot-protocol-smoke")
	Invoke-Docker @('cp', $probeGatewayBinary, "${container}:/opt/dbpilot-probe-gateway")
	Invoke-Docker @('cp', $spoolProbeBinary, "${container}:/opt/dbpilot-spool-probe")
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
chmod 0755 /opt/dbpilot-agent /opt/dbpilot-controlplane /opt/dbpilot-protocol-smoke /opt/dbpilot-probe-gateway /opt/dbpilot-spool-probe
chmod 0600 /runtime/*.pem /runtime/*.json /runtime/*.yaml
mkdir -p /runtime/data
chmod 0700 /runtime/data
mkdir -p /runtime/data/artifacts
chmod 0700 /runtime/data/artifacts
/opt/dbpilot-agent --version
/opt/dbpilot-controlplane --version

gateway_pid=''
agent_pid=''
cleanup_protocol() {
  if [ -n "$agent_pid" ] && kill -0 "$agent_pid" 2>/dev/null; then kill -TERM "$agent_pid" 2>/dev/null || true; fi
  if [ -n "$gateway_pid" ] && kill -0 "$gateway_pid" 2>/dev/null; then kill -TERM "$gateway_pid" 2>/dev/null || true; fi
  if [ -n "$agent_pid" ]; then wait "$agent_pid" 2>/dev/null || true; fi
  if [ -n "$gateway_pid" ]; then wait "$gateway_pid" 2>/dev/null || true; fi
}
trap cleanup_protocol EXIT
rm -f /runtime/gateway-ready /runtime/protocol-complete /runtime/probe-gateway.log /runtime/agent-startup.log
export DBPILOT_SECRET_HDFS_READER='kylin-read-only-fixture'
/opt/dbpilot-probe-gateway /runtime >/runtime/probe-gateway.log 2>&1 &
gateway_pid=$!
attempt=0
while [ ! -s /runtime/gateway-ready ]; do
  if ! kill -0 "$gateway_pid" 2>/dev/null; then cat /runtime/probe-gateway.log >&2; exit 42; fi
  attempt=$((attempt+1)); if [ "$attempt" -ge 100 ]; then cat /runtime/probe-gateway.log >&2; exit 43; fi
  sleep 0.1
done
/opt/dbpilot-agent --config /runtime/agent.yaml >/runtime/agent-startup.log 2>&1 &
agent_pid=$!
attempt=0
while [ ! -s /runtime/protocol-complete ]; do
  if ! kill -0 "$agent_pid" 2>/dev/null; then
    set +e; wait "$agent_pid"; unexpected_agent_status=$?; set -e
    cat /runtime/agent-startup.log >&2
    echo "Agent exited before protocol completion with status $unexpected_agent_status" >&2
    exit 44
  fi
  if ! kill -0 "$gateway_pid" 2>/dev/null; then cat /runtime/probe-gateway.log >&2; exit 45; fi
  attempt=$((attempt+1)); if [ "$attempt" -ge 200 ]; then cat /runtime/probe-gateway.log >&2; cat /runtime/agent-startup.log >&2; exit 46; fi
  sleep 0.1
done
kill -TERM "$agent_pid"
set +e; wait "$agent_pid"; agent_status=$?; set -e
agent_pid=''
case "$agent_status" in 0|143) ;; *) cat /runtime/agent-startup.log >&2; exit 47 ;; esac
kill -TERM "$gateway_pid" 2>/dev/null || true
set +e; wait "$gateway_pid"; gateway_status=$?; set -e
gateway_pid=''
case "$gateway_status" in 0|143) ;; *) cat /runtime/probe-gateway.log >&2; exit 48 ;; esac
trap - EXIT
test -s /runtime/data/command-journal.db
if grep -E 'parse configuration|load control-plane command public key|no usable signed policy' /runtime/agent-startup.log >/dev/null; then
  cat /runtime/agent-startup.log >&2
  exit 49
fi
/opt/dbpilot-protocol-smoke /runtime/data/command-journal.db
/opt/dbpilot-spool-probe /runtime/data

export DBPILOT_COMMAND_SIGNING_PRIVATE_KEY="$(cat /runtime/command-private.pem)"
export DBPILOT_COMMAND_EXECUTION_TOKEN_KEY='0123456789abcdef0123456789abcdef'
export DBPILOT_SECRET_CONTROLPLANE_ARTIFACT_DOWNLOAD='0123456789abcdef0123456789abcdef'
set +e
/opt/dbpilot-controlplane --config /runtime/controlplane.yaml >/runtime/controlplane-startup.log 2>&1
controlplane_status=$?
set -e
test "$controlplane_status" -ne 0
grep 'database readiness' /runtime/controlplane-startup.log >/dev/null
printf 'Kylin validation passed: ID=%s VERSION=%s ARCH=%s journal=opened policy=parsed protocol=two-phase host_snapshot=decoded native_reader=true\n' "${ID}" "${VERSION_ID:-unknown}" "$arch"
'@
    $smoke = $smoke.Replace("`r`n", "`n").Replace("`r", "`n")
    $encodedSmoke = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($smoke))
    Invoke-Docker @('exec', '-e', "DBPILOT_EXPECTED_ARCH=$Architecture", $container, '/bin/sh', '-c', "echo $encodedSmoke | base64 -d | /bin/sh")
}
catch {
    $primaryFailure = $_
    throw
}
finally {
	$cleanupFailures = @()
	try {
		Remove-DBPilotOwnedContainer -DockerBinary $DockerBinary -ContainerID $container
		if (-not [string]::IsNullOrWhiteSpace($container)) {
			$remaining = @(& $DockerBinary ps -a --no-trunc --filter "id=$container" --format '{{.ID}}')
			if ($LASTEXITCODE -ne 0) { throw 'Unable to verify Kylin container cleanup.' }
			if ($remaining -contains $container) { throw "Kylin verifier left container '$container' behind." }
		}
		$remainingByRun = @(& $DockerBinary ps -a --filter "label=dbpilot.run=$containerName" --format '{{.ID}}')
		if ($LASTEXITCODE -ne 0) { throw 'Unable to audit Kylin smoke cleanup by ownership label.' }
		if (($remainingByRun | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) { throw "Kylin verifier left a run-labelled container for '$containerName' behind." }
		foreach ($volume in $anonymousVolumes) {
			$remainingVolume = @(& $DockerBinary volume ls --filter "name=^$volume$" --format '{{.Name}}')
			if ($LASTEXITCODE -ne 0) { throw "Unable to audit Kylin anonymous volume cleanup for '$volume'." }
			if ($remainingVolume -contains $volume) { throw "Kylin verifier left anonymous volume '$volume' behind." }
		}
		Write-Host "Kylin cleanup audit passed: container=$container anonymous_volumes=$($anonymousVolumes.Count)."
	}
	catch {
		$cleanupFailures += $_
	}
	try {
		Remove-SafeTemporaryDirectory $temporaryRoot
		if (Test-Path -LiteralPath $temporaryRoot) {
			throw "Kylin verifier left temporary directory '$temporaryRoot' behind."
		}
	}
	catch {
		$cleanupFailures += $_
	}
	if ($cleanupFailures.Count -gt 0) {
		if ($null -eq $primaryFailure) { throw $cleanupFailures[0] }
		foreach ($cleanupFailure in $cleanupFailures) { Write-Error $cleanupFailure -ErrorAction Continue }
	}
}
