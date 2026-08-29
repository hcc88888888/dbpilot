package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/agentcontrol"
	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/controlplane"
	"dbpilot.local/platform/internal/ingest"
	"dbpilot.local/platform/internal/inspection"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// TestHostInspectionLifecycle catches a bypass of signed Prepare/Start, a
// weakened source/accepted_at fence, sibling cancellation after one target
// fails, mutable historical evidence, report regeneration, or duplicate rows
// after an exact idempotent replay. PostgreSQL and the in-memory Agent stream
// are the only test boundaries; lifecycle, ingest, worker, Artifact, and Audit
// components are the production implementations.
func TestHostInspectionLifecycle(t *testing.T) {
	if os.Getenv("DBPILOT_CONTRACT_E2E") != "1" {
		t.Skip("set DBPILOT_CONTRACT_E2E=1 to run the host inspection lifecycle")
	}
	dsn := os.Getenv("DBPILOT_CONTRACT_POSTGRES_DSN")
	require.NotEmpty(t, dsn, "DBPILOT_CONTRACT_POSTGRES_DSN is required")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database := contractDatabase(t, dsn)
	require.NoError(t, alert.RunMigrations(ctx, database))
	require.NoError(t, job.RunMigrations(ctx, database))
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, inspection.RunMigrations(ctx, database))

	scope := platformscope.Scope{TenantID: "tenant-inspection-e2e", ProjectID: "project-inspection-e2e"}
	metricScope := alert.Scope{TenantID: scope.TenantID, ProjectID: scope.ProjectID}
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	items := inspection.BuiltinHostItems()
	require.Len(t, items, 13)
	versions := make([]inspection.PolicyItem, len(items))

	jobRepository := job.NewPostgresRepository(database)
	repository := inspection.NewPostgresRepository(database, jobRepository)
	for index := range items {
		items[index].Scope = scope
		items[index].Enabled = true
		items[index].CreatedAt = createdAt
		items[index].UpdatedAt = createdAt
		versions[index] = inspection.PolicyItem{ItemID: items[index].ID, Version: items[index].Version}
		require.NoError(t, repository.CreateItem(ctx, items[index]))
	}
	cpuItem := items[0]
	targets, err := inspection.NewConfiguredTargetResolver([]inspection.HostTarget{
		{Scope: scope, AgentID: "agent-a", DisplayName: "Primary host", Host: "db-a.internal", Labels: map[string]string{"role": "database"}, Connectivity: "online", Capabilities: []string{"collect_now", "collect_now.host.v1"}, AdvertisedSources: []inspection.SourceType{inspection.SourceMetric, inspection.SourceMetadata, inspection.SourceLogSummary}},
		{Scope: scope, AgentID: "agent-b", DisplayName: "Standby host", Host: "db-b.internal", Labels: map[string]string{"role": "database"}, Connectivity: "online", Capabilities: []string{"collect_now", "collect_now.host.v1"}, AdvertisedSources: []inspection.SourceType{inspection.SourceMetric, inspection.SourceMetadata, inspection.SourceLogSummary}},
	})
	require.NoError(t, err)
	var idCounter atomic.Int32
	service := &inspection.Service{
		Repository: repository,
		Targets:    targets,
		Now:        func() time.Time { return createdAt },
		NewID: func() (string, error) {
			return fmt.Sprintf("inspection-e2e-%02d", idCounter.Add(1)), nil
		},
	}
	request := inspection.CreateRunRequest{
		Scope: scope, Selector: inspection.TargetSelector{AgentIDs: []string{"agent-a", "agent-b"}},
		Items: versions, TargetTimeout: 20 * time.Second, MaxConcurrency: 2,
		IdempotencyKey: "host-inspection-e2e", InitiatedBy: "operator-e2e", RequestID: "request-inspection-e2e",
		TraceID: "11111111111111111111111111111111", Trigger: inspection.RunTriggerManual,
	}
	run, err := service.CreateRun(ctx, request)
	require.NoError(t, err)
	replayed, err := service.CreateRun(ctx, request)
	require.NoError(t, err)
	require.Equal(t, run, replayed, "same-key same-request replay must return the exact persisted Run")
	assertInspectionCreationCounts(t, ctx, database, scope, run, 1, 2, 2)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := job.NewEd25519CommandSigner(privateKey)
	require.NoError(t, err)
	tokenProtector, err := job.NewAES256GCMTokenProtector(bytes.Repeat([]byte{0x71}, 32))
	require.NoError(t, err)
	auditService := audit.NewService(audit.NewPostgresStore(database))
	registry := agentcontrol.NewRegistry(8)
	lifecycle, err := job.NewCommandLifecycle(job.CommandLifecycleConfig{
		DispatchRepository: jobRepository, Jobs: jobRepository, Agents: registry, Signer: signer,
		Audit: auditService, ClaimLimit: 8, TokenProtector: tokenProtector,
	})
	require.NoError(t, err)
	resultErrors := make(chan error, 4)
	controlServer := agentcontrol.NewServer(registry, &resultErrorObserver{CommandLifecycle: lifecycle, errors: resultErrors})
	streams := map[string]*contractAgentStream{}
	for _, agentID := range []string{"agent-a", "agent-b"} {
		stream := newContractAgentStream(contractPeerContext(agentID), contractHello(agentID))
		streams[agentID] = stream
		done := make(chan error, 1)
		go func() { done <- controlServer.Connect(stream) }()
		t.Cleanup(func() {
			stream.closeReceive()
			require.NoError(t, <-done)
		})
		require.NotNil(t, stream.nextSent(t).GetHelloAck())
	}

	dispatched, err := lifecycle.DispatchPending(ctx, time.Now().UTC())
	require.NoError(t, err)
	require.Equal(t, 2, dispatched)
	starts := make(map[string]*agentv1.CommandStart, 2)
	commands := make(map[string]string, 2)
	for _, agentID := range []string{"agent-a", "agent-b"} {
		envelope := streams[agentID].nextSent(t).GetCommand()
		require.NotNil(t, envelope)
		require.Equal(t, agentID, envelope.GetAgentId())
		require.Equal(t, []string{"host"}, envelope.GetCollectNow().GetCollectionKinds())
		verifier, verifyErr := agent.NewCommandVerifier(agentID, publicKey, []string{"collect_now"})
		require.NoError(t, verifyErr)
		require.NoError(t, verifier.Verify(ctx, envelope))
		streams[agentID].push(contractPrepared(t, envelope))
		start := streams[agentID].nextSent(t).GetCommandStart()
		require.NotNil(t, start)
		require.Len(t, start.GetExecutionToken(), sha256.Size)
		starts[agentID] = start
		commands[agentID] = envelope.GetCommandId()
	}
	streams["agent-a"].push(contractAck(commands["agent-a"]), contractProgress(starts["agent-a"], 100), contractResult(starts["agent-a"], agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, ""))
	streams["agent-b"].push(contractAck(commands["agent-b"]), contractProgress(starts["agent-b"], 100), contractResult(starts["agent-b"], agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, ""))
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		value, getErr := jobRepository.Get(ctx, scope, run.JobID)
		assert.NoError(collect, getErr)
		assert.Equal(collect, job.StatusSucceeded, value.Status)
		assert.Equal(collect, job.OutcomePartial, value.Outcome)
		assert.Len(collect, value.TargetResults, 2)
	}, 5*time.Second, 20*time.Millisecond)
	for _, agentID := range []string{"agent-a", "agent-b"} {
		ack := streams[agentID].nextSent(t).GetCommandResultAcknowledgement()
		require.NotNil(t, ack)
		require.Equal(t, commands[agentID], ack.GetCommandId())
		require.True(t, ack.GetPersisted())
	}
	select {
	case resultErr := <-resultErrors:
		require.NoError(t, resultErr)
	default:
	}

	metricStore := alert.NewPostgresRepository(database)
	metricConsumer := controlplane.NewMetricConsumer(inspectionScopeResolver{"agent-a": metricScope}, metricStore)
	ingestService := ingest.NewService(ingest.AllowAnyVerifiedAgent{}, ingest.NewMemoryDeduplicator(), metricConsumer)
	wrongSourcePayload := inspectionMetricPayload(t, cpuItem.MetricRule.MetricName, 99, createdAt.Add(time.Microsecond), "unrelated-source")
	wrongSourceAck, err := ingestService.PushMetricBatch(inspectionIngestPeerContext("agent-a"), metricBatch("inspection-wrong-source", "agent-a", "unrelated-source", wrongSourcePayload))
	require.NoError(t, err)
	require.True(t, wrongSourceAck.GetAccepted())
	wrongSourceEvidence, err := repository.LoadHostSnapshot(ctx, scope, "agent-a", items, createdAt, createdAt.Add(10*time.Second), 256)
	require.NoError(t, err)
	require.False(t, wrongSourceEvidence.Complete, "same-name metric from another source must not satisfy the host snapshot")

	incompleteAt := createdAt.Add(2 * time.Microsecond)
	splitAt := createdAt.Add(3 * time.Microsecond)
	coherentAt := createdAt.Add(4 * time.Microsecond)
	incompleteValues := inspectionFullHostMetricValues()
	delete(incompleteValues, "dbpilot.inspection.host.log.critical_count")
	incompletePayload := inspectionMetricPayloadForValues(t, incompleteValues, incompleteAt, "inspection-host-snapshot")
	incompleteAck, err := ingestService.PushMetricBatch(inspectionIngestPeerContext("agent-a"), metricBatch("inspection-incomplete-source", "agent-a", "inspection-host-snapshot", incompletePayload))
	require.NoError(t, err)
	require.True(t, incompleteAck.GetAccepted())
	splitPayload := inspectionMetricPayloadForValues(t, map[string]float64{"dbpilot.inspection.host.log.critical_count": 0}, splitAt, "inspection-host-snapshot")
	splitAck, err := ingestService.PushMetricBatch(inspectionIngestPeerContext("agent-a"), metricBatch("inspection-split-source", "agent-a", "inspection-host-snapshot", splitPayload))
	require.NoError(t, err)
	require.True(t, splitAck.GetAccepted())
	splitEvidence, err := repository.LoadHostSnapshot(ctx, scope, "agent-a", items, createdAt, createdAt.Add(10*time.Second), 256)
	require.NoError(t, err)
	require.False(t, splitEvidence.Complete, "required observations split across timestamps must not form one host snapshot")

	validPayload := inspectionMetricPayloadForValues(t, inspectionFullHostMetricValues(), coherentAt, "inspection-host-snapshot")
	validAck, err := ingestService.PushMetricBatch(inspectionIngestPeerContext("agent-a"), metricBatch("inspection-valid-source", "agent-a", "inspection-host-snapshot", validPayload))
	require.NoError(t, err)
	require.True(t, validAck.GetAccepted())
	var acceptedAt, maximumAcceptedAt time.Time
	var coherentSamples int
	require.NoError(t, database.QueryRowContext(ctx, `SELECT min(accepted_at), max(accepted_at), count(*) FROM metric_samples WHERE tenant_id=$1 AND project_id=$2 AND agent_id=$3 AND labels->>'dbpilot_source_id'=$4 AND sampled_at=$5`, scope.TenantID, scope.ProjectID, "agent-a", "inspection-host-snapshot", coherentAt).Scan(&acceptedAt, &maximumAcceptedAt, &coherentSamples))
	acceptedAt = acceptedAt.UTC()
	maximumAcceptedAt = maximumAcceptedAt.UTC()
	require.Equal(t, 18, coherentSamples)
	require.Equal(t, acceptedAt, maximumAcceptedAt, "one atomic authenticated batch must share its server acceptance timestamp")
	require.True(t, acceptedAt.After(createdAt))
	tooEarly, err := repository.LoadHostSnapshot(ctx, scope, "agent-a", items, createdAt, acceptedAt.Add(-time.Microsecond), 256)
	require.NoError(t, err)
	require.False(t, tooEarly.Complete, "backdated data accepted after the server deadline must remain unusable")
	completeEvidence, err := repository.LoadHostSnapshot(ctx, scope, "agent-a", items, createdAt, createdAt.Add(10*time.Second), 256)
	require.NoError(t, err)
	require.True(t, completeEvidence.Complete)
	require.Equal(t, coherentAt, completeEvidence.SampledAt, "the newest complete coherent snapshot must win over incomplete/split distractors")

	blobRoot := filepath.Join(t.TempDir(), "artifacts")
	require.NoError(t, os.MkdirAll(blobRoot, 0o700))
	blobs := artifact.NewLocalBlobStore(blobRoot)
	require.NoError(t, blobs.Ready())
	t.Cleanup(func() { require.NoError(t, blobs.Close()) })
	artifactStore := artifact.NewPostgresStore(database, blobs)
	worker := &inspection.Worker{
		Runs: repository, Jobs: jobRepository, Evaluator: &inspection.Evaluator{Evidence: repository},
		Artifacts: artifactStore, Audit: auditService,
	}
	processed, err := worker.Process(ctx, time.Now().UTC(), 4)
	require.NoError(t, err)
	require.Equal(t, 1, processed)

	detail, err := repository.GetRun(ctx, scope, run.ID)
	require.NoError(t, err)
	require.Equal(t, inspection.RunPartial, detail.Run.Status)
	require.Equal(t, 1, detail.Run.CompletedTargetCount)
	require.Equal(t, 1, detail.Run.FailedTargetCount)
	require.Len(t, detail.Findings, 13)
	for _, finding := range detail.Findings {
		require.Equal(t, "agent-a", finding.TargetID)
		require.NotEqual(t, inspection.LevelMissingData, finding.Level, finding.ItemID)
		require.NotEqual(t, inspection.LevelUnsupported, finding.Level, finding.ItemID)
	}
	require.Equal(t, "12", inspectionFindingByItem(t, detail.Findings, "host.cpu.utilization").Evidence["value"])
	require.Equal(t, map[string]inspection.TargetStatus{"agent-a": inspection.TargetSucceeded, "agent-b": inspection.TargetFailed}, inspectionTargetStatuses(detail.Targets))

	report, err := repository.GetReport(ctx, scope, detail.Run.ReportID)
	require.NoError(t, err)
	require.Equal(t, inspection.ReportCompleted, report.Status)
	require.Len(t, report.Artifacts, 2)
	artifactRows := make([]artifact.Artifact, 0, 2)
	for _, reference := range report.Artifacts {
		stored, getErr := artifactStore.Get(ctx, scope, reference.ArtifactID)
		require.NoError(t, getErr)
		require.Equal(t, run.JobID, stored.JobID)
		require.Equal(t, artifact.ResourceReference{ResourceType: "inspection_report", ResourceID: report.ID}, stored.SourceResource)
		reader, openErr := blobs.Open(ctx, stored)
		require.NoError(t, openErr)
		contents, readErr := io.ReadAll(reader)
		require.NoError(t, readErr)
		require.NoError(t, reader.Close())
		require.Equal(t, stored.SizeBytes, int64(len(contents)))
		digest := sha256.Sum256(contents)
		require.Equal(t, stored.Checksum, "sha256:"+hex.EncodeToString(digest[:]))
		artifactRows = append(artifactRows, stored)
	}
	sort.Slice(artifactRows, func(i, j int) bool { return artifactRows[i].ContentType < artifactRows[j].ContentType })
	require.Equal(t, []string{"application/json", "text/html; charset=utf-8"}, []string{artifactRows[0].ContentType, artifactRows[1].ContentType})
	var document inspection.ReportDocument
	require.NoError(t, json.Unmarshal(report.Snapshot, &document))
	require.Len(t, document.Items, 13)
	require.Len(t, document.Findings, 13)
	require.Equal(t, run.JobID, document.References.JobID)
	require.Equal(t, run.AuditCorrelation, document.References.AuditCorrelation)
	require.ElementsMatch(t, []string{commands["agent-a"], commands["agent-b"]}, []string{document.References.Commands[0].CommandID, document.References.Commands[1].CommandID})

	audits, err := auditService.List(ctx, scope, audit.ListQuery{Limit: 100})
	require.NoError(t, err)
	commandAudits := map[string]bool{}
	reportAudits := 0
	for _, event := range audits.Items {
		require.Equal(t, run.RequestID, event.RequestID)
		require.Equal(t, run.TraceID, event.TraceID)
		require.Equal(t, run.JobID, event.JobID)
		if event.Action == "command.result" {
			commandAudits[event.CommandID] = true
		}
		if event.Action == "inspection.report.completed" {
			reportAudits++
			require.Equal(t, report.ID, event.Resource.ID)
		}
	}
	require.Equal(t, map[string]bool{commands["agent-a"]: true, commands["agent-b"]: true}, commandAudits)
	require.Equal(t, 1, reportAudits)

	_, err = database.ExecContext(ctx, "UPDATE inspection_findings SET summary='mutated' WHERE tenant_id=$1 AND project_id=$2 AND run_id=$3", scope.TenantID, scope.ProjectID, run.ID)
	require.Error(t, err, "Findings must be append-only")
	_, err = database.ExecContext(ctx, "UPDATE inspection_reports SET summary='mutated' WHERE tenant_id=$1 AND project_id=$2 AND id=$3", scope.TenantID, scope.ProjectID, report.ID)
	require.Error(t, err, "Reports must be append-only")
	_, err = database.ExecContext(ctx, "UPDATE audit_events SET result='mutated' WHERE tenant_id=$1 AND project_id=$2 AND dedupe_key=$3", scope.TenantID, scope.ProjectID, run.AuditCorrelation+":report")
	require.Error(t, err, "Audit must be append-only")

	originalArtifact := artifactRows[0]
	tampered := []byte("tampered report bytes")
	tamperedDigest := sha256.Sum256(tampered)
	originalArtifact.SizeBytes = int64(len(tampered))
	originalArtifact.Checksum = "sha256:" + hex.EncodeToString(tamperedDigest[:])
	originalArtifact.StorageReference = ""
	_, err = artifactStore.Put(ctx, originalArtifact, tampered)
	require.ErrorIs(t, err, artifact.ErrConflict)
	storedArtifact, err := artifactStore.Get(ctx, scope, originalArtifact.ID)
	require.NoError(t, err)
	require.Equal(t, artifactRows[0].Checksum, storedArtifact.Checksum)

	processed, err = worker.Process(ctx, time.Now().UTC().Add(time.Second), 4)
	require.NoError(t, err)
	require.Zero(t, processed)
	assertInspectionCompletionCounts(t, ctx, database, scope, run, 13, 1, 2, 1)
	finalReport, err := repository.GetReport(ctx, scope, report.ID)
	require.NoError(t, err)
	require.Equal(t, report, finalReport, "completed report and Artifact references must be byte-for-byte stable on retry")
	t.Logf("host inspection evidence: run=%s status=%s findings=13 reports=1 artifacts=2 accepted_at=%s commands=%s,%s", run.ID, detail.Run.Status, acceptedAt.Format(time.RFC3339Nano), commands["agent-a"], commands["agent-b"])
}

type inspectionScopeResolver map[string]alert.Scope

func (resolver inspectionScopeResolver) ScopeForAgent(_ context.Context, agentID string) (alert.Scope, error) {
	scope, ok := resolver[agentID]
	if !ok {
		return alert.Scope{}, errors.New("unknown inspection Agent")
	}
	return scope, nil
}

func inspectionIngestPeerContext(agentID string) context.Context {
	identity, _ := url.Parse("spiffe://dbpilot/agent/" + agentID)
	certificate := &x509.Certificate{URIs: []*url.URL{identity}}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: state}})
}

func inspectionMetricPayload(t *testing.T, metric string, value float64, sampledAt time.Time, sourceID string) []byte {
	return inspectionMetricPayloadForValues(t, map[string]float64{metric: value}, sampledAt, sourceID)
}

func inspectionMetricPayloadForValues(t *testing.T, values map[string]float64, sampledAt time.Time, sourceID string) []byte {
	t.Helper()
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	samples := make([]any, 0, len(names))
	for _, name := range names {
		samples = append(samples, map[string]any{
			"name": name, "value": values[name], "sampled_at": sampledAt.UTC().Format(time.RFC3339Nano),
			"labels": inspectionHostSnapshotLabels(sourceID),
		})
	}
	payload, err := json.Marshal(map[string]any{"samples": samples})
	require.NoError(t, err)
	return payload
}

func inspectionHostSnapshotLabels(sourceID string) map[string]string {
	return map[string]string{
		"instance": "inspection-host-snapshot", "component": "inspection-host-snapshot",
		"role": "collector", "host": "db-a", "dbpilot_source_id": sourceID,
	}
}

func inspectionFullHostMetricValues() map[string]float64 {
	return map[string]float64{
		"system.cpu.utilization":                                       12,
		"system.cpu.load_average.1m_per_cpu":                           0.5,
		"system.memory.utilization":                                    22,
		"system.swap.utilization":                                      3,
		"system.filesystem.utilization":                                40,
		"system.filesystem.inode_utilization":                          30,
		"dbpilot.inspection.host.agent.heartbeat_age_seconds":          0,
		"dbpilot.inspection.host.metric.age_seconds":                   0,
		"dbpilot.inspection.host.spool.utilization":                    10,
		"dbpilot.inspection.host.log.summary_available":                1,
		"dbpilot.inspection.host.oom.count":                            0,
		"dbpilot.inspection.host.time.synchronization_available":       1,
		"dbpilot.inspection.host.time.synchronized":                    1,
		"dbpilot.inspection.host.database.process_allowlist_available": 1,
		"dbpilot.inspection.host.database.required_process_count":      2,
		"dbpilot.inspection.host.log.warning_count":                    1,
		"dbpilot.inspection.host.log.error_count":                      0,
		"dbpilot.inspection.host.log.critical_count":                   0,
	}
}

func metricBatch(batchID, agentID, sourceID string, payload []byte) *agentv1.MetricBatch {
	digest := sha256.Sum256(payload)
	return &agentv1.MetricBatch{BatchId: batchID, AgentId: agentID, SourceId: sourceID, Payload: payload, Checksum: digest[:]}
}

func inspectionTargetStatuses(targets []inspection.TargetRun) map[string]inspection.TargetStatus {
	result := make(map[string]inspection.TargetStatus, len(targets))
	for _, target := range targets {
		result[target.TargetID] = target.Status
	}
	return result
}

func inspectionFindingByItem(t *testing.T, findings []inspection.Finding, itemID string) inspection.Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.ItemID == itemID {
			return finding
		}
	}
	t.Fatalf("inspection finding %q not found", itemID)
	return inspection.Finding{}
}

func assertInspectionCreationCounts(t *testing.T, ctx context.Context, database interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, scope platformscope.Scope, run inspection.Run, wantRuns, wantTargets, wantCommands int) {
	t.Helper()
	var runs, targets, commands int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM inspection_runs WHERE tenant_id=$1 AND project_id=$2 AND idempotency_key=$3", scope.TenantID, scope.ProjectID, "host-inspection-e2e").Scan(&runs))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM inspection_target_runs WHERE tenant_id=$1 AND project_id=$2 AND run_id=$3", scope.TenantID, scope.ProjectID, run.ID).Scan(&targets))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM command_outbox WHERE tenant_id=$1 AND project_id=$2 AND job_id=$3", scope.TenantID, scope.ProjectID, run.JobID).Scan(&commands))
	require.Equal(t, []int{wantRuns, wantTargets, wantCommands}, []int{runs, targets, commands})
}

func assertInspectionCompletionCounts(t *testing.T, ctx context.Context, database interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, scope platformscope.Scope, run inspection.Run, wantFindings, wantReports, wantArtifacts, wantReportAudits int) {
	t.Helper()
	var findings, reports, artifacts, reportAudits int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM inspection_findings WHERE tenant_id=$1 AND project_id=$2 AND run_id=$3", scope.TenantID, scope.ProjectID, run.ID).Scan(&findings))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM inspection_reports WHERE tenant_id=$1 AND project_id=$2 AND run_id=$3", scope.TenantID, scope.ProjectID, run.ID).Scan(&reports))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM artifacts WHERE tenant_id=$1 AND project_id=$2 AND job_id=$3 AND kind='inspection-report'", scope.TenantID, scope.ProjectID, run.JobID).Scan(&artifacts))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND project_id=$2 AND dedupe_key=$3", scope.TenantID, scope.ProjectID, run.AuditCorrelation+":report").Scan(&reportAudits))
	require.Equal(t, []int{wantFindings, wantReports, wantArtifacts, wantReportAudits}, []int{findings, reports, artifacts, reportAudits})
}
