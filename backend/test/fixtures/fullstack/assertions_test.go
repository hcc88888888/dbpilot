package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/commandjournal"
	"dbpilot.local/platform/internal/spool"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAssertDatabaseRequiresScopedRunTargetsFindingsReportArtifactsAuditsAndMetrics(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC)
	options := validAssertionOptions()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, job_id, report_id, status, target_count, completed_target_count, failed_target_count, audit_correlation, request_id, trace_id, started_at, finished_at FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND id = $3")).
		WithArgs(options.TenantID, options.ProjectID, options.RunID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "job_id", "report_id", "status", "target_count", "completed_target_count", "failed_target_count", "audit_correlation", "request_id", "trace_id", "started_at", "finished_at"}).
			AddRow(options.RunID, options.JobID, options.ReportID, "partial", 2, 1, 1, options.AuditCorrelation, "request-run", "trace-run", now, now.Add(time.Minute)))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT target_id, agent_id, command_id, status, error_code, observed_at FROM inspection_target_runs WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 ORDER BY target_id")).
		WithArgs(options.TenantID, options.ProjectID, options.RunID).
		WillReturnRows(sqlmock.NewRows([]string{"target_id", "agent_id", "command_id", "status", "error_code", "observed_at"}).
			AddRow("agent-offline", options.OfflineAgentID, "command-offline", "failed", "agent_offline", nil).
			AddRow("agent-online", options.OnlineAgentID, "command-online", "succeeded", "", now))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, target_id, message_type, command_phase, command_status, terminal_at FROM command_outbox WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3 ORDER BY id")).
		WithArgs(options.TenantID, options.ProjectID, options.JobID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "target_id", "message_type", "command_phase", "command_status", "terminal_at"}).
			AddRow("command-offline", options.OfflineAgentID, "agent.command", "timed_out", "timed_out", now).
			AddRow("command-online", options.OnlineAgentID, "agent.command", "succeeded", "succeeded", now))
	findingRows := sqlmock.NewRows([]string{"target_id", "item_id", "item_version", "level", "observed_at"})
	for index := 0; index < 13; index++ {
		findingRows.AddRow("agent-online", fmt.Sprintf("host.item.%02d", index), 1, "healthy", now)
	}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT target_id, item_id, item_version, level, observed_at FROM inspection_findings WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 ORDER BY target_id, item_id, item_version")).
		WithArgs(options.TenantID, options.ProjectID, options.RunID).WillReturnRows(findingRows)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, run_id, status, generated_at FROM inspection_reports WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 ORDER BY id")).
		WithArgs(options.TenantID, options.ProjectID, options.RunID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "run_id", "status", "generated_at"}).AddRow(options.ReportID, options.RunID, "completed", now.Add(2*time.Minute)))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, job_id, source_resource_type, source_resource_id, content_type, size_bytes, checksum, storage_reference FROM artifacts WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3 ORDER BY id")).
		WithArgs(options.TenantID, options.ProjectID, options.JobID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "job_id", "source_resource_type", "source_resource_id", "content_type", "size_bytes", "checksum", "storage_reference"}).
			AddRow("artifact-html", options.JobID, "inspection_report", options.ReportID, "text/html; charset=utf-8", 100, "sha256:html", "reports/report.html").
			AddRow("artifact-json", options.JobID, "inspection_report", options.ReportID, "application/json", 100, "sha256:json", "reports/report.json"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, action, resource_type, resource_id, request_id, trace_id, job_id, command_id, dedupe_key FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND (resource_id = $4 OR (job_id = $3 AND action IN ('inspection.report.completed', 'command.result', 'command.delivery_timed_out', 'command.undelivered_timed_out', 'command.prepared_timed_out', 'command.prepared_envelope_expired', 'command.execution_timed_out', 'command.skipped_terminal_job', 'command.prepared_terminal_job'))) ORDER BY id")).
		WithArgs(options.TenantID, options.ProjectID, options.JobID, options.RunID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "action", "resource_type", "resource_id", "request_id", "trace_id", "job_id", "command_id", "dedupe_key"}).
			AddRow("audit-run", "inspection.run.created", "inspection_run", options.RunID, "request-run", "trace-run", "", "", "http:inspection-run").
			AddRow("audit-command-offline", "command.prepared_timed_out", "job_target", options.OfflineAgentID, "request-command", "trace-command", options.JobID, "command-offline", "command.prepared_timed_out:command-offline").
			AddRow("audit-command-online", "command.result", "job_target", options.OnlineAgentID, "request-command", "trace-command", options.JobID, "command-online", "command.result:command-online").
			AddRow("audit-report", "inspection.report.completed", "inspection_report", options.ReportID, "request-report", "trace-report", options.JobID, "", options.AuditCorrelation+":report"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT agent_id, metric, series_fingerprint, labels->>'dbpilot_source_id' AS source_id, sampled_at, accepted_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND agent_id = $3 ORDER BY sampled_at, metric, series_fingerprint")).
		WithArgs(options.TenantID, options.ProjectID, options.OnlineAgentID).
		WillReturnRows(sqlmock.NewRows([]string{"agent_id", "metric", "series_fingerprint", "source_id", "sampled_at", "accepted_at"}).
			AddRow(options.OnlineAgentID, "system.cpu.utilization", "cpu-total", "inspection-host-snapshot", now, now.Add(time.Second)))
	mock.ExpectQuery(regexp.QuoteMeta(assertRogueRowsSQL)).
		WithArgs(options.TenantID, options.ProjectID, "agent-untrusted", "agent-claimed-id", "agent-certificate-id").
		WillReturnRows(sqlmock.NewRows([]string{"metric_rows", "monitoring_rows", "target_rows", "command_rows", "audit_rows"}).AddRow(0, 0, 0, 0, 0))

	require.NoError(t, AssertDatabase(context.Background(), database, options))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssertDatabaseRejectsDuplicateOrOutOfScopeFacts(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	options := validAssertionOptions()
	now := time.Now().UTC()
	mock.ExpectQuery("SELECT id, job_id, report_id").
		WithArgs(options.TenantID, options.ProjectID, options.RunID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "job_id", "report_id", "status", "target_count", "completed_target_count", "failed_target_count", "audit_correlation", "request_id", "trace_id", "started_at", "finished_at"}).
			AddRow(options.RunID, options.JobID, options.ReportID, "partial", 2, 1, 1, options.AuditCorrelation, "request", "trace", now, now).
			AddRow(options.RunID, options.JobID, options.ReportID, "partial", 2, 1, 1, options.AuditCorrelation, "request", "trace", now, now))

	err = AssertDatabase(context.Background(), database, options)
	require.ErrorContains(t, err, "exactly one scoped inspection Run")
}

func TestAssertDatabaseRedactsSensitiveDriverErrors(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	options := validAssertionOptions()
	options.SensitiveValues = []string{"postgres://dbpilot:super-secret@postgres/dbpilot", "token-secret"}
	mock.ExpectQuery("SELECT id, job_id, report_id").WillReturnError(errors.New("dial postgres://dbpilot:super-secret@postgres/dbpilot token-secret"))

	err = AssertDatabase(context.Background(), database, options)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "super-secret")
	require.NotContains(t, err.Error(), "token-secret")
	require.Contains(t, err.Error(), "[REDACTED]")
}

func TestBuildSuccessSummaryEmitsOnlyAllowlistedValidatedState(t *testing.T) {
	options := validAssertionOptions()
	options.TenantID = "tenant-must-not-be-emitted"
	options.PolicyID = "policy-must-not-be-emitted"
	options.AuditCorrelation = "correlation-must-not-be-emitted"
	options.ControlplaneStoppedAt = time.Date(2026, 8, 29, 4, 0, 10, 0, time.UTC)
	options.ControlplaneRestartedAt = time.Date(2026, 8, 29, 4, 1, 0, 0, time.UTC)
	options.TargetCount = 2
	options.FindingCount = 13
	options.ReportCount = 1
	options.ArtifactCount = 2
	options.AuditCount = 4

	summary, err := BuildSuccessSummary(options)
	require.NoError(t, err)
	body, err := json.Marshal(summary)
	require.NoError(t, err)
	require.JSONEq(t, `{"run_id":"run-acceptance","job_id":"job-acceptance","online_command_id":"command-online","offline_command_id":"command-offline","report_id":"report-acceptance","target_count":2,"finding_count":13,"report_count":1,"artifact_count":2,"audit_count":4,"controlplane_stopped_at":"2026-08-29T04:00:10Z","controlplane_restarted_at":"2026-08-29T04:01:00Z"}`, string(body))
	for _, forbidden := range []string{"tenant-must-not-be-emitted", "policy-must-not-be-emitted", "correlation-must-not-be-emitted", "replay_batch_id", "metric_sample_at"} {
		require.NotContains(t, string(body), forbidden)
	}

	options.ControlplaneRestartedAt = options.ControlplaneStoppedAt
	_, err = BuildSuccessSummary(options)
	require.EqualError(t, err, "success summary phase state is invalid")
}

func TestRunSummaryRejectsUnknownStateWithoutEchoingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase-state.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"version":1,"token":"Bearer eyJsecret.payload.signature"}`), 0o600))
	var stdout, stderr bytes.Buffer

	exitCode := runSummary([]string{"--phase-state-file", path}, &stdout, &stderr)

	require.Equal(t, 2, exitCode)
	require.Empty(t, stdout.String())
	require.Equal(t, "success summary phase state is unavailable or invalid\n", stderr.String())
	require.NotContains(t, stderr.String(), "eyJsecret")
}

func TestAssertJournalRequiresCompletedReportedCommandAndNoPendingResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "command-journal.db")
	now := time.Now().UTC()
	journal, err := commandjournal.Open(path)
	require.NoError(t, err)
	envelope := &agentv1.CommandEnvelope{
		CommandId: "command-online", JobId: "job-acceptance", AgentId: "agent-online", Nonce: []byte("nonce-command-online"),
		IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"host"}}},
	}
	inserted, err := journal.Prepare(context.Background(), envelope, now)
	require.NoError(t, err)
	require.True(t, inserted)
	token := bytes.Repeat([]byte{0x42}, sha256.Size)
	require.NoError(t, journal.AuthorizeStart(context.Background(), "command-online", token, 1, now.Add(30*time.Minute)))
	result := &agentv1.CommandResult{CommandId: "command-online", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "accepted", ExecutionToken: token, LeaseRevision: 1}
	require.NoError(t, journal.Complete(context.Background(), "command-online", result, now.Add(time.Minute)))
	pending, err := journal.PendingResults(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.NoError(t, journal.MarkReported(context.Background(), "command-online", pending[0].ResultDigest, now.Add(2*time.Minute)))
	require.NoError(t, journal.Close())

	require.NoError(t, AssertJournal(path, JournalAssertion{CommandID: "command-online"}))
}

func TestAssertJournalRejectsMissingPathWithoutRetainingIt(t *testing.T) {
	sensitivePath := filepath.Join(t.TempDir(), "missing", "token-secret-journal.db")
	err := AssertJournal(sensitivePath, JournalAssertion{CommandID: "command-online", SensitiveValues: []string{sensitivePath, "token-secret"}})
	require.Error(t, err)
	require.NotContains(t, err.Error(), sensitivePath)
	require.NotContains(t, err.Error(), "token-secret")
	require.Equal(t, "open Agent command journal: existing regular command journal is required", err.Error())
}

func TestRunJournalAssertionsReadsCommandIDFromPhaseState(t *testing.T) {
	root := t.TempDir()
	journalPath := filepath.Join(root, "command-journal.db")
	now := time.Now().UTC()
	journal, err := commandjournal.Open(journalPath)
	require.NoError(t, err)
	envelope := &agentv1.CommandEnvelope{
		CommandId: "command-online", JobId: "job-acceptance", AgentId: "agent-online", Nonce: []byte("nonce-command-online"),
		IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"host"}}},
	}
	inserted, err := journal.Prepare(context.Background(), envelope, now)
	require.NoError(t, err)
	require.True(t, inserted)
	token := bytes.Repeat([]byte{0x42}, sha256.Size)
	require.NoError(t, journal.AuthorizeStart(context.Background(), "command-online", token, 1, now.Add(30*time.Minute)))
	result := &agentv1.CommandResult{CommandId: "command-online", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, ExecutionToken: token, LeaseRevision: 1}
	require.NoError(t, journal.Complete(context.Background(), "command-online", result, now.Add(time.Minute)))
	pending, err := journal.PendingResults(context.Background())
	require.NoError(t, err)
	require.NoError(t, journal.MarkReported(context.Background(), "command-online", pending[0].ResultDigest, now.Add(2*time.Minute)))
	require.NoError(t, journal.Close())

	phasePath := filepath.Join(root, "phase-state.json")
	phaseBody, err := json.Marshal(validAssertionOptions())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(phasePath, phaseBody, 0o600))
	stderr := &bytes.Buffer{}
	code := run([]string{"journal", "--path", journalPath, "--phase-state-file", phasePath}, io.Discard, stderr)
	require.Zero(t, code, stderr.String())
}

func TestAssertDatabaseHonorsCancelledContext(t *testing.T) {
	database, _, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, AssertDatabase(ctx, database, validAssertionOptions()), context.Canceled)
}

func TestAssertMetricsAcceptsProductionMultiSeriesAtOneSampleTime(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	options := validAssertionOptions()
	now := time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT agent_id, metric, series_fingerprint, labels->>'dbpilot_source_id' AS source_id, sampled_at, accepted_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND agent_id = $3 ORDER BY sampled_at, metric, series_fingerprint")).
		WithArgs(options.TenantID, options.ProjectID, options.OnlineAgentID).
		WillReturnRows(sqlmock.NewRows([]string{"agent_id", "metric", "series_fingerprint", "source_id", "sampled_at", "accepted_at"}).
			AddRow(options.OnlineAgentID, "system.disk.io", "disk-sda-read", "inspection-host-snapshot", now, now.Add(time.Second)).
			AddRow(options.OnlineAgentID, "system.disk.io", "disk-sda-write", "inspection-host-snapshot", now, now.Add(time.Second)))

	require.NoError(t, assertMetrics(context.Background(), database, options))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssertMetricsRejectsDuplicateProductionIdentity(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	options := validAssertionOptions()
	now := time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT agent_id, metric, series_fingerprint, labels->>'dbpilot_source_id' AS source_id, sampled_at, accepted_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND agent_id = $3 ORDER BY sampled_at, metric, series_fingerprint")).
		WithArgs(options.TenantID, options.ProjectID, options.OnlineAgentID).
		WillReturnRows(sqlmock.NewRows([]string{"agent_id", "metric", "series_fingerprint", "source_id", "sampled_at", "accepted_at"}).
			AddRow(options.OnlineAgentID, "system.disk.io", "disk-sda-read", "inspection-host-snapshot", now, now.Add(time.Second)).
			AddRow(options.OnlineAgentID, "system.disk.io", "disk-sda-read", "inspection-host-snapshot", now, now.Add(time.Second)))

	err = assertMetrics(context.Background(), database, options)
	require.ErrorContains(t, err, "metric sample is duplicated")
}

func TestAssertAuditsRequiresBothExpectedCommandIDs(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	options := validAssertionOptions()
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, action, resource_type, resource_id, request_id, trace_id, job_id, command_id, dedupe_key FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND (resource_id = $4 OR (job_id = $3 AND action IN ('inspection.report.completed', 'command.result', 'command.delivery_timed_out', 'command.undelivered_timed_out', 'command.prepared_timed_out', 'command.prepared_envelope_expired', 'command.execution_timed_out', 'command.skipped_terminal_job', 'command.prepared_terminal_job'))) ORDER BY id")).
		WithArgs(options.TenantID, options.ProjectID, options.JobID, options.RunID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "action", "resource_type", "resource_id", "request_id", "trace_id", "job_id", "command_id", "dedupe_key"}).
			AddRow("audit-run", "inspection.run.created", "inspection_run", options.RunID, "request-run", "trace-run", "", "", "http:inspection-run").
			AddRow("audit-command-online", "command.result", "job_target", options.OnlineAgentID, "request-command", "trace-command", options.JobID, "command-online", "command.result:command-online").
			AddRow("audit-report", "inspection.report.completed", "inspection_report", options.ReportID, "request-report", "trace-report", options.JobID, "", options.AuditCorrelation+":report"))

	err = assertAudits(context.Background(), database, options, map[string]string{
		"command-online": options.OnlineAgentID, "command-offline": options.OfflineAgentID,
	})
	require.ErrorContains(t, err, "both expected Command Audit correlations")
}

func TestCommandAuditValidationAcceptsUndeliveredJobTimeout(t *testing.T) {
	const commandID = "command-offline"
	require.Contains(t, assertAuditsSQL, "'command.undelivered_timed_out'")
	require.True(t, validCommandAudit("command.undelivered_timed_out", "command.undelivered_timed_out:"+commandID, commandID, false))
}

func TestAssertCommandsRequiresBothScopedDurableTerminalRows(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	options := validAssertionOptions()
	now := time.Date(2026, 8, 29, 3, 0, 0, 0, time.UTC)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, target_id, message_type, command_phase, command_status, terminal_at FROM command_outbox WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3 ORDER BY id")).
		WithArgs(options.TenantID, options.ProjectID, options.JobID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "target_id", "message_type", "command_phase", "command_status", "terminal_at"}).
			AddRow("command-offline", options.OfflineAgentID, "agent.command", "timed_out", "timed_out", now).
			AddRow("command-online", options.OnlineAgentID, "agent.command", "succeeded", "succeeded", now))

	require.NoError(t, assertCommands(context.Background(), database, options, map[string]string{
		"command-online": options.OnlineAgentID, "command-offline": options.OfflineAgentID,
	}))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssertCommandsRejectsMissingOrNonterminalRows(t *testing.T) {
	tests := map[string]struct {
		rows *sqlmock.Rows
		want string
	}{
		"missing offline": {
			rows: sqlmock.NewRows([]string{"id", "target_id", "message_type", "command_phase", "command_status", "terminal_at"}).
				AddRow("command-online", "agent-online", "agent.command", "succeeded", "succeeded", time.Now().UTC()),
			want: "exactly both expected durable Commands",
		},
		"offline nonterminal": {
			rows: sqlmock.NewRows([]string{"id", "target_id", "message_type", "command_phase", "command_status", "terminal_at"}).
				AddRow("command-offline", "agent-offline", "agent.command", "prepared", "pending", nil).
				AddRow("command-online", "agent-online", "agent.command", "succeeded", "succeeded", time.Now().UTC()),
			want: "durable Command is not in an acceptable terminal phase",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			database, mock, err := sqlmock.New()
			require.NoError(t, err)
			t.Cleanup(func() { _ = database.Close() })
			options := validAssertionOptions()
			mock.ExpectQuery("SELECT id, target_id, message_type, command_phase, command_status, terminal_at FROM command_outbox").
				WithArgs(options.TenantID, options.ProjectID, options.JobID).WillReturnRows(test.rows)

			err = assertCommands(context.Background(), database, options, map[string]string{
				"command-online": options.OnlineAgentID, "command-offline": options.OfflineAgentID,
			})
			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestAssertTargetsRequiresExactPhaseStateCommandIDs(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	options := validAssertionOptions()
	now := time.Now().UTC()
	mock.ExpectQuery("SELECT target_id, agent_id, command_id").
		WithArgs(options.TenantID, options.ProjectID, options.RunID).
		WillReturnRows(sqlmock.NewRows([]string{"target_id", "agent_id", "command_id", "status", "error_code", "observed_at"}).
			AddRow("agent-offline", options.OfflineAgentID, "different-offline-command", "failed", "agent_offline", nil).
			AddRow("agent-online", options.OnlineAgentID, options.OnlineCommandID, "succeeded", "", now))

	_, err = assertTargets(context.Background(), database, options)
	require.ErrorContains(t, err, "phase state Command identity")
}

func TestAssertReplayRequiresExactOutageBatchAcceptedAfterRestartAndDrainedSpool(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	stoppedAt := time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC)
	restartedAt := stoppedAt.Add(time.Minute)
	sampledFrom, sampledTo, acceptedAt := stoppedAt.Add(10*time.Second), stoppedAt.Add(20*time.Second), restartedAt.Add(time.Second)
	mock.ExpectQuery("SELECT agent_id, batch_id, sampled_from, sampled_to, accepted_at").
		WithArgs("tenant-acceptance", "project-acceptance", "agent-online", stoppedAt, restartedAt).
		WillReturnRows(sqlmock.NewRows([]string{"agent_id", "batch_id", "sampled_from", "sampled_to", "accepted_at", "identity_count"}).
			AddRow("agent-online", "batch-outage-1", sampledFrom, sampledTo, acceptedAt, 1))
	spoolRoot := filepath.Join(t.TempDir(), "spool")
	store, err := spool.Open(spoolRoot, spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	require.NoError(t, store.Close())

	evidence, err := AssertReplay(context.Background(), database, spoolRoot, ReplayAssertion{
		TenantID: "tenant-acceptance", ProjectID: "project-acceptance", AgentID: "agent-online",
		ControlplaneStoppedAt: stoppedAt, ControlplaneRestartedAt: restartedAt,
	})
	require.NoError(t, err)
	require.Equal(t, "batch-outage-1", evidence.BatchID)
	require.Equal(t, sampledFrom, evidence.SampledFrom)
	require.Equal(t, sampledTo, evidence.SampledTo)
	require.Equal(t, acceptedAt, evidence.AcceptedAt)
	require.Zero(t, evidence.PendingBatchCount)
}

func TestAssertReplayRejectsFreshPostRestartBatchAndHistoricalGaugeEvidence(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	stoppedAt := time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC)
	restartedAt := stoppedAt.Add(time.Minute)
	freshAt := restartedAt.Add(time.Second)
	mock.ExpectQuery("SELECT agent_id, batch_id, sampled_from, sampled_to, accepted_at").
		WillReturnRows(sqlmock.NewRows([]string{"agent_id", "batch_id", "sampled_from", "sampled_to", "accepted_at", "identity_count"}).
			AddRow("agent-online", "batch-fresh", freshAt, freshAt, freshAt.Add(time.Second), 1))
	spoolRoot := filepath.Join(t.TempDir(), "spool")
	store, err := spool.Open(spoolRoot, spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	require.NoError(t, store.Close())

	_, err = AssertReplay(context.Background(), database, spoolRoot, ReplayAssertion{
		TenantID: "tenant-acceptance", ProjectID: "project-acceptance", AgentID: "agent-online",
		ControlplaneStoppedAt: stoppedAt, ControlplaneRestartedAt: restartedAt,
	})
	require.ErrorContains(t, err, "outage batch")
}

func TestAssertReplayRejectsExactOutageBatchWhileStoppedAgentSpoolIsPending(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	stoppedAt := time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC)
	restartedAt := stoppedAt.Add(time.Minute)
	mock.ExpectQuery("SELECT agent_id, batch_id, sampled_from, sampled_to, accepted_at").
		WillReturnRows(sqlmock.NewRows([]string{"agent_id", "batch_id", "sampled_from", "sampled_to", "accepted_at", "identity_count"}).
			AddRow("agent-online", "batch-outage", stoppedAt.Add(10*time.Second), stoppedAt.Add(20*time.Second), restartedAt.Add(time.Second), 1))
	spoolRoot := filepath.Join(t.TempDir(), "spool")
	store, err := spool.Open(spoolRoot, spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	require.NoError(t, store.Append(context.Background(), spool.Metric, spool.Batch{ID: "still-pending", SourceID: "acceptance-host", CreatedAt: stoppedAt, Payload: []byte("pending")}))
	require.NoError(t, store.Close())

	_, err = AssertReplay(context.Background(), database, spoolRoot, ReplayAssertion{
		TenantID: "tenant-acceptance", ProjectID: "project-acceptance", AgentID: "agent-online",
		ControlplaneStoppedAt: stoppedAt, ControlplaneRestartedAt: restartedAt,
	})
	require.ErrorContains(t, err, "1 pending batches")
}

func TestWithReplayEvidencePersistsOnlyExactBatchTimestampsAndCount(t *testing.T) {
	stoppedAt := time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC)
	restartedAt := stoppedAt.Add(time.Minute)
	options := validAssertionOptions()
	options.ControlplaneStoppedAt = stoppedAt
	options.ControlplaneRestartedAt = restartedAt
	evidence := ReplayEvidence{BatchID: "batch-outage-1", SampledFrom: stoppedAt.Add(10 * time.Second), SampledTo: stoppedAt.Add(20 * time.Second), AcceptedAt: restartedAt.Add(time.Second), PendingBatchCount: 0}

	updated, err := WithReplayEvidence(options, evidence)
	require.NoError(t, err)
	require.Equal(t, "batch-outage-1", updated.ReplayBatchID)
	require.Equal(t, evidence.SampledFrom, updated.ReplaySampledFrom)
	require.Equal(t, evidence.SampledTo, updated.ReplaySampledTo)
	require.Equal(t, evidence.AcceptedAt, updated.ReplayAcceptedAt)
	require.Zero(t, updated.ReplayPendingBatchCount)
	body, err := json.Marshal(updated)
	require.NoError(t, err)
	require.NotContains(t, string(body), `"accepted_at"`)
	require.NotContains(t, string(body), "spool_observed_count")
}

func TestWriteJSONFileAtomicReplacesPhaseStateWithPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase-state.json")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))
	require.NoError(t, writeJSONFileAtomic(path, map[string]any{"replay_batch_id": "batch-outage-1", "replay_pending_batch_count": 0}))
	var state map[string]any
	require.NoError(t, json.Unmarshal(mustRead(t, path), &state))
	require.Equal(t, "batch-outage-1", state["replay_batch_id"])
	info, err := os.Stat(path)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".phase-state-*.tmp"))
	require.NoError(t, err)
	require.Empty(t, matches)
}

func TestValidateAssertionOptionsRequiresReplayHeartbeatAndBothRoguePhasesAfterOutage(t *testing.T) {
	options := validAssertionOptions()
	options.ControlplaneStoppedAt = time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC)
	options.ControlplaneRestartedAt = options.ControlplaneStoppedAt.Add(time.Minute)
	options.PreRestartMetricSampleAt = options.ControlplaneStoppedAt.Add(-time.Second)
	options.PostRestartMetricSampleAt = options.ControlplaneRestartedAt.Add(time.Second)
	options.PreRestartAgentControlHeartbeatAt = options.ControlplaneStoppedAt.Add(-time.Second)
	options.PostRestartAgentControlHeartbeatAt = options.ControlplaneRestartedAt.Add(time.Second)
	options.ReplayBatchID = "batch-outage"
	options.ReplaySampledFrom = options.ControlplaneStoppedAt.Add(10 * time.Second)
	options.ReplaySampledTo = options.ControlplaneStoppedAt.Add(20 * time.Second)
	options.ReplayAcceptedAt = options.ControlplaneRestartedAt.Add(time.Second)

	err := validateAssertionOptions(options)
	require.ErrorContains(t, err, "rogue evidence is incomplete")
	options.RogueUntrustedVerifiedAt = options.ControlplaneRestartedAt.Add(2 * time.Second)
	options.RogueMismatchVerifiedAt = options.ControlplaneRestartedAt.Add(3 * time.Second)
	require.NoError(t, validateAssertionOptions(options))
}

func TestAssertRogueAgentsRequireZeroPersistentRows(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	options := validAssertionOptions()
	mock.ExpectQuery("SELECT").
		WithArgs(options.TenantID, options.ProjectID, "agent-untrusted", "agent-claimed-id", "agent-certificate-id").
		WillReturnRows(sqlmock.NewRows([]string{"metric_rows", "monitoring_rows", "target_rows", "command_rows", "audit_rows"}).AddRow(0, 0, 0, 0, 0))
	require.NoError(t, assertRogueRows(context.Background(), database, options))
	require.NoError(t, mock.ExpectationsWereMet())

	database2, mock2, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database2.Close() })
	mock2.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"metric_rows", "monitoring_rows", "target_rows", "command_rows", "audit_rows"}).AddRow(0, 1, 0, 0, 0))
	err = assertRogueRows(context.Background(), database2, options)
	require.ErrorContains(t, err, "rogue Agent created persistent rows")
}

func validAssertionOptions() AssertionOptions {
	return AssertionOptions{
		Version:  1,
		TenantID: "tenant-acceptance", ProjectID: "project-acceptance", RunID: "run-acceptance", JobID: "job-acceptance",
		ReportID: "report-acceptance", OnlineAgentID: "agent-online", OfflineAgentID: "agent-offline", AuditCorrelation: "acceptance-correlation",
		OnlineCommandID: "command-online", OfflineCommandID: "command-offline", JournalCommandID: "command-online",
	}
}

var _ *sql.DB
