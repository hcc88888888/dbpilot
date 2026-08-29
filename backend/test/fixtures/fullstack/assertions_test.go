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
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/commandjournal"
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
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, action, resource_type, resource_id, request_id, trace_id, job_id, command_id, dedupe_key FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND (resource_id = $4 OR (job_id = $3 AND action IN ('inspection.report.completed', 'command.result', 'command.delivery_timed_out', 'command.prepared_timed_out', 'command.prepared_envelope_expired', 'command.execution_timed_out', 'command.skipped_terminal_job', 'command.prepared_terminal_job'))) ORDER BY id")).
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

func TestAssertJournalRejectsPendingResultAndRedactsPath(t *testing.T) {
	sensitivePath := filepath.Join(t.TempDir(), "missing", "token-secret-journal.db")
	err := AssertJournal(sensitivePath, JournalAssertion{CommandID: "command-online", SensitiveValues: []string{sensitivePath, "token-secret"}})
	require.Error(t, err)
	require.NotContains(t, err.Error(), sensitivePath)
	require.NotContains(t, err.Error(), "token-secret")
	require.Contains(t, err.Error(), "[REDACTED]")
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
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, action, resource_type, resource_id, request_id, trace_id, job_id, command_id, dedupe_key FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND (resource_id = $4 OR (job_id = $3 AND action IN ('inspection.report.completed', 'command.result', 'command.delivery_timed_out', 'command.prepared_timed_out', 'command.prepared_envelope_expired', 'command.execution_timed_out', 'command.skipped_terminal_job', 'command.prepared_terminal_job'))) ORDER BY id")).
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

func TestAssertMetricsRequiresPostRestartReplaySample(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	options := validAssertionOptions()
	options.PreRestartAcceptedAt = time.Date(2026, 8, 29, 4, 0, 0, 0, time.UTC)
	options.PostRestartAcceptedAt = options.PreRestartAcceptedAt.Add(time.Minute)
	mock.ExpectQuery("SELECT agent_id, metric, series_fingerprint").
		WithArgs(options.TenantID, options.ProjectID, options.OnlineAgentID).
		WillReturnRows(sqlmock.NewRows([]string{"agent_id", "metric", "series_fingerprint", "source_id", "sampled_at", "accepted_at"}).
			AddRow(options.OnlineAgentID, "system.cpu.utilization", "cpu-total", "inspection-host-snapshot", options.PreRestartAcceptedAt, options.PreRestartAcceptedAt.Add(time.Second)))

	err = assertMetrics(context.Background(), database, options)
	require.ErrorContains(t, err, "post-restart replay sample")
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
		TenantID: "tenant-acceptance", ProjectID: "project-acceptance", RunID: "run-acceptance", JobID: "job-acceptance",
		ReportID: "report-acceptance", OnlineAgentID: "agent-online", OfflineAgentID: "agent-offline", AuditCorrelation: "acceptance-correlation",
		OnlineCommandID: "command-online", OfflineCommandID: "command-offline", JournalCommandID: "command-online",
	}
}

var _ *sql.DB
