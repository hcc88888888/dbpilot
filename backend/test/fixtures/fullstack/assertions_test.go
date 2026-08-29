package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
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
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, action, resource_type, resource_id, request_id, trace_id, job_id, command_id, dedupe_key FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND (job_id = $3 OR resource_id = $4) ORDER BY id")).
		WithArgs(options.TenantID, options.ProjectID, options.JobID, options.RunID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "action", "resource_type", "resource_id", "request_id", "trace_id", "job_id", "command_id", "dedupe_key"}).
			AddRow("audit-run", "inspection.run_created", "inspection_run", options.RunID, "request-run", "trace-run", "", "", "http:inspection-run").
			AddRow("audit-command", "command.completed", "job_target", "agent-online", "request-command", "trace-command", options.JobID, "command-online", "").
			AddRow("audit-report", "inspection.report_generated", "inspection_report", options.ReportID, "request-report", "trace-report", options.JobID, "", options.AuditCorrelation+":report"))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT agent_id, metric, labels->>'dbpilot_source_id' AS source_id, sampled_at, accepted_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND agent_id = $3 ORDER BY sampled_at, metric")).
		WithArgs(options.TenantID, options.ProjectID, options.OnlineAgentID).
		WillReturnRows(sqlmock.NewRows([]string{"agent_id", "metric", "source_id", "sampled_at", "accepted_at"}).
			AddRow(options.OnlineAgentID, "system.cpu.utilization", "inspection-host-snapshot", now, now.Add(time.Second)))

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

func TestAssertDatabaseHonorsCancelledContext(t *testing.T) {
	database, _, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, AssertDatabase(ctx, database, validAssertionOptions()), context.Canceled)
}

func validAssertionOptions() AssertionOptions {
	return AssertionOptions{
		TenantID: "tenant-acceptance", ProjectID: "project-acceptance", RunID: "run-acceptance", JobID: "job-acceptance",
		ReportID: "report-acceptance", OnlineAgentID: "agent-online", OfflineAgentID: "agent-offline", AuditCorrelation: "acceptance-correlation",
	}
}

var _ *sql.DB
