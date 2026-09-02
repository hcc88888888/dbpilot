package main

import (
	"context"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/commandjournal"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

type fixedTrialJournal struct {
	entry commandjournal.Entry
	err   error
}

func (journal fixedTrialJournal) Get(context.Context, string) (commandjournal.Entry, error) {
	return journal.entry, journal.err
}

func TestDiagnoseHostPluginTrialReportsOnlyBoundedLifecycleFields(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	mock.ExpectQuery("SELECT job.status, command.id, command.command_status, command.command_phase").
		WithArgs("tenant-a", "project-a", "job-high").
		WillReturnRows(sqlmock.NewRows([]string{"status", "id", "command_status", "command_phase"}).AddRow("running", "command-high", "active", "running"))
	journal := fixedTrialJournal{entry: commandjournal.Entry{
		CommandID:  "command-high",
		State:      commandjournal.StateCompleted,
		ReportedAt: time.Now().UTC(),
		Result: &agentv1.CommandResult{
			State:                     agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED,
			MetricTemplateTrialResult: &agentv1.MetricTemplateTrialResult{StatusCode: "high_cardinality"},
		},
	}}

	diagnostic, err := DiagnoseHostPluginTrial(context.Background(), database, journal, "tenant-a", "project-a", "job-high")
	require.NoError(t, err)
	require.Equal(t, trialDiagnostic{JobStatus: "running", CommandStatus: "active", CommandPhase: "running", JournalState: "completed", ResultState: "failed", TrialCode: "high_cardinality", Reported: true}, diagnostic)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssertHostPluginDatabaseRequiresCompleteScopedDurableEvidence(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	state := hostPluginState{EnrollmentRevision: 1, VersionID: "version-1", PluginVersion: "1.0.0", AssignmentID: "assignment-1", AssignmentPID: 42, FirstInstancePID: 42, InstanceIDs: []string{"mysql-1", "mysql-2"}, TemplateID: "template-1", TemplateRevisionID: "revision-1", HighCardinalityJobID: "job-high", HighCardinalityRevisionID: "revision-high", DiagnosticStage: "failure-canary", RestartBoundaries: map[string]hostPluginRestartBoundary{"agent": {ObservedAt: "2026-09-03T00:00:00Z", SampleAt: "2026-09-03T00:00:01Z"}, "server": {ObservedAt: "2026-09-03T00:00:02Z", SampleAt: "2026-09-03T00:00:03Z"}}}
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM managed_hosts").WithArgs("tenant-a", "project-a", "agent-a").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM managed_database_instances").WithArgs("tenant-a", "project-a", "mysql-1", "mysql-2").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM plugin_assignments").WithArgs("tenant-a", "project-a", "assignment-1").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM plugin_observations").WithArgs("tenant-a", "project-a", "assignment-1").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT COUNT\\(DISTINCT metric\\)").WithArgs("tenant-a", "project-a", "mysql-1", "mysql-2").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM metric_template_revisions").WithArgs("tenant-a", "project-a", "revision-1").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM metric_template_trials").WithArgs("tenant-a", "project-a", "job-high", "revision-high").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_events").WithArgs("tenant-a", "project-a").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(12))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_events.*detail::text").WithArgs("tenant-a", "project-a").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM \\(SELECT .* FROM metric_samples.*GROUP BY").WithArgs("tenant-a", "project-a").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("SELECT operation.command_id FROM plugin_reconcile_operations").WithArgs("tenant-a", "project-a", "assignment-1").WillReturnRows(sqlmock.NewRows([]string{"command_id"}).AddRow("command-1"))

	commandID, err := AssertHostPluginDatabase(context.Background(), database, "tenant-a", "project-a", "agent-a", state)
	require.NoError(t, err)
	require.Equal(t, "command-1", commandID)
	require.NoError(t, mock.ExpectationsWereMet())
}
