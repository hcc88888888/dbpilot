package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/commandjournal"
	"dbpilot.local/platform/internal/spool"
)

type hostPluginState struct {
	EnrollmentRevision        uint64                               `json:"enrollment_revision"`
	VersionID                 string                               `json:"version_id"`
	PluginVersion             string                               `json:"plugin_version"`
	AssignmentID              string                               `json:"assignment_id"`
	AssignmentPID             uint32                               `json:"assignment_pid"`
	FirstInstancePID          uint32                               `json:"first_instance_pid"`
	InstanceIDs               []string                             `json:"instance_ids"`
	TemplateID                string                               `json:"template_id"`
	TemplateRevisionID        string                               `json:"template_revision_id"`
	HighCardinalityJobID      string                               `json:"high_cardinality_job_id"`
	HighCardinalityRevisionID string                               `json:"high_cardinality_revision_id"`
	DiagnosticStage           string                               `json:"diagnostic_stage"`
	RestartBoundaries         map[string]hostPluginRestartBoundary `json:"restart_boundaries"`
}

type hostPluginRestartBoundary struct {
	ObservedAt string `json:"observed_at"`
	SampleAt   string `json:"sample_at"`
}

func runHostPluginAssertions(arguments []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("host-plugin", stderr)
	phase := flags.String("phase", "", "assertion phase")
	dsnFile := flags.String("dsn-file", "", "absolute PostgreSQL DSN file")
	agentData := flags.String("agent-data", "", "absolute stopped Agent data root")
	stateFile := flags.String("state-file", "", "absolute acceptance state file")
	tenantID := flags.String("tenant-id", "", "tenant")
	projectID := flags.String("project-id", "", "project")
	agentID := flags.String("agent-id", "", "agent")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || (*phase != "host-plugin" && *phase != "trial-diagnostic") || !filepath.IsAbs(*dsnFile) || !filepath.IsAbs(*agentData) || !filepath.IsAbs(*stateFile) || !safeAssertionID(*tenantID) || !safeAssertionID(*projectID) || !safeAssertionID(*agentID) {
		fmt.Fprintln(stderr, "host plugin assertion arguments are invalid")
		return 2
	}
	dsnBytes, err := readBoundedRegularFile(*dsnFile, 8<<10, true)
	if err != nil || len(dsnBytes) == 0 {
		fmt.Fprintln(stderr, "host plugin database credential is unavailable")
		return 2
	}
	dsn := string(dsnBytes)
	zeroBytes(dsnBytes)
	var state hostPluginState
	if decodeJSONFile(*stateFile, 64<<10, &state) != nil {
		fmt.Fprintln(stderr, "host plugin phase state is unavailable or invalid")
		return 2
	}
	if *phase == "host-plugin" {
		if reason := invalidHostPluginStateReason(state); reason != "" {
			fmt.Fprintln(stderr, "host plugin phase state invalid: "+reason)
			return 2
		}
	} else if !safeAssertionID(state.HighCardinalityJobID) {
		fmt.Fprintln(stderr, "host plugin phase state invalid: high-cardinality-job")
		return 2
	}
	database, err := sql.Open("postgres", dsn)
	if err != nil {
		fmt.Fprintln(stderr, "host plugin assertion connection failed")
		return 1
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if *phase == "trial-diagnostic" {
		journal, openErr := commandjournal.OpenReadOnly(filepath.Join(*agentData, "command-journal.db"))
		if openErr != nil {
			fmt.Fprintln(stderr, "Agent command journal diagnostic is unavailable")
			return 1
		}
		defer journal.Close()
		diagnostic, diagnoseErr := DiagnoseHostPluginTrial(ctx, database, journal, *tenantID, *projectID, state.HighCardinalityJobID)
		if diagnoseErr != nil || json.NewEncoder(stdout).Encode(diagnostic) != nil {
			fmt.Fprintln(stderr, "host plugin trial diagnostic is unavailable")
			return 1
		}
		return 0
	}
	commandID, err := AssertHostPluginDatabase(ctx, database, *tenantID, *projectID, *agentID, state)
	if err != nil {
		fmt.Fprintln(stderr, redactAssertionError(err, []string{dsn}))
		return 1
	}
	if err := AssertJournal(filepath.Join(*agentData, "command-journal.db"), JournalAssertion{CommandID: commandID}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	pending, err := spool.PendingBatchCount(*agentData)
	if err != nil || pending != 0 {
		fmt.Fprintln(stderr, "Agent spool retains pending metric batches")
		return 1
	}
	summary := map[string]any{"assignment_id": state.AssignmentID, "instance_count": len(state.InstanceIDs), "metric_count": 5, "spool_pending": pending, "journal_command_id": commandID, "audit_redaction": true}
	if json.NewEncoder(stdout).Encode(summary) != nil {
		return 1
	}
	return 0
}

type trialJournalReader interface {
	Get(context.Context, string) (commandjournal.Entry, error)
}

type trialDiagnostic struct {
	JobStatus     string `json:"job_status"`
	CommandStatus string `json:"command_status"`
	CommandPhase  string `json:"command_phase"`
	JournalState  string `json:"journal_state"`
	ResultState   string `json:"result_state"`
	TrialCode     string `json:"trial_code"`
	Reported      bool   `json:"reported"`
}

func DiagnoseHostPluginTrial(ctx context.Context, database *sql.DB, journal trialJournalReader, tenantID, projectID, jobID string) (trialDiagnostic, error) {
	if ctx == nil || database == nil || journal == nil || !safeAssertionID(tenantID) || !safeAssertionID(projectID) || !safeAssertionID(jobID) {
		return trialDiagnostic{}, errors.New("trial diagnostic input is invalid")
	}
	var diagnostic trialDiagnostic
	var commandID string
	err := database.QueryRowContext(ctx, `SELECT job.status, command.id, command.command_status, command.command_phase FROM jobs job JOIN command_outbox command ON command.tenant_id=job.tenant_id AND command.project_id=job.project_id AND command.job_id=job.id WHERE job.tenant_id=$1 AND job.project_id=$2 AND job.id=$3 ORDER BY command.id LIMIT 1`, tenantID, projectID, jobID).
		Scan(&diagnostic.JobStatus, &commandID, &diagnostic.CommandStatus, &diagnostic.CommandPhase)
	if err != nil || !safeAssertionID(commandID) {
		return trialDiagnostic{}, errors.New("trial diagnostic durable state is unavailable")
	}
	diagnostic.JobStatus = boundedDiagnosticValue(diagnostic.JobStatus, "dispatched", "running", "succeeded", "failed", "cancelled", "timed_out")
	diagnostic.CommandStatus = boundedDiagnosticValue(diagnostic.CommandStatus, "pending", "active", "succeeded", "failed", "rejected", "cancelled", "timed_out")
	diagnostic.CommandPhase = boundedDiagnosticValue(diagnostic.CommandPhase, "pending", "preparing", "prepared", "start_authorized", "running", "succeeded", "failed", "rejected", "cancelling", "cancelled", "timed_out")
	entry, err := journal.Get(ctx, commandID)
	if err != nil || entry.CommandID != commandID {
		return trialDiagnostic{}, errors.New("trial diagnostic journal state is unavailable")
	}
	diagnostic.JournalState = boundedDiagnosticValue(string(entry.State), "prepared", "start_authorized", "running", "interrupted", "completed", "cancelled", "result_conflicted")
	diagnostic.ResultState = boundedResultState(entry.Result.GetState())
	if typed := entry.Result.GetMetricTemplateTrialResult(); typed != nil {
		diagnostic.TrialCode = boundedDiagnosticValue(typed.GetStatusCode(), "succeeded", "lease_unavailable", "gateway_unavailable", "trial_rejected", "high_cardinality", "bounds_exceeded")
	} else {
		diagnostic.TrialCode = "none"
	}
	diagnostic.Reported = !entry.ReportedAt.IsZero()
	return diagnostic, nil
}

func boundedDiagnosticValue(value string, allowed ...string) string {
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return "other"
}

func boundedResultState(value agentv1.CommandResultState) string {
	switch value {
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED:
		return "succeeded"
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED:
		return "failed"
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED:
		return "cancelled"
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT:
		return "timed_out"
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED:
		return "interrupted"
	default:
		return "other"
	}
}

func AssertHostPluginDatabase(ctx context.Context, database *sql.DB, tenantID, projectID, agentID string, state hostPluginState) (string, error) {
	if ctx == nil || database == nil || !safeAssertionID(tenantID) || !safeAssertionID(projectID) || !safeAssertionID(agentID) || !validHostPluginState(state) {
		return "", errors.New("host plugin assertion input is invalid")
	}
	checks := []struct {
		name      string
		statement string
		arguments []any
		want      int
	}{
		{"host", `SELECT COUNT(*) FROM managed_hosts WHERE tenant_id=$1 AND project_id=$2 AND agent_id=$3 AND status IN ('online','stale')`, []any{tenantID, projectID, agentID}, 1},
		{"instances", `SELECT COUNT(*) FROM managed_database_instances WHERE tenant_id=$1 AND project_id=$2 AND instance_id IN ($3,$4) AND management_status IN ('managed','monitoring')`, []any{tenantID, projectID, state.InstanceIDs[0], state.InstanceIDs[1]}, 2},
		{"assignment", `SELECT COUNT(*) FROM plugin_assignments WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 AND desired_state='running' AND desired_version='1.0.0' AND jsonb_array_length(instance_ids)=2`, []any{tenantID, projectID, state.AssignmentID}, 1},
		{"observation", `SELECT COUNT(*) FROM plugin_observations WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 AND installed_version='1.0.0' AND process_state='running' AND bound_instance_count=2 AND active_configuration_revision>0 AND observed_operation_revision>0`, []any{tenantID, projectID, state.AssignmentID}, 1},
		{"metrics", `SELECT COUNT(DISTINCT metric) FROM metric_samples WHERE tenant_id=$1 AND project_id=$2 AND labels->>'instance' IN ($3,$4) AND metric IN ('mysql.connections.current','mysql.queries.total','mysql.threads.running','mysql.up','mysql.uptime.seconds')`, []any{tenantID, projectID, state.InstanceIDs[0], state.InstanceIDs[1]}, 5},
		{"template", `SELECT COUNT(*) FROM metric_template_revisions WHERE tenant_id=$1 AND project_id=$2 AND revision_id=$3 AND status='published' AND query_digest ~ '^[0-9a-f]{64}$' AND read_only_statement<>''`, []any{tenantID, projectID, state.TemplateRevisionID}, 1},
		{"high_cardinality", `SELECT COUNT(*) FROM metric_template_trials WHERE tenant_id=$1 AND project_id=$2 AND job_id=$3 AND revision_id=$4 AND status='failed' AND status_code='high_cardinality' AND candidate_metrics='[]'::jsonb`, []any{tenantID, projectID, state.HighCardinalityJobID, state.HighCardinalityRevisionID}, 1},
	}
	for _, check := range checks {
		var count int
		if err := database.QueryRowContext(ctx, check.statement, check.arguments...).Scan(&count); err != nil || count != check.want {
			return "", errors.New("host plugin durable evidence is incomplete: " + check.name)
		}
	}
	var auditCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE tenant_id=$1 AND project_id=$2 AND action IN ('host.enrollment_created','database_instance.accepted','plugin.version_uploaded','plugin.version_approved','plugin.version_published','plugin_assignment.created','plugin_assignment.configuration_changed','plugin_assignment.set_desired','metric_template.created','metric_template.revision_created','metric_template.validated','metric_template.trial_started','metric_template.approved','metric_template.published')`, tenantID, projectID).Scan(&auditCount); err != nil || auditCount < 10 {
		return "", errors.New("host plugin audit evidence is incomplete")
	}
	var sensitiveAudit int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE tenant_id=$1 AND project_id=$2 AND (detail::text ~* '(select[[:space:]]|delete[[:space:]]|secret://|private key|signed[_ -]?url|docker inspect|password)' OR detail::text LIKE '%DBPILOT_CANARY_%')`, tenantID, projectID).Scan(&sensitiveAudit); err != nil || sensitiveAudit != 0 {
		return "", errors.New("host plugin Audit detail contains forbidden material")
	}
	var duplicates int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT tenant_id,project_id,agent_id,metric,series_fingerprint,sampled_at FROM metric_samples WHERE tenant_id=$1 AND project_id=$2 GROUP BY tenant_id,project_id,agent_id,metric,series_fingerprint,sampled_at HAVING COUNT(*)>1) duplicate_samples`, tenantID, projectID).Scan(&duplicates); err != nil || duplicates != 0 {
		return "", errors.New("duplicate logical metric samples were retained")
	}
	var commandID string
	if err := database.QueryRowContext(ctx, `SELECT operation.command_id FROM plugin_reconcile_operations operation JOIN command_outbox command ON command.tenant_id=operation.tenant_id AND command.project_id=operation.project_id AND command.id=operation.command_id WHERE operation.tenant_id=$1 AND operation.project_id=$2 AND operation.assignment_id=$3 AND command.command_status='succeeded' AND command.command_phase='succeeded' ORDER BY operation.created_at DESC LIMIT 1`, tenantID, projectID, state.AssignmentID).Scan(&commandID); err != nil || !safeAssertionID(commandID) {
		return "", errors.New("plugin reconcile command evidence is missing")
	}
	return commandID, nil
}

func validHostPluginState(state hostPluginState) bool {
	return invalidHostPluginStateReason(state) == ""
}

func invalidHostPluginStateReason(state hostPluginState) string {
	if state.EnrollmentRevision == 0 {
		return "enrollment"
	}
	if !safeAssertionID(state.VersionID) || !safeAssertionID(state.PluginVersion) {
		return "version"
	}
	if !safeAssertionID(state.AssignmentID) {
		return "assignment"
	}
	if state.AssignmentPID == 0 || state.FirstInstancePID != state.AssignmentPID {
		return "assignment-pid"
	}
	if len(state.InstanceIDs) != 2 || state.InstanceIDs[0] == state.InstanceIDs[1] || !safeAssertionID(state.InstanceIDs[0]) || !safeAssertionID(state.InstanceIDs[1]) {
		return "instances"
	}
	if !safeAssertionID(state.TemplateID) || !safeAssertionID(state.TemplateRevisionID) {
		return "template"
	}
	if !safeAssertionID(state.HighCardinalityJobID) || !safeAssertionID(state.HighCardinalityRevisionID) {
		return "high-cardinality"
	}
	if state.DiagnosticStage != "failure-canary" || len(state.RestartBoundaries) != 2 {
		return "restart-boundaries"
	}
	for _, name := range []string{"agent", "server"} {
		boundary, ok := state.RestartBoundaries[name]
		observedAt, observedErr := time.Parse(time.RFC3339Nano, boundary.ObservedAt)
		sampleAt, sampleErr := time.Parse(time.RFC3339Nano, boundary.SampleAt)
		if !ok || observedErr != nil || sampleErr != nil || observedAt.IsZero() || sampleAt.IsZero() {
			return "restart-boundaries"
		}
	}
	return ""
}

func safeAssertionID(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t /\\")
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}
