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

	"dbpilot.local/platform/internal/spool"
)

type hostPluginState struct {
	EnrollmentRevision uint64   `json:"enrollment_revision"`
	VersionID          string   `json:"version_id"`
	PluginVersion      string   `json:"plugin_version"`
	AssignmentID       string   `json:"assignment_id"`
	AssignmentPID      uint32   `json:"assignment_pid"`
	InstanceIDs        []string `json:"instance_ids"`
	TemplateID         string   `json:"template_id"`
	TemplateRevisionID string   `json:"template_revision_id"`
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
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *phase != "host-plugin" || !filepath.IsAbs(*dsnFile) || !filepath.IsAbs(*agentData) || !filepath.IsAbs(*stateFile) || !safeAssertionID(*tenantID) || !safeAssertionID(*projectID) || !safeAssertionID(*agentID) {
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
	if decodeJSONFile(*stateFile, 64<<10, &state) != nil || !validHostPluginState(state) {
		fmt.Fprintln(stderr, "host plugin phase state is unavailable or invalid")
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
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE tenant_id=$1 AND project_id=$2 AND detail::text ~* '(select[[:space:]]|delete[[:space:]]|secret://|private key|signed[_ -]?url|docker inspect|password)'`, tenantID, projectID).Scan(&sensitiveAudit); err != nil || sensitiveAudit != 0 {
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
	return state.EnrollmentRevision > 0 && safeAssertionID(state.VersionID) && safeAssertionID(state.PluginVersion) && safeAssertionID(state.AssignmentID) && state.AssignmentPID > 0 && len(state.InstanceIDs) == 2 && state.InstanceIDs[0] != state.InstanceIDs[1] && safeAssertionID(state.InstanceIDs[0]) && safeAssertionID(state.InstanceIDs[1]) && safeAssertionID(state.TemplateID) && safeAssertionID(state.TemplateRevisionID)
}

func safeAssertionID(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t /\\")
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	return flags
}
