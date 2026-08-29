package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"dbpilot.local/platform/internal/agent/commandjournal"
)

type AssertionOptions struct {
	Version               int       `json:"version"`
	TenantID              string    `json:"tenant_id"`
	ProjectID             string    `json:"project_id"`
	PolicyID              string    `json:"policy_id"`
	RunID                 string    `json:"run_id"`
	JobID                 string    `json:"job_id"`
	ReportID              string    `json:"report_id"`
	OnlineAgentID         string    `json:"online_agent_id"`
	OfflineAgentID        string    `json:"offline_agent_id"`
	OnlineCommandID       string    `json:"online_command_id"`
	OfflineCommandID      string    `json:"offline_command_id"`
	JournalCommandID      string    `json:"journal_command_id"`
	AuditCorrelation      string    `json:"audit_correlation"`
	AcceptedAt            time.Time `json:"accepted_at"`
	HeartbeatAt           time.Time `json:"heartbeat_at"`
	PreRestartAcceptedAt  time.Time `json:"pre_restart_accepted_at"`
	PostRestartAcceptedAt time.Time `json:"post_restart_accepted_at"`
	AcceptedCount         int       `json:"accepted_count"`
	SpoolObservedCount    int       `json:"spool_observed_count"`
	SpoolPendingCount     int       `json:"spool_pending_count"`
	ReportCount           int       `json:"report_count"`
	FindingCount          int       `json:"finding_count"`
	AuditCount            int       `json:"audit_count"`
	SensitiveValues       []string  `json:"-"`
}

type JournalAssertion struct {
	CommandID       string   `json:"command_id"`
	SensitiveValues []string `json:"-"`
}

const (
	assertRunSQL       = "SELECT id, job_id, report_id, status, target_count, completed_target_count, failed_target_count, audit_correlation, request_id, trace_id, started_at, finished_at FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND id = $3"
	assertTargetsSQL   = "SELECT target_id, agent_id, command_id, status, error_code, observed_at FROM inspection_target_runs WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 ORDER BY target_id"
	assertCommandsSQL  = "SELECT id, target_id, message_type, command_phase, command_status, terminal_at FROM command_outbox WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3 ORDER BY id"
	assertFindingsSQL  = "SELECT target_id, item_id, item_version, level, observed_at FROM inspection_findings WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 ORDER BY target_id, item_id, item_version"
	assertReportSQL    = "SELECT id, run_id, status, generated_at FROM inspection_reports WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 ORDER BY id"
	assertArtifactsSQL = "SELECT id, job_id, source_resource_type, source_resource_id, content_type, size_bytes, checksum, storage_reference FROM artifacts WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3 ORDER BY id"
	assertAuditsSQL    = "SELECT id, action, resource_type, resource_id, request_id, trace_id, job_id, command_id, dedupe_key FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND (resource_id = $4 OR (job_id = $3 AND action IN ('inspection.report.completed', 'command.result', 'command.delivery_timed_out', 'command.prepared_timed_out', 'command.prepared_envelope_expired', 'command.execution_timed_out', 'command.skipped_terminal_job', 'command.prepared_terminal_job'))) ORDER BY id"
	assertMetricsSQL   = "SELECT agent_id, metric, series_fingerprint, labels->>'dbpilot_source_id' AS source_id, sampled_at, accepted_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND agent_id = $3 ORDER BY sampled_at, metric, series_fingerprint"
	assertRogueRowsSQL = "SELECT (SELECT COUNT(*) FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND agent_id IN ($3, $4, $5)), (SELECT COUNT(*) FROM monitoring_instances WHERE tenant_id = $1 AND project_id = $2 AND agent_id IN ($3, $4, $5)), (SELECT COUNT(*) FROM inspection_target_runs WHERE tenant_id = $1 AND project_id = $2 AND agent_id IN ($3, $4, $5)), (SELECT COUNT(*) FROM command_outbox WHERE tenant_id = $1 AND project_id = $2 AND target_id IN ($3, $4, $5)), (SELECT COUNT(*) FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND resource_id IN ($3, $4, $5))"
)

func AssertDatabase(ctx context.Context, database *sql.DB, options AssertionOptions) error {
	if ctx == nil {
		return errors.New("database assertion context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if database == nil {
		return errors.New("database assertion connection is required")
	}
	if err := validateAssertionOptions(options); err != nil {
		return err
	}
	if err := assertRun(ctx, database, options); err != nil {
		return redactAssertionError(err, options.SensitiveValues)
	}
	commands, err := assertTargets(ctx, database, options)
	if err != nil {
		return redactAssertionError(err, options.SensitiveValues)
	}
	if err := assertCommands(ctx, database, options, commands); err != nil {
		return redactAssertionError(err, options.SensitiveValues)
	}
	if err := assertFindings(ctx, database, options); err != nil {
		return redactAssertionError(err, options.SensitiveValues)
	}
	if err := assertReport(ctx, database, options); err != nil {
		return redactAssertionError(err, options.SensitiveValues)
	}
	if err := assertArtifacts(ctx, database, options); err != nil {
		return redactAssertionError(err, options.SensitiveValues)
	}
	if err := assertAudits(ctx, database, options, commands); err != nil {
		return redactAssertionError(err, options.SensitiveValues)
	}
	if err := assertMetrics(ctx, database, options); err != nil {
		return redactAssertionError(err, options.SensitiveValues)
	}
	if err := assertRogueRows(ctx, database, options); err != nil {
		return redactAssertionError(err, options.SensitiveValues)
	}
	return nil
}

func validateAssertionOptions(options AssertionOptions) error {
	values := []string{options.TenantID, options.ProjectID, options.RunID, options.JobID, options.ReportID, options.OnlineAgentID, options.OfflineAgentID, options.OnlineCommandID, options.OfflineCommandID, options.JournalCommandID, options.AuditCorrelation}
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\t") {
			return errors.New("database assertion identifiers are invalid")
		}
	}
	if options.OnlineAgentID == options.OfflineAgentID {
		return errors.New("database assertion Agent IDs must differ")
	}
	if options.OnlineCommandID == options.OfflineCommandID || options.JournalCommandID != options.OnlineCommandID {
		return errors.New("database assertion Command IDs are invalid")
	}
	if options.PreRestartAcceptedAt.IsZero() != options.PostRestartAcceptedAt.IsZero() || (!options.PreRestartAcceptedAt.IsZero() && !options.PostRestartAcceptedAt.After(options.PreRestartAcceptedAt)) {
		return errors.New("database assertion restart timestamps are invalid")
	}
	return nil
}

func assertRun(ctx context.Context, database *sql.DB, options AssertionOptions) error {
	rows, err := database.QueryContext(ctx, assertRunSQL, options.TenantID, options.ProjectID, options.RunID)
	if err != nil {
		return fmt.Errorf("query scoped inspection Run: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var id, jobID, reportID, status, correlation, requestID, traceID string
		var targetCount, completedTargetCount, failedTargetCount int
		var startedAt, finishedAt sql.NullTime
		if err := rows.Scan(&id, &jobID, &reportID, &status, &targetCount, &completedTargetCount, &failedTargetCount, &correlation, &requestID, &traceID, &startedAt, &finishedAt); err != nil {
			return fmt.Errorf("scan scoped inspection Run: %w", err)
		}
		if id != options.RunID || jobID != options.JobID || reportID != options.ReportID || status != "partial" || targetCount != 2 || completedTargetCount != 1 || failedTargetCount != 1 || correlation != options.AuditCorrelation || requestID == "" || traceID == "" || !startedAt.Valid || !finishedAt.Valid || finishedAt.Time.Before(startedAt.Time) {
			return errors.New("scoped inspection Run correlations or timestamps are invalid")
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate scoped inspection Run: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("require exactly one scoped inspection Run, got %d", count)
	}
	return nil
}

func assertTargets(ctx context.Context, database *sql.DB, options AssertionOptions) (map[string]string, error) {
	rows, err := database.QueryContext(ctx, assertTargetsSQL, options.TenantID, options.ProjectID, options.RunID)
	if err != nil {
		return nil, fmt.Errorf("query scoped TargetRuns: %w", err)
	}
	defer rows.Close()
	commands := make(map[string]string, 2)
	seenAgents := make(map[string]struct{}, 2)
	count := 0
	for rows.Next() {
		count++
		var targetID, agentID, commandID, status, errorCode string
		var observedAt sql.NullTime
		if err := rows.Scan(&targetID, &agentID, &commandID, &status, &errorCode, &observedAt); err != nil {
			return nil, fmt.Errorf("scan scoped TargetRun: %w", err)
		}
		if targetID == "" || commandID == "" {
			return nil, errors.New("TargetRun identity is empty")
		}
		if _, duplicate := commands[commandID]; duplicate {
			return nil, errors.New("TargetRun command is duplicated")
		}
		if _, duplicate := seenAgents[agentID]; duplicate {
			return nil, errors.New("TargetRun Agent is duplicated")
		}
		commands[commandID] = agentID
		seenAgents[agentID] = struct{}{}
		switch agentID {
		case options.OnlineAgentID:
			if commandID != options.OnlineCommandID {
				return nil, errors.New("online TargetRun does not match the phase state Command identity")
			}
			if status != "succeeded" || errorCode != "" || !observedAt.Valid {
				return nil, errors.New("online TargetRun did not succeed with an observation")
			}
		case options.OfflineAgentID:
			if commandID != options.OfflineCommandID {
				return nil, errors.New("offline TargetRun does not match the phase state Command identity")
			}
			if status != "failed" || errorCode != "agent_offline" {
				return nil, errors.New("offline TargetRun did not fail with agent_offline")
			}
		default:
			return nil, errors.New("TargetRun contains an unexpected Agent")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scoped TargetRuns: %w", err)
	}
	if count != 2 || len(seenAgents) != 2 {
		return nil, fmt.Errorf("require exactly two scoped TargetRuns and Commands, got %d", count)
	}
	return commands, nil
}

func assertCommands(ctx context.Context, database *sql.DB, options AssertionOptions, expected map[string]string) error {
	if len(expected) != 2 {
		return errors.New("exactly two expected Command identities are required")
	}
	rows, err := database.QueryContext(ctx, assertCommandsSQL, options.TenantID, options.ProjectID, options.JobID)
	if err != nil {
		return fmt.Errorf("query scoped durable Commands: %w", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, 2)
	for rows.Next() {
		var id, targetID, messageType, phase, status string
		var terminalAt sql.NullTime
		if err := rows.Scan(&id, &targetID, &messageType, &phase, &status, &terminalAt); err != nil {
			return fmt.Errorf("scan scoped durable Command: %w", err)
		}
		expectedTarget, ok := expected[id]
		if !ok || targetID != expectedTarget || messageType != "agent.command" {
			return errors.New("durable Command identity, target, or message type is invalid")
		}
		if _, duplicate := seen[id]; duplicate {
			return errors.New("durable Command is duplicated")
		}
		if !acceptableTerminalCommand(phase, status, targetID == options.OnlineAgentID) || !terminalAt.Valid || terminalAt.Time.IsZero() {
			return errors.New("durable Command is not in an acceptable terminal phase")
		}
		seen[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate scoped durable Commands: %w", err)
	}
	if len(seen) != len(expected) {
		return errors.New("exactly both expected durable Commands are required")
	}
	return nil
}

func acceptableTerminalCommand(phase, status string, online bool) bool {
	if phase != status {
		return false
	}
	if online {
		return phase == "succeeded"
	}
	switch phase {
	case "failed", "cancelled", "timed_out", "rejected":
		return true
	default:
		return false
	}
}

func assertFindings(ctx context.Context, database *sql.DB, options AssertionOptions) error {
	rows, err := database.QueryContext(ctx, assertFindingsSQL, options.TenantID, options.ProjectID, options.RunID)
	if err != nil {
		return fmt.Errorf("query scoped Findings: %w", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{}, 13)
	count := 0
	for rows.Next() {
		var targetID, itemID, level string
		var version int
		var observedAt time.Time
		if err := rows.Scan(&targetID, &itemID, &version, &level, &observedAt); err != nil {
			return fmt.Errorf("scan scoped Finding: %w", err)
		}
		if targetID != options.OnlineAgentID || itemID == "" || version <= 0 || observedAt.IsZero() || level == "missing_data" || level == "unsupported" {
			return errors.New("Finding belongs to the wrong target or is incomplete")
		}
		key := targetID + "\x00" + itemID + "\x00" + fmt.Sprint(version)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("Finding is duplicated")
		}
		seen[key] = struct{}{}
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate scoped Findings: %w", err)
	}
	if count != 13 {
		return fmt.Errorf("require 13 online and zero offline Findings, got %d", count)
	}
	return nil
}

func assertReport(ctx context.Context, database *sql.DB, options AssertionOptions) error {
	rows, err := database.QueryContext(ctx, assertReportSQL, options.TenantID, options.ProjectID, options.RunID)
	if err != nil {
		return fmt.Errorf("query scoped Report: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var id, runID, status string
		var generatedAt time.Time
		if err := rows.Scan(&id, &runID, &status, &generatedAt); err != nil {
			return fmt.Errorf("scan scoped Report: %w", err)
		}
		if id != options.ReportID || runID != options.RunID || status != "completed" || generatedAt.IsZero() {
			return errors.New("scoped Report identity or terminal state is invalid")
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate scoped Report: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("require exactly one scoped Report, got %d", count)
	}
	return nil
}

func assertArtifacts(ctx context.Context, database *sql.DB, options AssertionOptions) error {
	rows, err := database.QueryContext(ctx, assertArtifactsSQL, options.TenantID, options.ProjectID, options.JobID)
	if err != nil {
		return fmt.Errorf("query scoped Artifacts: %w", err)
	}
	defer rows.Close()
	seenIDs := make(map[string]struct{}, 2)
	seenContentTypes := make(map[string]struct{}, 2)
	for rows.Next() {
		var id, jobID, resourceType, resourceID, contentType, checksum, storageReference string
		var size int64
		if err := rows.Scan(&id, &jobID, &resourceType, &resourceID, &contentType, &size, &checksum, &storageReference); err != nil {
			return fmt.Errorf("scan scoped Artifact: %w", err)
		}
		if id == "" || jobID != options.JobID || resourceType != "inspection_report" || resourceID != options.ReportID || size <= 0 || checksum == "" || storageReference == "" {
			return errors.New("scoped Artifact metadata is invalid")
		}
		if _, duplicate := seenIDs[id]; duplicate {
			return errors.New("Artifact is duplicated")
		}
		seenIDs[id], seenContentTypes[contentType] = struct{}{}, struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate scoped Artifacts: %w", err)
	}
	if len(seenIDs) != 2 {
		return fmt.Errorf("require exactly two scoped Artifacts, got %d", len(seenIDs))
	}
	if _, ok := seenContentTypes["application/json"]; !ok {
		return errors.New("JSON inspection Artifact is missing")
	}
	if _, ok := seenContentTypes["text/html; charset=utf-8"]; !ok {
		return errors.New("HTML inspection Artifact is missing")
	}
	return nil
}

func assertAudits(ctx context.Context, database *sql.DB, options AssertionOptions, commands map[string]string) error {
	rows, err := database.QueryContext(ctx, assertAuditsSQL, options.TenantID, options.ProjectID, options.JobID, options.RunID)
	if err != nil {
		return fmt.Errorf("query scoped Audit correlations: %w", err)
	}
	defer rows.Close()
	seenIDs, seenDedupe := make(map[string]struct{}), make(map[string]struct{})
	runCorrelation, reportCorrelation := false, false
	auditedCommands := make(map[string]struct{}, len(commands))
	for rows.Next() {
		var id, action, resourceType, resourceID, requestID, traceID, jobID, commandID, dedupeKey string
		if err := rows.Scan(&id, &action, &resourceType, &resourceID, &requestID, &traceID, &jobID, &commandID, &dedupeKey); err != nil {
			return fmt.Errorf("scan scoped Audit correlation: %w", err)
		}
		if id == "" || action == "" || resourceType == "" || resourceID == "" || requestID == "" || traceID == "" {
			return errors.New("scoped Audit correlation is incomplete")
		}
		if _, duplicate := seenIDs[id]; duplicate {
			return errors.New("Audit event is duplicated")
		}
		if dedupeKey != "" {
			if _, duplicate := seenDedupe[dedupeKey]; duplicate {
				return errors.New("Audit dedupe key is duplicated")
			}
			seenDedupe[dedupeKey] = struct{}{}
		}
		seenIDs[id] = struct{}{}
		if resourceID == options.RunID {
			if action != "inspection.run.created" || resourceType != "inspection_run" || commandID != "" {
				return errors.New("Run Audit correlation is invalid")
			}
			runCorrelation = true
		}
		if resourceID == options.ReportID {
			if action != "inspection.report.completed" || resourceType != "inspection_report" || jobID != options.JobID || commandID != "" || dedupeKey != options.AuditCorrelation+":report" {
				return errors.New("Report Audit correlation is invalid")
			}
			reportCorrelation = true
		}
		if commandID != "" {
			targetID, matched := commands[commandID]
			if jobID != options.JobID || !matched || resourceType != "job_target" || resourceID != targetID || !validCommandAudit(action, dedupeKey, commandID, targetID == options.OnlineAgentID) {
				return errors.New("Command Audit correlation is invalid")
			}
			auditedCommands[commandID] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate scoped Audit correlations: %w", err)
	}
	if !runCorrelation || !reportCorrelation {
		return errors.New("Run or Report Audit correlation is missing")
	}
	if len(auditedCommands) != len(commands) {
		return errors.New("both expected Command Audit correlations are required")
	}
	return nil
}

func validCommandAudit(action, dedupeKey, commandID string, online bool) bool {
	if online {
		return action == "command.result" && dedupeKey == "command.result:"+commandID
	}
	switch action {
	case "command.delivery_timed_out", "command.prepared_timed_out", "command.prepared_envelope_expired", "command.execution_timed_out", "command.skipped_terminal_job", "command.prepared_terminal_job":
		return dedupeKey == action+":"+commandID
	default:
		return false
	}
}

func assertMetrics(ctx context.Context, database *sql.DB, options AssertionOptions) error {
	rows, err := database.QueryContext(ctx, assertMetricsSQL, options.TenantID, options.ProjectID, options.OnlineAgentID)
	if err != nil {
		return fmt.Errorf("query scoped metric acceptance: %w", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{})
	count := 0
	postRestartReplay := options.PostRestartAcceptedAt.IsZero()
	for rows.Next() {
		var agentID, metric, seriesFingerprint, sourceID string
		var sampledAt, acceptedAt time.Time
		if err := rows.Scan(&agentID, &metric, &seriesFingerprint, &sourceID, &sampledAt, &acceptedAt); err != nil {
			return fmt.Errorf("scan scoped metric acceptance: %w", err)
		}
		if agentID != options.OnlineAgentID || metric == "" || seriesFingerprint == "" || sampledAt.IsZero() || acceptedAt.IsZero() {
			return errors.New("metric source or acceptance timestamp is invalid")
		}
		switch sourceID {
		case "inspection-host-snapshot", "acceptance-host", "acceptance-filelog":
		default:
			return errors.New("metric source is not an acceptance source")
		}
		key := agentID + "\x00" + metric + "\x00" + seriesFingerprint + "\x00" + sampledAt.UTC().Format(time.RFC3339Nano)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("metric sample is duplicated")
		}
		seen[key] = struct{}{}
		if !options.PostRestartAcceptedAt.IsZero() && sampledAt.Equal(options.PostRestartAcceptedAt) && acceptedAt.After(options.PreRestartAcceptedAt) {
			postRestartReplay = true
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate scoped metric acceptance: %w", err)
	}
	if count == 0 {
		return errors.New("accepted online metric sample is missing")
	}
	if !postRestartReplay {
		return errors.New("post-restart replay sample is missing")
	}
	return nil
}

func assertRogueRows(ctx context.Context, database *sql.DB, options AssertionOptions) error {
	const untrustedID = "agent-untrusted"
	const claimedID = "agent-claimed-id"
	const certificateID = "agent-certificate-id"
	var metricRows, monitoringRows, targetRows, commandRows, auditRows int
	err := database.QueryRowContext(ctx, assertRogueRowsSQL, options.TenantID, options.ProjectID, untrustedID, claimedID, certificateID).
		Scan(&metricRows, &monitoringRows, &targetRows, &commandRows, &auditRows)
	if err != nil {
		return fmt.Errorf("query rogue Agent persistence: %w", err)
	}
	if metricRows != 0 || monitoringRows != 0 || targetRows != 0 || commandRows != 0 || auditRows != 0 {
		return errors.New("rogue Agent created persistent rows")
	}
	return nil
}

func AssertJournal(path string, assertion JournalAssertion) error {
	if !filepath.IsAbs(path) || assertion.CommandID == "" || assertion.CommandID != strings.TrimSpace(assertion.CommandID) || strings.ContainsAny(assertion.CommandID, "\r\n\t") {
		return errors.New("journal assertion input is invalid")
	}
	journal, err := commandjournal.Open(path)
	if err != nil {
		return redactAssertionError(fmt.Errorf("open Agent command journal: %w", err), assertion.SensitiveValues)
	}
	defer journal.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entry, err := journal.Get(ctx, assertion.CommandID)
	if err != nil {
		return redactAssertionError(fmt.Errorf("read asserted command journal entry: %w", err), assertion.SensitiveValues)
	}
	if entry.State != commandjournal.StateCompleted || entry.Result == nil || entry.Result.GetCommandId() != assertion.CommandID || entry.ReportedAt.IsZero() || entry.ResultDigest == ([sha256.Size]byte{}) {
		return errors.New("asserted command is not terminal and ResultAck-reported")
	}
	pending, err := journal.PendingResults(ctx)
	if err != nil {
		return redactAssertionError(fmt.Errorf("read pending Agent Results: %w", err), assertion.SensitiveValues)
	}
	if len(pending) != 0 {
		return fmt.Errorf("Agent command journal has %d pending Results", len(pending))
	}
	return nil
}

func redactAssertionError(err error, sensitiveValues []string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	message := err.Error()
	values := append([]string(nil), sensitiveValues...)
	sort.Slice(values, func(left, right int) bool { return len(values[left]) > len(values[right]) })
	for _, sensitive := range values {
		if sensitive != "" {
			message = strings.ReplaceAll(message, sensitive, "[REDACTED]")
		}
	}
	return errors.New(message)
}
