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
	TenantID         string   `json:"tenant_id"`
	ProjectID        string   `json:"project_id"`
	RunID            string   `json:"run_id"`
	JobID            string   `json:"job_id"`
	ReportID         string   `json:"report_id"`
	OnlineAgentID    string   `json:"online_agent_id"`
	OfflineAgentID   string   `json:"offline_agent_id"`
	AuditCorrelation string   `json:"audit_correlation"`
	SensitiveValues  []string `json:"-"`
}

type JournalAssertion struct {
	CommandID       string   `json:"command_id"`
	SensitiveValues []string `json:"-"`
}

const (
	assertRunSQL       = "SELECT id, job_id, report_id, status, target_count, completed_target_count, failed_target_count, audit_correlation, request_id, trace_id, started_at, finished_at FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND id = $3"
	assertTargetsSQL   = "SELECT target_id, agent_id, command_id, status, error_code, observed_at FROM inspection_target_runs WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 ORDER BY target_id"
	assertFindingsSQL  = "SELECT target_id, item_id, item_version, level, observed_at FROM inspection_findings WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 ORDER BY target_id, item_id, item_version"
	assertReportSQL    = "SELECT id, run_id, status, generated_at FROM inspection_reports WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 ORDER BY id"
	assertArtifactsSQL = "SELECT id, job_id, source_resource_type, source_resource_id, content_type, size_bytes, checksum, storage_reference FROM artifacts WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3 ORDER BY id"
	assertAuditsSQL    = "SELECT id, action, resource_type, resource_id, request_id, trace_id, job_id, command_id, dedupe_key FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND (job_id = $3 OR resource_id = $4) ORDER BY id"
	assertMetricsSQL   = "SELECT agent_id, metric, labels->>'dbpilot_source_id' AS source_id, sampled_at, accepted_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND agent_id = $3 ORDER BY sampled_at, metric"
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
	return nil
}

func validateAssertionOptions(options AssertionOptions) error {
	values := []string{options.TenantID, options.ProjectID, options.RunID, options.JobID, options.ReportID, options.OnlineAgentID, options.OfflineAgentID, options.AuditCorrelation}
	for _, value := range values {
		if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\t") {
			return errors.New("database assertion identifiers are invalid")
		}
	}
	if options.OnlineAgentID == options.OfflineAgentID {
		return errors.New("database assertion Agent IDs must differ")
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
			if status != "succeeded" || errorCode != "" || !observedAt.Valid {
				return nil, errors.New("online TargetRun did not succeed with an observation")
			}
		case options.OfflineAgentID:
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
	runCorrelation, reportCorrelation, commandCorrelation := false, false, false
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
			runCorrelation = true
		}
		if resourceID == options.ReportID {
			if jobID != options.JobID || dedupeKey != options.AuditCorrelation+":report" {
				return errors.New("Report Audit correlation is invalid")
			}
			reportCorrelation = true
		}
		if commandID != "" {
			_, matched := commands[commandID]
			if jobID != options.JobID || !matched {
				return errors.New("Command Audit correlation is invalid")
			}
			commandCorrelation = commandCorrelation || matched
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate scoped Audit correlations: %w", err)
	}
	if !runCorrelation || !reportCorrelation || !commandCorrelation {
		return errors.New("Run, Report, or Command Audit correlation is missing")
	}
	return nil
}

func assertMetrics(ctx context.Context, database *sql.DB, options AssertionOptions) error {
	rows, err := database.QueryContext(ctx, assertMetricsSQL, options.TenantID, options.ProjectID, options.OnlineAgentID)
	if err != nil {
		return fmt.Errorf("query scoped metric acceptance: %w", err)
	}
	defer rows.Close()
	seen := make(map[string]struct{})
	count := 0
	for rows.Next() {
		var agentID, metric, sourceID string
		var sampledAt, acceptedAt time.Time
		if err := rows.Scan(&agentID, &metric, &sourceID, &sampledAt, &acceptedAt); err != nil {
			return fmt.Errorf("scan scoped metric acceptance: %w", err)
		}
		if agentID != options.OnlineAgentID || metric == "" || sampledAt.IsZero() || acceptedAt.IsZero() {
			return errors.New("metric source or acceptance timestamp is invalid")
		}
		switch sourceID {
		case "inspection-host-snapshot", "acceptance-host", "acceptance-filelog":
		default:
			return errors.New("metric source is not an acceptance source")
		}
		key := agentID + "\x00" + metric + "\x00" + sourceID + "\x00" + sampledAt.UTC().Format(time.RFC3339Nano)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("metric sample is duplicated")
		}
		seen[key] = struct{}{}
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate scoped metric acceptance: %w", err)
	}
	if count == 0 {
		return errors.New("accepted online metric sample is missing")
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
