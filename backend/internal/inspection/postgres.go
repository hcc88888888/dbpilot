package inspection

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
)

const policyColumnsSQL = "tenant_id, project_id, id, name, enabled, version, schedule_cron, schedule_timezone, next_run_at, target_selector, item_snapshot, target_timeout_seconds, max_concurrency, created_at, updated_at, claim_token, lease_expires_at"
const runColumnsSQL = "tenant_id, project_id, id, policy_id, policy_version, retry_of_run_id, job_id, status, trigger_source, occurrence_key, scheduled_for, policy_snapshot, item_snapshot, target_count, completed_target_count, failed_target_count, report_id, audit_correlation, idempotency_key, initiated_by, request_id, trace_id, started_at, finished_at, created_at, target_timeout_seconds, max_concurrency, idempotency_actor, idempotency_operation, idempotency_fingerprint"

const selectRunsBeforeSQL = "SELECT " + runColumnsSQL + " FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND (created_at, id) < ($3, $4) ORDER BY created_at DESC, id DESC LIMIT $5"
const selectDuePoliciesSQL = "SELECT " + policyColumnsSQL + " FROM inspection_policies WHERE enabled = TRUE AND next_run_at <= $1 AND (lease_expires_at IS NULL OR lease_expires_at <= $1) ORDER BY next_run_at, tenant_id, project_id, id FOR UPDATE SKIP LOCKED LIMIT $2"
const claimPolicySQL = "UPDATE inspection_policies SET claim_token = $1, lease_expires_at = $2 WHERE tenant_id = $3 AND project_id = $4 AND id = $5 AND version = $6 RETURNING claim_token"
const insertItemSQL = "INSERT INTO inspection_items (tenant_id, project_id, item_id, version, enabled, system, category, source_type, snapshot, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
const insertRunSQL = "INSERT INTO inspection_runs (tenant_id, project_id, id, policy_id, policy_version, retry_of_run_id, job_id, status, trigger_source, occurrence_key, scheduled_for, policy_snapshot, item_snapshot, target_count, completed_target_count, failed_target_count, report_id, audit_correlation, idempotency_key, initiated_by, request_id, trace_id, started_at, finished_at, created_at, target_timeout_seconds, max_concurrency, idempotency_actor, idempotency_operation, idempotency_fingerprint) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30) ON CONFLICT (tenant_id, project_id, idempotency_actor, idempotency_operation, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING RETURNING id"
const insertScheduledRunSQL = "INSERT INTO inspection_runs (tenant_id, project_id, id, policy_id, policy_version, retry_of_run_id, job_id, status, trigger_source, occurrence_key, scheduled_for, policy_snapshot, item_snapshot, target_count, completed_target_count, failed_target_count, report_id, audit_correlation, idempotency_key, initiated_by, request_id, trace_id, started_at, finished_at, created_at, target_timeout_seconds, max_concurrency, idempotency_actor, idempotency_operation, idempotency_fingerprint) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30) ON CONFLICT (tenant_id, project_id, occurrence_key) DO NOTHING RETURNING id"
const insertTargetRunSQL = "INSERT INTO inspection_target_runs (tenant_id, project_id, run_id, target_id, agent_id, command_id, status, target_snapshot, error_code, observed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
const selectRunByOccurrenceSQL = "SELECT " + runColumnsSQL + " FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND occurrence_key = $3"
const selectRunByIdempotencySQL = "SELECT " + runColumnsSQL + " FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND idempotency_actor = $3 AND idempotency_operation = $4 AND idempotency_key = $5"
const advanceClaimedPolicySQL = "UPDATE inspection_policies SET next_run_at = $1, claim_token = NULL, lease_expires_at = NULL WHERE tenant_id = $2 AND project_id = $3 AND id = $4 AND version = $5 AND next_run_at = $6 AND claim_token = $7 RETURNING next_run_at"
const insertPolicySQL = "INSERT INTO inspection_policies (tenant_id, project_id, id, name, enabled, version, schedule_cron, schedule_timezone, next_run_at, target_selector, item_snapshot, target_timeout_seconds, max_concurrency, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"
const selectRunSQL = "SELECT " + runColumnsSQL + " FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND id = $3"
const selectTargetRunsSQL = "SELECT target_snapshot, status, error_code, observed_at FROM inspection_target_runs WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 ORDER BY target_id"
const findingColumnsSQL = "id, run_id, target_id, item_id, item_version, level, observed_at, evidence, warning_threshold, critical_threshold, summary, recommendation"
const selectFindingsSQL = "SELECT " + findingColumnsSQL + " FROM inspection_findings WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 ORDER BY target_id, item_id, item_version"
const selectItemsSQL = "SELECT created_at, snapshot FROM inspection_items WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at DESC, item_id DESC, version DESC LIMIT $3"
const selectItemsBeforeSQL = "SELECT created_at, snapshot FROM inspection_items WHERE tenant_id = $1 AND project_id = $2 AND (created_at, item_id, version) < ($3, $4, $5) ORDER BY created_at DESC, item_id DESC, version DESC LIMIT $6"
const selectPolicySQL = "SELECT " + policyColumnsSQL + " FROM inspection_policies WHERE tenant_id = $1 AND project_id = $2 AND id = $3"
const selectPoliciesSQL = "SELECT " + policyColumnsSQL + " FROM inspection_policies WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at DESC, id DESC LIMIT $3"
const selectPoliciesBeforeSQL = "SELECT " + policyColumnsSQL + " FROM inspection_policies WHERE tenant_id = $1 AND project_id = $2 AND (created_at, id) < ($3, $4) ORDER BY created_at DESC, id DESC LIMIT $5"
const selectRunsSQL = "SELECT " + runColumnsSQL + " FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at DESC, id DESC LIMIT $3"
const reportColumnsSQL = "tenant_id, project_id, id, run_id, policy_id, status, summary, snapshot, artifacts, generated_at, created_at"
const selectReportSQL = "SELECT " + reportColumnsSQL + " FROM inspection_reports WHERE tenant_id = $1 AND project_id = $2 AND id = $3"
const selectReportsSQL = "SELECT " + reportColumnsSQL + " FROM inspection_reports WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at DESC, id DESC LIMIT $3"
const selectReportsBeforeSQL = "SELECT " + reportColumnsSQL + " FROM inspection_reports WHERE tenant_id = $1 AND project_id = $2 AND (created_at, id) < ($3, $4) ORDER BY created_at DESC, id DESC LIMIT $5"
const claimRunsSQL = "SELECT " + runColumnsSQL + ", report_generated_at FROM inspection_runs WHERE status IN ('queued', 'collecting', 'evaluating', 'generating_report') AND (worker_lease_expires_at IS NULL OR worker_lease_expires_at <= $1) ORDER BY created_at, tenant_id, project_id, id FOR UPDATE SKIP LOCKED LIMIT $2"
const claimRunSQL = "UPDATE inspection_runs SET worker_claim_token = $1, worker_lease_expires_at = $2 WHERE tenant_id = $3 AND project_id = $4 AND id = $5 RETURNING worker_claim_token"
const freshSnapshotSQL = "SELECT MAX(sampled_at) FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND agent_id = $3 AND labels->>'dbpilot_source_id' = $4 AND sampled_at >= $5 AND sampled_at <= $6 AND accepted_at <= $6"
const hostSnapshotSQL = "SELECT metric, labels, value, sampled_at, accepted_at, series_fingerprint FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND agent_id = $3 AND metric = ANY($4) AND labels->>'dbpilot_source_id' = $5 AND sampled_at >= $6 AND sampled_at <= $7 AND accepted_at <= $7 ORDER BY sampled_at DESC, metric, series_fingerprint LIMIT $8"
const evidenceSamplesSQL = "SELECT metric, labels, value, sampled_at, series_fingerprint FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND agent_id = $3 AND metric = ANY($4) AND labels->>'dbpilot_source_id' = $5 AND sampled_at >= $6 AND sampled_at <= $7 AND accepted_at <= $7 ORDER BY sampled_at, metric, series_fingerprint LIMIT $8"

type jobCreator interface {
	CreateInTx(context.Context, *sql.Tx, job.Job, []job.OutboxMessage) error
}

type PostgresRepository struct {
	database *sql.DB
	jobs     jobCreator
}

func NewPostgresRepository(database *sql.DB, jobs jobCreator) *PostgresRepository {
	return &PostgresRepository{database: database, jobs: jobs}
}

func (repository *PostgresRepository) ListRuns(ctx context.Context, scope platformscope.Scope, filter RunFilter) (RunPage, error) {
	if err := validateList(ctx, repository, scope, filter.CursorFilter); err != nil {
		return RunPage{}, ErrInvalid
	}
	cursor, hasCursor, err := resolveInspectionCursor(scope, filter.CursorFilter, false)
	if err != nil {
		return RunPage{}, err
	}
	var rows *sql.Rows
	if !hasCursor {
		rows, err = repository.database.QueryContext(ctx, selectRunsSQL, scope.TenantID, scope.ProjectID, filter.Limit+1)
	} else {
		rows, err = repository.database.QueryContext(ctx, selectRunsBeforeSQL, scope.TenantID, scope.ProjectID, cursor.CreatedAt, cursor.ID, filter.Limit+1)
	}
	if err != nil {
		return RunPage{}, fmt.Errorf("list inspection runs: %w", err)
	}
	defer rows.Close()
	page := RunPage{Items: make([]Run, 0)}
	for rows.Next() {
		value, err := scanRun(rows)
		if err != nil {
			return RunPage{}, err
		}
		page.Items = append(page.Items, value)
	}
	if err := rows.Err(); err != nil {
		return RunPage{}, err
	}
	if len(page.Items) > filter.Limit {
		page.Items = page.Items[:filter.Limit]
		page.More = true
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodeInspectionCursor(inspectionCursor{Scope: scope, CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			return RunPage{}, err
		}
	}
	return page, nil
}

func (repository *PostgresRepository) UpdatePolicy(ctx context.Context, value Policy, currentVersion int64) (Policy, error) {
	if repository == nil || repository.database == nil || ctx == nil || validatePolicy(value) != nil || currentVersion < 1 {
		return Policy{}, ErrInvalid
	}
	selector, items, err := marshalPolicyParts(value)
	if err != nil {
		return Policy{}, err
	}
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Policy{}, fmt.Errorf("begin inspection policy update: %w", err)
	}
	rollback := func(cause error) (Policy, error) { _ = tx.Rollback(); return Policy{}, cause }
	cronValue, timezoneValue := scheduleValues(value.Schedule)
	query := "UPDATE inspection_policies SET name = $1, enabled = $2, version = version + 1, schedule_cron = $3, schedule_timezone = $4, next_run_at = $5, target_selector = $6, item_snapshot = $7, target_timeout_seconds = $8, max_concurrency = $9, updated_at = $10, claim_token = NULL, lease_expires_at = NULL WHERE tenant_id = $11 AND project_id = $12 AND id = $13 AND version = $14 RETURNING " + policyColumnsSQL
	updated, err := scanPolicy(tx.QueryRowContext(ctx, query, value.Name, value.Enabled, cronValue, timezoneValue, nullableTime(value.NextRunAt), selector, items, int(value.TargetTimeout/time.Second), value.MaxConcurrency, value.UpdatedAt.UTC(), value.Scope.TenantID, value.Scope.ProjectID, value.ID, currentVersion))
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrConflict)
	}
	if err != nil {
		return rollback(fmt.Errorf("update inspection policy: %w", err))
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM inspection_policy_items WHERE tenant_id = $1 AND project_id = $2 AND policy_id = $3", value.Scope.TenantID, value.Scope.ProjectID, value.ID); err != nil {
		return rollback(fmt.Errorf("replace inspection policy items: %w", err))
	}
	if err := insertPolicyItems(ctx, tx, updated); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return Policy{}, fmt.Errorf("commit inspection policy update: %w", err)
	}
	return updated, nil
}

func (repository *PostgresRepository) ClaimDuePolicies(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]Policy, error) {
	if repository == nil || repository.database == nil || ctx == nil || now.Location() != time.UTC || limit < 1 || limit > 100 || lease <= 0 || lease > 5*time.Minute {
		return nil, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin inspection policy claim: %w", err)
	}
	rollback := func(cause error) ([]Policy, error) { _ = tx.Rollback(); return nil, cause }
	rows, err := tx.QueryContext(ctx, selectDuePoliciesSQL, now, limit)
	if err != nil {
		return rollback(fmt.Errorf("select due inspection policies: %w", err))
	}
	policies := make([]Policy, 0)
	for rows.Next() {
		value, err := scanPolicy(rows)
		if err != nil {
			_ = rows.Close()
			return rollback(err)
		}
		policies = append(policies, value)
	}
	if err := rows.Close(); err != nil {
		return rollback(err)
	}
	if err := rows.Err(); err != nil {
		return rollback(err)
	}
	leaseExpiresAt := now.Add(lease)
	for index := range policies {
		token, err := randomToken()
		if err != nil {
			return rollback(err)
		}
		var persisted string
		err = tx.QueryRowContext(ctx, claimPolicySQL, token, leaseExpiresAt, policies[index].Scope.TenantID, policies[index].Scope.ProjectID, policies[index].ID, policies[index].Version).Scan(&persisted)
		if err != nil {
			return rollback(fmt.Errorf("lease inspection policy: %w", err))
		}
		policies[index].Claim = &PolicyClaim{Token: persisted, Occurrence: policies[index].NextRunAt.UTC(), LeaseExpiresAt: leaseExpiresAt}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit inspection policy claim: %w", err)
	}
	return policies, nil
}

func validateList(ctx context.Context, repository *PostgresRepository, scope platformscope.Scope, filter CursorFilter) error {
	if ctx == nil || repository == nil || repository.database == nil || scope.Validate() != nil || filter.Limit < 1 || filter.Limit > 100 {
		return ErrInvalid
	}
	return nil
}

type inspectionCursor struct {
	Scope     platformscope.Scope `json:"scope"`
	CreatedAt time.Time           `json:"created_at"`
	ID        string              `json:"id"`
	Version   int                 `json:"version,omitempty"`
}

func resolveInspectionCursor(scope platformscope.Scope, filter CursorFilter, versioned bool) (inspectionCursor, bool, error) {
	if filter.Cursor != "" {
		if !filter.Before.IsZero() || filter.BeforeID != "" || filter.BeforeVersion != 0 {
			return inspectionCursor{}, false, ErrInvalid
		}
		decoded, err := decodeInspectionCursor(filter.Cursor)
		if err != nil || decoded.Scope != scope || !isUTC(decoded.CreatedAt) || !validID(decoded.ID) || (versioned && decoded.Version < 1) || (!versioned && decoded.Version != 0) {
			return inspectionCursor{}, false, ErrInvalid
		}
		return decoded, true, nil
	}
	if filter.Before.IsZero() {
		if filter.BeforeID != "" || filter.BeforeVersion != 0 {
			return inspectionCursor{}, false, ErrInvalid
		}
		return inspectionCursor{}, false, nil
	}
	if !validID(filter.BeforeID) || (versioned && filter.BeforeVersion < 1) || (!versioned && filter.BeforeVersion != 0) {
		return inspectionCursor{}, false, ErrInvalid
	}
	return inspectionCursor{Scope: scope, CreatedAt: filter.Before.UTC(), ID: filter.BeforeID, Version: filter.BeforeVersion}, true, nil
}

func encodeInspectionCursor(value inspectionCursor) (string, error) {
	if value.Scope.Validate() != nil || !isUTC(value.CreatedAt) || !validID(value.ID) || value.Version < 0 {
		return "", ErrInvalid
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeInspectionCursor(value string) (inspectionCursor, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return inspectionCursor{}, err
	}
	var cursor inspectionCursor
	if err := json.Unmarshal(encoded, &cursor); err != nil {
		return inspectionCursor{}, err
	}
	return cursor, nil
}

func validatePolicy(value Policy) error {
	if value.Scope.Validate() != nil || !validID(value.ID) || strings.TrimSpace(value.Name) == "" || len(value.Name) > 120 || value.Version < 1 || len(value.Items) < 1 || len(value.Items) > maxSnapshotItems || value.TargetTimeout < time.Second || value.TargetTimeout > time.Hour || value.MaxConcurrency < 1 || value.MaxConcurrency > 1000 || !isUTC(value.CreatedAt) || !isUTC(value.UpdatedAt) {
		return ErrInvalid
	}
	if value.Schedule == nil {
		if value.NextRunAt != nil {
			return ErrInvalid
		}
	} else {
		if strings.TrimSpace(value.Schedule.Cron) == "" || strings.TrimSpace(value.Schedule.Timezone) == "" || value.NextRunAt == nil || !isUTC(*value.NextRunAt) {
			return ErrInvalid
		}
		if _, err := NextScheduledOccurrence(*value.Schedule, value.CreatedAt); err != nil {
			return ErrInvalid
		}
	}
	if len(value.Selector.AgentIDs) == 0 && len(value.Selector.Labels) == 0 {
		return ErrInvalid
	}
	if len(value.Selector.AgentIDs) > maxSnapshotTargets || !validSelectorLabels(value.Selector.Labels) {
		return ErrInvalid
	}
	for _, agentID := range value.Selector.AgentIDs {
		if !validID(agentID) {
			return ErrInvalid
		}
	}
	seen := make(map[string]struct{}, len(value.Items))
	for _, item := range value.Items {
		key := item.ItemID + "\x00" + fmt.Sprint(item.Version)
		if !validID(item.ItemID) || item.Version < 1 {
			return ErrInvalid
		}
		if _, duplicate := seen[key]; duplicate {
			return ErrInvalid
		}
		seen[key] = struct{}{}
	}
	return nil
}

func marshalPolicyParts(value Policy) ([]byte, []byte, error) {
	selector, err := json.Marshal(value.Selector)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	items, err := json.Marshal(value.Items)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	return selector, items, nil
}

func scheduleValues(value *Schedule) (any, any) {
	if value == nil {
		return nil, nil
	}
	return value.Cron, value.Timezone
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func scanPolicy(scanner interface{ Scan(...any) error }) (Policy, error) {
	var value Policy
	var cronValue, timezoneValue, claimToken sql.NullString
	var nextRunAt, leaseExpiresAt sql.NullTime
	var selector, items []byte
	err := scanner.Scan(&value.Scope.TenantID, &value.Scope.ProjectID, &value.ID, &value.Name, &value.Enabled, &value.Version, &cronValue, &timezoneValue, &nextRunAt, &selector, &items, &value.TargetTimeout, &value.MaxConcurrency, &value.CreatedAt, &value.UpdatedAt, &claimToken, &leaseExpiresAt)
	if err != nil {
		return Policy{}, err
	}
	value.TargetTimeout *= time.Second
	if cronValue.Valid && timezoneValue.Valid {
		value.Schedule = &Schedule{Cron: cronValue.String, Timezone: timezoneValue.String}
	}
	if nextRunAt.Valid {
		at := nextRunAt.Time.UTC()
		value.NextRunAt = &at
	}
	if err := json.Unmarshal(selector, &value.Selector); err != nil {
		return Policy{}, fmt.Errorf("decode inspection target selector: %w", err)
	}
	if err := json.Unmarshal(items, &value.Items); err != nil {
		return Policy{}, fmt.Errorf("decode inspection policy items: %w", err)
	}
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
	if claimToken.Valid && leaseExpiresAt.Valid && value.NextRunAt != nil {
		value.Claim = &PolicyClaim{Token: claimToken.String, ClaimedOccurrence: *value.NextRunAt, Occurrence: *value.NextRunAt, LeaseExpiresAt: leaseExpiresAt.Time.UTC()}
	}
	return value, nil
}

func scanRun(scanner interface{ Scan(...any) error }) (Run, error) {
	var value Run
	var policyID, retryID, occurrence, reportID, idempotency sql.NullString
	var policyVersion sql.NullInt64
	var targetTimeoutSeconds int64
	var scheduledFor, startedAt, finishedAt sql.NullTime
	var policySnapshot, itemSnapshot []byte
	err := scanner.Scan(&value.Scope.TenantID, &value.Scope.ProjectID, &value.ID, &policyID, &policyVersion, &retryID, &value.JobID, &value.Status, &value.Trigger, &occurrence, &scheduledFor, &policySnapshot, &itemSnapshot, &value.TargetCount, &value.CompletedTargetCount, &value.FailedTargetCount, &reportID, &value.AuditCorrelation, &idempotency, &value.InitiatedBy, &value.RequestID, &value.TraceID, &startedAt, &finishedAt, &value.CreatedAt, &targetTimeoutSeconds, &value.MaxConcurrency, &value.IdempotencyActor, &value.IdempotencyOperation, &value.IdempotencyFingerprint)
	if err != nil {
		return Run{}, err
	}
	value.PolicyID, value.PolicyVersion, value.RetryOfRunID, value.OccurrenceKey, value.ReportID, value.IdempotencyKey = policyID.String, policyVersion.Int64, retryID.String, occurrence.String, reportID.String, idempotency.String
	value.TargetTimeout = time.Duration(targetTimeoutSeconds) * time.Second
	if value.TargetTimeout < time.Second || value.TargetTimeout > time.Hour || value.MaxConcurrency < 1 || value.MaxConcurrency > 1000 || validatePersistedRunIdempotency(value) != nil {
		return Run{}, ErrInvalid
	}
	if scheduledFor.Valid {
		at := scheduledFor.Time.UTC()
		value.ScheduledFor = &at
	}
	if startedAt.Valid {
		at := startedAt.Time.UTC()
		value.StartedAt = &at
	}
	if finishedAt.Valid {
		at := finishedAt.Time.UTC()
		value.FinishedAt = &at
	}
	if len(policySnapshot) > 0 && string(policySnapshot) != "null" {
		value.PolicySnapshot = &Policy{}
		if err := json.Unmarshal(policySnapshot, value.PolicySnapshot); err != nil {
			return Run{}, err
		}
	}
	if err := json.Unmarshal(itemSnapshot, &value.ItemSnapshot); err != nil {
		return Run{}, err
	}
	normalizePersistedSystemItemLabels(value.ItemSnapshot)
	value.CreatedAt = value.CreatedAt.UTC()
	return value, nil
}

func normalizePersistedSystemItemLabels(items []Item) {
	for index := range items {
		if items[index].System && items[index].MetricRule != nil && items[index].MetricRule.Labels == nil {
			items[index].MetricRule.Labels = map[string]string{}
		}
	}
}

func insertPolicyItems(ctx context.Context, tx *sql.Tx, value Policy) error {
	for ordinal, item := range value.Items {
		if _, err := tx.ExecContext(ctx, "INSERT INTO inspection_policy_items (tenant_id, project_id, policy_id, item_id, item_version, ordinal) VALUES ($1, $2, $3, $4, $5, $6)", value.Scope.TenantID, value.Scope.ProjectID, value.ID, item.ItemID, item.Version, ordinal); err != nil {
			return fmt.Errorf("insert inspection policy item: %w", err)
		}
	}
	return nil
}

func randomToken() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("create inspection claim token: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

func runColumnNames() []string { return strings.Split(runColumnsSQL, ", ") }

var _ Repository = (*PostgresRepository)(nil)

func (repository *PostgresRepository) CreateItem(ctx context.Context, value Item) error {
	if repository == nil || repository.database == nil || ctx == nil || validateStoredItem(value) != nil {
		return ErrInvalid
	}
	snapshot, err := json.Marshal(value)
	if err != nil {
		return ErrInvalid
	}
	_, err = repository.database.ExecContext(ctx, insertItemSQL,
		value.Scope.TenantID, value.Scope.ProjectID, value.ID, value.Version, value.Enabled, value.System,
		value.Category, value.SourceType, snapshot, value.CreatedAt.UTC(), value.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert inspection item: %w", err)
	}
	return nil
}
func (repository *PostgresRepository) ListItems(ctx context.Context, scope platformscope.Scope, filter ItemFilter) (ItemPage, error) {
	var rows *sql.Rows
	var err error
	paginated := len(filter.Versions) == 0
	if len(filter.Versions) > 0 {
		if ctx == nil || repository == nil || repository.database == nil || scope.Validate() != nil {
			return ItemPage{}, ErrInvalid
		}
		query, args, buildErr := itemVersionsQuery(scope, filter)
		if buildErr != nil {
			return ItemPage{}, buildErr
		}
		rows, err = repository.database.QueryContext(ctx, query, args...)
	} else {
		if err := validateList(ctx, repository, scope, filter.CursorFilter); err != nil {
			return ItemPage{}, ErrInvalid
		}
		cursor, hasCursor, cursorErr := resolveInspectionCursor(scope, filter.CursorFilter, true)
		if cursorErr != nil {
			return ItemPage{}, cursorErr
		}
		if !hasCursor {
			rows, err = repository.database.QueryContext(ctx, selectItemsSQL, scope.TenantID, scope.ProjectID, filter.Limit+1)
		} else {
			rows, err = repository.database.QueryContext(ctx, selectItemsBeforeSQL, scope.TenantID, scope.ProjectID, cursor.CreatedAt, cursor.ID, cursor.Version, filter.Limit+1)
		}
	}
	if err != nil {
		return ItemPage{}, fmt.Errorf("list inspection items: %w", err)
	}
	defer rows.Close()
	page := ItemPage{Items: make([]Item, 0)}
	for rows.Next() {
		var snapshot []byte
		var createdAt time.Time
		if err := rows.Scan(&createdAt, &snapshot); err != nil {
			return ItemPage{}, fmt.Errorf("scan inspection item: %w", err)
		}
		var value Item
		if err := json.Unmarshal(snapshot, &value); err != nil {
			return ItemPage{}, fmt.Errorf("decode inspection item: %w", err)
		}
		if value.Scope != scope {
			return ItemPage{}, ErrConflict
		}
		value.CreatedAt = createdAt.UTC()
		page.Items = append(page.Items, value)
	}
	if err := rows.Err(); err != nil {
		return ItemPage{}, err
	}
	if paginated && len(page.Items) > filter.Limit {
		page.Items = page.Items[:filter.Limit]
		page.More = true
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodeInspectionCursor(inspectionCursor{Scope: scope, CreatedAt: last.CreatedAt, ID: last.ID, Version: last.Version})
		if err != nil {
			return ItemPage{}, err
		}
	}
	return page, nil
}
func (repository *PostgresRepository) CreatePolicy(ctx context.Context, value Policy) error {
	if repository == nil || repository.database == nil || ctx == nil || validatePolicy(value) != nil {
		return ErrInvalid
	}
	selector, items, err := marshalPolicyParts(value)
	if err != nil {
		return err
	}
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin inspection policy creation: %w", err)
	}
	rollback := func(cause error) error { _ = tx.Rollback(); return cause }
	cronValue, timezoneValue := scheduleValues(value.Schedule)
	if _, err := tx.ExecContext(ctx, insertPolicySQL,
		value.Scope.TenantID, value.Scope.ProjectID, value.ID, value.Name, value.Enabled, value.Version,
		cronValue, timezoneValue, nullableTime(value.NextRunAt), selector, items,
		int(value.TargetTimeout/time.Second), value.MaxConcurrency, value.CreatedAt.UTC(), value.UpdatedAt.UTC(),
	); err != nil {
		return rollback(fmt.Errorf("insert inspection policy: %w", err))
	}
	if err := insertPolicyItems(ctx, tx, value); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit inspection policy creation: %w", err)
	}
	return nil
}
func (repository *PostgresRepository) ListPolicies(ctx context.Context, scope platformscope.Scope, filter PolicyFilter) (PolicyPage, error) {
	if err := validateList(ctx, repository, scope, filter.CursorFilter); err != nil {
		return PolicyPage{}, ErrInvalid
	}
	cursor, hasCursor, err := resolveInspectionCursor(scope, filter.CursorFilter, false)
	if err != nil {
		return PolicyPage{}, err
	}
	var rows *sql.Rows
	if !hasCursor {
		rows, err = repository.database.QueryContext(ctx, selectPoliciesSQL, scope.TenantID, scope.ProjectID, filter.Limit+1)
	} else {
		rows, err = repository.database.QueryContext(ctx, selectPoliciesBeforeSQL, scope.TenantID, scope.ProjectID, cursor.CreatedAt, cursor.ID, filter.Limit+1)
	}
	if err != nil {
		return PolicyPage{}, fmt.Errorf("list inspection policies: %w", err)
	}
	defer rows.Close()
	page := PolicyPage{Items: make([]Policy, 0)}
	for rows.Next() {
		value, err := scanPolicy(rows)
		if err != nil {
			return PolicyPage{}, fmt.Errorf("scan inspection policy: %w", err)
		}
		page.Items = append(page.Items, value)
	}
	if err := rows.Err(); err != nil {
		return PolicyPage{}, err
	}
	if len(page.Items) > filter.Limit {
		page.Items = page.Items[:filter.Limit]
		page.More = true
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodeInspectionCursor(inspectionCursor{Scope: scope, CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			return PolicyPage{}, err
		}
	}
	return page, nil
}
func (repository *PostgresRepository) GetPolicy(ctx context.Context, scope platformscope.Scope, id string) (Policy, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !validID(id) {
		return Policy{}, ErrInvalid
	}
	value, err := scanPolicy(repository.database.QueryRowContext(ctx, selectPolicySQL, scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("get inspection policy: %w", err)
	}
	return value, nil
}
func (repository *PostgresRepository) CreateRunWithJob(ctx context.Context, run Run, targets []TargetRun, value job.Job, messages []job.OutboxMessage) error {
	if err := validateRunCreation(repository, ctx, run, targets, value, messages); err != nil {
		return err
	}
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin inspection run creation: %w", err)
	}
	rollback := func(cause error) error { _ = tx.Rollback(); return cause }
	inserted, err := insertRun(ctx, tx, insertRunSQL, run)
	if errors.Is(err, sql.ErrNoRows) {
		existing, getErr := scanRun(tx.QueryRowContext(ctx, selectRunByIdempotencySQL, run.Scope.TenantID, run.Scope.ProjectID, run.IdempotencyActor, run.IdempotencyOperation, run.IdempotencyKey))
		if getErr != nil {
			return rollback(getErr)
		}
		if existing.IdempotencyFingerprint != run.IdempotencyFingerprint {
			return rollback(ErrIdempotencyConflict)
		}
		return rollback(ErrDuplicate)
	}
	if err != nil {
		return rollback(err)
	}
	if inserted != run.ID {
		return rollback(ErrConflict)
	}
	if err := insertTargetRuns(ctx, tx, run, targets); err != nil {
		return rollback(err)
	}
	if err := repository.jobs.CreateInTx(ctx, tx, value, messages); err != nil {
		return rollback(fmt.Errorf("create inspection job and outbox: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit inspection run creation: %w", err)
	}
	return nil
}
func (repository *PostgresRepository) CreateClaimedRunWithJob(ctx context.Context, policy Policy, run Run, targets []TargetRun, value job.Job, messages []job.OutboxMessage) (Run, error) {
	if err := validateClaimedRun(policy, run); err != nil {
		return Run{}, err
	}
	if err := validateRunCreation(repository, ctx, run, targets, value, messages); err != nil {
		return Run{}, err
	}
	next := policy.Claim.NextOccurrence.UTC()
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return Run{}, fmt.Errorf("begin claimed inspection run creation: %w", err)
	}
	rollback := func(cause error) (Run, error) { _ = tx.Rollback(); return Run{}, cause }
	inserted, err := insertRun(ctx, tx, insertScheduledRunSQL, run)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return rollback(err)
	}
	result := run
	if errors.Is(err, sql.ErrNoRows) {
		result, err = scanRun(tx.QueryRowContext(ctx, selectRunByOccurrenceSQL, run.Scope.TenantID, run.Scope.ProjectID, run.OccurrenceKey))
		if err != nil {
			return rollback(fmt.Errorf("get duplicate inspection occurrence: %w", err))
		}
	} else {
		if inserted != run.ID {
			return rollback(ErrConflict)
		}
		if err := insertTargetRuns(ctx, tx, run, targets); err != nil {
			return rollback(err)
		}
		if err := repository.jobs.CreateInTx(ctx, tx, value, messages); err != nil {
			return rollback(fmt.Errorf("create scheduled inspection job and outbox: %w", err))
		}
	}
	var persistedNext time.Time
	err = tx.QueryRowContext(ctx, advanceClaimedPolicySQL,
		next, policy.Scope.TenantID, policy.Scope.ProjectID, policy.ID, policy.Version, policy.Claim.ClaimedOccurrence.UTC(), policy.Claim.Token,
	).Scan(&persistedNext)
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrConflict)
	}
	if err != nil {
		return rollback(fmt.Errorf("advance claimed inspection policy: %w", err))
	}
	if !persistedNext.UTC().Equal(next) {
		return rollback(ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return Run{}, fmt.Errorf("commit claimed inspection run creation: %w", err)
	}
	return result, nil
}
func (repository *PostgresRepository) GetRun(ctx context.Context, scope platformscope.Scope, id string) (RunDetail, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !validID(id) {
		return RunDetail{}, ErrInvalid
	}
	value, err := scanRun(repository.database.QueryRowContext(ctx, selectRunSQL, scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return RunDetail{}, ErrNotFound
	}
	if err != nil {
		return RunDetail{}, fmt.Errorf("get inspection run: %w", err)
	}
	targets, err := repository.getTargetRuns(ctx, scope, id)
	if err != nil {
		return RunDetail{}, err
	}
	findings, err := repository.getFindings(ctx, scope, id)
	if err != nil {
		return RunDetail{}, err
	}
	return RunDetail{Run: value, Targets: targets, Findings: findings}, nil
}
func (repository *PostgresRepository) GetRunByIdempotency(ctx context.Context, scope platformscope.Scope, correlation RunIdempotency) (Run, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || validateRunIdempotency(correlation) != nil {
		return Run{}, ErrInvalid
	}
	value, err := scanRun(repository.database.QueryRowContext(ctx, selectRunByIdempotencySQL, scope.TenantID, scope.ProjectID, correlation.Actor, correlation.Operation, correlation.Key))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil {
		return Run{}, fmt.Errorf("get inspection run by scoped idempotency key: %w", err)
	}
	if value.IdempotencyFingerprint != correlation.Fingerprint {
		return Run{}, ErrIdempotencyConflict
	}
	return value, nil
}
func (repository *PostgresRepository) GetReport(ctx context.Context, scope platformscope.Scope, id string) (ReportSnapshot, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !validStoredReportID(id) {
		return ReportSnapshot{}, ErrInvalid
	}
	value, err := scanReport(repository.database.QueryRowContext(ctx, selectReportSQL, scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ReportSnapshot{}, ErrNotFound
	}
	if err != nil {
		return ReportSnapshot{}, fmt.Errorf("get inspection report: %w", err)
	}
	return value, nil
}
func (repository *PostgresRepository) ListReports(ctx context.Context, scope platformscope.Scope, filter ReportFilter) (ReportPage, error) {
	if err := validateList(ctx, repository, scope, filter.CursorFilter); err != nil {
		return ReportPage{}, ErrInvalid
	}
	cursor, hasCursor, err := resolveInspectionCursor(scope, filter.CursorFilter, false)
	if err != nil {
		return ReportPage{}, err
	}
	var rows *sql.Rows
	if !hasCursor {
		rows, err = repository.database.QueryContext(ctx, selectReportsSQL, scope.TenantID, scope.ProjectID, filter.Limit+1)
	} else {
		rows, err = repository.database.QueryContext(ctx, selectReportsBeforeSQL, scope.TenantID, scope.ProjectID, cursor.CreatedAt, cursor.ID, filter.Limit+1)
	}
	if err != nil {
		return ReportPage{}, fmt.Errorf("list inspection reports: %w", err)
	}
	defer rows.Close()
	page := ReportPage{Items: make([]ReportSnapshot, 0)}
	for rows.Next() {
		value, err := scanReport(rows)
		if err != nil {
			return ReportPage{}, fmt.Errorf("scan inspection report: %w", err)
		}
		page.Items = append(page.Items, value)
	}
	if err := rows.Err(); err != nil {
		return ReportPage{}, err
	}
	if len(page.Items) > filter.Limit {
		page.Items = page.Items[:filter.Limit]
		page.More = true
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodeInspectionCursor(inspectionCursor{Scope: scope, CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			return ReportPage{}, err
		}
	}
	return page, nil
}

func validateStoredItem(value Item) error {
	if value.Scope.Validate() != nil || value.Validate() != nil || !isUTC(value.CreatedAt) || !isUTC(value.UpdatedAt) {
		return ErrInvalid
	}
	return nil
}

func validateRunCreation(repository *PostgresRepository, ctx context.Context, run Run, targets []TargetRun, value job.Job, messages []job.OutboxMessage) error {
	if repository == nil || repository.database == nil || repository.jobs == nil || ctx == nil || run.Scope.Validate() != nil || !validID(run.ID) || !validID(run.JobID) || run.JobID != value.ID || run.Scope != value.Scope || run.Status != RunQueued || (run.Trigger != RunTriggerManual && run.Trigger != RunTriggerScheduled && run.Trigger != RunTriggerRetry) || !isUTC(run.CreatedAt) || validateRunIdempotency(RunIdempotency{Actor: run.IdempotencyActor, Operation: run.IdempotencyOperation, Key: run.IdempotencyKey, Fingerprint: run.IdempotencyFingerprint}) != nil || run.IdempotencyActor != run.InitiatedBy || run.TargetCount != len(targets) || len(targets) == 0 || len(targets) > maxSnapshotTargets || len(messages) != len(targets) || len(run.ItemSnapshot) == 0 || run.TargetTimeout < time.Second || run.TargetTimeout > time.Hour || run.MaxConcurrency < 1 || run.MaxConcurrency > 1000 || run.TargetTimeout != value.TargetTimeout || run.MaxConcurrency != value.MaxConcurrency {
		return ErrInvalid
	}
	seenTargets := make(map[string]struct{}, len(targets))
	seenCommands := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target.Validate() != nil || !validID(target.CommandID) {
			return ErrInvalid
		}
		if _, duplicate := seenTargets[target.TargetID]; duplicate {
			return ErrInvalid
		}
		if _, duplicate := seenCommands[target.CommandID]; duplicate {
			return ErrInvalid
		}
		seenTargets[target.TargetID] = struct{}{}
		seenCommands[target.CommandID] = struct{}{}
	}
	return nil
}

func validateClaimedRun(policy Policy, run Run) error {
	if policy.Claim == nil || policy.Schedule == nil || policy.Scope != run.Scope || policy.ID != run.PolicyID || policy.Version != run.PolicyVersion || run.Trigger != RunTriggerScheduled || run.ScheduledFor == nil || !run.ScheduledFor.Equal(policy.Claim.Occurrence) || policy.NextRunAt == nil || !policy.NextRunAt.Equal(policy.Claim.ClaimedOccurrence) || !canonicalText(policy.Claim.Token) || !isUTC(policy.Claim.ClaimedOccurrence) || !isUTC(policy.Claim.Occurrence) || !isUTC(policy.Claim.NextOccurrence) || policy.Claim.Occurrence.Before(policy.Claim.ClaimedOccurrence) || run.OccurrenceKey != scheduledOccurrenceKey(policy, policy.Claim.Occurrence) {
		return ErrConflict
	}
	next, err := NextScheduledOccurrence(*policy.Schedule, policy.Claim.Occurrence)
	if err != nil || !next.Equal(policy.Claim.NextOccurrence) {
		return ErrConflict
	}
	return nil
}

func insertRun(ctx context.Context, tx *sql.Tx, query string, run Run) (string, error) {
	policySnapshot, itemSnapshot, err := marshalRunSnapshots(run)
	if err != nil {
		return "", err
	}
	var inserted string
	err = tx.QueryRowContext(ctx, query, runInsertArgs(run, policySnapshot, itemSnapshot)...).Scan(&inserted)
	return inserted, err
}

func marshalRunSnapshots(run Run) ([]byte, []byte, error) {
	var policySnapshot []byte
	var err error
	if run.PolicySnapshot != nil {
		policySnapshot, err = json.Marshal(run.PolicySnapshot)
		if err != nil {
			return nil, nil, ErrInvalid
		}
	}
	itemSnapshot, err := json.Marshal(run.ItemSnapshot)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	return policySnapshot, itemSnapshot, nil
}

func runInsertArgs(run Run, policySnapshot, itemSnapshot []byte) []any {
	return []any{
		run.Scope.TenantID, run.Scope.ProjectID, run.ID, nullableText(run.PolicyID), nullableInteger(run.PolicyVersion), nullableText(run.RetryOfRunID), run.JobID,
		run.Status, run.Trigger, nullableText(run.OccurrenceKey), nullableTime(run.ScheduledFor), nullableJSON(policySnapshot), itemSnapshot,
		run.TargetCount, run.CompletedTargetCount, run.FailedTargetCount, nullableText(run.ReportID), run.AuditCorrelation, nullableText(run.IdempotencyKey),
		run.InitiatedBy, run.RequestID, run.TraceID, nullableTime(run.StartedAt), nullableTime(run.FinishedAt), run.CreatedAt.UTC(),
		int64(run.TargetTimeout / time.Second), run.MaxConcurrency,
		run.IdempotencyActor, run.IdempotencyOperation, run.IdempotencyFingerprint,
	}
}

func insertTargetRuns(ctx context.Context, tx *sql.Tx, run Run, targets []TargetRun) error {
	for _, target := range targets {
		snapshot, err := json.Marshal(target)
		if err != nil {
			return ErrInvalid
		}
		if _, err := tx.ExecContext(ctx, insertTargetRunSQL,
			run.Scope.TenantID, run.Scope.ProjectID, run.ID, target.TargetID, target.AgentID, target.CommandID,
			target.Status, snapshot, target.ErrorCode, nullableTime(nonZeroTimePointer(target.ObservedAt)),
		); err != nil {
			return fmt.Errorf("insert inspection target run: %w", err)
		}
	}
	return nil
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableInteger(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullableJSON(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nonZeroTimePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

func (repository *PostgresRepository) getTargetRuns(ctx context.Context, scope platformscope.Scope, runID string) ([]TargetRun, error) {
	rows, err := repository.database.QueryContext(ctx, selectTargetRunsSQL, scope.TenantID, scope.ProjectID, runID)
	if err != nil {
		return nil, fmt.Errorf("list inspection target runs: %w", err)
	}
	defer rows.Close()
	result := make([]TargetRun, 0)
	for rows.Next() {
		var snapshot []byte
		var status TargetStatus
		var errorCode string
		var observedAt sql.NullTime
		if err := rows.Scan(&snapshot, &status, &errorCode, &observedAt); err != nil {
			return nil, fmt.Errorf("scan inspection target run: %w", err)
		}
		var target TargetRun
		if err := json.Unmarshal(snapshot, &target); err != nil {
			return nil, fmt.Errorf("decode inspection target run: %w", err)
		}
		target.Status = status
		target.ErrorCode = errorCode
		if observedAt.Valid {
			target.ObservedAt = observedAt.Time.UTC()
		} else {
			target.ObservedAt = time.Time{}
		}
		result = append(result, target)
	}
	return result, rows.Err()
}

func (repository *PostgresRepository) getFindings(ctx context.Context, scope platformscope.Scope, runID string) ([]Finding, error) {
	rows, err := repository.database.QueryContext(ctx, selectFindingsSQL, scope.TenantID, scope.ProjectID, runID)
	if err != nil {
		return nil, fmt.Errorf("list inspection findings: %w", err)
	}
	defer rows.Close()
	result := make([]Finding, 0)
	for rows.Next() {
		var value Finding
		var evidence []byte
		var warning, critical sql.NullFloat64
		if err := rows.Scan(
			&value.ID, &value.RunID, &value.TargetID, &value.ItemID, &value.ItemVersion, &value.Level,
			&value.ObservedAt, &evidence, &warning, &critical, &value.Summary, &value.Recommendation,
		); err != nil {
			return nil, fmt.Errorf("scan inspection finding: %w", err)
		}
		value.Scope = scope
		value.ObservedAt = value.ObservedAt.UTC()
		if err := json.Unmarshal(evidence, &value.Evidence); err != nil {
			return nil, fmt.Errorf("decode inspection finding evidence: %w", err)
		}
		if warning.Valid {
			value.WarningThreshold = &warning.Float64
		}
		if critical.Valid {
			value.CriticalThreshold = &critical.Float64
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func itemVersionsQuery(scope platformscope.Scope, filter ItemFilter) (string, []any, error) {
	if len(filter.Versions) == 0 || len(filter.Versions) > maxSnapshotItems || filter.Limit < 1 || filter.Limit > maxSnapshotItems+1 || filter.Cursor != "" || !filter.Before.IsZero() || filter.BeforeID != "" || filter.BeforeVersion != 0 {
		return "", nil, ErrInvalid
	}
	clauses := make([]string, len(filter.Versions))
	args := []any{scope.TenantID, scope.ProjectID}
	seen := make(map[string]struct{}, len(filter.Versions))
	for index, item := range filter.Versions {
		if !validID(item.ItemID) || item.Version < 1 {
			return "", nil, ErrInvalid
		}
		key := fmt.Sprintf("%s\x00%d", item.ItemID, item.Version)
		if _, duplicate := seen[key]; duplicate {
			return "", nil, ErrInvalid
		}
		seen[key] = struct{}{}
		itemPosition := 3 + index*2
		clauses[index] = fmt.Sprintf("(item_id = $%d AND version = $%d)", itemPosition, itemPosition+1)
		args = append(args, item.ItemID, item.Version)
	}
	args = append(args, filter.Limit)
	query := fmt.Sprintf("SELECT created_at, snapshot FROM inspection_items WHERE tenant_id = $1 AND project_id = $2 AND (%s) ORDER BY created_at DESC, item_id DESC, version DESC LIMIT $%d", strings.Join(clauses, " OR "), len(args))
	return query, args, nil
}

func scanReport(scanner interface{ Scan(...any) error }) (ReportSnapshot, error) {
	var value ReportSnapshot
	var policyID sql.NullString
	var artifacts []byte
	if err := scanner.Scan(
		&value.Scope.TenantID, &value.Scope.ProjectID, &value.ID, &value.RunID, &policyID,
		&value.Status, &value.Summary, &value.Snapshot, &artifacts, &value.GeneratedAt, &value.CreatedAt,
	); err != nil {
		return ReportSnapshot{}, err
	}
	value.PolicyID = policyID.String
	value.Snapshot = append([]byte(nil), value.Snapshot...)
	if err := json.Unmarshal(artifacts, &value.Artifacts); err != nil {
		return ReportSnapshot{}, fmt.Errorf("decode inspection report artifacts: %w", err)
	}
	value.GeneratedAt = value.GeneratedAt.UTC()
	value.CreatedAt = value.CreatedAt.UTC()
	return value, nil
}

func (repository *PostgresRepository) ClaimRuns(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]RunClaim, error) {
	if repository == nil || repository.database == nil || ctx == nil || now.IsZero() || limit < 1 || limit > maximumWorkerClaims || lease <= 0 {
		return nil, ErrInvalid
	}
	now = now.UTC()
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin inspection Run claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, claimRunsSQL, now, limit)
	if err != nil {
		return nil, fmt.Errorf("select inspection Run claims: %w", err)
	}
	claims := make([]RunClaim, 0, limit)
	for rows.Next() {
		value, generatedAt, err := scanRunClaim(rows)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan inspection Run claim: %w", err)
		}
		claims = append(claims, RunClaim{Detail: RunDetail{Run: value}, ReportGeneratedAt: generatedAt})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	leaseExpiresAt := now.Add(lease)
	for index := range claims {
		token, err := randomToken()
		if err != nil {
			return nil, err
		}
		var persisted string
		run := claims[index].Detail.Run
		if err := tx.QueryRowContext(ctx, claimRunSQL, token, leaseExpiresAt, run.Scope.TenantID, run.Scope.ProjectID, run.ID).Scan(&persisted); err != nil {
			return nil, fmt.Errorf("persist inspection Run claim: %w", err)
		}
		claims[index].Token = persisted
		claims[index].LeaseExpiresAt = leaseExpiresAt
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit inspection Run claims: %w", err)
	}
	for index := range claims {
		run := claims[index].Detail.Run
		targets, err := repository.getTargetRuns(ctx, run.Scope, run.ID)
		if err != nil {
			return nil, err
		}
		findings, err := repository.getFindings(ctx, run.Scope, run.ID)
		if err != nil {
			return nil, err
		}
		claims[index].Detail.Targets = targets
		claims[index].Detail.Findings = findings
		if run.Status == RunGeneratingReport && claims[index].ReportGeneratedAt.IsZero() {
			return nil, ErrInvalid
		}
	}
	return claims, nil
}

func scanRunClaim(scanner interface{ Scan(...any) error }) (Run, time.Time, error) {
	var value Run
	var policyID, retryID, occurrence, reportID, idempotency sql.NullString
	var policyVersion sql.NullInt64
	var scheduledFor, startedAt, finishedAt, reportGeneratedAt sql.NullTime
	var targetTimeoutSeconds int64
	var policySnapshot, itemSnapshot []byte
	err := scanner.Scan(
		&value.Scope.TenantID, &value.Scope.ProjectID, &value.ID, &policyID, &policyVersion, &retryID, &value.JobID,
		&value.Status, &value.Trigger, &occurrence, &scheduledFor, &policySnapshot, &itemSnapshot,
		&value.TargetCount, &value.CompletedTargetCount, &value.FailedTargetCount, &reportID, &value.AuditCorrelation, &idempotency,
		&value.InitiatedBy, &value.RequestID, &value.TraceID, &startedAt, &finishedAt, &value.CreatedAt,
		&targetTimeoutSeconds, &value.MaxConcurrency, &value.IdempotencyActor, &value.IdempotencyOperation, &value.IdempotencyFingerprint, &reportGeneratedAt,
	)
	if err != nil {
		return Run{}, time.Time{}, err
	}
	value.PolicyID, value.PolicyVersion, value.RetryOfRunID, value.OccurrenceKey, value.ReportID, value.IdempotencyKey = policyID.String, policyVersion.Int64, retryID.String, occurrence.String, reportID.String, idempotency.String
	value.TargetTimeout = time.Duration(targetTimeoutSeconds) * time.Second
	if value.TargetTimeout < time.Second || value.TargetTimeout > time.Hour || value.MaxConcurrency < 1 || value.MaxConcurrency > 1000 || validatePersistedRunIdempotency(value) != nil {
		return Run{}, time.Time{}, ErrInvalid
	}
	if scheduledFor.Valid {
		value.ScheduledFor = timePointerValueUTC(scheduledFor.Time)
	}
	if startedAt.Valid {
		value.StartedAt = timePointerValueUTC(startedAt.Time)
	}
	if finishedAt.Valid {
		value.FinishedAt = timePointerValueUTC(finishedAt.Time)
	}
	if len(policySnapshot) > 0 && string(policySnapshot) != "null" {
		value.PolicySnapshot = &Policy{}
		if err := json.Unmarshal(policySnapshot, value.PolicySnapshot); err != nil {
			return Run{}, time.Time{}, err
		}
	}
	if err := json.Unmarshal(itemSnapshot, &value.ItemSnapshot); err != nil {
		return Run{}, time.Time{}, err
	}
	normalizePersistedSystemItemLabels(value.ItemSnapshot)
	value.CreatedAt = value.CreatedAt.UTC()
	if reportGeneratedAt.Valid {
		return value, reportGeneratedAt.Time.UTC(), nil
	}
	return value, time.Time{}, nil
}

func (repository *PostgresRepository) MarkCollecting(ctx context.Context, claim RunClaim, at time.Time) (RunClaim, error) {
	if !validWorkerClaim(repository, ctx, claim) || at.IsZero() || claim.Detail.Run.Status != RunQueued {
		return RunClaim{}, ErrInvalid
	}
	run := claim.Detail.Run
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return RunClaim{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var startedAt time.Time
	err = tx.QueryRowContext(ctx, "UPDATE inspection_runs SET status = 'collecting', started_at = COALESCE(started_at, $1) WHERE tenant_id = $2 AND project_id = $3 AND id = $4 AND status = 'queued' AND worker_claim_token = $5 RETURNING started_at", at.UTC(), run.Scope.TenantID, run.Scope.ProjectID, run.ID, claim.Token).Scan(&startedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RunClaim{}, ErrConflict
	}
	if err != nil {
		return RunClaim{}, err
	}
	result, err := tx.ExecContext(ctx, "UPDATE inspection_target_runs SET status = 'collecting' WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 AND status = 'pending'", run.Scope.TenantID, run.Scope.ProjectID, run.ID)
	if err != nil {
		return RunClaim{}, err
	}
	if rowsAffected(result) != int64(run.TargetCount) {
		return RunClaim{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return RunClaim{}, err
	}
	claim.Detail.Run.Status = RunCollecting
	claim.Detail.Run.StartedAt = timePointerValueUTC(startedAt)
	for index := range claim.Detail.Targets {
		claim.Detail.Targets[index].Status = TargetCollecting
	}
	return claim, nil
}

func (repository *PostgresRepository) BeginEvaluation(ctx context.Context, claim RunClaim) (RunClaim, error) {
	if !validWorkerClaim(repository, ctx, claim) || claim.Detail.Run.Status != RunCollecting {
		return RunClaim{}, ErrInvalid
	}
	run := claim.Detail.Run
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return RunClaim{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var id string
	err = tx.QueryRowContext(ctx, "UPDATE inspection_runs SET status = 'evaluating' WHERE tenant_id = $1 AND project_id = $2 AND id = $3 AND status = 'collecting' AND worker_claim_token = $4 RETURNING id", run.Scope.TenantID, run.Scope.ProjectID, run.ID, claim.Token).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return RunClaim{}, ErrConflict
	}
	if err != nil {
		return RunClaim{}, err
	}
	result, err := tx.ExecContext(ctx, "UPDATE inspection_target_runs SET status = 'evaluating' WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 AND status = 'collecting'", run.Scope.TenantID, run.Scope.ProjectID, run.ID)
	if err != nil {
		return RunClaim{}, err
	}
	if rowsAffected(result) != int64(run.TargetCount) {
		return RunClaim{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return RunClaim{}, err
	}
	claim.Detail.Run.Status = RunEvaluating
	for index := range claim.Detail.Targets {
		claim.Detail.Targets[index].Status = TargetEvaluating
	}
	return claim, nil
}

func (repository *PostgresRepository) FreshSnapshotAt(ctx context.Context, scope platformscope.Scope, targetID, sourceID string, from, to time.Time) (time.Time, bool, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !validID(targetID) || sourceID != hostSnapshotSourceID || from.IsZero() || to.IsZero() || to.Before(from) {
		return time.Time{}, false, ErrInvalid
	}
	var sampledAt sql.NullTime
	if err := repository.database.QueryRowContext(ctx, freshSnapshotSQL, scope.TenantID, scope.ProjectID, targetID, sourceID, from.UTC(), to.UTC()).Scan(&sampledAt); err != nil {
		return time.Time{}, false, err
	}
	if !sampledAt.Valid {
		return time.Time{}, false, nil
	}
	return sampledAt.Time.UTC(), true, nil
}

func (repository *PostgresRepository) LoadHostSnapshot(ctx context.Context, scope platformscope.Scope, targetID string, items []Item, from, to time.Time, limit int) (HostSnapshotEvidence, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !validID(targetID) || len(items) == 0 || len(items) > maxSnapshotItems || from.IsZero() || to.IsZero() || to.Before(from) || limit < 1 || limit > maxEvidenceSamples {
		return HostSnapshotEvidence{}, ErrInvalidEvaluation
	}
	required := inspectionMetricRequirements(items)
	if len(required) == 0 {
		return HostSnapshotEvidence{}, nil
	}
	names := make([]string, 0, len(required))
	for name := range required {
		names = append(names, name)
	}
	sort.Strings(names)
	rows, err := repository.database.QueryContext(ctx, hostSnapshotSQL, scope.TenantID, scope.ProjectID, targetID, pq.Array(names), hostSnapshotSourceID, from.UTC(), to.UTC(), limit)
	if err != nil {
		return HostSnapshotEvidence{}, err
	}
	defer rows.Close()
	type snapshotGroup struct {
		sampledAt    time.Time
		seen         map[string]struct{}
		observations []Observation
	}
	groups := make([]snapshotGroup, 0)
	for rows.Next() {
		var metric, fingerprint string
		var labels []byte
		var value float64
		var sampledAt, acceptedAt time.Time
		if err := rows.Scan(&metric, &labels, &value, &sampledAt, &acceptedAt, &fingerprint); err != nil {
			return HostSnapshotEvidence{}, err
		}
		source, expected := required[metric]
		if !expected || acceptedAt.After(to) || sampledAt.Before(from) || sampledAt.After(to) {
			return HostSnapshotEvidence{}, ErrInvalidEvaluation
		}
		sampledAt = sampledAt.UTC()
		if len(groups) == 0 || !groups[len(groups)-1].sampledAt.Equal(sampledAt) {
			groups = append(groups, snapshotGroup{sampledAt: sampledAt, seen: make(map[string]struct{})})
		}
		group := &groups[len(groups)-1]
		group.seen[metric] = struct{}{}
		if source == SourceMetric {
			continue
		}
		var decodedLabels map[string]string
		if err := json.Unmarshal(labels, &decodedLabels); err != nil {
			return HostSnapshotEvidence{}, err
		}
		identity := targetID + "\x00" + metric + "\x00" + fingerprint + "\x00" + sampledAt.Format(time.RFC3339Nano)
		digest := sha256.Sum256([]byte(identity))
		group.observations = append(group.observations, Observation{
			ID: "metric-" + hex.EncodeToString(digest[:16]), TargetID: targetID, Name: metric, SourceType: source,
			Labels: decodedLabels, Value: value, ObservedAt: sampledAt,
		})
	}
	if err := rows.Err(); err != nil {
		return HostSnapshotEvidence{}, err
	}
	if len(groups) == 0 {
		return HostSnapshotEvidence{}, nil
	}
	selected := groups[0]
	for _, group := range groups {
		if len(group.seen) == len(required) {
			selected = group
			break
		}
	}
	sort.Slice(selected.observations, func(i, j int) bool {
		if selected.observations[i].Name != selected.observations[j].Name {
			return selected.observations[i].Name < selected.observations[j].Name
		}
		return selected.observations[i].ID < selected.observations[j].ID
	})
	if len(selected.observations) > maxTargetObservations {
		return HostSnapshotEvidence{}, ErrInvalidEvaluation
	}
	return HostSnapshotEvidence{SampledAt: selected.sampledAt, Observations: selected.observations, Complete: len(selected.seen) == len(required)}, nil
}

func (repository *PostgresRepository) Samples(ctx context.Context, scope platformscope.Scope, targetID string, names []string, from, to time.Time, limit int) ([]Observation, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !validID(targetID) || len(names) == 0 || len(names) > maxSnapshotItems || from.IsZero() || to.IsZero() || to.Before(from) || limit < 1 || limit > maxEvidenceSamples {
		return nil, ErrInvalidEvaluation
	}
	for _, name := range names {
		if !validMetricName(name) {
			return nil, ErrInvalidEvaluation
		}
	}
	rows, err := repository.database.QueryContext(ctx, evidenceSamplesSQL, scope.TenantID, scope.ProjectID, targetID, pq.Array(names), hostSnapshotSourceID, from.UTC(), to.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Observation, 0)
	for rows.Next() {
		var observation Observation
		var labels []byte
		var fingerprint string
		if err := rows.Scan(&observation.Name, &labels, &observation.Value, &observation.ObservedAt, &fingerprint); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(labels, &observation.Labels); err != nil {
			return nil, err
		}
		identity := targetID + "\x00" + observation.Name + "\x00" + fingerprint + "\x00" + observation.ObservedAt.UTC().Format(time.RFC3339Nano)
		digest := sha256.Sum256([]byte(identity))
		observation.ID = "metric-" + hex.EncodeToString(digest[:16])
		observation.TargetID = targetID
		observation.SourceType = SourceMetric
		observation.ObservedAt = observation.ObservedAt.UTC()
		result = append(result, observation)
	}
	return result, rows.Err()
}

func (repository *PostgresRepository) SaveEvaluation(ctx context.Context, claim RunClaim, targets []TargetRun, findings []Finding, generatedAt time.Time) (RunClaim, error) {
	if !validWorkerClaim(repository, ctx, claim) || claim.Detail.Run.Status != RunEvaluating || generatedAt.IsZero() || len(targets) != claim.Detail.Run.TargetCount {
		return RunClaim{}, ErrInvalid
	}
	run := claim.Detail.Run
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return RunClaim{}, err
	}
	defer func() { _ = tx.Rollback() }()
	seenTargets := make(map[string]struct{}, len(targets))
	completed, failed := 0, 0
	for _, target := range targets {
		if target.Validate() != nil || !validTerminalTargetStatus(target.Status) {
			return RunClaim{}, ErrInvalid
		}
		if _, duplicate := seenTargets[target.TargetID]; duplicate {
			return RunClaim{}, ErrInvalid
		}
		seenTargets[target.TargetID] = struct{}{}
		if target.Status == TargetSucceeded {
			completed++
		} else {
			failed++
		}
		result, err := tx.ExecContext(ctx, "UPDATE inspection_target_runs SET status = $1, error_code = $2, observed_at = $3 WHERE tenant_id = $4 AND project_id = $5 AND run_id = $6 AND target_id = $7", target.Status, target.ErrorCode, nullableTime(nonZeroTimePointer(target.ObservedAt)), run.Scope.TenantID, run.Scope.ProjectID, run.ID, target.TargetID)
		if err != nil || !exactlyOneRow(result) {
			if err != nil {
				return RunClaim{}, err
			}
			return RunClaim{}, ErrConflict
		}
	}
	for _, finding := range findings {
		if finding.Validate() != nil || finding.Scope != run.Scope || finding.RunID != run.ID {
			return RunClaim{}, ErrInvalid
		}
		if _, exists := seenTargets[finding.TargetID]; !exists {
			return RunClaim{}, ErrInvalid
		}
		if err := insertFindingOnce(ctx, tx, finding); err != nil {
			return RunClaim{}, err
		}
	}
	var persistedGeneratedAt time.Time
	err = tx.QueryRowContext(ctx, "UPDATE inspection_runs SET status = 'generating_report', completed_target_count = $1, failed_target_count = $2, report_generated_at = COALESCE(report_generated_at, $3) WHERE tenant_id = $4 AND project_id = $5 AND id = $6 AND status = 'evaluating' AND worker_claim_token = $7 RETURNING report_generated_at", completed, failed, generatedAt.UTC(), run.Scope.TenantID, run.Scope.ProjectID, run.ID, claim.Token).Scan(&persistedGeneratedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RunClaim{}, ErrConflict
	}
	if err != nil {
		return RunClaim{}, err
	}
	if err := tx.Commit(); err != nil {
		return RunClaim{}, err
	}
	persistedTargets, err := repository.getTargetRuns(ctx, run.Scope, run.ID)
	if err != nil {
		return RunClaim{}, err
	}
	persistedFindings, err := repository.getFindings(ctx, run.Scope, run.ID)
	if err != nil {
		return RunClaim{}, err
	}
	claim.Detail.Run.Status = RunGeneratingReport
	claim.Detail.Run.CompletedTargetCount = completed
	claim.Detail.Run.FailedTargetCount = failed
	claim.Detail.Targets = persistedTargets
	claim.Detail.Findings = persistedFindings
	claim.ReportGeneratedAt = persistedGeneratedAt.UTC()
	return claim, nil
}

func insertFindingOnce(ctx context.Context, tx *sql.Tx, finding Finding) error {
	evidence, err := json.Marshal(finding.Evidence)
	if err != nil {
		return err
	}
	var id string
	err = tx.QueryRowContext(ctx, "INSERT INTO inspection_findings (tenant_id, project_id, id, run_id, target_id, item_id, item_version, level, observed_at, evidence, warning_threshold, critical_threshold, summary, recommendation) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) ON CONFLICT (tenant_id, project_id, run_id, target_id, item_id, item_version) DO NOTHING RETURNING id", finding.Scope.TenantID, finding.Scope.ProjectID, finding.ID, finding.RunID, finding.TargetID, finding.ItemID, finding.ItemVersion, finding.Level, finding.ObservedAt.UTC(), evidence, finding.WarningThreshold, finding.CriticalThreshold, finding.Summary, finding.Recommendation).Scan(&id)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	existing, err := scanFinding(tx.QueryRowContext(ctx, "SELECT "+findingColumnsSQL+" FROM inspection_findings WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 AND target_id = $4 AND item_id = $5 AND item_version = $6", finding.Scope.TenantID, finding.Scope.ProjectID, finding.RunID, finding.TargetID, finding.ItemID, finding.ItemVersion), finding.Scope)
	if err != nil {
		return err
	}
	if !equalFinding(existing, finding) {
		return ErrConflict
	}
	return nil
}

func (repository *PostgresRepository) ReleaseRun(ctx context.Context, claim RunClaim) error {
	if !validWorkerClaim(repository, ctx, claim) {
		return ErrInvalid
	}
	run := claim.Detail.Run
	_, err := repository.database.ExecContext(ctx, "UPDATE inspection_runs SET worker_claim_token = NULL, worker_lease_expires_at = NULL WHERE tenant_id = $1 AND project_id = $2 AND id = $3 AND worker_claim_token = $4", run.Scope.TenantID, run.Scope.ProjectID, run.ID, claim.Token)
	return err
}

func (repository *PostgresRepository) FailReport(ctx context.Context, claim RunClaim, at time.Time) error {
	if !validWorkerClaim(repository, ctx, claim) || claim.Detail.Run.Status != RunGeneratingReport || at.IsZero() {
		return ErrInvalid
	}
	run := claim.Detail.Run
	var runID string
	err := repository.database.QueryRowContext(ctx, "UPDATE inspection_runs SET status = 'failed', finished_at = $1, worker_claim_token = NULL, worker_lease_expires_at = NULL WHERE tenant_id = $2 AND project_id = $3 AND id = $4 AND status = 'generating_report' AND worker_claim_token = $5 RETURNING id", at.UTC(), run.Scope.TenantID, run.Scope.ProjectID, run.ID, claim.Token).Scan(&runID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict
	}
	return err
}

func (repository *PostgresRepository) FinalizeReport(ctx context.Context, claim RunClaim, report ReportSnapshot, terminal RunStatus, event audit.Event, at time.Time) (ReportAuditClaim, error) {
	if !validWorkerClaim(repository, ctx, claim) || claim.Detail.Run.Status != RunGeneratingReport || !isTerminalRunStatus(terminal) || report.Scope != claim.Detail.Run.Scope || report.RunID != claim.Detail.Run.ID || report.Status != ReportCompleted || len(report.Snapshot) == 0 || len(report.Snapshot) > maximumReportBytes || len(report.Artifacts) != 2 || at.IsZero() || event.Scope != report.Scope || !canonicalText(event.DedupeKey) {
		return ReportAuditClaim{}, ErrInvalid
	}
	artifacts, err := json.Marshal(report.Artifacts)
	if err != nil {
		return ReportAuditClaim{}, err
	}
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return ReportAuditClaim{}, err
	}
	run := claim.Detail.Run
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return ReportAuditClaim{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var reportID string
	err = tx.QueryRowContext(ctx, "INSERT INTO inspection_reports (tenant_id, project_id, id, run_id, policy_id, status, summary, snapshot, artifacts, generated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (tenant_id, project_id, run_id) DO NOTHING RETURNING id", report.Scope.TenantID, report.Scope.ProjectID, report.ID, report.RunID, nullableText(report.PolicyID), report.Status, report.Summary, report.Snapshot, artifacts, report.GeneratedAt.UTC()).Scan(&reportID)
	if errors.Is(err, sql.ErrNoRows) {
		existing, getErr := scanReport(tx.QueryRowContext(ctx, selectReportSQL, report.Scope.TenantID, report.Scope.ProjectID, report.ID))
		if getErr != nil || !equalReportSnapshot(existing, report) {
			if getErr != nil && !errors.Is(getErr, sql.ErrNoRows) {
				return ReportAuditClaim{}, getErr
			}
			return ReportAuditClaim{}, ErrConflict
		}
	} else if err != nil {
		return ReportAuditClaim{}, err
	}
	completed, failed := targetCounts(claim.Detail.Targets)
	var runID string
	err = tx.QueryRowContext(ctx, "UPDATE inspection_runs SET status = $1, report_id = $2, completed_target_count = $3, failed_target_count = $4, finished_at = $5, report_audit_pending = TRUE, report_audit_event = $6, report_audit_dedupe_key = $7, report_audit_claim_token = NULL, report_audit_lease_expires_at = NULL, worker_claim_token = NULL, worker_lease_expires_at = NULL WHERE tenant_id = $8 AND project_id = $9 AND id = $10 AND status = 'generating_report' AND worker_claim_token = $11 RETURNING id", terminal, report.ID, completed, failed, at.UTC(), eventJSON, event.DedupeKey, run.Scope.TenantID, run.Scope.ProjectID, run.ID, claim.Token).Scan(&runID)
	if errors.Is(err, sql.ErrNoRows) {
		return ReportAuditClaim{}, ErrConflict
	}
	if err != nil {
		return ReportAuditClaim{}, err
	}
	if err := tx.Commit(); err != nil {
		return ReportAuditClaim{}, err
	}
	return ReportAuditClaim{Scope: run.Scope, RunID: run.ID, Event: event}, nil
}

func (repository *PostgresRepository) ClaimPendingReportAudits(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]ReportAuditClaim, error) {
	if repository == nil || repository.database == nil || ctx == nil || now.IsZero() || limit < 1 || limit > maximumWorkerClaims || lease <= 0 {
		return nil, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, "SELECT tenant_id, project_id, id, report_audit_event, report_audit_dedupe_key FROM inspection_runs WHERE report_audit_pending = TRUE AND (report_audit_lease_expires_at IS NULL OR report_audit_lease_expires_at <= $1) ORDER BY finished_at, tenant_id, project_id, id FOR UPDATE SKIP LOCKED LIMIT $2", now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	claims := make([]ReportAuditClaim, 0, limit)
	for rows.Next() {
		var claim ReportAuditClaim
		var encoded []byte
		var dedupe string
		if err := rows.Scan(&claim.Scope.TenantID, &claim.Scope.ProjectID, &claim.RunID, &encoded, &dedupe); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(encoded, &claim.Event); err != nil {
			_ = rows.Close()
			return nil, err
		}
		claim.Event.DedupeKey = dedupe
		if claim.Event.Scope != claim.Scope {
			_ = rows.Close()
			return nil, ErrInvalid
		}
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	leaseExpiresAt := now.UTC().Add(lease)
	for index := range claims {
		token, err := randomToken()
		if err != nil {
			return nil, err
		}
		var persisted string
		claim := claims[index]
		err = tx.QueryRowContext(ctx, "UPDATE inspection_runs SET report_audit_claim_token = $1, report_audit_lease_expires_at = $2, report_audit_attempts = report_audit_attempts + 1 WHERE tenant_id = $3 AND project_id = $4 AND id = $5 AND report_audit_pending = TRUE RETURNING report_audit_claim_token", token, leaseExpiresAt, claim.Scope.TenantID, claim.Scope.ProjectID, claim.RunID).Scan(&persisted)
		if err != nil {
			return nil, err
		}
		claims[index].Token = persisted
		claims[index].LeaseExpiresAt = leaseExpiresAt
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claims, nil
}

func (repository *PostgresRepository) MarkReportAuditRecorded(ctx context.Context, claim ReportAuditClaim, at time.Time) error {
	if repository == nil || repository.database == nil || ctx == nil || claim.Scope.Validate() != nil || !validID(claim.RunID) || !canonicalText(claim.Event.DedupeKey) || at.IsZero() {
		return ErrInvalid
	}
	statement := "UPDATE inspection_runs SET report_audit_pending = FALSE, report_audit_claim_token = NULL, report_audit_lease_expires_at = NULL, report_audit_recorded_at = $1 WHERE tenant_id = $2 AND project_id = $3 AND id = $4 AND report_audit_pending = TRUE AND report_audit_dedupe_key = $5 AND report_audit_claim_token IS NULL"
	arguments := []any{at.UTC(), claim.Scope.TenantID, claim.Scope.ProjectID, claim.RunID, claim.Event.DedupeKey}
	if claim.Token != "" {
		statement = "UPDATE inspection_runs SET report_audit_pending = FALSE, report_audit_claim_token = NULL, report_audit_lease_expires_at = NULL, report_audit_recorded_at = $1 WHERE tenant_id = $2 AND project_id = $3 AND id = $4 AND report_audit_pending = TRUE AND report_audit_dedupe_key = $5 AND report_audit_claim_token = $6"
		arguments = append(arguments, claim.Token)
	}
	result, err := repository.database.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return err
	}
	if !exactlyOneRow(result) {
		return ErrConflict
	}
	return nil
}

func (repository *PostgresRepository) ReleaseReportAudit(ctx context.Context, claim ReportAuditClaim) error {
	if repository == nil || repository.database == nil || ctx == nil || claim.Scope.Validate() != nil || !validID(claim.RunID) {
		return ErrInvalid
	}
	if claim.Token == "" {
		return nil
	}
	_, err := repository.database.ExecContext(ctx, "UPDATE inspection_runs SET report_audit_claim_token = NULL, report_audit_lease_expires_at = NULL WHERE tenant_id = $1 AND project_id = $2 AND id = $3 AND report_audit_pending = TRUE AND report_audit_claim_token = $4", claim.Scope.TenantID, claim.Scope.ProjectID, claim.RunID, claim.Token)
	return err
}

func scanFinding(scanner interface{ Scan(...any) error }, scope platformscope.Scope) (Finding, error) {
	var value Finding
	var evidence []byte
	var warning, critical sql.NullFloat64
	err := scanner.Scan(&value.ID, &value.RunID, &value.TargetID, &value.ItemID, &value.ItemVersion, &value.Level, &value.ObservedAt, &evidence, &warning, &critical, &value.Summary, &value.Recommendation)
	if err != nil {
		return Finding{}, err
	}
	value.Scope = scope
	value.ObservedAt = value.ObservedAt.UTC()
	if err := json.Unmarshal(evidence, &value.Evidence); err != nil {
		return Finding{}, err
	}
	if warning.Valid {
		value.WarningThreshold = &warning.Float64
	}
	if critical.Valid {
		value.CriticalThreshold = &critical.Float64
	}
	return value, nil
}

func equalFinding(first, second Finding) bool {
	firstEvidence, _ := json.Marshal(first.Evidence)
	secondEvidence, _ := json.Marshal(second.Evidence)
	return first.ID == second.ID && first.Scope == second.Scope && first.RunID == second.RunID && first.TargetID == second.TargetID && first.ItemID == second.ItemID && first.ItemVersion == second.ItemVersion && first.Level == second.Level && first.ObservedAt.Equal(second.ObservedAt) && nullableFloatEqual(first.WarningThreshold, second.WarningThreshold) && nullableFloatEqual(first.CriticalThreshold, second.CriticalThreshold) && first.Summary == second.Summary && first.Recommendation == second.Recommendation && bytes.Equal(firstEvidence, secondEvidence)
}

func equalReportSnapshot(first, second ReportSnapshot) bool {
	firstArtifacts, _ := json.Marshal(first.Artifacts)
	secondArtifacts, _ := json.Marshal(second.Artifacts)
	return first.ID == second.ID && first.Scope == second.Scope && first.RunID == second.RunID && first.PolicyID == second.PolicyID && first.Status == second.Status && first.Summary == second.Summary && bytes.Equal(first.Snapshot, second.Snapshot) && bytes.Equal(firstArtifacts, secondArtifacts) && first.GeneratedAt.Equal(second.GeneratedAt)
}

func nullableFloatEqual(first, second *float64) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return *first == *second
}

func validWorkerClaim(repository *PostgresRepository, ctx context.Context, claim RunClaim) bool {
	return repository != nil && repository.database != nil && ctx != nil && claim.Detail.Run.Scope.Validate() == nil && validID(claim.Detail.Run.ID) && canonicalText(claim.Token)
}

func exactlyOneRow(result sql.Result) bool {
	if result == nil {
		return false
	}
	rows, err := result.RowsAffected()
	return err == nil && rows == 1
}

func rowsAffected(result sql.Result) int64 {
	if result == nil {
		return -1
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return -1
	}
	return rows
}

func timePointerValueUTC(value time.Time) *time.Time {
	at := value.UTC()
	return &at
}

func targetCounts(targets []TargetRun) (int, int) {
	completed, failed := 0, 0
	for _, target := range targets {
		if target.Status == TargetSucceeded {
			completed++
		} else {
			failed++
		}
	}
	return completed, failed
}

var _ RunWorkerRepository = (*PostgresRepository)(nil)
var _ EvidenceStore = (*PostgresRepository)(nil)
