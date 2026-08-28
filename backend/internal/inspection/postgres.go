package inspection

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
)

const policyColumnsSQL = "tenant_id, project_id, id, name, enabled, version, schedule_cron, schedule_timezone, next_run_at, target_selector, item_snapshot, target_timeout_seconds, max_concurrency, created_at, updated_at, claim_token, lease_expires_at"
const runColumnsSQL = "tenant_id, project_id, id, policy_id, policy_version, retry_of_run_id, job_id, status, trigger_source, occurrence_key, scheduled_for, policy_snapshot, item_snapshot, target_count, completed_target_count, failed_target_count, report_id, audit_correlation, idempotency_key, initiated_by, request_id, trace_id, started_at, finished_at, created_at"

const selectRunsBeforeSQL = "SELECT " + runColumnsSQL + " FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND (created_at, id) < ($3, $4) ORDER BY created_at DESC, id DESC LIMIT $5"
const selectDuePoliciesSQL = "SELECT " + policyColumnsSQL + " FROM inspection_policies WHERE enabled = TRUE AND next_run_at <= $1 AND (lease_expires_at IS NULL OR lease_expires_at <= $1) ORDER BY next_run_at, tenant_id, project_id, id FOR UPDATE SKIP LOCKED LIMIT $2"
const claimPolicySQL = "UPDATE inspection_policies SET claim_token = $1, lease_expires_at = $2 WHERE tenant_id = $3 AND project_id = $4 AND id = $5 AND version = $6 RETURNING claim_token"
const insertItemSQL = "INSERT INTO inspection_items (tenant_id, project_id, item_id, version, enabled, system, category, source_type, snapshot, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
const insertRunSQL = "INSERT INTO inspection_runs (tenant_id, project_id, id, policy_id, policy_version, retry_of_run_id, job_id, status, trigger_source, occurrence_key, scheduled_for, policy_snapshot, item_snapshot, target_count, completed_target_count, failed_target_count, report_id, audit_correlation, idempotency_key, initiated_by, request_id, trace_id, started_at, finished_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25) ON CONFLICT (tenant_id, project_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING RETURNING id"
const insertScheduledRunSQL = "INSERT INTO inspection_runs (tenant_id, project_id, id, policy_id, policy_version, retry_of_run_id, job_id, status, trigger_source, occurrence_key, scheduled_for, policy_snapshot, item_snapshot, target_count, completed_target_count, failed_target_count, report_id, audit_correlation, idempotency_key, initiated_by, request_id, trace_id, started_at, finished_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25) ON CONFLICT (tenant_id, project_id, occurrence_key) DO NOTHING RETURNING id"
const insertTargetRunSQL = "INSERT INTO inspection_target_runs (tenant_id, project_id, run_id, target_id, agent_id, command_id, status, target_snapshot, error_code, observed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
const selectRunByOccurrenceSQL = "SELECT " + runColumnsSQL + " FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND occurrence_key = $3"
const selectRunByIdempotencySQL = "SELECT " + runColumnsSQL + " FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND idempotency_key = $3"
const advanceClaimedPolicySQL = "UPDATE inspection_policies SET next_run_at = $1, claim_token = NULL, lease_expires_at = NULL WHERE tenant_id = $2 AND project_id = $3 AND id = $4 AND version = $5 AND next_run_at = $6 AND claim_token = $7 RETURNING next_run_at"
const insertPolicySQL = "INSERT INTO inspection_policies (tenant_id, project_id, id, name, enabled, version, schedule_cron, schedule_timezone, next_run_at, target_selector, item_snapshot, target_timeout_seconds, max_concurrency, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"
const selectRunSQL = "SELECT " + runColumnsSQL + " FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND id = $3"
const selectTargetRunsSQL = "SELECT target_snapshot FROM inspection_target_runs WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 ORDER BY target_id"
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
		value.Claim = &PolicyClaim{Token: claimToken.String, Occurrence: *value.NextRunAt, LeaseExpiresAt: leaseExpiresAt.Time.UTC()}
	}
	return value, nil
}

func scanRun(scanner interface{ Scan(...any) error }) (Run, error) {
	var value Run
	var policyID, retryID, occurrence, reportID, idempotency sql.NullString
	var policyVersion sql.NullInt64
	var scheduledFor, startedAt, finishedAt sql.NullTime
	var policySnapshot, itemSnapshot []byte
	err := scanner.Scan(&value.Scope.TenantID, &value.Scope.ProjectID, &value.ID, &policyID, &policyVersion, &retryID, &value.JobID, &value.Status, &value.Trigger, &occurrence, &scheduledFor, &policySnapshot, &itemSnapshot, &value.TargetCount, &value.CompletedTargetCount, &value.FailedTargetCount, &reportID, &value.AuditCorrelation, &idempotency, &value.InitiatedBy, &value.RequestID, &value.TraceID, &startedAt, &finishedAt, &value.CreatedAt)
	if err != nil {
		return Run{}, err
	}
	value.PolicyID, value.PolicyVersion, value.RetryOfRunID, value.OccurrenceKey, value.ReportID, value.IdempotencyKey = policyID.String, policyVersion.Int64, retryID.String, occurrence.String, reportID.String, idempotency.String
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
	value.CreatedAt = value.CreatedAt.UTC()
	return value, nil
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
	next, err := NextScheduledOccurrence(*policy.Schedule, policy.Claim.Occurrence)
	if err != nil {
		return Run{}, err
	}
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
		next, policy.Scope.TenantID, policy.Scope.ProjectID, policy.ID, policy.Version, policy.Claim.Occurrence.UTC(), policy.Claim.Token,
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
func (repository *PostgresRepository) GetRunByIdempotencyKey(ctx context.Context, scope platformscope.Scope, key string) (Run, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !canonicalText(key) {
		return Run{}, ErrInvalid
	}
	value, err := scanRun(repository.database.QueryRowContext(ctx, selectRunByIdempotencySQL, scope.TenantID, scope.ProjectID, key))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil {
		return Run{}, fmt.Errorf("get inspection run by idempotency key: %w", err)
	}
	return value, nil
}
func (repository *PostgresRepository) GetReport(ctx context.Context, scope platformscope.Scope, id string) (ReportSnapshot, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !validID(id) {
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
	if repository == nil || repository.database == nil || repository.jobs == nil || ctx == nil || run.Scope.Validate() != nil || !validID(run.ID) || !validID(run.JobID) || run.JobID != value.ID || run.Scope != value.Scope || run.Status != RunQueued || (run.Trigger != RunTriggerManual && run.Trigger != RunTriggerScheduled && run.Trigger != RunTriggerRetry) || !isUTC(run.CreatedAt) || !canonicalText(run.IdempotencyKey) || run.TargetCount != len(targets) || len(targets) == 0 || len(targets) > maxSnapshotTargets || len(messages) != len(targets) || len(run.ItemSnapshot) == 0 {
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
	if policy.Claim == nil || policy.Schedule == nil || policy.Scope != run.Scope || policy.ID != run.PolicyID || policy.Version != run.PolicyVersion || run.Trigger != RunTriggerScheduled || run.ScheduledFor == nil || !run.ScheduledFor.Equal(policy.Claim.Occurrence) || policy.NextRunAt == nil || !policy.NextRunAt.Equal(policy.Claim.Occurrence) || !canonicalText(policy.Claim.Token) || run.OccurrenceKey != scheduledOccurrenceKey(policy, policy.Claim.Occurrence) {
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
		if err := rows.Scan(&snapshot); err != nil {
			return nil, fmt.Errorf("scan inspection target run: %w", err)
		}
		var target TargetRun
		if err := json.Unmarshal(snapshot, &target); err != nil {
			return nil, fmt.Errorf("decode inspection target run: %w", err)
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
