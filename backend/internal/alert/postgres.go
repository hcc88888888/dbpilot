package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

var (
	ErrNotFound = errors.New("alert record not found")
)

const ruleColumnsSQL = "id, tenant_id, project_id, name, metric, aggregation, operator, threshold, evaluation_every_ns, for_duration_ns, missing_data, severity, notification_policy_ids, labels, enabled, created_at, updated_at"
const eventColumnsSQL = "id, tenant_id, project_id, rule_id, fingerprint, labels, evidence, state, first_seen, last_seen, firing_at, acknowledged_at, resolved_at, last_actor"
const eventUpsertSQL = "INSERT INTO alert_events (id, tenant_id, project_id, rule_id, fingerprint, labels, evidence, state, first_seen, last_seen, firing_at, acknowledged_at, resolved_at, last_actor) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) ON CONFLICT (tenant_id, project_id, fingerprint) DO UPDATE SET labels = EXCLUDED.labels, evidence = EXCLUDED.evidence, state = EXCLUDED.state, last_seen = EXCLUDED.last_seen, firing_at = EXCLUDED.firing_at, acknowledged_at = EXCLUDED.acknowledged_at, resolved_at = EXCLUDED.resolved_at, last_actor = EXCLUDED.last_actor RETURNING " + eventColumnsSQL
const eventLockSQL = "SELECT " + eventColumnsSQL + " FROM alert_events WHERE tenant_id = $1 AND project_id = $2 AND fingerprint = $3 FOR UPDATE"
const auditInsertSQL = "INSERT INTO alert_audit_log (id, tenant_id, project_id, actor, action, target_id, occurred_at, details) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) CreateRule(ctx context.Context, rule AlertRule) (AlertRule, error) {
	if err := rule.Validate(); err != nil {
		return AlertRule{}, err
	}
	actor, err := auditActorFromContext(ctx)
	if err != nil {
		return AlertRule{}, err
	}
	labels, err := marshalMap(rule.Labels)
	if err != nil {
		return AlertRule{}, err
	}
	query := "WITH changed AS (INSERT INTO alert_rules (id, tenant_id, project_id, name, metric, aggregation, operator, threshold, evaluation_every_ns, for_duration_ns, missing_data, severity, notification_policy_ids, labels, enabled) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING " + ruleColumnsSQL + "), audited AS (INSERT INTO alert_audit_log (id, tenant_id, project_id, actor, action, target_id, occurred_at, details) SELECT 'audit-' || md5(id || ':created:' || created_at::text), tenant_id, project_id, $16, 'rule.created', id, created_at, jsonb_build_object('aggregation', aggregation, 'operator', operator, 'threshold', threshold::text, 'severity', severity, 'enabled', enabled::text) FROM changed) SELECT " + ruleColumnsSQL + " FROM changed"
	return scanRule(r.db.QueryRowContext(ctx, query, rule.ID, rule.Scope.TenantID, rule.Scope.ProjectID, rule.Name, rule.Metric, rule.Aggregation, rule.Operator, rule.Threshold, rule.EvaluationEvery.Nanoseconds(), rule.For.Nanoseconds(), rule.MissingData, rule.Severity, pq.Array(rule.NotificationPolicyIDs), labels, rule.Enabled, actor))
}

func (r *PostgresRepository) UpdateRule(ctx context.Context, rule AlertRule) (AlertRule, error) {
	if err := rule.Validate(); err != nil {
		return AlertRule{}, err
	}
	actor, err := auditActorFromContext(ctx)
	if err != nil {
		return AlertRule{}, err
	}
	labels, err := marshalMap(rule.Labels)
	if err != nil {
		return AlertRule{}, err
	}
	query := "WITH changed AS (UPDATE alert_rules SET name = $1, metric = $2, aggregation = $3, operator = $4, threshold = $5, evaluation_every_ns = $6, for_duration_ns = $7, missing_data = $8, severity = $9, notification_policy_ids = $10, labels = $11, enabled = $12, updated_at = NOW() WHERE tenant_id = $13 AND project_id = $14 AND id = $15 RETURNING " + ruleColumnsSQL + "), audited AS (INSERT INTO alert_audit_log (id, tenant_id, project_id, actor, action, target_id, occurred_at, details) SELECT 'audit-' || md5(id || ':updated:' || updated_at::text), tenant_id, project_id, $16, 'rule.updated', id, updated_at, jsonb_build_object('aggregation', aggregation, 'operator', operator, 'threshold', threshold::text, 'severity', severity, 'enabled', enabled::text) FROM changed) SELECT " + ruleColumnsSQL + " FROM changed"
	rule, err = scanRule(r.db.QueryRowContext(ctx, query, rule.Name, rule.Metric, rule.Aggregation, rule.Operator, rule.Threshold, rule.EvaluationEvery.Nanoseconds(), rule.For.Nanoseconds(), rule.MissingData, rule.Severity, pq.Array(rule.NotificationPolicyIDs), labels, rule.Enabled, rule.Scope.TenantID, rule.Scope.ProjectID, rule.ID, actor))
	if errors.Is(err, sql.ErrNoRows) {
		return AlertRule{}, ErrNotFound
	}
	return rule, err
}

func (r *PostgresRepository) ListRules(ctx context.Context, scope Scope) ([]AlertRule, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	query := "SELECT " + ruleColumnsSQL + " FROM alert_rules WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at DESC"
	rows, err := r.db.QueryContext(ctx, query, scope.TenantID, scope.ProjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]AlertRule, 0)
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (r *PostgresRepository) GetRule(ctx context.Context, scope Scope, id string) (AlertRule, error) {
	if err := scope.Validate(); err != nil {
		return AlertRule{}, err
	}
	query := "SELECT " + ruleColumnsSQL + " FROM alert_rules WHERE tenant_id = $1 AND project_id = $2 AND id = $3"
	rule, err := scanRule(r.db.QueryRowContext(ctx, query, scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return AlertRule{}, ErrNotFound
	}
	return rule, err
}

func (r *PostgresRepository) PutEvent(ctx context.Context, event AlertEvent) (AlertEvent, error) {
	return r.mutateEvent(ctx, event, nil)
}

func (r *PostgresRepository) PutEventAndAudit(ctx context.Context, event AlertEvent, record AuditRecord) (AlertEvent, error) {
	if err := event.Validate(); err != nil {
		return AlertEvent{}, err
	}
	if err := validateAuditDetailTypes(record); err != nil {
		return AlertEvent{}, err
	}
	record = sanitizeAuditRecord(record)
	if err := record.Validate(); err != nil {
		return AlertEvent{}, err
	}
	if err := validateLifecycleAudit(event, record); err != nil {
		return AlertEvent{}, ErrInvalidAuditRecord
	}
	return r.mutateEvent(ctx, event, &record)
}

func (r *PostgresRepository) mutateEvent(ctx context.Context, event AlertEvent, suppliedAudit *AuditRecord) (AlertEvent, error) {
	if err := event.Validate(); err != nil {
		return AlertEvent{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return AlertEvent{}, err
	}
	defer func() { _ = tx.Rollback() }()

	previous, found, err := findEventForUpdate(ctx, tx, event.Scope, event.Fingerprint)
	if err != nil {
		return AlertEvent{}, err
	}
	stateChanged, err := validateStoredEventMutation(previous, found, event)
	if err != nil {
		return AlertEvent{}, err
	}
	if suppliedAudit != nil && !stateChanged {
		return AlertEvent{}, ErrInvalidAuditRecord
	}
	stored, err := putEvent(ctx, tx, event)
	if err != nil {
		return AlertEvent{}, err
	}
	if stateChanged {
		record, auditErr := lifecycleAuditRecord(stored, suppliedAudit)
		if auditErr != nil {
			return AlertEvent{}, auditErr
		}
		if err := appendAudit(ctx, tx, record); err != nil {
			return AlertEvent{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return AlertEvent{}, err
	}
	return stored, nil
}

func findEventForUpdate(ctx context.Context, tx *sql.Tx, scope Scope, fingerprint string) (AlertEvent, bool, error) {
	event, err := scanEvent(tx.QueryRowContext(ctx, eventLockSQL, scope.TenantID, scope.ProjectID, fingerprint))
	if errors.Is(err, sql.ErrNoRows) {
		return AlertEvent{}, false, nil
	}
	return event, err == nil, err
}

func validateStoredEventMutation(previous AlertEvent, found bool, next AlertEvent) (bool, error) {
	if strings.TrimSpace(next.LastActor) == "" {
		return false, ErrInvalidEventTransition
	}
	if !found {
		if next.State != EventPending && next.State != EventResolved {
			return false, ErrInvalidEventTransition
		}
		if next.State == EventResolved && !next.ResolvedAt.Equal(next.LastSeen) {
			return false, ErrInvalidEventTransition
		}
		return true, nil
	}
	if previous.ID != next.ID || previous.Scope != next.Scope || previous.RuleID != next.RuleID || previous.Fingerprint != next.Fingerprint || !previous.FirstSeen.Equal(next.FirstSeen) || next.LastSeen.Before(previous.LastSeen) {
		return false, ErrInvalidEventTransition
	}
	if previous.State == next.State {
		if !sameTime(previous.FiringAt, next.FiringAt) || !sameTime(previous.AcknowledgedAt, next.AcknowledgedAt) || !sameTime(previous.ResolvedAt, next.ResolvedAt) {
			return false, ErrInvalidEventTransition
		}
		return false, nil
	}
	if previous.State == EventResolved && next.State == EventPending {
		if !next.FiringAt.IsZero() || !next.AcknowledgedAt.IsZero() || !next.ResolvedAt.IsZero() {
			return false, ErrInvalidEventTransition
		}
		return true, nil
	}
	expected, err := previous.Transition(next.State, next.LastSeen, next.LastActor)
	if err != nil || !sameTime(expected.FiringAt, next.FiringAt) || !sameTime(expected.AcknowledgedAt, next.AcknowledgedAt) || !sameTime(expected.ResolvedAt, next.ResolvedAt) {
		return false, ErrInvalidEventTransition
	}
	return true, nil
}

func validateLifecycleAudit(event AlertEvent, record AuditRecord) error {
	if record.Scope != event.Scope || record.TargetID != event.ID || record.Action != "event."+string(event.State) || record.Actor != event.LastActor || !record.OccurredAt.Equal(event.LastSeen) {
		return ErrInvalidAuditRecord
	}
	return nil
}

func lifecycleAuditRecord(event AlertEvent, supplied *AuditRecord) (AuditRecord, error) {
	if supplied != nil {
		record := *supplied
		record.TargetID = event.ID
		return record, nil
	}
	id, err := newControlPlaneID("audit", nil)
	if err != nil {
		return AuditRecord{}, err
	}
	details := cloneMap(event.Evidence)
	details["state"] = string(event.State)
	return sanitizeAuditRecord(AuditRecord{ID: id, Scope: event.Scope, Actor: event.LastActor, Action: "event." + string(event.State), TargetID: event.ID, OccurredAt: event.LastSeen, Details: details}), nil
}

func sameTime(left, right time.Time) bool { return left.Equal(right) }

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func putEvent(ctx context.Context, database queryRower, event AlertEvent) (AlertEvent, error) {
	if err := event.Validate(); err != nil {
		return AlertEvent{}, err
	}
	event.Labels = sanitizeDetails(event.Labels)
	event.Evidence = sanitizeDetails(event.Evidence)
	labels, err := marshalMap(event.Labels)
	if err != nil {
		return AlertEvent{}, err
	}
	evidence, err := marshalMap(event.Evidence)
	if err != nil {
		return AlertEvent{}, err
	}
	return scanEvent(database.QueryRowContext(ctx, eventUpsertSQL, event.ID, event.Scope.TenantID, event.Scope.ProjectID, event.RuleID, event.Fingerprint, labels, evidence, event.State, event.FirstSeen, event.LastSeen, nullableTimestamp(event.FiringAt), nullableTimestamp(event.AcknowledgedAt), nullableTimestamp(event.ResolvedAt), event.LastActor))
}

func (r *PostgresRepository) FindEventByFingerprint(ctx context.Context, scope Scope, fingerprint string) (AlertEvent, bool, error) {
	if err := scope.Validate(); err != nil {
		return AlertEvent{}, false, err
	}
	query := "SELECT " + eventColumnsSQL + " FROM alert_events WHERE tenant_id = $1 AND project_id = $2 AND fingerprint = $3"
	event, err := scanEvent(r.db.QueryRowContext(ctx, query, scope.TenantID, scope.ProjectID, fingerprint))
	if errors.Is(err, sql.ErrNoRows) {
		return AlertEvent{}, false, nil
	}
	return event, err == nil, err
}

func (r *PostgresRepository) ListEvents(ctx context.Context, scope Scope, filter EventFilter) ([]AlertEvent, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := "SELECT " + eventColumnsSQL + " FROM alert_events WHERE tenant_id = $1 AND project_id = $2"
	arguments := []any{scope.TenantID, scope.ProjectID}
	if len(filter.States) > 0 {
		states := make([]string, len(filter.States))
		for index, state := range filter.States {
			states[index] = string(state)
		}
		query += " AND state = ANY($3) ORDER BY last_seen DESC LIMIT $4 OFFSET $5"
		arguments = append(arguments, pq.Array(states), limit, offset)
	} else {
		query += " ORDER BY last_seen DESC LIMIT $3 OFFSET $4"
		arguments = append(arguments, limit, offset)
	}
	rows, err := r.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]AlertEvent, 0)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (r *PostgresRepository) ListRuleEvents(ctx context.Context, scope Scope, ruleID string, filter EventFilter) ([]AlertEvent, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(ruleID) == "" {
		return nil, ErrInvalidEvent
	}
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	query := "SELECT " + eventColumnsSQL + " FROM alert_events WHERE tenant_id = $1 AND project_id = $2 AND rule_id = $3"
	arguments := []any{scope.TenantID, scope.ProjectID, ruleID}
	if len(filter.States) > 0 {
		states := make([]string, len(filter.States))
		for index, state := range filter.States {
			states[index] = string(state)
		}
		query += " AND state = ANY($4) ORDER BY id ASC LIMIT $5 OFFSET $6"
		arguments = append(arguments, pq.Array(states), limit, offset)
	} else {
		query += " ORDER BY id ASC LIMIT $4 OFFSET $5"
		arguments = append(arguments, limit, offset)
	}
	rows, err := r.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]AlertEvent, 0)
	for rows.Next() {
		event, scanErr := scanEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (r *PostgresRepository) AppendAudit(ctx context.Context, record AuditRecord) error {
	return appendAudit(ctx, r.db, record)
}

type contextExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func appendAudit(ctx context.Context, database contextExecer, record AuditRecord) error {
	if err := validateAuditDetailTypes(record); err != nil {
		return err
	}
	record = sanitizeAuditRecord(record)
	if err := record.Validate(); err != nil {
		return err
	}
	details, err := marshalMap(record.Details)
	if err != nil {
		return err
	}
	_, err = database.ExecContext(ctx, auditInsertSQL, record.ID, record.Scope.TenantID, record.Scope.ProjectID, record.Actor, record.Action, record.TargetID, record.OccurredAt, details)
	return err
}

type rowScanner interface {
	Scan(...any) error
}

func scanRule(scanner rowScanner) (AlertRule, error) {
	var rule AlertRule
	var policyIDs pq.StringArray
	var labels []byte
	var evaluationEveryNS, forDurationNS int64
	if err := scanner.Scan(&rule.ID, &rule.Scope.TenantID, &rule.Scope.ProjectID, &rule.Name, &rule.Metric, &rule.Aggregation, &rule.Operator, &rule.Threshold, &evaluationEveryNS, &forDurationNS, &rule.MissingData, &rule.Severity, &policyIDs, &labels, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
		return AlertRule{}, err
	}
	rule.EvaluationEvery = durationFromNanoseconds(evaluationEveryNS)
	rule.For = durationFromNanoseconds(forDurationNS)
	rule.NotificationPolicyIDs = []string(policyIDs)
	if err := unmarshalMap(labels, &rule.Labels); err != nil {
		return AlertRule{}, err
	}
	return rule, nil
}

func scanEvent(scanner rowScanner) (AlertEvent, error) {
	var event AlertEvent
	var labels, evidence []byte
	var firingAt, acknowledgedAt, resolvedAt sql.NullTime
	if err := scanner.Scan(&event.ID, &event.Scope.TenantID, &event.Scope.ProjectID, &event.RuleID, &event.Fingerprint, &labels, &evidence, &event.State, &event.FirstSeen, &event.LastSeen, &firingAt, &acknowledgedAt, &resolvedAt, &event.LastActor); err != nil {
		return AlertEvent{}, err
	}
	if firingAt.Valid {
		event.FiringAt = firingAt.Time
	}
	if acknowledgedAt.Valid {
		event.AcknowledgedAt = acknowledgedAt.Time
	}
	if resolvedAt.Valid {
		event.ResolvedAt = resolvedAt.Time
	}
	if err := unmarshalMap(labels, &event.Labels); err != nil {
		return AlertEvent{}, err
	}
	if err := unmarshalMap(evidence, &event.Evidence); err != nil {
		return AlertEvent{}, err
	}
	return event, nil
}

func marshalMap(values map[string]string) ([]byte, error) {
	if values == nil {
		return []byte("{}"), nil
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("encode JSONB: %w", err)
	}
	return encoded, nil
}

func unmarshalMap(encoded []byte, target *map[string]string) error {
	if len(encoded) == 0 {
		*target = map[string]string{}
		return nil
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		return fmt.Errorf("decode JSONB: %w", err)
	}
	return nil
}

func durationFromNanoseconds(value int64) time.Duration {
	return time.Duration(value)
}

func nullableTimestamp(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

var _ Repository = (*PostgresRepository)(nil)
var _ AuditWriter = (*PostgresRepository)(nil)
