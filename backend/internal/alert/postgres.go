package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

var ErrNotFound = errors.New("alert record not found")

const ruleColumnsSQL = "id, tenant_id, project_id, name, metric, aggregation, operator, threshold, evaluation_every_ms, for_duration_ms, missing_data, severity, notification_policy_ids, labels, enabled, created_at, updated_at"
const eventColumnsSQL = "id, tenant_id, project_id, rule_id, fingerprint, labels, evidence, state, first_seen, last_seen, firing_at, acknowledged_at, resolved_at, last_actor"

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
	labels, err := marshalMap(rule.Labels)
	if err != nil {
		return AlertRule{}, err
	}
	query := "INSERT INTO alert_rules (id, tenant_id, project_id, name, metric, aggregation, operator, threshold, evaluation_every_ms, for_duration_ms, missing_data, severity, notification_policy_ids, labels, enabled) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING " + ruleColumnsSQL
	return scanRule(r.db.QueryRowContext(ctx, query, rule.ID, rule.Scope.TenantID, rule.Scope.ProjectID, rule.Name, rule.Metric, rule.Aggregation, rule.Operator, rule.Threshold, rule.EvaluationEvery.Milliseconds(), rule.For.Milliseconds(), rule.MissingData, rule.Severity, pq.Array(rule.NotificationPolicyIDs), labels, rule.Enabled))
}

func (r *PostgresRepository) UpdateRule(ctx context.Context, rule AlertRule) (AlertRule, error) {
	if err := rule.Validate(); err != nil {
		return AlertRule{}, err
	}
	labels, err := marshalMap(rule.Labels)
	if err != nil {
		return AlertRule{}, err
	}
	query := "UPDATE alert_rules SET name = $1, metric = $2, aggregation = $3, operator = $4, threshold = $5, evaluation_every_ms = $6, for_duration_ms = $7, missing_data = $8, severity = $9, notification_policy_ids = $10, labels = $11, enabled = $12, updated_at = NOW() WHERE tenant_id = $13 AND project_id = $14 AND id = $15 RETURNING " + ruleColumnsSQL
	rule, err = scanRule(r.db.QueryRowContext(ctx, query, rule.Name, rule.Metric, rule.Aggregation, rule.Operator, rule.Threshold, rule.EvaluationEvery.Milliseconds(), rule.For.Milliseconds(), rule.MissingData, rule.Severity, pq.Array(rule.NotificationPolicyIDs), labels, rule.Enabled, rule.Scope.TenantID, rule.Scope.ProjectID, rule.ID))
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
	if err := event.Scope.Validate(); err != nil {
		return AlertEvent{}, err
	}
	labels, err := marshalMap(event.Labels)
	if err != nil {
		return AlertEvent{}, err
	}
	evidence, err := marshalMap(event.Evidence)
	if err != nil {
		return AlertEvent{}, err
	}
	query := "INSERT INTO alert_events (id, tenant_id, project_id, rule_id, fingerprint, labels, evidence, state, first_seen, last_seen, firing_at, acknowledged_at, resolved_at, last_actor) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) ON CONFLICT (tenant_id, project_id, fingerprint) DO UPDATE SET labels = EXCLUDED.labels, evidence = EXCLUDED.evidence, state = EXCLUDED.state, last_seen = EXCLUDED.last_seen, firing_at = EXCLUDED.firing_at, acknowledged_at = EXCLUDED.acknowledged_at, resolved_at = EXCLUDED.resolved_at, last_actor = EXCLUDED.last_actor RETURNING " + eventColumnsSQL
	return scanEvent(r.db.QueryRowContext(ctx, query, event.ID, event.Scope.TenantID, event.Scope.ProjectID, event.RuleID, event.Fingerprint, labels, evidence, event.State, event.FirstSeen, event.LastSeen, nullableTimestamp(event.FiringAt), nullableTimestamp(event.AcknowledgedAt), nullableTimestamp(event.ResolvedAt), event.LastActor))
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

func (r *PostgresRepository) AppendAudit(ctx context.Context, record AuditRecord) error {
	if err := record.Scope.Validate(); err != nil {
		return err
	}
	query := "INSERT INTO alert_audit_log (id, tenant_id, project_id, actor, action, target_id, occurred_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
	_, err := r.db.ExecContext(ctx, query, record.ID, record.Scope.TenantID, record.Scope.ProjectID, record.Actor, record.Action, record.TargetID, record.OccurredAt)
	return err
}

type rowScanner interface {
	Scan(...any) error
}

func scanRule(scanner rowScanner) (AlertRule, error) {
	var rule AlertRule
	var policyIDs pq.StringArray
	var labels []byte
	var evaluationEveryMS, forDurationMS int64
	if err := scanner.Scan(&rule.ID, &rule.Scope.TenantID, &rule.Scope.ProjectID, &rule.Name, &rule.Metric, &rule.Aggregation, &rule.Operator, &rule.Threshold, &evaluationEveryMS, &forDurationMS, &rule.MissingData, &rule.Severity, &policyIDs, &labels, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
		return AlertRule{}, err
	}
	rule.EvaluationEvery = durationFromMilliseconds(evaluationEveryMS)
	rule.For = durationFromMilliseconds(forDurationMS)
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

func durationFromMilliseconds(value int64) time.Duration {
	return time.Duration(value) * time.Millisecond
}

func nullableTimestamp(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
