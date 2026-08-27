package alert

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

var (
	ErrNotFound               = errors.New("alert record not found")
	ErrConfigurationInUse     = errors.New("alert configuration is in use")
	ErrInvalidPolicyReference = errors.New("alert rule references an unavailable notification policy")
	ErrRuleScheduleLeaseLost  = errors.New("alert rule evaluation lease was lost")
)

const ruleColumnsSQL = "id, tenant_id, project_id, name, metric, aggregation, operator, threshold, evaluation_every_ns, lookback_window_ns, for_duration_ns, missing_data, severity, notification_policy_ids, labels, enabled, created_at, updated_at"
const eventColumnsSQL = "id, tenant_id, project_id, rule_id, fingerprint, labels, evidence, state, first_seen, last_seen, firing_at, acknowledged_at, resolved_at, last_actor"
const eventUpsertSQL = "INSERT INTO alert_events (id, tenant_id, project_id, rule_id, fingerprint, labels, evidence, state, first_seen, last_seen, firing_at, acknowledged_at, resolved_at, last_actor) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) ON CONFLICT (tenant_id, project_id, fingerprint) DO UPDATE SET labels = EXCLUDED.labels, evidence = EXCLUDED.evidence, state = EXCLUDED.state, last_seen = EXCLUDED.last_seen, firing_at = EXCLUDED.firing_at, acknowledged_at = EXCLUDED.acknowledged_at, resolved_at = EXCLUDED.resolved_at, last_actor = EXCLUDED.last_actor RETURNING " + eventColumnsSQL
const eventAdvisoryLockSQL = "SELECT pg_advisory_xact_lock($1)"
const eventLockSQL = "SELECT " + eventColumnsSQL + " FROM alert_events WHERE tenant_id = $1 AND project_id = $2 AND fingerprint = $3 FOR UPDATE"
const auditInsertSQL = "INSERT INTO alert_audit_log (id, tenant_id, project_id, actor, action, target_id, occurred_at, details) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
const dispositionInsertSQL = "INSERT INTO alert_event_dispositions (id, tenant_id, project_id, event_id, kind, category, reason, actor, occurred_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
const notificationRouteSQL = "SELECT p.id AS policy_id, p.tenant_id AS policy_tenant_id, p.project_id AS policy_project_id, p.name AS policy_name, p.channel, p.target, p.secret_ref, COALESCE(p.template_id, ''), p.severities, p.match_labels, COALESCE(to_char(p.window_start_utc, 'HH24:MI'), '') AS window_start_utc, COALESCE(to_char(p.window_end_utc, 'HH24:MI'), '') AS window_end_utc, p.enabled, p.created_at AS policy_created_at, p.updated_at AS policy_updated_at, t.id AS resolved_template_id, t.tenant_id AS template_tenant_id, t.project_id AS template_project_id, t.name AS template_name, t.subject, t.body, t.revision AS template_revision, t.legacy_version_from_updated_at, t.created_at AS template_created_at, t.updated_at AS template_updated_at FROM alert_rules r JOIN notification_policies p ON p.tenant_id = r.tenant_id AND p.project_id = r.project_id AND p.id = ANY(r.notification_policy_ids) LEFT JOIN notification_templates t ON t.tenant_id = p.tenant_id AND t.project_id = p.project_id AND t.id = p.template_id WHERE r.tenant_id = $1 AND r.project_id = $2 AND r.id = $3 ORDER BY p.id ASC"
const notificationPolicyColumnsSQL = "id, tenant_id, project_id, name, channel, target, secret_ref, template_id, severities, match_labels, COALESCE(to_char(window_start_utc, 'HH24:MI'), ''), COALESCE(to_char(window_end_utc, 'HH24:MI'), ''), enabled, created_at, updated_at"
const notificationTemplateColumnsSQL = "id, tenant_id, project_id, name, subject, body, revision, legacy_version_from_updated_at, created_at, updated_at"
const notificationDeliveryColumnsSQL = "id, tenant_id, project_id, event_id, policy_id, idempotency_key, event_state, channel, template_id, template_version, status, attempts, attempted_at, next_attempt_at, delivered_at, lease_owner, lease_expires_at, failure_class, request_target, request_subject, request_body, request_labels, request_secret_ref"
const qualifiedNotificationDeliveryColumnsSQL = "d.id, d.tenant_id, d.project_id, d.event_id, d.policy_id, d.idempotency_key, d.event_state, d.channel, d.template_id, d.template_version, d.status, d.attempts, d.attempted_at, d.next_attempt_at, d.delivered_at, d.lease_owner, d.lease_expires_at, d.failure_class, d.request_target, d.request_subject, d.request_body, d.request_labels, d.request_secret_ref"
const deliveryInsertSQL = "INSERT INTO notification_deliveries (" + notificationDeliveryColumnsSQL + ") SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23 WHERE NOT EXISTS (SELECT 1 FROM notification_deliveries existing WHERE existing.tenant_id = $2 AND existing.project_id = $3 AND (existing.idempotency_key = $6 OR (existing.idempotency_key = $24 AND existing.policy_id = $5 AND existing.event_state = $7 AND existing.channel = $8 AND existing.template_id = $9 AND existing.template_version = $10 AND existing.request_target = $19 AND existing.request_secret_ref = $23))) ON CONFLICT (tenant_id, project_id, idempotency_key) DO NOTHING"
const deliveryUpdateSQL = "UPDATE notification_deliveries SET status = $1, attempted_at = $2, next_attempt_at = $3, delivered_at = $4, lease_owner = $5, lease_expires_at = $6, failure_class = $7 WHERE tenant_id = $8 AND project_id = $9 AND id = $10 AND status = 'attempting' AND lease_owner = $11"
const claimDeliveriesSQL = "WITH candidates AS (SELECT tenant_id, project_id, id FROM notification_deliveries WHERE ((status = 'retry_scheduled' AND next_attempt_at <= $1) OR (status = 'attempting' AND lease_expires_at <= $1)) AND idempotency_key <> '' AND event_state IN ('pending', 'firing', 'acknowledged', 'resolved') AND channel <> '' AND template_id <> '' AND template_version <> '' AND attempts >= 1 ORDER BY COALESCE(next_attempt_at, lease_expires_at), attempted_at FOR UPDATE SKIP LOCKED LIMIT $2), claimed AS (UPDATE notification_deliveries AS d SET status = 'attempting', attempts = d.attempts + 1, attempted_at = $1, next_attempt_at = NULL, lease_owner = $3, lease_expires_at = $4 FROM candidates AS c WHERE d.tenant_id = c.tenant_id AND d.project_id = c.project_id AND d.id = c.id RETURNING " + qualifiedNotificationDeliveryColumnsSQL + ") SELECT " + notificationDeliveryColumnsSQL + " FROM claimed ORDER BY attempted_at, id"

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) NewID(prefix string) (string, error) {
	return newControlPlaneID(prefix, nil)
}

func (r *PostgresRepository) CreateRule(ctx context.Context, rule AlertRule) (AlertRule, error) {
	return r.mutateRule(ctx, rule, false)
}

func (r *PostgresRepository) UpdateRule(ctx context.Context, rule AlertRule) (AlertRule, error) {
	return r.mutateRule(ctx, rule, true)
}

func (r *PostgresRepository) mutateRule(ctx context.Context, rule AlertRule, update bool) (AlertRule, error) {
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
	policyIDs := append([]string{}, rule.NotificationPolicyIDs...)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return AlertRule{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := validateRulePolicyReferences(ctx, tx, rule.Scope, rule.NotificationPolicyIDs); err != nil {
		return AlertRule{}, err
	}
	query := "WITH changed AS (INSERT INTO alert_rules (id, tenant_id, project_id, name, metric, aggregation, operator, threshold, evaluation_every_ns, lookback_window_ns, for_duration_ns, missing_data, severity, notification_policy_ids, labels, enabled) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING " + ruleColumnsSQL + "), audited AS (INSERT INTO alert_audit_log (id, tenant_id, project_id, actor, action, target_id, occurred_at, details) SELECT 'audit-' || md5(id || ':created:' || created_at::text), tenant_id, project_id, $17, 'rule.created', id, created_at, jsonb_build_object('aggregation', aggregation, 'operator', operator, 'threshold', threshold::text, 'severity', severity, 'enabled', enabled::text) FROM changed) SELECT " + ruleColumnsSQL + " FROM changed"
	args := []any{rule.ID, rule.Scope.TenantID, rule.Scope.ProjectID, rule.Name, rule.Metric, rule.Aggregation, rule.Operator, rule.Threshold, rule.EvaluationEvery.Nanoseconds(), rule.EffectiveLookbackWindow().Nanoseconds(), rule.For.Nanoseconds(), rule.MissingData, rule.Severity, pq.Array(policyIDs), labels, rule.Enabled, actor}
	if update {
		query = "WITH changed AS (UPDATE alert_rules SET name = $1, metric = $2, aggregation = $3, operator = $4, threshold = $5, evaluation_every_ns = $6, lookback_window_ns = $7, for_duration_ns = $8, missing_data = $9, severity = $10, notification_policy_ids = $11, labels = $12, enabled = $13, next_evaluation_at = NOW(), evaluation_lease_owner = '', evaluation_lease_expires_at = NULL, updated_at = NOW() WHERE tenant_id = $14 AND project_id = $15 AND id = $16 RETURNING " + ruleColumnsSQL + "), audited AS (INSERT INTO alert_audit_log (id, tenant_id, project_id, actor, action, target_id, occurred_at, details) SELECT 'audit-' || md5(id || ':updated:' || updated_at::text), tenant_id, project_id, $17, 'rule.updated', id, updated_at, jsonb_build_object('aggregation', aggregation, 'operator', operator, 'threshold', threshold::text, 'severity', severity, 'enabled', enabled::text) FROM changed) SELECT " + ruleColumnsSQL + " FROM changed"
		args = []any{rule.Name, rule.Metric, rule.Aggregation, rule.Operator, rule.Threshold, rule.EvaluationEvery.Nanoseconds(), rule.EffectiveLookbackWindow().Nanoseconds(), rule.For.Nanoseconds(), rule.MissingData, rule.Severity, pq.Array(policyIDs), labels, rule.Enabled, rule.Scope.TenantID, rule.Scope.ProjectID, rule.ID, actor}
	}
	stored, err := scanRule(tx.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return AlertRule{}, ErrNotFound
	}
	if err != nil {
		return AlertRule{}, err
	}
	if err := tx.Commit(); err != nil {
		return AlertRule{}, err
	}
	return stored, nil
}

func validateRulePolicyReferences(ctx context.Context, tx *sql.Tx, scope Scope, policyIDs []string) error {
	if len(policyIDs) == 0 {
		return nil
	}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM notification_policies WHERE tenant_id = $1 AND project_id = $2 AND id = ANY($3) ORDER BY id FOR SHARE", scope.TenantID, scope.ProjectID, pq.Array(policyIDs))
	if err != nil {
		return err
	}
	defer rows.Close()
	found := make(map[string]struct{}, len(policyIDs))
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		found[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(found) != len(policyIDs) {
		return ErrInvalidPolicyReference
	}
	for _, id := range policyIDs {
		if _, ok := found[id]; !ok {
			return ErrInvalidPolicyReference
		}
	}
	return nil
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

func (r *PostgresRepository) ClaimDueRules(ctx context.Context, scope Scope, at time.Time, owner string, leaseUntil time.Time, limit int) ([]DueAlertRule, int, error) {
	if scope.Validate() != nil || at.IsZero() || strings.TrimSpace(owner) == "" || !leaseUntil.After(at) || limit <= 0 {
		return nil, 0, ErrInvalidRule
	}
	if limit > maxDueRulesPerPass {
		limit = maxDueRulesPerPass
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	const duePredicate = "tenant_id = $1 AND project_id = $2 AND enabled AND next_evaluation_at <= $3 AND (evaluation_lease_expires_at IS NULL OR evaluation_lease_expires_at <= $3)"
	var dueCount int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_rules WHERE "+duePredicate, scope.TenantID, scope.ProjectID, at).Scan(&dueCount); err != nil {
		return nil, 0, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+ruleColumnsSQL+", next_evaluation_at FROM alert_rules WHERE "+duePredicate+" ORDER BY next_evaluation_at, id FOR UPDATE SKIP LOCKED LIMIT $4", scope.TenantID, scope.ProjectID, at, limit)
	if err != nil {
		return nil, 0, err
	}
	due := make([]DueAlertRule, 0, limit)
	ids := make([]string, 0, limit)
	for rows.Next() {
		claimed, scanErr := scanDueRule(rows)
		if scanErr != nil {
			_ = rows.Close()
			return nil, 0, scanErr
		}
		due = append(due, claimed)
		ids = append(ids, claimed.Rule.ID)
	}
	if err := rows.Close(); err != nil {
		return nil, 0, err
	}
	if len(ids) > 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE alert_rules SET evaluation_lease_owner = $1, evaluation_lease_expires_at = $2 WHERE tenant_id = $3 AND project_id = $4 AND id = ANY($5)", owner, leaseUntil, scope.TenantID, scope.ProjectID, pq.Array(ids)); err != nil {
			return nil, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, err
	}
	queueDepth := dueCount - len(due)
	if queueDepth < 0 {
		queueDepth = 0
	}
	return due, queueDepth, nil
}

func (r *PostgresRepository) CompleteRuleEvaluation(ctx context.Context, scope Scope, ruleID, owner string, evaluatedAt, nextAt time.Time) error {
	if scope.Validate() != nil || !validIdentifier(ruleID) || strings.TrimSpace(owner) == "" || evaluatedAt.IsZero() || !nextAt.After(evaluatedAt) {
		return ErrInvalidRule
	}
	result, err := r.db.ExecContext(ctx, "UPDATE alert_rules SET last_evaluated_at = $1, next_evaluation_at = $2, evaluation_lease_owner = '', evaluation_lease_expires_at = NULL WHERE tenant_id = $3 AND project_id = $4 AND id = $5 AND evaluation_lease_owner = $6", evaluatedAt, nextAt, scope.TenantID, scope.ProjectID, ruleID, owner)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrRuleScheduleLeaseLost
	}
	return nil
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

func (r *PostgresRepository) DeleteRule(ctx context.Context, scope Scope, id string) error {
	return r.deleteRule(ctx, scope, id)
}

func (r *PostgresRepository) PutEvent(ctx context.Context, event AlertEvent) (AlertEvent, error) {
	return r.mutateEvent(ctx, event, nil, nil)
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
	return r.mutateEvent(ctx, event, &record, nil)
}

func (r *PostgresRepository) PutEventAndDisposition(ctx context.Context, event AlertEvent, record AuditRecord, disposition EventDisposition) (AlertEvent, error) {
	if err := disposition.Validate(); err != nil || disposition.Scope != event.Scope || disposition.EventID != event.ID || disposition.Actor != event.LastActor || !disposition.OccurredAt.Equal(event.LastSeen) {
		return AlertEvent{}, ErrInvalidDisposition
	}
	wantKind := DispositionAcknowledgement
	if event.State == EventResolved {
		wantKind = DispositionResolution
	}
	if disposition.Kind != wantKind {
		return AlertEvent{}, ErrInvalidDisposition
	}
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
	return r.mutateEvent(ctx, event, &record, &disposition)
}

func (r *PostgresRepository) mutateEvent(ctx context.Context, event AlertEvent, suppliedAudit *AuditRecord, suppliedDisposition *EventDisposition) (AlertEvent, error) {
	if err := event.Validate(); err != nil {
		return AlertEvent{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return AlertEvent{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := lockEventMutation(ctx, tx, event.Scope, event.Fingerprint); err != nil {
		return AlertEvent{}, err
	}
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
	if suppliedDisposition != nil {
		if !stateChanged {
			return AlertEvent{}, ErrInvalidDisposition
		}
		if err := insertEventDisposition(ctx, tx, *suppliedDisposition); err != nil {
			return AlertEvent{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return AlertEvent{}, err
	}
	return stored, nil
}

func lockEventMutation(ctx context.Context, tx *sql.Tx, scope Scope, fingerprint string) error {
	_, err := tx.ExecContext(ctx, eventAdvisoryLockSQL, eventAdvisoryLockKey(scope, fingerprint))
	return err
}

func eventAdvisoryLockKey(scope Scope, fingerprint string) int64 {
	// Length-prefixing prevents ambiguous tuples and no raw identity reaches SQL.
	// A 64-bit digest collision only over-serializes unrelated events; it cannot
	// let concurrent mutations of the same tuple acquire different locks.
	hash := sha256.New()
	writeLockKeyPart(hash, "dbpilot.alert.event.v1")
	writeLockKeyPart(hash, scope.TenantID)
	writeLockKeyPart(hash, scope.ProjectID)
	writeLockKeyPart(hash, fingerprint)
	digest := hash.Sum(nil)
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func writeLockKeyPart(hash interface{ Write([]byte) (int, error) }, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write([]byte(value))
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

func (r *PostgresRepository) GetEvent(ctx context.Context, scope Scope, id string) (AlertEvent, error) {
	if err := scope.Validate(); err != nil {
		return AlertEvent{}, err
	}
	event, err := scanEvent(r.db.QueryRowContext(ctx, "SELECT "+eventColumnsSQL+" FROM alert_events WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return AlertEvent{}, ErrNotFound
	}
	if err == nil && event.Scope != scope {
		return AlertEvent{}, ErrInvalidScope
	}
	return event, err
}

func (r *PostgresRepository) ListEvents(ctx context.Context, scope Scope, filter EventFilter) ([]AlertEvent, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := "SELECT " + eventColumnsSQL + " FROM alert_events WHERE tenant_id = $1 AND project_id = $2"
	arguments := []any{scope.TenantID, scope.ProjectID}
	if len(filter.States) > 0 {
		states := make([]string, len(filter.States))
		for index, state := range filter.States {
			states[index] = string(state)
		}
		arguments = append(arguments, pq.Array(states))
		query += fmt.Sprintf(" AND state = ANY($%d)", len(arguments))
	}
	if filter.OrderByID {
		if filter.AfterID != "" {
			if len(filter.AfterID) > 512 || strings.ContainsRune(filter.AfterID, '\x00') {
				return nil, ErrInvalidEvent
			}
			arguments = append(arguments, filter.AfterID)
			query += fmt.Sprintf(" AND id > $%d", len(arguments))
		}
		arguments = append(arguments, limit)
		query += fmt.Sprintf(" ORDER BY id ASC LIMIT $%d", len(arguments))
	} else {
		offset := filter.Offset
		if offset < 0 {
			offset = 0
		}
		arguments = append(arguments, limit, offset)
		query += fmt.Sprintf(" ORDER BY last_seen DESC, id ASC LIMIT $%d OFFSET $%d", len(arguments)-1, len(arguments))
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

func (r *PostgresRepository) CountEventsByState(ctx context.Context, scope Scope) (map[EventState]int, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, "SELECT state, COUNT(*) FROM alert_events WHERE tenant_id = $1 AND project_id = $2 GROUP BY state ORDER BY state", scope.TenantID, scope.ProjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make(map[EventState]int)
	for rows.Next() {
		var state EventState
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		if !allowedEventState(state) {
			return nil, ErrInvalidEvent
		}
		counts[state] = count
	}
	return counts, rows.Err()
}

func (r *PostgresRepository) AppendEventDisposition(ctx context.Context, disposition EventDisposition, record AuditRecord) error {
	if err := disposition.Validate(); err != nil || disposition.Kind != DispositionRootCause || record.Scope != disposition.Scope || record.TargetID != disposition.EventID || record.Actor != disposition.Actor || !record.OccurredAt.Equal(disposition.OccurredAt) || record.Action != "event.root_cause" {
		return ErrInvalidDisposition
	}
	if err := validateAuditDetailTypes(record); err != nil {
		return err
	}
	record = sanitizeAuditRecord(record)
	if err := record.Validate(); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var eventID string
	if err := tx.QueryRowContext(ctx, "SELECT id FROM alert_events WHERE tenant_id = $1 AND project_id = $2 AND id = $3 FOR SHARE", disposition.Scope.TenantID, disposition.Scope.ProjectID, disposition.EventID).Scan(&eventID); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if err := appendAudit(ctx, tx, record); err != nil {
		return err
	}
	if err := insertEventDisposition(ctx, tx, disposition); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *PostgresRepository) ListEventDispositions(ctx context.Context, scope Scope, eventID string, limit, offset int) ([]EventDisposition, error) {
	if scope.Validate() != nil || !validIdentifier(eventID) || limit < 1 || limit > 500 || offset < 0 {
		return nil, ErrInvalidDisposition
	}
	rows, err := r.db.QueryContext(ctx, "SELECT id, tenant_id, project_id, event_id, kind, category, reason, actor, occurred_at FROM alert_event_dispositions WHERE tenant_id = $1 AND project_id = $2 AND event_id = $3 ORDER BY occurred_at DESC, id DESC LIMIT $4 OFFSET $5", scope.TenantID, scope.ProjectID, eventID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]EventDisposition, 0)
	for rows.Next() {
		var value EventDisposition
		if err := rows.Scan(&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.EventID, &value.Kind, &value.Category, &value.Reason, &value.Actor, &value.OccurredAt); err != nil {
			return nil, err
		}
		if err := value.Validate(); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
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
		if event.Scope != scope {
			return nil, ErrInvalidScope
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (r *PostgresRepository) AppendAudit(ctx context.Context, record AuditRecord) error {
	return appendAudit(ctx, r.db, record)
}

func (r *PostgresRepository) RecordOrphanedEvent(ctx context.Context, event AlertEvent, at time.Time) error {
	if event.Validate() != nil || at.IsZero() {
		return ErrInvalidNotification
	}
	delivery := NotificationDelivery{
		ID:    "orphan-" + fingerprintParts(event.Scope.Key(), event.ID, string(event.State))[:24],
		Scope: event.Scope, EventID: event.ID, PolicyID: "orphan-rule", EventState: event.State,
		Status: DeliveryAbandoned, Attempts: 0, AttemptedAt: at.UTC(), FailureClass: "orphan_rule",
		Request: DeliveryRequest{Scope: event.Scope, EventID: event.ID, State: event.State, Channel: "orphan", PolicyID: "orphan-rule", TemplateID: "orphan-rule", TemplateVersion: "orphan-rule"},
	}
	record := notificationAudit(delivery, "delivery.abandoned", at)
	details, err := marshalMap(record.Details)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, auditInsertSQL+" ON CONFLICT (tenant_id, project_id, id) DO NOTHING", record.ID, record.Scope.TenantID, record.Scope.ProjectID, record.Actor, record.Action, event.ID, record.OccurredAt, details)
	return err
}

func (r *PostgresRepository) ListNotificationRoutes(ctx context.Context, scope Scope, ruleID string) ([]NotificationRoute, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if !validIdentifier(ruleID) {
		return nil, ErrInvalidNotification
	}
	rows, err := r.db.QueryContext(ctx, notificationRouteSQL, scope.TenantID, scope.ProjectID, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	routes := make([]NotificationRoute, 0)
	for rows.Next() {
		var route NotificationRoute
		var severities pq.StringArray
		var labels []byte
		var templateID, templateTenantID, templateProjectID, templateName, subject, body sql.NullString
		var templateRevision sql.NullInt64
		var templateLegacyVersion sql.NullBool
		var templateCreatedAt, templateUpdatedAt sql.NullTime
		if err := rows.Scan(
			&route.Policy.ID, &route.Policy.Scope.TenantID, &route.Policy.Scope.ProjectID, &route.Policy.Name,
			&route.Policy.Channel, &route.Policy.Target, &route.Policy.SecretRef, &route.Policy.TemplateID,
			&severities, &labels, &route.Policy.WindowStartUTC, &route.Policy.WindowEndUTC, &route.Policy.Enabled,
			&route.Policy.CreatedAt, &route.Policy.UpdatedAt,
			&templateID, &templateTenantID, &templateProjectID, &templateName,
			&subject, &body, &templateRevision, &templateLegacyVersion, &templateCreatedAt, &templateUpdatedAt,
		); err != nil {
			return nil, err
		}
		if route.Policy.Scope != scope {
			return nil, ErrNotificationScopeMismatch
		}
		route.Policy.Severities = []string(severities)
		if err := unmarshalMap(labels, &route.Policy.MatchLabels); err != nil {
			return nil, err
		}
		if templateID.Valid {
			route.Template = NotificationTemplate{
				ID: templateID.String, Scope: Scope{TenantID: templateTenantID.String, ProjectID: templateProjectID.String},
				Name: templateName.String, Subject: subject.String, Body: body.String, Revision: templateRevision.Int64,
				LegacyVersionFromUpdatedAt: templateLegacyVersion.Bool,
			}
			if templateCreatedAt.Valid {
				route.Template.CreatedAt = templateCreatedAt.Time
			}
			if templateUpdatedAt.Valid {
				route.Template.UpdatedAt = templateUpdatedAt.Time
			}
		}
		routes = append(routes, route)
	}
	return routes, rows.Err()
}

func (r *PostgresRepository) CreateNotificationTemplate(ctx context.Context, template NotificationTemplate) (NotificationTemplate, error) {
	return r.mutateNotificationTemplate(ctx, template, false)
}

func (r *PostgresRepository) UpdateNotificationTemplate(ctx context.Context, template NotificationTemplate) (NotificationTemplate, error) {
	return r.mutateNotificationTemplate(ctx, template, true)
}

func (r *PostgresRepository) ListNotificationTemplates(ctx context.Context, scope Scope) ([]NotificationTemplate, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, "SELECT "+notificationTemplateColumnsSQL+" FROM notification_templates WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at DESC", scope.TenantID, scope.ProjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]NotificationTemplate, 0)
	for rows.Next() {
		value, scanErr := scanNotificationTemplate(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		if value.Scope != scope {
			return nil, ErrNotificationScopeMismatch
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (r *PostgresRepository) GetNotificationTemplate(ctx context.Context, scope Scope, id string) (NotificationTemplate, error) {
	if err := scope.Validate(); err != nil {
		return NotificationTemplate{}, err
	}
	value, err := scanNotificationTemplate(r.db.QueryRowContext(ctx, "SELECT "+notificationTemplateColumnsSQL+" FROM notification_templates WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return NotificationTemplate{}, ErrNotFound
	}
	if err == nil && value.Scope != scope {
		return NotificationTemplate{}, ErrNotificationScopeMismatch
	}
	return value, err
}

func (r *PostgresRepository) DeleteNotificationTemplate(ctx context.Context, scope Scope, id string) error {
	return r.deleteConfiguration(ctx, scope, id, "notification_templates", "template.deleted")
}

func (r *PostgresRepository) mutateNotificationTemplate(ctx context.Context, template NotificationTemplate, update bool) (NotificationTemplate, error) {
	if err := validateNotificationTemplate(template); err != nil {
		return NotificationTemplate{}, err
	}
	actor, err := auditActorFromContext(ctx)
	if err != nil {
		return NotificationTemplate{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return NotificationTemplate{}, err
	}
	defer func() { _ = tx.Rollback() }()
	query := "INSERT INTO notification_templates (id, tenant_id, project_id, name, subject, body, revision) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING " + notificationTemplateColumnsSQL
	args := []any{template.ID, template.Scope.TenantID, template.Scope.ProjectID, template.Name, template.Subject, template.Body, template.Revision}
	action := "template.created"
	if update {
		query = "UPDATE notification_templates SET name = $1, subject = $2, body = $3, revision = $4, legacy_version_from_updated_at = FALSE, updated_at = NOW() WHERE tenant_id = $5 AND project_id = $6 AND id = $7 AND revision < $4 RETURNING " + notificationTemplateColumnsSQL
		args = []any{template.Name, template.Subject, template.Body, template.Revision, template.Scope.TenantID, template.Scope.ProjectID, template.ID}
		action = "template.updated"
	}
	stored, err := scanNotificationTemplate(tx.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return NotificationTemplate{}, ErrNotFound
	}
	if err != nil {
		return NotificationTemplate{}, err
	}
	at := stored.CreatedAt
	if update {
		at = stored.UpdatedAt
	}
	if err := appendAudit(ctx, tx, configurationAudit(stored.Scope, actor, action, stored.ID, at, map[string]string{"version": strconv.FormatInt(stored.Revision, 10)})); err != nil {
		return NotificationTemplate{}, err
	}
	if err := tx.Commit(); err != nil {
		return NotificationTemplate{}, err
	}
	return stored, nil
}

func (r *PostgresRepository) CreateNotificationPolicy(ctx context.Context, policy NotificationPolicy) (NotificationPolicy, error) {
	return r.mutateNotificationPolicy(ctx, policy, false)
}

func (r *PostgresRepository) UpdateNotificationPolicy(ctx context.Context, policy NotificationPolicy) (NotificationPolicy, error) {
	return r.mutateNotificationPolicy(ctx, policy, true)
}

func (r *PostgresRepository) ListNotificationPolicies(ctx context.Context, scope Scope) ([]NotificationPolicy, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, "SELECT "+notificationPolicyColumnsSQL+" FROM notification_policies WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at DESC", scope.TenantID, scope.ProjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]NotificationPolicy, 0)
	for rows.Next() {
		value, scanErr := scanNotificationPolicy(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		if value.Scope != scope {
			return nil, ErrNotificationScopeMismatch
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (r *PostgresRepository) GetNotificationPolicy(ctx context.Context, scope Scope, id string) (NotificationPolicy, error) {
	if err := scope.Validate(); err != nil {
		return NotificationPolicy{}, err
	}
	value, err := scanNotificationPolicy(r.db.QueryRowContext(ctx, "SELECT "+notificationPolicyColumnsSQL+" FROM notification_policies WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return NotificationPolicy{}, ErrNotFound
	}
	if err == nil && value.Scope != scope {
		return NotificationPolicy{}, ErrNotificationScopeMismatch
	}
	return value, err
}

func (r *PostgresRepository) DeleteNotificationPolicy(ctx context.Context, scope Scope, id string) error {
	return r.deletePolicy(ctx, scope, id)
}

func (r *PostgresRepository) mutateNotificationPolicy(ctx context.Context, policy NotificationPolicy, update bool) (NotificationPolicy, error) {
	if err := validateNotificationPolicy(policy); err != nil {
		return NotificationPolicy{}, err
	}
	actor, err := auditActorFromContext(ctx)
	if err != nil {
		return NotificationPolicy{}, err
	}
	labels, err := marshalMap(policy.MatchLabels)
	if err != nil {
		return NotificationPolicy{}, err
	}
	severities := policy.Severities
	if severities == nil {
		severities = []string{}
	}
	start, end := nullableTimeOfDay(policy.WindowStartUTC), nullableTimeOfDay(policy.WindowEndUTC)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return NotificationPolicy{}, err
	}
	defer func() { _ = tx.Rollback() }()
	query := "INSERT INTO notification_policies (id, tenant_id, project_id, name, channel, target, secret_ref, template_id, severities, match_labels, window_start_utc, window_end_utc, enabled) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::time, $12::time, $13) RETURNING " + notificationPolicyColumnsSQL
	args := []any{policy.ID, policy.Scope.TenantID, policy.Scope.ProjectID, policy.Name, policy.Channel, policy.Target, policy.SecretRef, policy.TemplateID, pq.Array(severities), labels, start, end, policy.Enabled}
	action := "policy.created"
	if update {
		query = "UPDATE notification_policies SET name = $1, channel = $2, target = $3, secret_ref = $4, template_id = $5, severities = $6, match_labels = $7, window_start_utc = $8::time, window_end_utc = $9::time, enabled = $10, updated_at = NOW() WHERE tenant_id = $11 AND project_id = $12 AND id = $13 RETURNING " + notificationPolicyColumnsSQL
		args = []any{policy.Name, policy.Channel, policy.Target, policy.SecretRef, policy.TemplateID, pq.Array(severities), labels, start, end, policy.Enabled, policy.Scope.TenantID, policy.Scope.ProjectID, policy.ID}
		action = "policy.updated"
	}
	stored, err := scanNotificationPolicy(tx.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return NotificationPolicy{}, ErrNotFound
	}
	if err != nil {
		return NotificationPolicy{}, err
	}
	at := stored.CreatedAt
	if update {
		at = stored.UpdatedAt
	}
	details := map[string]string{"channel": stored.Channel, "template_id": stored.TemplateID, "enabled": strconv.FormatBool(stored.Enabled)}
	if err := appendAudit(ctx, tx, configurationAudit(stored.Scope, actor, action, stored.ID, at, details)); err != nil {
		return NotificationPolicy{}, err
	}
	if err := tx.Commit(); err != nil {
		return NotificationPolicy{}, err
	}
	return stored, nil
}

func scanNotificationTemplate(scanner rowScanner) (NotificationTemplate, error) {
	var template NotificationTemplate
	err := scanner.Scan(&template.ID, &template.Scope.TenantID, &template.Scope.ProjectID, &template.Name, &template.Subject, &template.Body, &template.Revision, &template.LegacyVersionFromUpdatedAt, &template.CreatedAt, &template.UpdatedAt)
	return template, err
}

func scanNotificationPolicy(scanner rowScanner) (NotificationPolicy, error) {
	var policy NotificationPolicy
	var severities pq.StringArray
	var labels []byte
	if err := scanner.Scan(&policy.ID, &policy.Scope.TenantID, &policy.Scope.ProjectID, &policy.Name, &policy.Channel, &policy.Target, &policy.SecretRef, &policy.TemplateID, &severities, &labels, &policy.WindowStartUTC, &policy.WindowEndUTC, &policy.Enabled, &policy.CreatedAt, &policy.UpdatedAt); err != nil {
		return NotificationPolicy{}, err
	}
	policy.Severities = []string(severities)
	if err := unmarshalMap(labels, &policy.MatchLabels); err != nil {
		return NotificationPolicy{}, err
	}
	return policy, nil
}

func nullableTimeOfDay(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func configurationAudit(scope Scope, actor, action, target string, at time.Time, details map[string]string) AuditRecord {
	id := "audit-" + fingerprintParts(scope.TenantID, scope.ProjectID, target, action, at.UTC().Format(time.RFC3339Nano))[:24]
	return AuditRecord{ID: id, Scope: scope, Actor: actor, Action: action, TargetID: target, OccurredAt: at.UTC(), Details: details}
}

func (r *PostgresRepository) ListActiveSilences(ctx context.Context, scope Scope, at time.Time) ([]Silence, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if at.IsZero() {
		return nil, ErrInvalidNotification
	}
	query := "SELECT id, tenant_id, project_id, matchers, starts_at, ends_at, created_by, reason, created_at, updated_at FROM alert_silences WHERE tenant_id = $1 AND project_id = $2 AND starts_at <= $3 AND ends_at > $3 ORDER BY created_at ASC"
	rows, err := r.db.QueryContext(ctx, query, scope.TenantID, scope.ProjectID, at.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	silences := make([]Silence, 0)
	for rows.Next() {
		var silence Silence
		var matchers []byte
		if err := rows.Scan(&silence.ID, &silence.Scope.TenantID, &silence.Scope.ProjectID, &matchers, &silence.StartsAt, &silence.EndsAt, &silence.CreatedBy, &silence.Reason, &silence.CreatedAt, &silence.UpdatedAt); err != nil {
			return nil, err
		}
		if silence.Scope != scope {
			return nil, ErrNotificationScopeMismatch
		}
		if err := unmarshalMap(matchers, &silence.Matchers); err != nil {
			return nil, err
		}
		silences = append(silences, silence)
	}
	return silences, rows.Err()
}

func (r *PostgresRepository) ListSilences(ctx context.Context, scope Scope) ([]Silence, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, "SELECT id, tenant_id, project_id, matchers, starts_at, ends_at, created_by, reason, created_at, updated_at FROM alert_silences WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at DESC", scope.TenantID, scope.ProjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Silence, 0)
	for rows.Next() {
		value, scanErr := scanSilence(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		if value.Scope != scope {
			return nil, ErrNotificationScopeMismatch
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (r *PostgresRepository) GetSilence(ctx context.Context, scope Scope, id string) (Silence, error) {
	if err := scope.Validate(); err != nil {
		return Silence{}, err
	}
	value, err := scanSilence(r.db.QueryRowContext(ctx, "SELECT id, tenant_id, project_id, matchers, starts_at, ends_at, created_by, reason, created_at, updated_at FROM alert_silences WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Silence{}, ErrNotFound
	}
	if err == nil && value.Scope != scope {
		return Silence{}, ErrNotificationScopeMismatch
	}
	return value, err
}

func (r *PostgresRepository) PersistInAppNotification(ctx context.Context, request DeliveryRequest) error {
	if request.Scope.Validate() != nil || request.DeliveryID == "" || request.EventID == "" || !allowedEventState(request.State) || strings.TrimSpace(request.Target) == "" {
		return ErrInvalidNotification
	}
	digest := sha256.Sum256([]byte(canonicalParts(request.Scope.TenantID, request.Scope.ProjectID, request.DeliveryID, request.Target)))
	id := "notice-" + hex.EncodeToString(digest[:12])
	query := "INSERT INTO in_app_notifications (id, tenant_id, project_id, delivery_id, event_id, event_state, recipient, subject, body, created_at) SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, NOW() WHERE EXISTS (SELECT 1 FROM notification_deliveries WHERE tenant_id = $2 AND project_id = $3 AND id = $4 AND event_id = $5 AND channel = 'in_app') ON CONFLICT (tenant_id, project_id, delivery_id, recipient) DO UPDATE SET id = in_app_notifications.id RETURNING id"
	var storedID string
	err := r.db.QueryRowContext(ctx, query, id, request.Scope.TenantID, request.Scope.ProjectID, request.DeliveryID, request.EventID, request.State, request.Target, request.Subject, request.Body).Scan(&storedID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotificationScopeMismatch
	}
	return err
}

func (r *PostgresRepository) ListInAppNotifications(ctx context.Context, scope Scope, recipient string, limit int) ([]InAppNotification, error) {
	if scope.Validate() != nil || strings.TrimSpace(recipient) == "" {
		return nil, ErrInvalidNotification
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := "SELECT id, tenant_id, project_id, delivery_id, event_id, event_state, recipient, subject, body, created_at, read_at FROM in_app_notifications WHERE tenant_id = $1 AND project_id = $2 AND recipient = $3 ORDER BY created_at DESC LIMIT $4"
	rows, err := r.db.QueryContext(ctx, query, scope.TenantID, scope.ProjectID, recipient, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]InAppNotification, 0)
	for rows.Next() {
		var notification InAppNotification
		var readAt sql.NullTime
		if err := rows.Scan(&notification.ID, &notification.Scope.TenantID, &notification.Scope.ProjectID, &notification.DeliveryID, &notification.EventID, &notification.EventState, &notification.Recipient, &notification.Subject, &notification.Body, &notification.CreatedAt, &readAt); err != nil {
			return nil, err
		}
		if notification.Scope != scope {
			return nil, ErrNotificationScopeMismatch
		}
		if readAt.Valid {
			notification.ReadAt = readAt.Time
		}
		result = append(result, notification)
	}
	return result, rows.Err()
}

func (r *PostgresRepository) CreateSilence(ctx context.Context, silence Silence) (Silence, error) {
	actor, err := auditActorFromContext(ctx)
	if err != nil {
		return Silence{}, err
	}
	if err := validateSilence(silence); err != nil || silence.CreatedBy != actor {
		return Silence{}, ErrInvalidNotification
	}
	matchers, err := marshalMap(silence.Matchers)
	if err != nil {
		return Silence{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Silence{}, err
	}
	defer func() { _ = tx.Rollback() }()
	query := "INSERT INTO alert_silences (id, tenant_id, project_id, matchers, starts_at, ends_at, created_by, reason) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, tenant_id, project_id, matchers, starts_at, ends_at, created_by, reason, created_at, updated_at"
	stored, err := scanSilence(tx.QueryRowContext(ctx, query, silence.ID, silence.Scope.TenantID, silence.Scope.ProjectID, matchers, silence.StartsAt, silence.EndsAt, actor, silence.Reason))
	if err != nil {
		return Silence{}, err
	}
	audit := silenceAudit(stored, actor, "silence.created", stored.CreatedAt)
	if err := appendAudit(ctx, tx, audit); err != nil {
		return Silence{}, err
	}
	if err := tx.Commit(); err != nil {
		return Silence{}, err
	}
	return stored, nil
}

func (r *PostgresRepository) UpdateSilence(ctx context.Context, silence Silence) (Silence, error) {
	actor, err := auditActorFromContext(ctx)
	if err != nil {
		return Silence{}, err
	}
	if err := validateSilence(silence); err != nil {
		return Silence{}, err
	}
	matchers, err := marshalMap(silence.Matchers)
	if err != nil {
		return Silence{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Silence{}, err
	}
	defer func() { _ = tx.Rollback() }()
	query := "UPDATE alert_silences SET matchers = $1, starts_at = $2, ends_at = $3, reason = $4, updated_at = NOW() WHERE tenant_id = $5 AND project_id = $6 AND id = $7 RETURNING id, tenant_id, project_id, matchers, starts_at, ends_at, created_by, reason, created_at, updated_at"
	stored, err := scanSilence(tx.QueryRowContext(ctx, query, matchers, silence.StartsAt, silence.EndsAt, silence.Reason, silence.Scope.TenantID, silence.Scope.ProjectID, silence.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return Silence{}, ErrNotFound
	}
	if err != nil {
		return Silence{}, err
	}
	if err := appendAudit(ctx, tx, silenceAudit(stored, actor, "silence.updated", stored.UpdatedAt)); err != nil {
		return Silence{}, err
	}
	if err := tx.Commit(); err != nil {
		return Silence{}, err
	}
	return stored, nil
}

func (r *PostgresRepository) DeleteSilence(ctx context.Context, scope Scope, id string) error {
	actor, err := auditActorFromContext(ctx)
	if err != nil {
		return err
	}
	if scope.Validate() != nil || !validIdentifier(id) {
		return ErrInvalidNotification
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	query := "DELETE FROM alert_silences WHERE tenant_id = $1 AND project_id = $2 AND id = $3 RETURNING id, tenant_id, project_id, matchers, starts_at, ends_at, created_by, reason, created_at, updated_at"
	deleted, err := scanSilence(tx.QueryRowContext(ctx, query, scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := appendAudit(ctx, tx, silenceAudit(deleted, actor, "silence.deleted", time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}

func validateSilence(silence Silence) error {
	if silence.Scope.Validate() != nil || !validIdentifier(silence.ID) || len(silence.Matchers) == 0 || !validSilenceMatchers(silence.Matchers) || strings.TrimSpace(silence.CreatedBy) == "" || strings.TrimSpace(silence.Reason) == "" || containsSecretMaterial(silence.Reason) || silence.StartsAt.IsZero() || !silence.EndsAt.After(silence.StartsAt) {
		return ErrInvalidNotification
	}
	return nil
}

func scanSilence(scanner rowScanner) (Silence, error) {
	var silence Silence
	var matchers []byte
	if err := scanner.Scan(&silence.ID, &silence.Scope.TenantID, &silence.Scope.ProjectID, &matchers, &silence.StartsAt, &silence.EndsAt, &silence.CreatedBy, &silence.Reason, &silence.CreatedAt, &silence.UpdatedAt); err != nil {
		return Silence{}, err
	}
	if err := unmarshalMap(matchers, &silence.Matchers); err != nil {
		return Silence{}, err
	}
	return silence, nil
}

func silenceAudit(silence Silence, actor, action string, at time.Time) AuditRecord {
	id := "audit-" + fingerprintParts(silence.Scope.TenantID, silence.Scope.ProjectID, silence.ID, action, at.UTC().Format(time.RFC3339Nano))[:24]
	return AuditRecord{ID: id, Scope: silence.Scope, Actor: actor, Action: action, TargetID: silence.ID, OccurredAt: at.UTC(), Details: map[string]string{
		"starts_at": silence.StartsAt.UTC().Format(time.RFC3339Nano), "ends_at": silence.EndsAt.UTC().Format(time.RFC3339Nano),
		"matcher_count": strconv.Itoa(len(silence.Matchers)), "reason_present": "true",
	}}
}

func (r *PostgresRepository) ReserveNotificationDelivery(ctx context.Context, delivery NotificationDelivery, audit *AuditRecord) (bool, error) {
	if err := validateNotificationDelivery(delivery); err != nil {
		return false, err
	}
	if audit != nil {
		if audit.Scope != delivery.Scope || audit.TargetID != delivery.ID {
			return false, ErrInvalidAuditRecord
		}
		if err := validateNotificationAudit(*audit); err != nil {
			return false, err
		}
	}
	labels, err := marshalMap(delivery.Request.Labels)
	if err != nil {
		return false, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, deliveryInsertSQL,
		delivery.ID, delivery.Scope.TenantID, delivery.Scope.ProjectID, delivery.EventID, delivery.PolicyID,
		delivery.IdempotencyKey, delivery.Request.State, delivery.Request.Channel, delivery.Request.TemplateID, delivery.Request.TemplateVersion,
		delivery.Status, delivery.Attempts, delivery.AttemptedAt, nullableTimestamp(delivery.NextAttemptAt), nullableTimestamp(delivery.DeliveredAt),
		delivery.LeaseOwner, nullableTimestamp(delivery.LeaseExpiresAt), delivery.FailureClass,
		delivery.Request.Target, delivery.Request.Subject, delivery.Request.Body, labels, delivery.Request.SecretRef,
		legacyDeliveryIdempotencyKey(delivery.EventID, delivery.EventState, delivery.Request.Channel, delivery.Request.TemplateVersion),
	)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rows == 0 {
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	if audit != nil {
		if err := appendNotificationAudit(ctx, tx, *audit); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (r *PostgresRepository) UpdateNotificationDelivery(ctx context.Context, delivery NotificationDelivery, audit AuditRecord) error {
	if err := validateNotificationDelivery(delivery); err != nil {
		return err
	}
	if audit.Scope != delivery.Scope || audit.TargetID != delivery.ID {
		return ErrInvalidAuditRecord
	}
	if err := validateNotificationAudit(audit); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, deliveryUpdateSQL,
		delivery.Status, delivery.AttemptedAt, nullableTimestamp(delivery.NextAttemptAt), nullableTimestamp(delivery.DeliveredAt),
		delivery.LeaseOwner, nullableTimestamp(delivery.LeaseExpiresAt), delivery.FailureClass,
		delivery.Scope.TenantID, delivery.Scope.ProjectID, delivery.ID, delivery.ClaimOwner,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	if err := appendNotificationAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *PostgresRepository) ClaimDueNotificationDeliveries(ctx context.Context, at time.Time, owner string, leaseUntil time.Time, limit int) ([]NotificationDelivery, error) {
	if at.IsZero() || leaseUntil.IsZero() || !leaseUntil.After(at) || strings.TrimSpace(owner) == "" {
		return nil, ErrInvalidNotification
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	leaseUntil = leaseUntil.UTC().Truncate(time.Microsecond)
	rows, err := r.db.QueryContext(ctx, claimDeliveriesSQL, at.UTC(), limit, owner, leaseUntil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deliveries := make([]NotificationDelivery, 0)
	for rows.Next() {
		delivery, err := scanNotificationDelivery(rows)
		if err != nil {
			return nil, err
		}
		if delivery.Status != DeliveryAttempting || delivery.LeaseOwner != owner || !delivery.LeaseExpiresAt.Equal(leaseUntil) {
			return nil, ErrInvalidNotification
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, rows.Err()
}

func (r *PostgresRepository) ListNotificationDeliveries(ctx context.Context, scope Scope, eventID string) ([]NotificationDelivery, error) {
	if scope.Validate() != nil || strings.TrimSpace(eventID) == "" {
		return nil, ErrInvalidNotification
	}
	rows, err := r.db.QueryContext(ctx, "SELECT "+notificationDeliveryColumnsSQL+" FROM notification_deliveries WHERE tenant_id = $1 AND project_id = $2 AND event_id = $3 ORDER BY attempted_at DESC, id ASC", scope.TenantID, scope.ProjectID, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]NotificationDelivery, 0)
	for rows.Next() {
		value, scanErr := scanNotificationDelivery(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		if value.Scope != scope || value.EventID != eventID {
			return nil, ErrNotificationScopeMismatch
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (r *PostgresRepository) deleteRule(ctx context.Context, scope Scope, id string) error {
	actor, err := auditActorFromContext(ctx)
	if err != nil {
		return err
	}
	if scope.Validate() != nil || !validIdentifier(id) {
		return ErrInvalidRule
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var lockedID string
	if err := tx.QueryRowContext(ctx, "SELECT id FROM alert_rules WHERE tenant_id = $1 AND project_id = $2 AND id = $3 FOR UPDATE", scope.TenantID, scope.ProjectID, id).Scan(&lockedID); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	var hasEvents bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM alert_events WHERE tenant_id = $1 AND project_id = $2 AND rule_id = $3)", scope.TenantID, scope.ProjectID, id).Scan(&hasEvents); err != nil {
		return err
	}
	if hasEvents {
		return ErrConfigurationInUse
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM alert_rules WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, id); err != nil {
		return err
	}
	at := time.Now().UTC()
	if err := appendAudit(ctx, tx, configurationAudit(scope, actor, "rule.deleted", id, at, nil)); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *PostgresRepository) deletePolicy(ctx context.Context, scope Scope, id string) error {
	actor, err := auditActorFromContext(ctx)
	if err != nil {
		return err
	}
	if scope.Validate() != nil || !validIdentifier(id) {
		return ErrInvalidNotification
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var lockedID string
	if err := tx.QueryRowContext(ctx, "SELECT id FROM notification_policies WHERE tenant_id = $1 AND project_id = $2 AND id = $3 FOR UPDATE", scope.TenantID, scope.ProjectID, id).Scan(&lockedID); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	var inUse bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM alert_rules WHERE tenant_id = $1 AND project_id = $2 AND $3 = ANY(notification_policy_ids))", scope.TenantID, scope.ProjectID, id).Scan(&inUse); err != nil {
		return err
	}
	if inUse {
		return ErrConfigurationInUse
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM notification_policies WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, id); err != nil {
		return err
	}
	at := time.Now().UTC()
	if err := appendAudit(ctx, tx, configurationAudit(scope, actor, "policy.deleted", id, at, nil)); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *PostgresRepository) deleteConfiguration(ctx context.Context, scope Scope, id, table, action string) error {
	actor, err := auditActorFromContext(ctx)
	if err != nil {
		return err
	}
	if scope.Validate() != nil || !validIdentifier(id) {
		return ErrInvalidNotification
	}
	switch table {
	case "notification_templates":
	default:
		return errors.New("unsupported configuration table")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	query := "DELETE FROM " + table + " WHERE tenant_id = $1 AND project_id = $2 AND id = $3"
	result, err := tx.ExecContext(ctx, query, scope.TenantID, scope.ProjectID, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	at := time.Now().UTC()
	if err := appendAudit(ctx, tx, configurationAudit(scope, actor, action, id, at, nil)); err != nil {
		return err
	}
	return tx.Commit()
}

func scanNotificationDelivery(scanner rowScanner) (NotificationDelivery, error) {
	var delivery NotificationDelivery
	var nextAttemptAt, deliveredAt, leaseExpiresAt sql.NullTime
	var labels []byte
	if err := scanner.Scan(
		&delivery.ID, &delivery.Scope.TenantID, &delivery.Scope.ProjectID, &delivery.EventID, &delivery.PolicyID,
		&delivery.IdempotencyKey, &delivery.Request.State, &delivery.Request.Channel, &delivery.Request.TemplateID, &delivery.Request.TemplateVersion,
		&delivery.Status, &delivery.Attempts, &delivery.AttemptedAt, &nextAttemptAt, &deliveredAt,
		&delivery.LeaseOwner, &leaseExpiresAt, &delivery.FailureClass,
		&delivery.Request.Target, &delivery.Request.Subject, &delivery.Request.Body, &labels, &delivery.Request.SecretRef,
	); err != nil {
		return NotificationDelivery{}, err
	}
	delivery.Request.DeliveryID = delivery.ID
	delivery.Request.Scope = delivery.Scope
	delivery.Request.EventID = delivery.EventID
	delivery.Request.PolicyID = delivery.PolicyID
	delivery.EventState = delivery.Request.State
	delivery.ClaimOwner = delivery.LeaseOwner
	if nextAttemptAt.Valid {
		delivery.NextAttemptAt = nextAttemptAt.Time
	}
	if deliveredAt.Valid {
		delivery.DeliveredAt = deliveredAt.Time
	}
	if leaseExpiresAt.Valid {
		delivery.LeaseExpiresAt = leaseExpiresAt.Time
	}
	if err := unmarshalMap(labels, &delivery.Request.Labels); err != nil {
		return NotificationDelivery{}, err
	}
	if err := validateNotificationDelivery(delivery); err != nil {
		return NotificationDelivery{}, err
	}
	return delivery, nil
}

func validateNotificationDelivery(delivery NotificationDelivery) error {
	if delivery.Scope.Validate() != nil || strings.TrimSpace(delivery.ID) == "" || delivery.ID != delivery.IdempotencyKey || strings.TrimSpace(delivery.EventID) == "" || strings.TrimSpace(delivery.PolicyID) == "" || delivery.Attempts < 1 || delivery.AttemptedAt.IsZero() {
		return ErrInvalidNotification
	}
	if delivery.Request.Scope != delivery.Scope || delivery.Request.EventID != delivery.EventID || delivery.Request.PolicyID != delivery.PolicyID || delivery.Request.Channel == "" || delivery.Request.TemplateID == "" || delivery.Request.TemplateVersion == "" {
		return ErrInvalidNotification
	}
	switch delivery.Request.Channel {
	case "in_app":
		if delivery.Request.SecretRef != "" {
			return ErrInvalidNotification
		}
	case "smtp", "webhook":
		if ValidateSecretReference(delivery.Request.SecretRef) != nil {
			return ErrInvalidNotification
		}
	default:
		return ErrInvalidNotification
	}
	if containsSecretMaterial(delivery.Request.Target) || containsSecretMaterial(delivery.Request.Subject) || containsSecretMaterial(delivery.Request.Body) {
		return ErrInvalidNotification
	}
	for key, value := range delivery.Request.Labels {
		if strings.TrimSpace(key) == "" || sensitiveField(key) || containsSecretMaterial(value) {
			return ErrInvalidNotification
		}
	}
	switch delivery.Status {
	case DeliveryAttempting, DeliveryDelivered, DeliverySuppressed, DeliveryRetryScheduled, DeliveryAbandoned:
	default:
		return ErrInvalidNotification
	}
	if delivery.Status == DeliveryRetryScheduled && delivery.NextAttemptAt.IsZero() {
		return ErrInvalidNotification
	}
	if delivery.Status == DeliveryAttempting && (delivery.LeaseOwner == "" || delivery.LeaseExpiresAt.IsZero()) {
		return ErrInvalidNotification
	}
	if delivery.FailureClass != "" && sanitizeFailureClass(delivery.FailureClass) != delivery.FailureClass {
		return ErrInvalidNotification
	}
	return nil
}

func appendNotificationAudit(ctx context.Context, database contextExecer, record AuditRecord) error {
	if err := validateNotificationAudit(record); err != nil {
		return err
	}
	details, err := marshalMap(record.Details)
	if err != nil {
		return err
	}
	_, err = database.ExecContext(ctx, auditInsertSQL, record.ID, record.Scope.TenantID, record.Scope.ProjectID, record.Actor, record.Action, record.TargetID, record.OccurredAt, details)
	return err
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

func insertEventDisposition(ctx context.Context, database contextExecer, disposition EventDisposition) error {
	if err := disposition.Validate(); err != nil {
		return err
	}
	_, err := database.ExecContext(ctx, dispositionInsertSQL, disposition.ID, disposition.Scope.TenantID, disposition.Scope.ProjectID, disposition.EventID, disposition.Kind, disposition.Category, disposition.Reason, disposition.Actor, disposition.OccurredAt)
	return err
}

type rowScanner interface {
	Scan(...any) error
}

func scanRule(scanner rowScanner) (AlertRule, error) {
	var rule AlertRule
	var policyIDs pq.StringArray
	var labels []byte
	var evaluationEveryNS, lookbackWindowNS, forDurationNS int64
	if err := scanner.Scan(&rule.ID, &rule.Scope.TenantID, &rule.Scope.ProjectID, &rule.Name, &rule.Metric, &rule.Aggregation, &rule.Operator, &rule.Threshold, &evaluationEveryNS, &lookbackWindowNS, &forDurationNS, &rule.MissingData, &rule.Severity, &policyIDs, &labels, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
		return AlertRule{}, err
	}
	rule.EvaluationEvery = durationFromNanoseconds(evaluationEveryNS)
	rule.LookbackWindow = durationFromNanoseconds(lookbackWindowNS)
	rule.For = durationFromNanoseconds(forDurationNS)
	rule.NotificationPolicyIDs = []string(policyIDs)
	if err := unmarshalMap(labels, &rule.Labels); err != nil {
		return AlertRule{}, err
	}
	return rule, nil
}

func scanDueRule(scanner rowScanner) (DueAlertRule, error) {
	var due DueAlertRule
	var policyIDs pq.StringArray
	var labels []byte
	var evaluationEveryNS, lookbackWindowNS, forDurationNS int64
	if err := scanner.Scan(&due.Rule.ID, &due.Rule.Scope.TenantID, &due.Rule.Scope.ProjectID, &due.Rule.Name, &due.Rule.Metric, &due.Rule.Aggregation, &due.Rule.Operator, &due.Rule.Threshold, &evaluationEveryNS, &lookbackWindowNS, &forDurationNS, &due.Rule.MissingData, &due.Rule.Severity, &policyIDs, &labels, &due.Rule.Enabled, &due.Rule.CreatedAt, &due.Rule.UpdatedAt, &due.DueAt); err != nil {
		return DueAlertRule{}, err
	}
	due.Rule.EvaluationEvery = durationFromNanoseconds(evaluationEveryNS)
	due.Rule.LookbackWindow = durationFromNanoseconds(lookbackWindowNS)
	due.Rule.For = durationFromNanoseconds(forDurationNS)
	due.Rule.NotificationPolicyIDs = []string(policyIDs)
	if err := unmarshalMap(labels, &due.Rule.Labels); err != nil {
		return DueAlertRule{}, err
	}
	return due, nil
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
var _ NotificationRepository = (*PostgresRepository)(nil)
var _ InAppNotificationRepository = (*PostgresRepository)(nil)
var _ SilenceRepository = (*PostgresRepository)(nil)
var _ NotificationConfigurationRepository = (*PostgresRepository)(nil)
