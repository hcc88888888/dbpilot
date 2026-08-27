package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	"dbpilot.local/platform/internal/platformscope"
)

const auditColumnsSQL = "id, tenant_id, project_id, occurred_at, action, actor_type, actor_id, resource_type, resource_id, result, request_id, trace_id, job_id, command_id, dedupe_key, detail, created_at"
const auditInsertSQL = "INSERT INTO audit_events (" + auditColumnsSQL + ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)"
const auditInsertOnceSQL = "INSERT INTO audit_events (" + auditColumnsSQL + ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) ON CONFLICT (tenant_id, project_id, dedupe_key) WHERE dedupe_key <> '' DO NOTHING RETURNING " + auditColumnsSQL
const auditGetDedupeSQL = "SELECT " + auditColumnsSQL + " FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND dedupe_key = $3"
const auditListSQL = "SELECT " + auditColumnsSQL + " FROM audit_events WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at ASC, id ASC LIMIT $3"
const auditListAfterSQL = "SELECT " + auditColumnsSQL + " FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND (created_at, id) > ($3, $4) ORDER BY created_at ASC, id ASC LIMIT $5"

type PostgresStore struct{ database *sql.DB }

func NewPostgresStore(database *sql.DB) *PostgresStore { return &PostgresStore{database: database} }

func (store *PostgresStore) Append(ctx context.Context, value Event) error {
	if store == nil || store.database == nil || ctx == nil {
		return ErrInvalidEvent
	}
	if err := validateStored(value); err != nil {
		return err
	}
	detail, err := normalizeSanitizedDetailMap(value.Detail)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return ErrInvalidEvent
	}
	_, err = store.database.ExecContext(ctx, auditInsertSQL, auditInsertArgs(value, encoded)...)
	return err
}

func (store *PostgresStore) AppendOnce(ctx context.Context, value Event) (Event, error) {
	if store == nil || store.database == nil || ctx == nil || !canonical(value.DedupeKey) {
		return Event{}, ErrInvalidEvent
	}
	if err := validateStored(value); err != nil {
		return Event{}, err
	}
	detail, err := normalizeSanitizedDetailMap(value.Detail)
	if err != nil {
		return Event{}, err
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return Event{}, ErrInvalidEvent
	}
	value.Detail = detail
	inserted, err := scanAuditEvent(store.database.QueryRowContext(ctx, auditInsertOnceSQL, auditInsertArgs(value, encoded)...))
	if err == nil {
		return inserted, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Event{}, err
	}
	existing, err := scanAuditEvent(store.database.QueryRowContext(ctx, auditGetDedupeSQL, value.Scope.TenantID, value.Scope.ProjectID, value.DedupeKey))
	if err != nil {
		return Event{}, err
	}
	if !sameDedupeSemantics(existing, value) {
		return Event{}, ErrDedupeConflict
	}
	return existing, nil
}

func (store *PostgresStore) List(ctx context.Context, scope platformscope.Scope, query StoreListQuery) ([]Event, error) {
	if store == nil || store.database == nil || ctx == nil || scope.Validate() != nil || query.Limit <= 0 || (query.After.IsZero() != (query.AfterID == "")) {
		return nil, ErrInvalidEvent
	}
	var rows *sql.Rows
	var err error
	if query.After.IsZero() {
		rows, err = store.database.QueryContext(ctx, auditListSQL, scope.TenantID, scope.ProjectID, query.Limit)
	} else {
		rows, err = store.database.QueryContext(ctx, auditListAfterSQL, scope.TenantID, scope.ProjectID, query.After.UTC(), query.AfterID, query.Limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Event, 0)
	for rows.Next() {
		value, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		if value.Scope != scope {
			return nil, ErrInvalidCursor
		}
		items = append(items, value)
	}
	return items, rows.Err()
}

func scanAuditEvent(scanner interface{ Scan(...any) error }) (Event, error) {
	var value Event
	var detail []byte
	if err := scanner.Scan(&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.OccurredAt, &value.Action, &value.Actor.Type, &value.Actor.ID, &value.Resource.Type, &value.Resource.ID, &value.Result, &value.RequestID, &value.TraceID, &value.JobID, &value.CommandID, &value.DedupeKey, &detail, &value.CreatedAt); err != nil {
		return Event{}, err
	}
	decoded, err := decodeCanonicalDetail(detail)
	if err != nil {
		return Event{}, err
	}
	value.Detail = decoded
	value.OccurredAt = value.OccurredAt.UTC()
	value.CreatedAt = value.CreatedAt.UTC()
	return value, nil
}

func auditColumnNames() []string { return strings.Split(auditColumnsSQL, ", ") }

func auditInsertArgs(value Event, detail []byte) []any {
	return []any{
		value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.OccurredAt.UTC(), value.Action,
		value.Actor.Type, value.Actor.ID, value.Resource.Type, value.Resource.ID, value.Result,
		value.RequestID, value.TraceID, value.JobID, value.CommandID, value.DedupeKey, detail, value.CreatedAt.UTC(),
	}
}

func sameDedupeSemantics(first, second Event) bool {
	return first.Scope == second.Scope && first.DedupeKey == second.DedupeKey && first.Action == second.Action &&
		first.Actor == second.Actor && first.Resource == second.Resource && first.Result == second.Result &&
		first.RequestID == second.RequestID && first.TraceID == second.TraceID && first.JobID == second.JobID &&
		first.CommandID == second.CommandID && reflect.DeepEqual(first.Detail, second.Detail)
}

var _ Store = (*PostgresStore)(nil)
