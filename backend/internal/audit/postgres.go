package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"dbpilot.local/platform/internal/platformscope"
)

const auditColumnsSQL = "id, tenant_id, project_id, occurred_at, action, actor_type, actor_id, resource_type, resource_id, result, request_id, trace_id, job_id, command_id, detail, created_at"
const auditInsertSQL = "INSERT INTO audit_events (" + auditColumnsSQL + ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)"
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
	_, err = store.database.ExecContext(ctx, auditInsertSQL,
		value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.OccurredAt.UTC(), value.Action,
		value.Actor.Type, value.Actor.ID, value.Resource.Type, value.Resource.ID, value.Result,
		value.RequestID, value.TraceID, value.JobID, value.CommandID, encoded, value.CreatedAt.UTC(),
	)
	return err
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
	if err := scanner.Scan(&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.OccurredAt, &value.Action, &value.Actor.Type, &value.Actor.ID, &value.Resource.Type, &value.Resource.ID, &value.Result, &value.RequestID, &value.TraceID, &value.JobID, &value.CommandID, &detail, &value.CreatedAt); err != nil {
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

var _ Store = (*PostgresStore)(nil)
