package artifact

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"dbpilot.local/platform/internal/platformscope"
)

const artifactColumnsSQL = "id, tenant_id, project_id, kind, content_type, size_bytes, checksum, source_resource_type, source_resource_id, job_id, created_by, created_at, expires_at, storage_reference"
const artifactGetSQL = "SELECT " + artifactColumnsSQL + " FROM artifacts WHERE tenant_id = $1 AND project_id = $2 AND id = $3"

type PostgresStore struct{ database *sql.DB }

func NewPostgresStore(database *sql.DB) *PostgresStore { return &PostgresStore{database: database} }

func (store *PostgresStore) Get(ctx context.Context, scope platformscope.Scope, id string) (Artifact, error) {
	if store == nil || store.database == nil || ctx == nil || scope.Validate() != nil || strings.TrimSpace(id) == "" {
		return Artifact{}, ErrInvalid
	}
	value, err := scanArtifact(store.database.QueryRowContext(ctx, artifactGetSQL, scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	if err != nil {
		return Artifact{}, err
	}
	if value.Scope != scope || value.ID != id {
		return Artifact{}, ErrNotFound
	}
	return value, nil
}

func scanArtifact(scanner interface{ Scan(...any) error }) (Artifact, error) {
	var value Artifact
	var expires sql.NullTime
	err := scanner.Scan(&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.Kind, &value.ContentType, &value.SizeBytes, &value.Checksum, &value.SourceResource.ResourceType, &value.SourceResource.ResourceID, &value.JobID, &value.CreatedBy, &value.CreatedAt, &expires, &value.StorageReference)
	if err != nil {
		return Artifact{}, err
	}
	value.CreatedAt = value.CreatedAt.UTC()
	if expires.Valid {
		at := expires.Time.UTC()
		value.ExpiresAt = &at
	}
	return value, nil
}

func artifactColumnNames() []string { return strings.Split(artifactColumnsSQL, ", ") }

var _ Store = (*PostgresStore)(nil)
