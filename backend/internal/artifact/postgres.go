package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"dbpilot.local/platform/internal/platformscope"
)

const artifactColumnsSQL = "id, tenant_id, project_id, kind, content_type, size_bytes, checksum, source_resource_type, source_resource_id, job_id, created_by, created_at, expires_at, storage_reference"
const artifactGetSQL = "SELECT " + artifactColumnsSQL + " FROM artifacts WHERE tenant_id = $1 AND project_id = $2 AND id = $3"
const artifactInsertSQL = "INSERT INTO artifacts (id, tenant_id, project_id, kind, content_type, size_bytes, checksum, source_resource_type, source_resource_id, job_id, created_by, created_at, expires_at, storage_reference) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) ON CONFLICT (tenant_id, project_id, id) DO NOTHING RETURNING " + artifactColumnsSQL

type PostgresStore struct {
	database *sql.DB
	blobs    *LocalBlobStore
}

func NewPostgresStore(database *sql.DB, blobs ...*LocalBlobStore) *PostgresStore {
	store := &PostgresStore{database: database}
	if len(blobs) == 1 {
		store.blobs = blobs[0]
	}
	return store
}

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

func (store *PostgresStore) Put(ctx context.Context, value Artifact, contents []byte) (Artifact, error) {
	if len(contents) > 64<<20 || !validArtifact(value, contents) {
		return Artifact{}, ErrInvalid
	}
	return store.PutReader(ctx, value, bytes.NewReader(contents))
}

// PutReader publishes immutable Artifact bytes with bounded memory, then
// inserts metadata. A retry with the same ID/checksum returns the existing
// metadata; an ID can never be rebound to a different checksum.
func (store *PostgresStore) PutReader(ctx context.Context, value Artifact, source io.Reader) (Artifact, error) {
	if store == nil || store.database == nil || store.blobs == nil || ctx == nil || ctx.Err() != nil || source == nil || !validArtifactMetadata(value) {
		return Artifact{}, ErrInvalid
	}
	reference, err := store.blobs.PutReader(ctx, value.Checksum, value.SizeBytes, source)
	if err != nil {
		return Artifact{}, err
	}
	return store.insertMetadata(ctx, value, reference)
}

func (store *PostgresStore) insertMetadata(ctx context.Context, value Artifact, reference string) (Artifact, error) {
	if value.StorageReference != "" && value.StorageReference != reference {
		return Artifact{}, ErrInvalid
	}
	value.StorageReference = reference
	value.CreatedAt = value.CreatedAt.UTC()
	if value.ExpiresAt != nil {
		expires := value.ExpiresAt.UTC()
		value.ExpiresAt = &expires
	}
	stored, err := scanArtifact(store.database.QueryRowContext(ctx, artifactInsertSQL,
		value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.Kind, value.ContentType, value.SizeBytes, value.Checksum,
		value.SourceResource.ResourceType, value.SourceResource.ResourceID, value.JobID, value.CreatedBy, value.CreatedAt, value.ExpiresAt, value.StorageReference,
	))
	if err == nil {
		return stored, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, fmt.Errorf("insert artifact metadata: %w", err)
	}
	existing, err := store.Get(ctx, value.Scope, value.ID)
	if err != nil {
		return Artifact{}, err
	}
	if existing.Checksum != value.Checksum {
		return Artifact{}, ErrConflict
	}
	return existing, nil
}

func validArtifact(value Artifact, contents []byte) bool {
	if !validArtifactMetadata(value) || value.SizeBytes != int64(len(contents)) {
		return false
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(value.Checksum, "sha256:"))
	if err != nil || len(expected) != sha256.Size {
		return false
	}
	digest := sha256.Sum256(contents)
	return equalBytes(digest[:], expected)
}

func validArtifactMetadata(value Artifact) bool {
	if !validArtifactID(value.ID) || value.Scope.Validate() != nil || strings.TrimSpace(value.Kind) == "" || strings.TrimSpace(value.ContentType) == "" || value.SizeBytes < 0 || value.SizeBytes > 256<<20 || value.CreatedAt.IsZero() || (value.SourceResource.ResourceType == "") != (value.SourceResource.ResourceID == "") || !strings.HasPrefix(value.Checksum, "sha256:") {
		return false
	}
	if value.ExpiresAt != nil && !value.ExpiresAt.After(value.CreatedAt) {
		return false
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(value.Checksum, "sha256:"))
	return err == nil && len(expected) == sha256.Size
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
