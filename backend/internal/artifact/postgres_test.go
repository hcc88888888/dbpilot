package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestPostgresStoreGetScopesMetadataQueryByTenantAndProject(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	created := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT .* FROM artifacts WHERE tenant_id = \\$1 AND project_id = \\$2 AND id = \\$3").
		WithArgs(scope.TenantID, scope.ProjectID, "artifact-1").
		WillReturnRows(sqlmock.NewRows(artifactColumnNames()).AddRow("artifact-1", scope.TenantID, scope.ProjectID, "report", "application/json", 42, "sha256:abc", "job", "job-1", "job-1", "operator-1", created, nil, "storage/object-1"))

	value, err := NewPostgresStore(database).Get(context.Background(), scope, "artifact-1")
	require.NoError(t, err)
	require.Equal(t, int64(42), value.SizeBytes)
	require.Equal(t, "sha256:abc", value.Checksum)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreGetMapsScopedMissToNotFound(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-other"}
	mock.ExpectQuery("SELECT .* FROM artifacts WHERE tenant_id = \\$1 AND project_id = \\$2 AND id = \\$3").WithArgs(scope.TenantID, scope.ProjectID, "artifact-1").WillReturnError(sql.ErrNoRows)

	_, err = NewPostgresStore(database).Get(context.Background(), scope, "artifact-1")
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStorePutPublishesContentAddressedBlobBeforeMetadata(t *testing.T) {
	// Break caught: committing metadata before a durable blob creates a report
	// that can be listed but never downloaded after a worker crash.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	rootPath := t.TempDir()
	blobs := NewLocalBlobStore(rootPath)
	t.Cleanup(func() { require.NoError(t, blobs.Close()) })
	payload := []byte("immutable report\n")
	value := putArtifactFixture(payload)
	wantReference := filepath.ToSlash(filepath.Join("sha256", value.Checksum[len("sha256:"):]+".blob"))
	stored := value
	stored.StorageReference = wantReference
	mock.ExpectQuery("INSERT INTO artifacts .* ON CONFLICT .* DO NOTHING RETURNING").
		WithArgs(value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.Kind, value.ContentType, value.SizeBytes, value.Checksum, value.SourceResource.ResourceType, value.SourceResource.ResourceID, value.JobID, value.CreatedBy, value.CreatedAt, nil, wantReference).
		WillReturnRows(artifactRows(stored))

	got, err := NewPostgresStore(database, blobs).Put(context.Background(), value, payload)

	require.NoError(t, err)
	require.Equal(t, wantReference, got.StorageReference)
	contents, err := os.ReadFile(filepath.Join(rootPath, filepath.FromSlash(wantReference)))
	require.NoError(t, err)
	require.Equal(t, payload, contents)
	temporary, err := filepath.Glob(filepath.Join(rootPath, "sha256", ".tmp-*"))
	require.NoError(t, err)
	require.Empty(t, temporary, "temporary files must be removed after atomic publication")
	t.Logf("artifact evidence: id=%s reference=%s checksum=%s bytes=%d", got.ID, got.StorageReference, got.Checksum, got.SizeBytes)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStorePutReaderStreamsBoundedImmutableBlobBeforeMetadata(t *testing.T) {
	// Break caught: buffering a plugin upload in memory defeats the streaming
	// contract, while metadata-before-blob creates an unusable Artifact.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	rootPath := t.TempDir()
	blobs := NewLocalBlobStore(rootPath)
	t.Cleanup(func() { require.NoError(t, blobs.Close()) })
	payload := bytes.Repeat([]byte("streamed-plugin-package\n"), 128*1024)
	value := putArtifactFixture(payload)
	value.ID = "plugin-package-streamed"
	value.Kind = "plugin-package"
	value.ContentType = "application/gzip"
	wantReference := filepath.ToSlash(filepath.Join("sha256", value.Checksum[len("sha256:"):]+".blob"))
	stored := value
	stored.StorageReference = wantReference
	mock.ExpectQuery("INSERT INTO artifacts .* ON CONFLICT .* DO NOTHING RETURNING").
		WithArgs(value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.Kind, value.ContentType, value.SizeBytes, value.Checksum, value.SourceResource.ResourceType, value.SourceResource.ResourceID, value.JobID, value.CreatedBy, value.CreatedAt, nil, wantReference).
		WillReturnRows(artifactRows(stored))
	reader := &boundedReadRecorder{reader: bytes.NewReader(payload)}

	got, err := NewPostgresStore(database, blobs).PutReader(context.Background(), value, reader)

	require.NoError(t, err)
	require.Equal(t, wantReference, got.StorageReference)
	require.LessOrEqual(t, reader.maximumRequest, 64<<10, "streaming must use a bounded copy buffer")
	contents, err := os.ReadFile(filepath.Join(rootPath, filepath.FromSlash(wantReference)))
	require.NoError(t, err)
	require.Equal(t, payload, contents)
	temporary, err := filepath.Glob(filepath.Join(rootPath, "sha256", ".tmp-*"))
	require.NoError(t, err)
	require.Empty(t, temporary)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStorePutIdenticalChecksumRetrySucceedsAndConflictingIDFails(t *testing.T) {
	// Break caught: crash repair must accept the exact same artifact bytes, but
	// an Artifact ID can never be rebound to a different checksum.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	blobs := NewLocalBlobStore(t.TempDir())
	t.Cleanup(func() { require.NoError(t, blobs.Close()) })
	payload := []byte("immutable report\n")
	value := putArtifactFixture(payload)
	reference := filepath.ToSlash(filepath.Join("sha256", value.Checksum[len("sha256:"):]+".blob"))
	stored := value
	stored.StorageReference = reference

	mock.ExpectQuery("INSERT INTO artifacts .* ON CONFLICT .* DO NOTHING RETURNING").WillReturnRows(sqlmock.NewRows(artifactColumnNames()))
	mock.ExpectQuery("SELECT .* FROM artifacts WHERE tenant_id = \\$1 AND project_id = \\$2 AND id = \\$3").
		WithArgs(value.Scope.TenantID, value.Scope.ProjectID, value.ID).
		WillReturnRows(artifactRows(stored))
	first, err := NewPostgresStore(database, blobs).Put(context.Background(), value, payload)
	require.NoError(t, err)
	require.Equal(t, stored, first)

	conflictingPayload := []byte("different immutable report\n")
	conflict := putArtifactFixture(conflictingPayload)
	conflict.ID = value.ID
	mock.ExpectQuery("INSERT INTO artifacts .* ON CONFLICT .* DO NOTHING RETURNING").WillReturnRows(sqlmock.NewRows(artifactColumnNames()))
	mock.ExpectQuery("SELECT .* FROM artifacts WHERE tenant_id = \\$1 AND project_id = \\$2 AND id = \\$3").
		WithArgs(value.Scope.TenantID, value.Scope.ProjectID, value.ID).
		WillReturnRows(artifactRows(stored))
	_, err = NewPostgresStore(database, blobs).Put(context.Background(), conflict, conflictingPayload)
	require.ErrorIs(t, err, ErrConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func putArtifactFixture(payload []byte) Artifact {
	digest := sha256.Sum256(payload)
	return Artifact{
		ID: "inspection-report-run-a.json", Scope: platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"},
		Kind: "inspection-report", ContentType: "application/json", SizeBytes: int64(len(payload)), Checksum: fmt.Sprintf("sha256:%x", digest),
		SourceResource: ResourceReference{ResourceType: "inspection_report", ResourceID: "inspection-report-run-a"},
		JobID:          "job-a", CreatedBy: "inspection-worker", CreatedAt: time.Date(2026, 8, 29, 10, 2, 0, 0, time.UTC),
	}
}

func artifactRows(values ...Artifact) *sqlmock.Rows {
	rows := sqlmock.NewRows(artifactColumnNames())
	for _, value := range values {
		rows.AddRow(value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.Kind, value.ContentType, value.SizeBytes, value.Checksum, value.SourceResource.ResourceType, value.SourceResource.ResourceID, value.JobID, value.CreatedBy, value.CreatedAt, value.ExpiresAt, value.StorageReference)
	}
	return rows
}

type boundedReadRecorder struct {
	reader         *bytes.Reader
	maximumRequest int
}

func (reader *boundedReadRecorder) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.maximumRequest {
		reader.maximumRequest = len(buffer)
	}
	return reader.reader.Read(buffer)
}
