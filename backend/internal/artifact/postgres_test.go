package artifact

import (
	"context"
	"database/sql"
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
