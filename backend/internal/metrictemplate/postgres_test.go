package metrictemplate

import (
	"context"
	"testing"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestRevisionCursorBindsScopeTemplateAndDescendingRevisionKey(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	encoded, err := encodeRevisionCursor(scope, "mysql.custom", 7, "revision-a")
	require.NoError(t, err)
	revision, id, err := decodeRevisionCursor(scope, "mysql.custom", encoded)
	require.NoError(t, err)
	require.Equal(t, uint64(7), revision)
	require.Equal(t, "revision-a", id)
	_, _, err = decodeRevisionCursor(platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-b"}, "mysql.custom", encoded)
	require.ErrorIs(t, err, ErrInvalid)
	_, _, err = decodeRevisionCursor(scope, "mysql.other", encoded)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestPostgresReadyRequiresCompleteMetricTemplateSchema(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer database.Close()
	mock.ExpectQuery("to_regclass").WillReturnRows(sqlmock.NewRows([]string{"ready"}).AddRow(false))
	require.EqualError(t, NewPostgresRepository(database, nil).Ready(context.Background()), "metric template schema is unavailable")
	require.NoError(t, mock.ExpectationsWereMet())
}
