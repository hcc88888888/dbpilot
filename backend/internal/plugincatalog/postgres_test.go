package plugincatalog

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestPostgresRepositoryCreateScopesDefinitionAndImmutableVersionTransaction(t *testing.T) {
	// Break caught: an unscoped or partially committed insert can expose a
	// plugin across projects or leave a version without its definition.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	version := validServiceVersion()
	definition := PluginDefinition{
		Scope: version.Scope, PluginID: version.PluginID, Name: "mysql", DatabaseFamily: "mysql", ProtocolVersion: "v1",
		SupportedVariants: []string{"mysql"}, Capabilities: []string{"metrics.collect"},
	}
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO plugin_definitions .* ON CONFLICT .* RETURNING").
		WithArgs(definition.Scope.TenantID, definition.Scope.ProjectID, definition.PluginID, definition.Name, definition.DatabaseFamily, definition.ProtocolVersion, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(definitionRows(definition))
	mock.ExpectQuery("INSERT INTO plugin_versions .* ON CONFLICT DO NOTHING RETURNING").
		WithArgs(version.ID, version.Scope.TenantID, version.Scope.ProjectID, version.PluginID, version.Version, version.Status, version.ArtifactID, version.PackageSHA256, version.ManifestDigest, version.PublisherID, version.SigningKeyID, version.ProtocolVersion, version.MinimumAgentProtocolVersion, version.MaximumAgentProtocolVersion, sqlmock.AnyArg(), version.DatabaseVersionRange, sqlmock.AnyArg(), version.MetricTemplateSchemaVersion, sqlmock.AnyArg(), version.Revision, version.CreatedAt, nil, "").
		WillReturnRows(versionRows(version))
	mock.ExpectCommit()

	stored, err := NewPostgresRepository(database).Create(context.Background(), definition, version)

	require.NoError(t, err)
	require.Equal(t, version, stored)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRepositoryTransitionUsesScopeStatusAndRevisionCAS(t *testing.T) {
	// Break caught: omitting any WHERE fence permits cross-project, stale, or
	// invalid lifecycle transitions.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	at := time.Date(2026, 8, 30, 5, 0, 0, 0, time.UTC)
	want := validServiceVersion()
	want.Status, want.Revision = StatusApproved, 8
	want.ApprovedAt = &at
	mock.ExpectQuery("UPDATE plugin_versions SET status = \\$1, revision = revision \\+ 1.*WHERE tenant_id = \\$4 AND project_id = \\$5 AND version_id = \\$6 AND revision = \\$7 AND status = ANY\\(\\$8\\) RETURNING").
		WithArgs(StatusApproved, at, "", scope.TenantID, scope.ProjectID, want.ID, uint64(7), sqlmock.AnyArg()).
		WillReturnRows(versionRows(want))

	got, err := NewPostgresRepositoryWithClock(database, func() time.Time { return at }).Transition(context.Background(), TransitionRequest{
		Scope: scope, VersionID: want.ID, ExpectedRevision: 7, AllowedFrom: []Status{StatusVerified}, To: StatusApproved,
	})

	require.NoError(t, err)
	require.Equal(t, want, got)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRepositoryTransitionDistinguishesScopedMissingFromRevisionConflict(t *testing.T) {
	// Break caught: a scoped miss must not leak whether another project owns the
	// same opaque ID, while a same-scope stale ETag maps to a precondition error.
	for _, test := range []struct {
		name   string
		exists bool
		want   error
	}{
		{name: "missing", exists: false, want: ErrNotFound},
		{name: "stale revision", exists: true, want: ErrRevisionConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, mock, err := sqlmock.New()
			require.NoError(t, err)
			t.Cleanup(func() { _ = database.Close() })
			scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
			mock.ExpectQuery("UPDATE plugin_versions .* WHERE tenant_id = \\$4 AND project_id = \\$5").WillReturnError(sql.ErrNoRows)
			mock.ExpectQuery("SELECT EXISTS .* FROM plugin_versions WHERE tenant_id = \\$1 AND project_id = \\$2 AND version_id = \\$3").
				WithArgs(scope.TenantID, scope.ProjectID, "plugin-version-1").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(test.exists))

			_, err = NewPostgresRepository(database).Transition(context.Background(), TransitionRequest{Scope: scope, VersionID: "plugin-version-1", ExpectedRevision: 7, AllowedFrom: []Status{StatusVerified}, To: StatusApproved})
			require.ErrorIs(t, err, test.want)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestPostgresRepositoryListVersionsFiltersInsideScopedSQL(t *testing.T) {
	// Break caught: filtering after retrieval can expose another project's
	// plugin metadata even when the returned page is later trimmed in Go.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	want := validServiceVersion()
	want.Status = StatusAvailable
	mock.ExpectQuery("SELECT .* FROM plugin_versions WHERE tenant_id = \\$1 AND project_id = \\$2 AND plugin_id = \\$3 AND status = \\$4 ORDER BY created_at DESC, version_id DESC LIMIT \\$5").
		WithArgs(scope.TenantID, scope.ProjectID, "mysql", StatusAvailable, 3).
		WillReturnRows(versionRows(want))

	page, err := NewPostgresRepository(database).ListVersions(context.Background(), scope, VersionFilter{PluginID: "mysql", Status: StatusAvailable, Limit: 2})

	require.NoError(t, err)
	require.Equal(t, []PluginVersion{want}, page.Items)
	require.False(t, page.More)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRunMigrationsRegistersPluginCatalogSchemaAtomically(t *testing.T) {
	// Break caught: applying DDL without the shared registry/advisory lock can
	// race another control-plane process and partially create catalog tables.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(int64(0x444250494c4f54)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS .* dbpilot_schema_migrations").WithArgs("plugincatalog/migrations/0001_plugin_catalog.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("CREATE TABLE plugin_definitions").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("plugincatalog/migrations/0001_plugin_catalog.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(int64(0x444250494c4f54)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS .* dbpilot_schema_migrations").WithArgs("plugincatalog/migrations/0002_plugin_catalog_operations.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("CREATE TABLE plugin_catalog_operations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("plugincatalog/migrations/0002_plugin_catalog_operations.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(int64(0x444250494c4f54)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS .* dbpilot_schema_migrations").WithArgs("plugincatalog/migrations/0003_plugin_catalog_operation_leases.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("ALTER TABLE plugin_catalog_operations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("plugincatalog/migrations/0003_plugin_catalog_operation_leases.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	require.NoError(t, RunMigrations(context.Background(), database))
	require.NoError(t, mock.ExpectationsWereMet())
}

func definitionRows(values ...PluginDefinition) *sqlmock.Rows {
	rows := sqlmock.NewRows(definitionColumnNames())
	for _, value := range values {
		rows.AddRow(value.Scope.TenantID, value.Scope.ProjectID, value.PluginID, value.Name, value.DatabaseFamily, value.ProtocolVersion, jsonStringArray(value.SupportedVariants), jsonStringArray(value.Capabilities), nullableString(value.LatestAvailableVersion))
	}
	return rows
}

func versionRows(values ...PluginVersion) *sqlmock.Rows {
	rows := sqlmock.NewRows(versionColumnNames())
	for _, value := range values {
		platforms, _ := json.Marshal(value.Platforms)
		rows.AddRow(value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.PluginID, value.Version, value.Status, value.ArtifactID, value.PackageSHA256, value.ManifestDigest, value.PublisherID, value.SigningKeyID, value.ProtocolVersion, value.MinimumAgentProtocolVersion, value.MaximumAgentProtocolVersion, jsonStringArray(value.SupportedVariants), value.DatabaseVersionRange, jsonStringArray(value.Capabilities), value.MetricTemplateSchemaVersion, platforms, value.Revision, value.CreatedAt, value.ApprovedAt)
	}
	return rows
}

func jsonStringArray(values []string) []byte {
	encoded, _ := json.Marshal(values)
	return encoded
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
