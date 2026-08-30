package hostinventory

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

func TestPostgresGetUsesTenantProjectAndHostPredicates(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	host := validHostFixture()
	mock.ExpectQuery(`SELECT .* FROM managed_hosts WHERE tenant_id = \$1 AND project_id = \$2 AND host_id = \$3`).
		WithArgs(host.Scope.TenantID, host.Scope.ProjectID, host.ID).
		WillReturnRows(hostRows(host))

	got, err := NewPostgresRepository(database).Get(context.Background(), host.Scope, host.ID)

	require.NoError(t, err)
	require.Equal(t, host.ID, got.ID)
	require.Equal(t, host.Scope, got.Scope)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresListScopesStatusClassificationCursorAndLimit(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	filter := Filter{Status: HostStale, Cursor: "host-0", Limit: 1, now: now, staleAfter: time.Minute, offlineAfter: 5 * time.Minute}
	host := validHostFixture()
	host.Status = HostStale
	mock.ExpectQuery(`(?s)SELECT .*CASE.*last_heartbeat_at.*FROM managed_hosts WHERE tenant_id = \$1 AND project_id = \$2.*host_id > \$3.*ORDER BY host_id.*LIMIT \$[0-9]+`).
		WithArgs(scope.TenantID, scope.ProjectID, filter.Cursor, now, filter.staleAfter.Microseconds(), filter.offlineAfter.Microseconds(), string(filter.Status), filter.Limit+1).
		WillReturnRows(hostRows(host, func(host *Host) { host.ID, host.AgentID = "host-2", "agent-2" }))

	page, err := NewPostgresRepository(database).List(context.Background(), scope, filter)

	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.Equal(t, "host-1", page.Items[0].ID)
	require.Equal(t, "host-1", page.NextCursor)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRecordObservationUsesScopedMonotonicUpsertAndAppend(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	observation := validObservationFixture()
	receivedAt := observation.ObservedAt.Add(time.Second)
	host := validHostFixture()
	host.LastHeartbeatAt = time.Time{}
	host.Status = HostEnrolling
	mock.ExpectQuery(`(?s)WITH upserted AS \(\s*INSERT INTO managed_hosts.*ON CONFLICT \(host_id\) DO UPDATE.*managed_hosts.tenant_id = EXCLUDED.tenant_id.*managed_hosts.project_id = EXCLUDED.project_id.*managed_hosts.agent_id = EXCLUDED.agent_id.*managed_hosts.observation_revision < EXCLUDED.observation_revision.*INSERT INTO host_observations.*SELECT .* FROM upserted.*SELECT .* FROM upserted`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(hostRows(host))

	got, err := NewPostgresRepository(database).RecordObservation(context.Background(), scope, observation, receivedAt)

	require.NoError(t, err)
	require.Equal(t, observation.Revision, got.ObservationRevision)
	require.True(t, got.LastHeartbeatAt.IsZero(), "inventory must not masquerade as AgentControl heartbeat")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRecordObservationRejectsLowerRevisionAndAcceptsEqualReplay(t *testing.T) {
	for _, test := range []struct {
		name     string
		revision uint64
		wantErr  error
	}{
		{name: "lower revision", revision: 1, wantErr: ErrStaleRevision},
		{name: "equal revision", revision: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, mock, err := sqlmock.New()
			require.NoError(t, err)
			t.Cleanup(func() { _ = database.Close() })
			scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
			observation := validObservationFixture()
			observation.Revision = test.revision
			current := validHostFixture()
			current.ObservationRevision = 2
			expectObservationUpsertNoRows(mock)
			mock.ExpectQuery(`SELECT .* FROM managed_hosts WHERE tenant_id = \$1 AND project_id = \$2 AND host_id = \$3`).
				WithArgs(scope.TenantID, scope.ProjectID, observation.HostID).
				WillReturnRows(hostRows(current))

			got, err := NewPostgresRepository(database).RecordObservation(context.Background(), scope, observation, observation.ObservedAt.Add(time.Second))

			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				require.Equal(t, Host{}, got)
			} else {
				require.NoError(t, err)
				require.Equal(t, current.ObservationRevision, got.ObservationRevision)
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestPostgresRecordHeartbeatUsesScopeAndMonotonicTimestamp(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	host := validHostFixture()
	at := host.LastHeartbeatAt.Add(time.Minute)
	host.LastHeartbeatAt, host.Status, host.Version = at, HostOnline, host.Version+1
	mock.ExpectQuery(`(?s)UPDATE managed_hosts SET last_heartbeat_at = \$1.*status = 'online'.*version = version \+ 1.*WHERE tenant_id = \$2 AND project_id = \$3 AND agent_id = \$4.*last_heartbeat_at IS NULL OR last_heartbeat_at < \$1.*RETURNING`).
		WithArgs(at, host.Scope.TenantID, host.Scope.ProjectID, host.AgentID).
		WillReturnRows(hostRows(host))

	got, err := NewPostgresRepository(database).RecordHeartbeat(context.Background(), host.Scope, host.AgentID, at)

	require.NoError(t, err)
	require.Equal(t, at, got.LastHeartbeatAt)
	require.Equal(t, HostOnline, got.Status)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresDecommissionUsesScopedVersionCAS(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	host := validHostFixture()
	expected := host.Version
	at := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	transition := validDecommissionTransition()
	host.Status, host.Version = HostDecommissioned, expected+1
	host.DecommissionTransition = &transition
	mock.ExpectQuery(`(?s)UPDATE managed_hosts SET status = 'decommissioned'.*decommission_actor = \$6.*decommission_operation = \$7.*decommission_idempotency_key = \$8.*decommission_fingerprint = \$9.*decommission_owner_token = \$10.*version = version \+ 1.*WHERE tenant_id = \$1 AND project_id = \$2 AND host_id = \$3 AND version = \$4 AND status <> 'decommissioned'.*RETURNING`).
		WithArgs(host.Scope.TenantID, host.Scope.ProjectID, host.ID, expected, at, transition.Actor, transition.OperationID, transition.IdempotencyKey, transition.Fingerprint, transition.OwnerToken).
		WillReturnRows(hostRows(host))

	got, err := NewPostgresRepository(database).Decommission(context.Background(), host.Scope, host.ID, expected, at, transition)

	require.NoError(t, err)
	require.Equal(t, HostDecommissioned, got.Status)
	require.Equal(t, expected+1, got.Version)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresDecommissionDistinguishesNotFoundFromVersionConflict(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	transition := validDecommissionTransition()
	mock.ExpectQuery(`UPDATE managed_hosts SET`).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT version FROM managed_hosts WHERE tenant_id = \$1 AND project_id = \$2 AND host_id = \$3`).
		WithArgs(scope.TenantID, scope.ProjectID, "host-1").
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(3))

	_, err = NewPostgresRepository(database).Decommission(context.Background(), scope, "host-1", 2, time.Now().UTC(), transition)

	require.ErrorIs(t, err, ErrConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRunMigrationsUsesSharedRegistryExactlyOnce(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("hostinventory/migrations/0001_host_inventory.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(`(?s)CREATE TABLE managed_hosts.*CREATE TABLE host_observations.*host_observations_append_only`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("hostinventory/migrations/0001_host_inventory.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("hostinventory/migrations/0002_decommission_correlation.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(`(?s)ALTER TABLE managed_hosts.*decommission_actor.*managed_hosts_decommission_correlation`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("hostinventory/migrations/0002_decommission_correlation.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	require.NoError(t, RunMigrations(context.Background(), database))
	require.NoError(t, mock.ExpectationsWereMet())
}

func hostRows(first Host, mutate ...func(*Host)) *sqlmock.Rows {
	values := []Host{first}
	for _, change := range mutate {
		copy := first
		change(&copy)
		values = append(values, copy)
	}
	rows := sqlmock.NewRows(hostColumnNames())
	for _, host := range values {
		filesystems, _ := json.Marshal(host.Filesystems)
		addresses, _ := json.Marshal(host.NetworkAddresses)
		labels, _ := json.Marshal(host.Labels)
		capabilities, _ := json.Marshal(host.Capabilities)
		var actor, operation, key, fingerprint, owner any
		if host.DecommissionTransition != nil {
			actor = host.DecommissionTransition.Actor
			operation = host.DecommissionTransition.OperationID
			key = host.DecommissionTransition.IdempotencyKey
			fingerprint = host.DecommissionTransition.Fingerprint
			owner = host.DecommissionTransition.OwnerToken
		}
		rows.AddRow(host.Scope.TenantID, host.Scope.ProjectID, host.ID, host.AgentID, host.DisplayName, host.Hostname,
			host.OperatingSystem, host.OperatingSystemVersion, host.KernelVersion, host.Architecture, host.CPU.Capacity,
			host.Memory.Capacity, filesystems, addresses, labels, host.ContainerRuntime, capabilities, host.AgentVersion,
			host.EnrollmentRevision, host.ObservationRevision, host.EnrolledAt, nullableTime(host.LastHelloAt), nullableTime(host.LastHeartbeatAt), host.Status, host.Version,
			actor, operation, key, fingerprint, owner)
	}
	return rows
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func expectObservationUpsertNoRows(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`(?s)WITH upserted AS \(\s*INSERT INTO managed_hosts.*ON CONFLICT \(host_id\) DO UPDATE.*managed_hosts.observation_revision < EXCLUDED.observation_revision.*SELECT .* FROM upserted`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(hostColumnNames()))
}
