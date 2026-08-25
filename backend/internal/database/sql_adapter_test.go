package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

func TestMySQLFactoryBuildsFixedDriverDSNWithTLS(t *testing.T) {
	state := &sqlDriverState{}
	opener := &fakeSQLOpener{db: newTestSQLDB(t, state)}
	config := adapterTestConfig(MySQLFamily)
	config.Database = "app data"
	config.TLS = TLSConfig{Enabled: true, ServerName: "db.internal.test"}

	adapter, err := NewMySQLFactory(opener, staticCatalog{}).Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()

	if got, want := opener.driverName, "mysql"; got != want {
		t.Fatalf("driver name = %q, want fixed %q", got, want)
	}
	if got, want := opener.dsn, "readonly@tcp(db.example.test:3306)/app%20data?readTimeout=15s&timeout=5s&tls=true&writeTimeout=15s"; got != want {
		t.Fatalf("DSN = %q, want %q", got, want)
	}
	if got := adapter.Family(); got != MySQLFamily {
		t.Fatalf("Family() = %q, want %q", got, MySQLFamily)
	}
}

func TestPostgresFactoryBuildsFixedDriverDSNWithTLS(t *testing.T) {
	state := &sqlDriverState{}
	opener := &fakeSQLOpener{db: newTestSQLDB(t, state)}
	config := adapterTestConfig(PostgresFamily)
	config.Address = "postgres://db.example.test:5432"
	config.Database = "app data"
	config.TLS = TLSConfig{Enabled: true, ServerName: "db.internal.test"}

	adapter, err := NewPostgresFactory(opener, staticCatalog{}).Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()

	if got, want := opener.driverName, "postgres"; got != want {
		t.Fatalf("driver name = %q, want fixed %q", got, want)
	}
	if got, want := opener.dsn, "postgres://readonly@db.example.test:5432/app%20data?connect_timeout=5&sslmode=verify-full&statement_timeout=15000"; got != want {
		t.Fatalf("DSN = %q, want %q", got, want)
	}
	if got := adapter.Family(); got != PostgresFamily {
		t.Fatalf("Family() = %q, want %q", got, PostgresFamily)
	}
}

func TestAdapterPingUsesConnectionDeadline(t *testing.T) {
	state := &sqlDriverState{}
	adapter, err := NewMySQLFactory(&fakeSQLOpener{db: newTestSQLDB(t, state)}, staticCatalog{}).Open(context.Background(), adapterTestConfig(MySQLFamily))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()

	deadline := time.Now().Add(100 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := adapter.Ping(ctx); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if state.pingDeadline.After(deadline.Add(10 * time.Millisecond)) {
		t.Fatalf("ping deadline = %v, exceeds caller deadline %v", state.pingDeadline, deadline)
	}
}

func TestAdapterQueryMetricSelectsFamilyTemplateAndUsesQueryDeadline(t *testing.T) {
	template := MetricTemplate{ID: "db.connections", Statement: "SELECT value FROM metrics", MaxRows: 2, ValueColumns: []string{"value"}}
	catalog := staticCatalog{templates: map[EngineFamily]map[string]MetricTemplate{
		PostgresFamily: {template.ID: template},
	}}
	state := &sqlDriverState{columns: []string{"value"}, rows: [][]driver.Value{{int64(9)}}}
	adapter, err := NewPostgresFactory(&fakeSQLOpener{db: newTestSQLDB(t, state)}, catalog).Open(context.Background(), adapterTestConfig(PostgresFamily))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()

	deadline := time.Now().Add(100 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	got, err := adapter.QueryMetric(ctx, template.ID, map[string]any{"tenant": "blue"})
	if err != nil {
		t.Fatalf("QueryMetric() error = %v", err)
	}
	if len(got) != 1 || got[0]["value"] != 9 {
		t.Fatalf("QueryMetric() = %#v, want one row with value 9", got)
	}
	if got, want := state.statement, template.Statement; got != want {
		t.Fatalf("query statement = %q, want template statement %q", got, want)
	}
	if state.queryDeadline.After(deadline.Add(10 * time.Millisecond)) {
		t.Fatalf("query deadline = %v, exceeds caller deadline %v", state.queryDeadline, deadline)
	}
}

func TestMySQLFactoryRequiresExplicitMySQLProtocolFamily(t *testing.T) {
	for _, family := range []EngineFamily{MariaDBFamily, TiDBFamily, OceanBaseFamily} {
		t.Run(string(family), func(t *testing.T) {
			state := &sqlDriverState{}
			adapter, err := NewMySQLFactory(&fakeSQLOpener{db: newTestSQLDB(t, state)}, staticCatalog{}).Open(context.Background(), adapterTestConfig(family))
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer adapter.Close()
			if got := adapter.Family(); got != family {
				t.Fatalf("Family() = %q, want explicitly selected family %q", got, family)
			}
		})
	}

	if _, err := NewMySQLFactory(&fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}).Open(context.Background(), adapterTestConfig(PostgresFamily)); err == nil {
		t.Fatal("Open() error = nil, want PostgreSQL family rejected by MySQL factory")
	}
}

func TestPostgresFactoryRequiresExplicitPostgresProtocolFamily(t *testing.T) {
	state := &sqlDriverState{}
	adapter, err := NewPostgresFactory(&fakeSQLOpener{db: newTestSQLDB(t, state)}, staticCatalog{}).Open(context.Background(), adapterTestConfig(OpenGaussFamily))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()
	if got := adapter.Family(); got != OpenGaussFamily {
		t.Fatalf("Family() = %q, want explicitly selected family %q", got, OpenGaussFamily)
	}

	if _, err := NewPostgresFactory(&fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}).Open(context.Background(), adapterTestConfig(MySQLFamily)); err == nil {
		t.Fatal("Open() error = nil, want MySQL family rejected by PostgreSQL factory")
	}
}

func TestAdapterCapabilitiesDifferByProtocol(t *testing.T) {
	mysql := NewMySQLFactory(&fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}).Capabilities()
	postgres := NewPostgresFactory(&fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}).Capabilities()
	if !mysql.ReadOnlySQL || !mysql.Metrics || mysql.Transactions {
		t.Fatalf("MySQL capabilities = %#v, want read-only metrics without transaction access", mysql)
	}
	if !postgres.ReadOnlySQL || !postgres.Metrics || !postgres.Transactions {
		t.Fatalf("Postgres capabilities = %#v, want read-only metrics with transaction capability", postgres)
	}
}

func TestAdapterCloseIsIdempotent(t *testing.T) {
	state := &sqlDriverState{}
	adapter, err := NewMySQLFactory(&fakeSQLOpener{db: newTestSQLDB(t, state)}, staticCatalog{}).Open(context.Background(), adapterTestConfig(MySQLFamily))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if got, want := state.closeCalls, 1; got != want {
		t.Fatalf("driver Close calls = %d, want %d", got, want)
	}
}

func adapterTestConfig(family EngineFamily) InstanceConfig {
	return InstanceConfig{
		ID:             "db-primary",
		Family:         family,
		Address:        "mysql://db.example.test:3306",
		Database:       "app",
		User:           "readonly",
		SecretRef:      "secret://runtime/db-primary",
		ConnectTimeout: 5 * time.Second,
		QueryTimeout:   15 * time.Second,
	}
}

type fakeSQLOpener struct {
	db         *sql.DB
	err        error
	driverName string
	dsn        string
}

func (opener *fakeSQLOpener) Open(driverName, dsn string) (*sql.DB, error) {
	opener.driverName = driverName
	opener.dsn = dsn
	return opener.db, opener.err
}

const testSQLDriverName = "dbpilot-database-adapter-test"

var (
	testSQLDriverOnce sync.Once
	testSQLDriverMu   sync.Mutex
	testSQLDriverNext uint64
	testSQLDriverDBs  = map[string]*sqlDriverState{}
)

func newTestSQLDB(t *testing.T, state *sqlDriverState) *sql.DB {
	t.Helper()
	testSQLDriverOnce.Do(func() { sql.Register(testSQLDriverName, testSQLDriver{}) })
	testSQLDriverMu.Lock()
	testSQLDriverNext++
	dsn := fmt.Sprintf("%d", testSQLDriverNext)
	testSQLDriverDBs[dsn] = state
	testSQLDriverMu.Unlock()
	db, err := sql.Open(testSQLDriverName, dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		testSQLDriverMu.Lock()
		delete(testSQLDriverDBs, dsn)
		testSQLDriverMu.Unlock()
	})
	return db
}

type testSQLDriver struct{}

func (testSQLDriver) Open(dsn string) (driver.Conn, error) {
	testSQLDriverMu.Lock()
	state := testSQLDriverDBs[dsn]
	testSQLDriverMu.Unlock()
	if state == nil {
		return nil, errors.New("unknown test SQL database")
	}
	return &testSQLConn{state: state}, nil
}

type sqlDriverState struct {
	mu            sync.Mutex
	pingDeadline  time.Time
	queryDeadline time.Time
	statement     string
	columns       []string
	rows          [][]driver.Value
	closeCalls    int
}

type testSQLConn struct{ state *sqlDriverState }

func (*testSQLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("Prepare must not be used")
}
func (*testSQLConn) Begin() (driver.Tx, error) { return nil, errors.New("Begin must not be used") }
func (conn *testSQLConn) Close() error {
	conn.state.mu.Lock()
	conn.state.closeCalls++
	conn.state.mu.Unlock()
	return nil
}
func (conn *testSQLConn) Ping(ctx context.Context) error {
	conn.state.mu.Lock()
	conn.state.pingDeadline, _ = ctx.Deadline()
	conn.state.mu.Unlock()
	return nil
}
func (conn *testSQLConn) QueryContext(ctx context.Context, statement string, _ []driver.NamedValue) (driver.Rows, error) {
	conn.state.mu.Lock()
	conn.state.queryDeadline, _ = ctx.Deadline()
	conn.state.statement = statement
	columns := append([]string(nil), conn.state.columns...)
	rows := append([][]driver.Value(nil), conn.state.rows...)
	conn.state.mu.Unlock()
	return &testSQLRows{columns: columns, rows: rows}, nil
}

var _ driver.Pinger = (*testSQLConn)(nil)
var _ driver.QueryerContext = (*testSQLConn)(nil)

type testSQLRows struct {
	columns []string
	rows    [][]driver.Value
	index   int
}

func (rows *testSQLRows) Columns() []string { return rows.columns }
func (*testSQLRows) Close() error           { return nil }
func (rows *testSQLRows) Next(dest []driver.Value) error {
	if rows.index == len(rows.rows) {
		return io.EOF
	}
	copy(dest, rows.rows[rows.index])
	rows.index++
	return nil
}
