package database

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"database/sql/driver"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
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

	adapter, err := mysqlFactoryForTest(opener, staticCatalog{}).Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()

	if got, want := opener.driverName, "mysql"; got != want {
		t.Fatalf("driver name = %q, want fixed %q", got, want)
	}
	if got, want := opener.dsn, "readonly:runtime-password@tcp(db.example.test:3306)/app%20data?readTimeout=15s&timeout=5s&tls=custom&writeTimeout=15s"; got != want {
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

	adapter, err := postgresFactoryForTest(opener, staticCatalog{}).Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()

	if got, want := opener.driverName, "postgres"; got != want {
		t.Fatalf("driver name = %q, want fixed %q", got, want)
	}
	if got, want := opener.dsn, "postgres://readonly:runtime-password@db.example.test:5432/app%20data?connect_timeout=5&sslmode=verify-full&statement_timeout=15000"; got != want {
		t.Fatalf("DSN = %q, want %q", got, want)
	}
	if got := adapter.Family(); got != PostgresFamily {
		t.Fatalf("Family() = %q, want %q", got, PostgresFamily)
	}
}

func TestAdapterPingUsesConnectionDeadline(t *testing.T) {
	state := &sqlDriverState{}
	adapter, err := mysqlFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, state)}, staticCatalog{}).Open(context.Background(), adapterTestConfig(MySQLFamily))
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
	adapter, err := postgresFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, state)}, catalog).Open(context.Background(), adapterTestConfig(PostgresFamily))
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
			adapter, err := mysqlFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, state)}, staticCatalog{}).Open(context.Background(), adapterTestConfig(family))
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer adapter.Close()
			if got := adapter.Family(); got != family {
				t.Fatalf("Family() = %q, want explicitly selected family %q", got, family)
			}
		})
	}

	if _, err := mysqlFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}).Open(context.Background(), adapterTestConfig(PostgresFamily)); err == nil {
		t.Fatal("Open() error = nil, want PostgreSQL family rejected by MySQL factory")
	}
}

func TestPostgresFactoryRequiresExplicitPostgresProtocolFamily(t *testing.T) {
	state := &sqlDriverState{}
	adapter, err := postgresFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, state)}, staticCatalog{}).Open(context.Background(), adapterTestConfig(OpenGaussFamily))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()
	if got := adapter.Family(); got != OpenGaussFamily {
		t.Fatalf("Family() = %q, want explicitly selected family %q", got, OpenGaussFamily)
	}

	if _, err := postgresFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}).Open(context.Background(), adapterTestConfig(MySQLFamily)); err == nil {
		t.Fatal("Open() error = nil, want MySQL family rejected by PostgreSQL factory")
	}
}

func TestAdapterCapabilitiesDifferByProtocol(t *testing.T) {
	mysql := mysqlFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}).Capabilities()
	postgres := postgresFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}).Capabilities()
	if !mysql.ReadOnlySQL || !mysql.Metrics || mysql.Transactions {
		t.Fatalf("MySQL capabilities = %#v, want read-only metrics without transaction access", mysql)
	}
	if !postgres.ReadOnlySQL || !postgres.Metrics || !postgres.Transactions {
		t.Fatalf("Postgres capabilities = %#v, want read-only metrics with transaction capability", postgres)
	}
}

func TestAdapterCloseIsIdempotent(t *testing.T) {
	state := &sqlDriverState{}
	adapter, err := mysqlFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, state)}, staticCatalog{}).Open(context.Background(), adapterTestConfig(MySQLFamily))
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

func TestMySQLFactoryResolvesRuntimeCredentialsAndTLSWithoutLeakingReferences(t *testing.T) {
	caPEM, certificatePEM, keyPEM := testTLSMaterial(t)
	resolver := &fakeSecretResolver{secrets: map[string][]byte{
		"secret://runtime/db-primary":  []byte("password with spaces"),
		"secret://runtime/database-ca": caPEM,
		"secret://runtime/client-cert": certificatePEM,
		"secret://runtime/client-key":  keyPEM,
	}}
	state := &sqlDriverState{}
	opener := &fakeSQLOpener{db: newTestSQLDB(t, state)}
	config := adapterTestConfig(MySQLFamily)
	config.TLS = TLSConfig{
		Enabled:              true,
		ServerName:           "db.internal.test",
		CASecretRef:          "secret://runtime/database-ca",
		CertificateSecretRef: "secret://runtime/client-cert",
		KeySecretRef:         "secret://runtime/client-key",
	}

	adapter, err := NewMySQLFactoryWithRuntime(opener, staticCatalog{}, resolver).Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()

	if got, want := resolver.references, []string{"secret://runtime/db-primary", "secret://runtime/database-ca", "secret://runtime/client-cert", "secret://runtime/client-key"}; !slices.Equal(got, want) {
		t.Fatalf("resolved references = %q, want %q", got, want)
	}
	if !strings.Contains(opener.dsn, "password+with+spaces") {
		t.Fatalf("DSN does not contain the resolved password: %q", opener.dsn)
	}
	if strings.Contains(opener.dsn, config.SecretRef) || strings.Contains(opener.dsn, config.TLS.CASecretRef) || strings.Contains(opener.dsn, config.TLS.CertificateSecretRef) || strings.Contains(opener.dsn, config.TLS.KeySecretRef) {
		t.Fatalf("DSN leaked a secret reference: %q", opener.dsn)
	}
	if opener.tlsConfig == nil || opener.tlsConfig.ServerName != "db.internal.test" || opener.tlsConfig.RootCAs == nil || len(opener.tlsConfig.Certificates) != 1 {
		t.Fatalf("TLS config = %#v, want server name, CA pool, and client certificate", opener.tlsConfig)
	}
}

func TestFactoryRejectsTLSWhenOpenerCannotApplyIt(t *testing.T) {
	config := adapterTestConfig(PostgresFamily)
	config.TLS = TLSConfig{Enabled: true, ServerName: "db.internal.test"}
	resolver := &fakeSecretResolver{secrets: map[string][]byte{config.SecretRef: []byte("password")}}
	opener := basicSQLOpener{delegate: &fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}}

	_, err := NewPostgresFactoryWithRuntime(opener, staticCatalog{}, resolver).Open(context.Background(), config)
	if err == nil {
		t.Fatal("Open() error = nil, want TLS mapping rejection")
	}
	if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), config.SecretRef) {
		t.Fatalf("Open() error leaked a secret: %v", err)
	}
}

func TestPublicFactoryUsesEnvironmentRuntimeSecretResolver(t *testing.T) {
	t.Setenv("DBPILOT_SECRET_RUNTIME_DB_PRIMARY", "environment-password")
	opener := &fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}

	adapter, err := NewMySQLFactory(opener, staticCatalog{}).Open(context.Background(), adapterTestConfig(MySQLFamily))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()
	if !strings.Contains(opener.dsn, "environment-password") {
		t.Fatalf("DSN does not use the environment-resolved password: %q", opener.dsn)
	}
}

func TestFactorySanitizesOpenerErrors(t *testing.T) {
	const secret = "never-return-this-password"
	opener := failingSQLOpener{err: errors.New("driver rejected DSN containing " + secret)}
	_, err := NewMySQLFactoryWithRuntime(opener, staticCatalog{}, StaticSecretResolver{
		"secret://runtime/db-primary": []byte(secret),
	}).Open(context.Background(), adapterTestConfig(MySQLFamily))
	if err == nil {
		t.Fatal("Open() error = nil, want opener failure")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "DSN") {
		t.Fatalf("Open() leaked driver details: %v", err)
	}
}

func TestFactoryBoundsOpenAndTLSOpenWithConnectionDeadline(t *testing.T) {
	for _, test := range []struct {
		name string
		tls  bool
	}{
		{name: "open without TLS"},
		{name: "open with TLS", tls: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			opener := &blockingSQLOpener{}
			config := adapterTestConfig(MySQLFamily)
			config.ConnectTimeout = 20 * time.Millisecond
			config.TLS.Enabled = test.tls
			_, err := NewMySQLFactoryWithRuntime(opener, staticCatalog{}, StaticSecretResolver{
				config.SecretRef: []byte("runtime-password"),
			}).Open(context.Background(), config)
			if err == nil {
				t.Fatal("Open() error = nil, want bounded opener timeout")
			}
			if !opener.contextCancelled {
				t.Fatal("opener context was not cancelled at the connection deadline")
			}
			if test.tls != opener.usedTLS {
				t.Fatalf("OpenWithTLS used = %t, want %t", opener.usedTLS, test.tls)
			}
		})
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

func mysqlFactoryForTest(opener SQLOpener, catalog TemplateCatalog) Factory {
	return NewMySQLFactoryWithRuntime(opener, catalog, adapterTestResolver())
}

func postgresFactoryForTest(opener SQLOpener, catalog TemplateCatalog) Factory {
	return NewPostgresFactoryWithRuntime(opener, catalog, adapterTestResolver())
}

func adapterTestResolver() SecretResolver {
	return &fakeSecretResolver{secrets: map[string][]byte{"secret://runtime/db-primary": []byte("runtime-password")}}
}

type fakeSecretResolver struct {
	secrets    map[string][]byte
	references []string
}

func (resolver *fakeSecretResolver) ResolveSecret(_ context.Context, reference string) ([]byte, error) {
	resolver.references = append(resolver.references, reference)
	secret, ok := resolver.secrets[reference]
	if !ok {
		return nil, errors.New("secret was not found")
	}
	return append([]byte(nil), secret...), nil
}

func testTLSMaterial(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	now := time.Now()
	certificate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "database-test-ca"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificate, certificate, publicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certificatePEM, certificatePEM, keyPEM
}

type fakeSQLOpener struct {
	db         *sql.DB
	err        error
	driverName string
	dsn        string
	tlsConfig  *tls.Config
}

func (opener *fakeSQLOpener) OpenWithTLS(_ context.Context, driverName, dsn string, config *tls.Config) (*sql.DB, error) {
	opener.driverName = driverName
	opener.dsn = dsn
	opener.tlsConfig = config.Clone()
	return opener.db, opener.err
}

type basicSQLOpener struct{ delegate *fakeSQLOpener }

func (opener basicSQLOpener) Open(ctx context.Context, driverName, dsn string) (*sql.DB, error) {
	return opener.delegate.Open(ctx, driverName, dsn)
}

type failingSQLOpener struct{ err error }

func (opener failingSQLOpener) Open(context.Context, string, string) (*sql.DB, error) {
	return nil, opener.err
}

type blockingSQLOpener struct {
	contextCancelled bool
	usedTLS          bool
}

func (opener *blockingSQLOpener) Open(ctx context.Context, _ string, _ string) (*sql.DB, error) {
	return opener.wait(ctx, false)
}

func (opener *blockingSQLOpener) OpenWithTLS(ctx context.Context, _ string, _ string, _ *tls.Config) (*sql.DB, error) {
	return opener.wait(ctx, true)
}

func (opener *blockingSQLOpener) wait(ctx context.Context, usedTLS bool) (*sql.DB, error) {
	<-ctx.Done()
	opener.contextCancelled = true
	opener.usedTLS = usedTLS
	return nil, ctx.Err()
}

func (opener *fakeSQLOpener) Open(_ context.Context, driverName, dsn string) (*sql.DB, error) {
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
