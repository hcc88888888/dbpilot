package database

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

func TestDatabaseAdaptersIntegration(t *testing.T) {
	if os.Getenv("DBPILOT_DB_INTEGRATION") != "1" {
		t.Skip("database adapter integration tests require DBPILOT_DB_INTEGRATION=1 and the Docker Compose services")
	}

	testCases := []integrationDatabaseCase{
		{
			name:              "mysql",
			family:            MySQLFamily,
			factory:           NewMySQLFactory(SQLDriverOpener{}, integrationTemplateCatalog(MySQLFamily, "SELECT SLEEP(2) AS value")),
			driver:            mysqlDriverName,
			addressVariable:   "DBPILOT_MYSQL_ADDRESS",
			databaseVariable:  "DBPILOT_MYSQL_DATABASE",
			userVariable:      "DBPILOT_MYSQL_USER",
			secretRef:         "secret://integration/mysql",
			adminUserVariable: "DBPILOT_MYSQL_ADMIN_USER",
			adminSecretRef:    "secret://integration/mysql-admin",
			timeoutStatement:  "SELECT SLEEP(2) AS value",
		},
		{
			name:              "postgres",
			family:            PostgresFamily,
			factory:           NewPostgresFactory(SQLDriverOpener{}, integrationTemplateCatalog(PostgresFamily, "SELECT pg_sleep(2)::float8 AS value")),
			driver:            postgresDriverName,
			addressVariable:   "DBPILOT_POSTGRES_ADDRESS",
			databaseVariable:  "DBPILOT_POSTGRES_DATABASE",
			userVariable:      "DBPILOT_POSTGRES_USER",
			secretRef:         "secret://integration/postgres",
			adminUserVariable: "DBPILOT_POSTGRES_ADMIN_USER",
			adminSecretRef:    "secret://integration/postgres-admin",
			timeoutStatement:  "SELECT pg_sleep(2)::float8 AS value",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			config := InstanceConfig{
				ID:             "integration-" + testCase.name,
				Family:         testCase.family,
				Address:        integrationEnvironment(t, testCase.addressVariable),
				Database:       integrationEnvironment(t, testCase.databaseVariable),
				User:           integrationEnvironment(t, testCase.userVariable),
				SecretRef:      testCase.secretRef,
				ConnectTimeout: 5 * time.Second,
				QueryTimeout:   500 * time.Millisecond,
			}
			setupIntegrationMetricFixture(t, testCase, config)

			adapter, err := testCase.factory.Open(context.Background(), config)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			t.Cleanup(func() {
				if closeErr := adapter.Close(); closeErr != nil {
					t.Errorf("Close() error = %v", closeErr)
				}
			})

			rows, err := adapter.QueryMetric(context.Background(), "integration.value", nil)
			if err != nil {
				t.Fatalf("QueryMetric(integration.value) error = %v", err)
			}
			if len(rows) != 1 || rows[0]["value"] != 42 {
				t.Fatalf("QueryMetric(integration.value) = %#v, want one row with value 42", rows)
			}

			if _, err := adapter.QueryMetric(context.Background(), "integration.unsafe", nil); !errors.Is(err, ErrUnsafeReadOnlyStatement) {
				t.Fatalf("QueryMetric(integration.unsafe) error = %v, want ErrUnsafeReadOnlyStatement", err)
			}

			deadline, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			started := time.Now()
			if _, err := adapter.QueryMetric(deadline, "integration.timeout", nil); err == nil {
				t.Fatal("QueryMetric(integration.timeout) error = nil, want timeout")
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("QueryMetric(integration.timeout) exceeded bounded deadline: %s", elapsed)
			}
		})
	}
}

type integrationDatabaseCase struct {
	name              string
	family            EngineFamily
	factory           Factory
	driver            string
	addressVariable   string
	databaseVariable  string
	userVariable      string
	secretRef         string
	adminUserVariable string
	adminSecretRef    string
	timeoutStatement  string
}

func integrationTemplateCatalog(family EngineFamily, timeoutStatement string) TemplateCatalog {
	return staticCatalog{templates: map[EngineFamily]map[string]MetricTemplate{
		family: {
			"integration.value": {
				ID:           "integration.value",
				Statement:    "SELECT value FROM integration_metric_fixture",
				MaxRows:      1,
				ValueColumns: []string{"value"},
			},
			"integration.unsafe": {
				ID:           "integration.unsafe",
				Statement:    "DELETE FROM integration_metric_fixture",
				MaxRows:      1,
				ValueColumns: []string{"value"},
			},
			"integration.timeout": {
				ID:           "integration.timeout",
				Statement:    timeoutStatement,
				MaxRows:      1,
				ValueColumns: []string{"value"},
			},
		},
	}}
}

func setupIntegrationMetricFixture(t *testing.T, testCase integrationDatabaseCase, readerConfig InstanceConfig) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	adminConfig := readerConfig
	adminConfig.User = integrationEnvironment(t, testCase.adminUserVariable)
	adminConfig.SecretRef = testCase.adminSecretRef
	adminDatabase := openIntegrationDatabase(t, ctx, testCase.driver, adminConfig)
	t.Cleanup(func() { _ = adminDatabase.Close() })
	if _, err := adminDatabase.ExecContext(ctx, "DROP TABLE IF EXISTS integration_metric_fixture"); err != nil {
		t.Fatalf("drop integration metric fixture: %v", err)
	}
	if _, err := adminDatabase.ExecContext(ctx, "CREATE TABLE integration_metric_fixture (value BIGINT NOT NULL)"); err != nil {
		t.Fatalf("create integration metric fixture: %v", err)
	}
	grantStatement := "GRANT SELECT ON TABLE integration_metric_fixture TO dbpilot_reader"
	if testCase.family == MySQLFamily {
		grantStatement = "GRANT SELECT ON dbpilot_integration.integration_metric_fixture TO 'dbpilot_reader'@'%'"
	}
	if _, err := adminDatabase.ExecContext(ctx, grantStatement); err != nil {
		t.Fatalf("grant SELECT on integration metric fixture: %v", err)
	}
	if _, err := adminDatabase.ExecContext(ctx, "INSERT INTO integration_metric_fixture (value) VALUES (42)"); err != nil {
		t.Fatalf("insert integration metric fixture: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, err := adminDatabase.ExecContext(cleanupContext, "DROP TABLE IF EXISTS integration_metric_fixture"); err != nil {
			t.Errorf("drop integration metric fixture during cleanup: %v", err)
		}
	})

	readerDatabase := openIntegrationDatabase(t, ctx, testCase.driver, readerConfig)
	t.Cleanup(func() { _ = readerDatabase.Close() })
	if _, err := readerDatabase.ExecContext(ctx, "DELETE FROM integration_metric_fixture"); err == nil {
		t.Fatal("reader account deleted integration metric fixture, want SELECT-only permissions")
	}
}

func openIntegrationDatabase(t *testing.T, ctx context.Context, driver string, config InstanceConfig) *sql.DB {
	t.Helper()
	password, err := EnvironmentSecretResolver{}.ResolveSecret(ctx, config.SecretRef)
	if err != nil {
		t.Fatalf("resolve runtime secret %q: %v", config.SecretRef, err)
	}
	var dataSourceName string
	switch config.Family {
	case MySQLFamily:
		dataSourceName, err = mysqlDSN(config, password)
	case PostgresFamily:
		dataSourceName, err = postgresDSN(config, password)
	default:
		t.Fatalf("unsupported integration fixture family %q", config.Family)
	}
	if err != nil {
		t.Fatalf("build %s fixture DSN: %v", config.Family, err)
	}
	database, err := sql.Open(driver, dataSourceName)
	if err != nil {
		t.Fatalf("open %s fixture database: %v", config.Family, err)
	}
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		t.Fatalf("ping %s fixture database: %v", config.Family, err)
	}
	return database
}

func integrationEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required when DBPILOT_DB_INTEGRATION=1", name)
	}
	return value
}
