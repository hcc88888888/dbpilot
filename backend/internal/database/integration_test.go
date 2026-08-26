package database

import (
	"context"
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

	testCases := []struct {
		name             string
		family           EngineFamily
		factory          Factory
		addressVariable  string
		databaseVariable string
		userVariable     string
		secretRef        string
		timeoutStatement string
	}{
		{
			name:             "mysql",
			family:           MySQLFamily,
			factory:          NewMySQLFactory(SQLDriverOpener{}, integrationTemplateCatalog(MySQLFamily, "SELECT SLEEP(2) AS value")),
			addressVariable:  "DBPILOT_MYSQL_ADDRESS",
			databaseVariable: "DBPILOT_MYSQL_DATABASE",
			userVariable:     "DBPILOT_MYSQL_USER",
			secretRef:        "secret://integration/mysql",
			timeoutStatement: "SELECT SLEEP(2) AS value",
		},
		{
			name:             "postgres",
			family:           PostgresFamily,
			factory:          NewPostgresFactory(SQLDriverOpener{}, integrationTemplateCatalog(PostgresFamily, "SELECT pg_sleep(2)::float8 AS value")),
			addressVariable:  "DBPILOT_POSTGRES_ADDRESS",
			databaseVariable: "DBPILOT_POSTGRES_DATABASE",
			userVariable:     "DBPILOT_POSTGRES_USER",
			secretRef:        "secret://integration/postgres",
			timeoutStatement: "SELECT pg_sleep(2)::float8 AS value",
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
			if len(rows) != 1 || rows[0]["value"] != 1 {
				t.Fatalf("QueryMetric(integration.value) = %#v, want one row with value 1", rows)
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

func integrationTemplateCatalog(family EngineFamily, timeoutStatement string) TemplateCatalog {
	return staticCatalog{templates: map[EngineFamily]map[string]MetricTemplate{
		family: {
			"integration.value": {
				ID:           "integration.value",
				Statement:    "SELECT 1 AS value",
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

func integrationEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required when DBPILOT_DB_INTEGRATION=1", name)
	}
	return value
}
