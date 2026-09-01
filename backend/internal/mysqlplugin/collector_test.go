package mysqlplugin

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestCollectorEmitsFiveCanonicalMetricsWithTypesUnitsAndTimestamp(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	runtime, mock, cleanup := runtimeWithSQLMock(t, "mysql-a")
	defer cleanup()
	mock.ExpectPing()
	mock.ExpectQuery("SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status").WillReturnRows(sqlmock.NewRows([]string{"VARIABLE_NAME", "VARIABLE_VALUE"}).AddRows(
		[]driver.Value{"Threads_connected", "12"}, []driver.Value{"Questions", "999"}, []driver.Value{"Threads_running", "3"}, []driver.Value{"Uptime", "3600"},
	))
	collector := NewCollector(runtime, CollectorOptions{Now: func() time.Time { return now }, MaxConcurrent: 4})

	batch := collector.Collect(context.Background(), "mysql-a", SortedBuiltinTemplateIDs(BuiltinCatalog()))
	require.Equal(t, CollectionSucceeded, batch.Status)
	require.Len(t, batch.Samples, 5)
	byName := sampleMap(batch.Samples)
	require.Equal(t, float64(1), byName["mysql.up"].Value)
	require.Equal(t, "1", byName["mysql.connections.current"].Unit)
	require.Equal(t, "{query}", byName["mysql.queries.total"].Unit)
	require.Equal(t, "s", byName["mysql.uptime.seconds"].Unit)
	require.Equal(t, now.Add(-time.Hour), byName["mysql.queries.total"].StartTime)
	for _, sample := range batch.Samples {
		require.Equal(t, now, sample.SampledAt)
	}
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCollectorDetectsCounterResetWithoutProducingNegativeDelta(t *testing.T) {
	runtime, mock, cleanup := runtimeWithSQLMock(t, "mysql-a")
	defer cleanup()
	current := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for _, queries := range []string{"100", "3"} {
		mock.ExpectPing()
		mock.ExpectQuery("SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status").WillReturnRows(sqlmock.NewRows([]string{"VARIABLE_NAME", "VARIABLE_VALUE"}).AddRow("Threads_connected", "1").AddRow("Questions", queries).AddRow("Threads_running", "1").AddRow("Uptime", "5"))
	}
	collector := NewCollector(runtime, CollectorOptions{MaxConcurrent: 1, Now: func() time.Time { return current }})
	first := collector.Collect(context.Background(), "mysql-a", []string{"mysql.queries.total"})
	current = current.Add(time.Second)
	second := collector.Collect(context.Background(), "mysql-a", []string{"mysql.queries.total"})
	require.False(t, first.Samples[0].CounterReset)
	require.Equal(t, current.Add(-6*time.Second), first.Samples[0].StartTime)
	require.True(t, second.Samples[0].CounterReset)
	require.Equal(t, float64(3), second.Samples[0].Value)
	require.Equal(t, current, second.Samples[0].StartTime)
}

func TestCollectorTreatsUptimeDropAsResetEvenWhenQuestionsIncreases(t *testing.T) {
	runtime, mock, cleanup := runtimeWithSQLMock(t, "mysql-a")
	defer cleanup()
	for _, row := range []struct{ questions, uptime string }{{"100", "100"}, {"1000", "2"}} {
		mock.ExpectPing()
		mock.ExpectQuery("SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status").WillReturnRows(sqlmock.NewRows([]string{"VARIABLE_NAME", "VARIABLE_VALUE"}).AddRow("Questions", row.questions).AddRow("Uptime", row.uptime))
	}
	current := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	collector := NewCollector(runtime, CollectorOptions{Now: func() time.Time { return current }})
	first := collector.Collect(context.Background(), "mysql-a", []string{"mysql.queries.total"})
	current = current.Add(time.Second)
	second := collector.Collect(context.Background(), "mysql-a", []string{"mysql.queries.total"})
	require.False(t, first.Samples[0].CounterReset)
	require.True(t, second.Samples[0].CounterReset)
	require.Equal(t, current.Add(-2*time.Second), second.Samples[0].StartTime)
}

func TestCollectorFailureAndCircuitAreIsolatedPerInstance(t *testing.T) {
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 1}, map[string]InstanceRuntime{
		"mysql-a": {Config: fixtureDecodedInstance("mysql-a", "one"), Pool: &fakePool{pingErr: errors.New("down")}},
		"mysql-b": {Config: fixtureDecodedInstance("mysql-b", "two"), Pool: &statusPool{}},
	})
	collector := NewCollector(runtime, CollectorOptions{FailureThreshold: 1, CircuitOpenFor: time.Minute, MaxConcurrent: 1})
	failed := collector.Collect(context.Background(), "mysql-a", []string{"mysql.up"})
	require.Equal(t, CollectionFailed, failed.Status)
	require.Len(t, failed.Samples, 1)
	up, exists := sampleMap(failed.Samples)["mysql.up"]
	require.True(t, exists)
	require.Equal(t, float64(0), up.Value)
	require.Equal(t, "connection_unavailable", collector.Collect(context.Background(), "mysql-a", []string{"mysql.up"}).ErrorCode)
	require.Equal(t, CollectionSucceeded, collector.Collect(context.Background(), "mysql-b", []string{"mysql.up"}).Status)
}

func TestCollectorKeepsMySQLUpContinuousAcrossCredentialCircuitAndStatusFailures(t *testing.T) {
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 1}, map[string]InstanceRuntime{"waiting": {Config: fixtureDecodedInstance("waiting", ""), Pool: nil}, "status-fails": {Config: fixtureDecodedInstance("status-fails", "monitor"), Pool: &queryFailurePool{}}})
	collector := NewCollector(runtime, CollectorOptions{FailureThreshold: 1})
	waiting := collector.Collect(context.Background(), "waiting", []string{"mysql.up"})
	require.Equal(t, CollectionFailed, waiting.Status)
	require.Len(t, waiting.Samples, 1)
	require.Zero(t, waiting.Samples[0].Value)
	require.Equal(t, "waiting_credentials", waiting.ErrorCode)
	status := collector.Collect(context.Background(), "status-fails", []string{"mysql.up", "mysql.connections.current"})
	require.Equal(t, CollectionPartial, status.Status)
	require.Len(t, status.Samples, 1)
	require.Equal(t, float64(1), status.Samples[0].Value)
	require.Equal(t, "query_failed", status.ErrorCode)
}

type queryFailurePool struct{}

func (*queryFailurePool) PingContext(context.Context) error { return nil }
func (*queryFailurePool) QueryContext(context.Context, string, ...any) (Rows, error) {
	return nil, errors.New("raw driver detail must not escape")
}
func (*queryFailurePool) Close() error { return nil }

func TestCollectorRejectsUnknownOrEmptyTemplatesAndNormalizesStatusNames(t *testing.T) {
	runtime, mock, cleanup := runtimeWithSQLMock(t, "mysql-a")
	defer cleanup()
	collector := NewCollector(runtime, CollectorOptions{})
	require.Equal(t, CollectionFailed, collector.Collect(context.Background(), "mysql-a", nil).Status)
	require.Equal(t, CollectionFailed, collector.Collect(context.Background(), "mysql-a", []string{"mysql.unknown"}).Status)
	mock.ExpectPing()
	mock.ExpectQuery("SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status").WillReturnRows(sqlmock.NewRows([]string{"VARIABLE_NAME", "VARIABLE_VALUE"}).AddRow("threads_connected", "4"))
	batch := collector.Collect(context.Background(), "mysql-a", []string{"mysql.connections.current"})
	require.Equal(t, CollectionSucceeded, batch.Status)
	require.Equal(t, float64(4), batch.Samples[0].Value)
}

func TestCustomCollectorRejectsDuplicateColumnsUnsafeLabelsAndMetricSeriesCardinality(t *testing.T) {
	tests := []struct {
		name     string
		pool     Pool
		template TemplateConfig
		code     string
	}{
		{name: "duplicate columns", pool: &customRowsPool{columns: []string{"value", "value"}, values: [][]any{{[]byte("1"), []byte("2")}}}, template: customTemplate(10), code: "result_rejected"},
		{name: "control label", pool: &customRowsPool{columns: []string{"value", "role_name"}, values: [][]any{{[]byte("1"), []byte("bad\nrole")}}}, template: customTemplate(10), code: "result_rejected"},
		{name: "metric series cardinality", pool: &customRowsPool{columns: []string{"value", "role_name"}, values: [][]any{{[]byte("1"), []byte("primary")}}}, template: func() TemplateConfig {
			value := customTemplate(1)
			value.ValueMappings = append(value.ValueMappings, &pluginv1.MetricValueMapping{SourceColumn: "value", MetricName: "mysql.custom.other", MetricType: "gauge", Unit: "1"})
			return value
		}(), code: "cardinality_limit_exceeded"},
		{name: "non finite numeric", pool: &customRowsPool{columns: []string{"value", "role_name"}, values: [][]any{{[]byte("NaN"), []byte("primary")}}}, template: customTemplate(10), code: "result_rejected"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
			runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 1}, map[string]InstanceRuntime{"mysql-a": {Config: fixtureDecodedInstance("mysql-a", "monitor"), Pool: test.pool}})
			batch := NewCollector(runtime, CollectorOptions{}).CollectTemplate(context.Background(), "mysql-a", test.template)
			require.Equal(t, CollectionFailed, batch.Status)
			require.Equal(t, test.code, batch.ErrorCode)
		})
	}
}

func customTemplate(cardinality uint32) TemplateConfig {
	return TemplateConfig{ID: "custom-a", Revision: 1, Statement: "SELECT 1 AS value", Timeout: time.Second, MaxRows: 10, MaxColumns: 4, Cardinality: cardinality, ValueMappings: []*pluginv1.MetricValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: "gauge", Unit: "1"}}, LabelMappings: []*pluginv1.MetricLabelMapping{{SourceColumn: "role_name", Label: "role"}}}
}

type customRowsPool struct {
	columns []string
	values  [][]any
}

func (*customRowsPool) PingContext(context.Context) error { return nil }
func (pool *customRowsPool) QueryContext(context.Context, string, ...any) (Rows, error) {
	return &customRows{columns: pool.columns, values: pool.values}, nil
}
func (*customRowsPool) Close() error { return nil }

type customRows struct {
	columns []string
	values  [][]any
	index   int
}

func (rows *customRows) Next() bool { return rows.index < len(rows.values) }
func (rows *customRows) Scan(dest ...any) error {
	for i, value := range rows.values[rows.index] {
		*(dest[i].(*any)) = value
	}
	rows.index++
	return nil
}
func (rows *customRows) Columns() ([]string, error) {
	return append([]string(nil), rows.columns...), nil
}
func (*customRows) Err() error   { return nil }
func (*customRows) Close() error { return nil }

func runtimeWithSQLMock(t *testing.T, id string) (*Runtime, sqlmock.Sqlmock, func()) {
	t.Helper()
	database, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 1}, map[string]InstanceRuntime{id: {Config: fixtureDecodedInstance(id, "monitor"), Pool: SQLPool{DB: database}}})
	return runtime, mock, func() { _ = database.Close() }
}

type statusPool struct{}

func (*statusPool) PingContext(context.Context) error { return nil }
func (*statusPool) QueryContext(context.Context, string, ...any) (Rows, error) {
	return &staticRows{rows: [][]string{{"Threads_connected", "1"}, {"Questions", "1"}, {"Threads_running", "1"}, {"Uptime", "1"}}}, nil
}
func (*statusPool) Close() error { return nil }

type staticRows struct {
	rows  [][]string
	index int
}

func (rows *staticRows) Next() bool { return rows.index < len(rows.rows) }
func (rows *staticRows) Scan(dest ...any) error {
	current := rows.rows[rows.index]
	rows.index++
	*(dest[0].(*string)) = current[0]
	*(dest[1].(*string)) = current[1]
	return nil
}
func (*staticRows) Columns() ([]string, error) {
	return []string{"VARIABLE_NAME", "VARIABLE_VALUE"}, nil
}
func (*staticRows) Err() error   { return nil }
func (*staticRows) Close() error { return nil }

func sampleMap(samples []Sample) map[string]Sample {
	result := map[string]Sample{}
	for _, sample := range samples {
		result[sample.Name] = sample
	}
	return result
}
