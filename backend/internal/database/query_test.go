package database

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestReadOnlyRejectsUnknownMetricIDBeforeQuery(t *testing.T) {
	queryer := &recordingQueryer{}
	_, err := ExecuteReadOnly(context.Background(), queryer, MySQLFamily, staticCatalog{}, "unknown.metric", nil, 10)
	if !errors.Is(err, ErrUnknownMetricTemplate) {
		t.Fatalf("ExecuteReadOnly() error = %v, want ErrUnknownMetricTemplate", err)
	}
	if queryer.calls != 0 {
		t.Fatalf("query calls = %d, want 0", queryer.calls)
	}
}

func TestReadOnlyRejectsUnsafeCatalogStatementsBeforeQuery(t *testing.T) {
	for name, statement := range map[string]string{
		"semicolon":     "SELECT value FROM metrics;",
		"line comment":  "SELECT value -- diagnostic\nFROM metrics",
		"block comment": "/* diagnostic */ SELECT value FROM metrics",
		"write":         "WITH changed AS (DELETE FROM metrics RETURNING value) SELECT value FROM changed",
		"into":          "SELECT value INTO snapshot FROM metrics",
		"outfile":       "SELECT value INTO OUTFILE '/tmp/metrics' FROM metrics",
		"dumpfile":      "SELECT value INTO DUMPFILE '/tmp/metrics' FROM metrics",
	} {
		t.Run(name, func(t *testing.T) {
			queryer := &recordingQueryer{}
			catalog := staticCatalog{templates: map[EngineFamily]map[string]MetricTemplate{
				MySQLFamily: {"safe.metric": {ID: "safe.metric", Statement: statement, MaxRows: 2, ValueColumns: []string{"value"}}},
			}}
			_, err := ExecuteReadOnly(context.Background(), queryer, MySQLFamily, catalog, "safe.metric", nil, 2)
			if !errors.Is(err, ErrUnsafeReadOnlyStatement) {
				t.Fatalf("ExecuteReadOnly() error = %v, want ErrUnsafeReadOnlyStatement", err)
			}
			if queryer.calls != 0 {
				t.Fatalf("query calls = %d, want 0", queryer.calls)
			}
		})
	}
}

func TestReadOnlyBoundsRowsColumnsAndNumericValues(t *testing.T) {
	template := MetricTemplate{ID: "db.connections", Statement: "SELECT value FROM metrics", MaxRows: 2, ValueColumns: []string{"value"}}
	catalog := staticCatalog{templates: map[EngineFamily]map[string]MetricTemplate{MySQLFamily: {template.ID: template}}}

	t.Run("row limit", func(t *testing.T) {
		queryer := &recordingQueryer{rows: &fakeRows{columns: []string{"value"}, values: [][]any{{1}, {2}, {3}}}}
		_, err := ExecuteReadOnly(context.Background(), queryer, MySQLFamily, catalog, template.ID, nil, 10)
		if !errors.Is(err, ErrQueryResultBounds) {
			t.Fatalf("ExecuteReadOnly() error = %v, want ErrQueryResultBounds", err)
		}
	})

	t.Run("unexpected column", func(t *testing.T) {
		queryer := &recordingQueryer{rows: &fakeRows{columns: []string{"value", "extra"}, values: [][]any{{1, 2}}}}
		_, err := ExecuteReadOnly(context.Background(), queryer, MySQLFamily, catalog, template.ID, nil, 10)
		if !errors.Is(err, ErrQueryResultBounds) {
			t.Fatalf("ExecuteReadOnly() error = %v, want ErrQueryResultBounds", err)
		}
	})

	t.Run("non-numeric value", func(t *testing.T) {
		queryer := &recordingQueryer{rows: &fakeRows{columns: []string{"value"}, values: [][]any{{"not-a-number"}}}}
		_, err := ExecuteReadOnly(context.Background(), queryer, MySQLFamily, catalog, template.ID, nil, 10)
		if !errors.Is(err, ErrNonNumericMetricValue) {
			t.Fatalf("ExecuteReadOnly() error = %v, want ErrNonNumericMetricValue", err)
		}
	})
}

func TestReadOnlyUsesCatalogStatementAndCallerDeadline(t *testing.T) {
	template := MetricTemplate{ID: "db.connections", Statement: "SELECT value FROM metrics", MaxRows: 3, ValueColumns: []string{"value"}}
	catalog := staticCatalog{templates: map[EngineFamily]map[string]MetricTemplate{PostgresFamily: {template.ID: template}}}
	deadline := time.Now().Add(200 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	queryer := &recordingQueryer{rows: &fakeRows{columns: []string{"value"}, values: [][]any{{int64(7)}}}}

	got, err := ExecuteReadOnly(ctx, queryer, PostgresFamily, catalog, template.ID, map[string]any{"tenant": "blue"}, 99)
	if err != nil {
		t.Fatalf("ExecuteReadOnly() error = %v", err)
	}
	if len(got) != 1 || got[0]["value"] != 7 {
		t.Fatalf("ExecuteReadOnly() = %#v, want one numeric row", got)
	}
	if queryer.statement != template.Statement {
		t.Fatalf("statement = %q, want catalog statement %q", queryer.statement, template.Statement)
	}
	if queryer.deadline.After(deadline.Add(10 * time.Millisecond)) {
		t.Fatalf("query deadline = %v, exceeds caller deadline %v", queryer.deadline, deadline)
	}
	if !queryer.rows.closed {
		t.Fatal("rows were not closed")
	}
}

type staticCatalog struct {
	templates map[EngineFamily]map[string]MetricTemplate
}

func (catalog staticCatalog) Lookup(family EngineFamily, id string) (MetricTemplate, bool) {
	template, ok := catalog.templates[family][id]
	return template, ok
}

type recordingQueryer struct {
	rows      *fakeRows
	err       error
	calls     int
	statement string
	deadline  time.Time
}

func (queryer *recordingQueryer) QueryContext(ctx context.Context, statement string, _ ...any) (Rows, error) {
	queryer.calls++
	queryer.statement = statement
	queryer.deadline, _ = ctx.Deadline()
	if queryer.err != nil {
		return nil, queryer.err
	}
	return queryer.rows, nil
}

type fakeRows struct {
	columns []string
	values  [][]any
	index   int
	closed  bool
	err     error
}

func (rows *fakeRows) Columns() ([]string, error) { return append([]string(nil), rows.columns...), nil }
func (rows *fakeRows) Next() bool                 { return rows.index < len(rows.values) }
func (rows *fakeRows) Scan(dest ...any) error {
	if rows.index >= len(rows.values) {
		return fmt.Errorf("Scan called after rows exhausted")
	}
	if len(dest) != len(rows.values[rows.index]) {
		return fmt.Errorf("Scan destination count = %d, want %d", len(dest), len(rows.values[rows.index]))
	}
	for index, value := range rows.values[rows.index] {
		pointer, ok := dest[index].(*any)
		if !ok {
			return fmt.Errorf("destination %d is %T, want *any", index, dest[index])
		}
		*pointer = value
	}
	rows.index++
	return nil
}
func (rows *fakeRows) Err() error   { return rows.err }
func (rows *fakeRows) Close() error { rows.closed = true; return nil }
