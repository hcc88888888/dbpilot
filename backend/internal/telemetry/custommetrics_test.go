package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/policy"
)

func TestHTTPCollectorRejectsPlainHTTP(t *testing.T) {
	_, err := NewHTTPCollector().Collect(context.Background(), policy.HTTPJSONMetricSpec{
		Endpoint: "http://metrics.example.test/value", MetricName: "db_connections", JSONPath: "value",
	})
	if !errors.Is(err, ErrUnsafeHTTPMetric) {
		t.Fatalf("Collect() error = %v, want ErrUnsafeHTTPMetric", err)
	}
}

func TestHTTPCollectorMapsConfiguredNumericJSONValue(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, password, ok := r.BasicAuth(); !ok || user != "reader" || password != "secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"result":{"connections":"12.5"}}`)
	}))
	defer server.Close()

	points, err := NewHTTPCollector(server.Client()).Collect(context.Background(), policy.HTTPJSONMetricSpec{
		Endpoint: server.URL, MetricName: "db_connections", JSONPath: "result.connections",
		BasicAuth: policy.BasicAuth{Username: "reader", Password: "secret"}, Labels: map[string]string{" cluster ": " primary "},
	})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(points) != 1 || points[0].Value != 12.5 || points[0].Labels["cluster"] != "primary" {
		t.Fatalf("Collect() points = %#v, want normalized numeric point", points)
	}
}

func TestHTTPCollectorRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"value":12345}`)
	}))
	defer server.Close()

	_, err := NewHTTPCollector(server.Client()).Collect(context.Background(), policy.HTTPJSONMetricSpec{
		Endpoint: server.URL, MetricName: "db_connections", JSONPath: "value", MaxResponseBytes: 8,
	})
	if !errors.Is(err, ErrMetricResponseTooLarge) {
		t.Fatalf("Collect() error = %v, want ErrMetricResponseTooLarge", err)
	}
}

func TestHTTPCollectorRejectsNonNumericJSONValue(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"value":false}`)
	}))
	defer server.Close()

	_, err := NewHTTPCollector(server.Client()).Collect(context.Background(), policy.HTTPJSONMetricSpec{
		Endpoint: server.URL, MetricName: "db_connections", JSONPath: "value",
	})
	if !errors.Is(err, ErrInvalidMetricValue) {
		t.Fatalf("Collect() error = %v, want ErrInvalidMetricValue", err)
	}
}

func TestHTTPCollectorRejectsConflictingOrUnboundedAuthorization(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	for name, spec := range map[string]policy.HTTPJSONMetricSpec{
		"header": {
			Endpoint: server.URL, MetricName: "db_connections", JSONPath: "value", Headers: map[string]string{"Authorization": "Basic ignored"},
		},
		"modes": {
			Endpoint: server.URL, MetricName: "db_connections", JSONPath: "value", BearerToken: "token", BasicAuth: policy.BasicAuth{Username: "reader", Password: "secret"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewHTTPCollector(server.Client()).Collect(context.Background(), spec)
			if !errors.Is(err, ErrUnsafeHTTPMetric) {
				t.Fatalf("Collect() error = %v, want ErrUnsafeHTTPMetric", err)
			}
		})
	}
}

func TestSQLCollectorRejectsMultipleStatements(t *testing.T) {
	_, err := NewSQLCollector().Collect(context.Background(), fakeQueryer{}, policy.SQLMetricSpec{Statement: "SELECT 1; DROP TABLE users"})
	if !errors.Is(err, ErrUnsafeSQLMetric) {
		t.Fatalf("Collect() error = %v, want ErrUnsafeSQLMetric", err)
	}
}

func TestSQLCollectorRejectsWriteKeywordAfterCommentRemoval(t *testing.T) {
	_, err := NewSQLCollector().Collect(context.Background(), fakeQueryer{}, policy.SQLMetricSpec{Statement: "/* diagnostic */ WITH sample AS (DELETE FROM users RETURNING 1) SELECT * FROM sample"})
	if !errors.Is(err, ErrUnsafeSQLMetric) {
		t.Fatalf("Collect() error = %v, want ErrUnsafeSQLMetric", err)
	}
}

func TestSQLCollectorRejectsSelectIntoWrite(t *testing.T) {
	_, err := NewSQLCollector().Collect(context.Background(), fakeQueryer{}, policy.SQLMetricSpec{Statement: "SELECT 1 INTO telemetry_snapshot"})
	if !errors.Is(err, ErrUnsafeSQLMetric) {
		t.Fatalf("Collect() error = %v, want ErrUnsafeSQLMetric", err)
	}
}

func TestSQLCollectorPassesBoundedContextAndRowsToReadOnlyQueryer(t *testing.T) {
	queryer := &recordingQueryer{rows: []map[string]any{{"value": int64(9)}}}
	points, err := NewSQLCollector().Collect(context.Background(), queryer, policy.SQLMetricSpec{
		Statement: "SELECT connections AS value", MetricName: "db_connections", ValueColumn: "value", MaxRows: 3, Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if queryer.maxRows != 3 || queryer.deadline.IsZero() || len(points) != 1 || points[0].Value != 9 {
		t.Fatalf("query bounds = rows:%d deadline:%v points:%#v", queryer.maxRows, queryer.deadline, points)
	}
}

func TestPluginCollectorRejectsUnknownPlugin(t *testing.T) {
	_, err := NewPluginCollector().Collect(context.Background(), fakeRegistry{}, policy.PluginMetricSpec{PluginID: "../../bin/sh"})
	if !errors.Is(err, ErrUnknownPlugin) {
		t.Fatalf("Collect() error = %v, want ErrUnknownPlugin", err)
	}
}

func TestPluginCollectorRejectsExtraPluginParameter(t *testing.T) {
	plugin := testPlugin(t, "json")
	plugin.AllowedParameters = map[string]PluginParameter{"database": {Flag: "--database", MaxLength: 16}}
	_, err := NewPluginCollector().Collect(context.Background(), fakeRegistry{plugin: plugin}, policy.PluginMetricSpec{
		PluginID: "disk-check", Params: map[string]string{"command": "whoami"},
	})
	if !errors.Is(err, ErrUnsafePluginParameter) {
		t.Fatalf("Collect() error = %v, want ErrUnsafePluginParameter", err)
	}
}

func TestPluginCollectorRejectsDigestMismatch(t *testing.T) {
	plugin := testPlugin(t, "json")
	plugin.SHA256 = strings.Repeat("0", sha256.Size*2)
	_, err := NewPluginCollector().Collect(context.Background(), fakeRegistry{plugin: plugin}, policy.PluginMetricSpec{PluginID: "disk-check"})
	if !errors.Is(err, ErrPluginDigestMismatch) {
		t.Fatalf("Collect() error = %v, want ErrPluginDigestMismatch", err)
	}
}

func TestPluginCollectorRejectsCommandInterpreterLauncher(t *testing.T) {
	plugin := testPlugin(t, "json")
	plugin.Executable = `C:\dbpilot\disk-check.cmd`
	_, err := NewPluginCollector().Collect(context.Background(), fakeRegistry{plugin: plugin}, policy.PluginMetricSpec{PluginID: "disk-check"})
	if !errors.Is(err, ErrUnknownPlugin) {
		t.Fatalf("Collect() error = %v, want ErrUnknownPlugin", err)
	}
}

func TestPluginCollectorRejectsOversizedOutput(t *testing.T) {
	plugin := testPlugin(t, "large")
	plugin.MaxOutputBytes = 8
	_, err := NewPluginCollector().Collect(context.Background(), fakeRegistry{plugin: plugin}, policy.PluginMetricSpec{PluginID: "disk-check"})
	if !errors.Is(err, ErrPluginOutputTooLarge) {
		t.Fatalf("Collect() error = %v, want ErrPluginOutputTooLarge", err)
	}
}

func TestPluginCollectorUsesRegistryOwnedDecoder(t *testing.T) {
	plugin := testPlugin(t, "json")
	points, err := NewPluginCollector().Collect(context.Background(), fakeRegistry{plugin: plugin}, policy.PluginMetricSpec{PluginID: "disk-check", Labels: map[string]string{" role ": " primary "}})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(points) != 1 || points[0].Name != "disk_free" || points[0].Labels["role"] != "primary" {
		t.Fatalf("Collect() points = %#v, want decoded point with normalized labels", points)
	}
}

func TestMetricPointValidationRejectsInvalidNameAndTooManyLabels(t *testing.T) {
	labels := make(map[string]string, maximumMetricLabels+1)
	for i := range maximumMetricLabels + 1 {
		labels["label"+string(rune('a'+i))] = "value"
	}
	if err := ValidateMetricPoint(MetricPoint{Name: "not a metric", Type: MetricGauge, Value: 1}); !errors.Is(err, ErrInvalidMetricName) {
		t.Fatalf("ValidateMetricPoint() error = %v, want ErrInvalidMetricName", err)
	}
	if err := ValidateMetricPoint(MetricPoint{Name: "db_connections", Type: MetricGauge, Value: 1, Labels: labels}); !errors.Is(err, ErrTooManyMetricLabels) {
		t.Fatalf("ValidateMetricPoint() error = %v, want ErrTooManyMetricLabels", err)
	}
}

func TestNormalizeMetricPointReturnsNormalizedCopy(t *testing.T) {
	point, err := NormalizeMetricPoint(MetricPoint{Name: " db_connections ", Value: 1, Labels: map[string]string{" cluster ": " primary "}})
	if err != nil {
		t.Fatalf("NormalizeMetricPoint() error = %v", err)
	}
	if point.Name != "db_connections" || point.Type != MetricGauge || point.Labels["cluster"] != "primary" || point.Timestamp.IsZero() {
		t.Fatalf("NormalizeMetricPoint() = %#v, want normalized point", point)
	}
}

type fakeQueryer struct{}

func (fakeQueryer) Query(context.Context, string, int) ([]map[string]any, error) { return nil, nil }

type recordingQueryer struct {
	rows     []map[string]any
	maxRows  int
	deadline time.Time
}

func (q *recordingQueryer) Query(ctx context.Context, _ string, maxRows int) ([]map[string]any, error) {
	q.maxRows = maxRows
	q.deadline, _ = ctx.Deadline()
	return q.rows, nil
}

type fakeRegistry struct{ plugin RegisteredPlugin }

func (r fakeRegistry) Resolve(id string) (RegisteredPlugin, error) {
	if id != "disk-check" {
		return RegisteredPlugin{}, ErrUnknownPlugin
	}
	return r.plugin, nil
}

func testPlugin(t *testing.T, mode string) RegisteredPlugin {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binary)
	return RegisteredPlugin{
		Executable: executable, SHA256: hex.EncodeToString(digest[:]), Timeout: time.Second, MaxOutputBytes: 1024,
		AllowedParameters: map[string]PluginParameter{"mode": {Flag: "--mode", MaxLength: 16}},
		FixedArguments:    []string{"-test.run=TestCustomMetricPluginHelper", "--", "--mode=" + mode},
		Decoder: func(output []byte) ([]MetricPoint, error) {
			if string(output) != `{"name":"disk_free","value":42}` {
				return nil, errors.New("unexpected plugin output")
			}
			return []MetricPoint{{Name: "disk_free", Type: MetricGauge, Value: 42}}, nil
		},
	}
}

func TestCustomMetricPluginHelper(t *testing.T) {
	if !strings.Contains(strings.Join(os.Args, " "), "--mode=") {
		return
	}
	for _, argument := range os.Args {
		if argument == "--mode=large" {
			_, _ = io.WriteString(os.Stdout, strings.Repeat("x", 128))
			os.Exit(0)
		}
	}
	_, _ = io.WriteString(os.Stdout, `{"name":"disk_free","value":42}`)
	os.Exit(0)
}
