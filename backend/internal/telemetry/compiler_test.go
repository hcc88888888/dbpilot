package telemetry_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/telemetry"
)

func TestCompileBuildsOnlyApprovedComponents(t *testing.T) {
	cfg, err := telemetry.Compile(policyWithFileHostAndPrometheus(), telemetry.NewCatalog())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	assertElementsMatch(t, []string{"file_log/app", "host_metrics/base", "prometheus/custom"}, cfg.ReceiverIDs())
	if got := cfg.ProcessorIDs(); !reflect.DeepEqual(got, []string{"memory_limiter", "batch"}) {
		t.Errorf("ProcessorIDs() = %v, want [memory_limiter batch]", got)
	}
	if got := cfg.ExporterIDs(); !reflect.DeepEqual(got, []string{"dbpilot"}) {
		t.Errorf("ExporterIDs() = %v, want [dbpilot]", got)
	}
}

func TestCatalogDoesNotExposeExecReceiver(t *testing.T) {
	if _, ok := telemetry.NewCatalog().ReceiverFactory("exec"); ok {
		t.Fatal("ReceiverFactory(exec) unexpectedly returned a factory")
	}
}

func TestCompileMapsFileLogMultilineAndResourceLabels(t *testing.T) {
	p := validPolicy(policy.Source{
		ID: "app", Kind: policy.SourceFileLog, Path: "/var/log/app/current.log", Interval: 5 * time.Second,
		Labels: map[string]string{"service.name": "billing"},
		Params: map[string]string{
			"multiline_line_start_pattern": `^\\d{4}-\\d{2}-\\d{2}`,
			"multiline_line_end_pattern":   `^END$`,
		},
	})
	cfg, err := telemetry.Compile(p, telemetry.NewCatalog())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	source, ok := cfg.Source("file_log/app")
	if !ok {
		t.Fatal("Source(file_log/app) = not found")
	}
	if source.PipelineID != "dbpilot/logs" {
		t.Errorf("PipelineID = %q, want dbpilot/logs", source.PipelineID)
	}
	if got := source.ResourceAttributes["service.name"]; got != "billing" {
		t.Errorf("service.name = %q, want billing", got)
	}
	if got := source.ResourceAttributes["dbpilot.agent.id"]; got != "agent-1" {
		t.Errorf("dbpilot.agent.id = %q, want agent-1", got)
	}
	if got := source.FileLog.MultilineLineStartPattern; got != `^\\d{4}-\\d{2}-\\d{2}` {
		t.Errorf("multiline line-start pattern = %q", got)
	}
	if got := source.FileLog.MultilineLineEndPattern; got != `^END$` {
		t.Errorf("multiline line-end pattern = %q", got)
	}
}

func TestCompileMapsJournaldUnitFilter(t *testing.T) {
	p := validPolicy(policy.Source{
		ID: "ssh", Kind: policy.SourceJournald, Interval: 5 * time.Second,
		Params: map[string]string{"unit": "sshd.service"},
	})
	cfg, err := telemetry.Compile(p, telemetry.NewCatalog())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	source, ok := cfg.Source("journald/ssh")
	if !ok {
		t.Fatal("Source(journald/ssh) = not found")
	}
	if source.PipelineID != "dbpilot/logs" {
		t.Errorf("PipelineID = %q, want dbpilot/logs", source.PipelineID)
	}
	if got := source.Journald.Matches; !reflect.DeepEqual(got, []string{"_SYSTEMD_UNIT=sshd.service"}) {
		t.Errorf("journald matches = %v", got)
	}
}

func TestCompileMapsPrometheusTLSAndAuthentication(t *testing.T) {
	p := validPolicy(policy.Source{
		ID: "custom", Kind: policy.SourcePrometheus, Endpoint: "https://metrics.example.test:9443/metrics", Interval: 10 * time.Second,
		Params: map[string]string{
			"tls_ca_file": "/etc/dbpilot/ca.pem", "tls_cert_file": "/etc/dbpilot/client.pem",
			"tls_key_file": "/etc/dbpilot/client.key", "username": "metrics-reader", "password": "secret",
		},
	})
	cfg, err := telemetry.Compile(p, telemetry.NewCatalog())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	source, ok := cfg.Source("prometheus/custom")
	if !ok {
		t.Fatal("Source(prometheus/custom) = not found")
	}
	if source.PipelineID != "dbpilot/metrics" || source.Prometheus.Target != "https://metrics.example.test:9443/metrics" {
		t.Errorf("prometheus pipeline/target = %q/%q", source.PipelineID, source.Prometheus.Target)
	}
	if got := source.Prometheus.TLSCAFile; got != "/etc/dbpilot/ca.pem" {
		t.Errorf("TLSCAFile = %q", got)
	}
	if got := source.Prometheus.TLSCertFile; got != "/etc/dbpilot/client.pem" {
		t.Errorf("TLSCertFile = %q", got)
	}
	if got := source.Prometheus.TLSKeyFile; got != "/etc/dbpilot/client.key" {
		t.Errorf("TLSKeyFile = %q", got)
	}
	if got := source.Prometheus.Username; got != "metrics-reader" {
		t.Errorf("Username = %q", got)
	}
	if got := source.Prometheus.Password; got != "secret" {
		t.Errorf("Password = %q", got)
	}
}

func TestCompileAppliesMemoryAndSpoolLimits(t *testing.T) {
	p := policyWithFileHostAndPrometheus()
	p.Limits.MaxSpoolBytes, p.Limits.MaxBatchBytes, p.Limits.MaxEventsPerSec = 8<<20, 2<<20, 200
	cfg, err := telemetry.Compile(p, telemetry.NewCatalog())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if got := cfg.MaxSpoolBytes(); got != 8<<20 {
		t.Errorf("MaxSpoolBytes() = %d", got)
	}
	if got := cfg.BatchMaxBytes(); got != 2<<20 {
		t.Errorf("BatchMaxBytes() = %d", got)
	}
	if got := cfg.MemoryLimiterCheckIntervalEvents(); got != 200 {
		t.Errorf("MemoryLimiterCheckIntervalEvents() = %d", got)
	}
}

func TestCompileRejectsUnknownSource(t *testing.T) {
	p := validPolicy(policy.Source{ID: "unknown", Kind: "UNKNOWN", Interval: 5 * time.Second})
	_, err := telemetry.Compile(p, telemetry.NewCatalog())
	if !errors.Is(err, telemetry.ErrUnsupportedSource) {
		t.Fatalf("Compile() error = %v, want ErrUnsupportedSource", err)
	}
}

func TestCompileRejectsPolicyWithNoPipelines(t *testing.T) {
	p := validPolicy()
	_, err := telemetry.Compile(p, telemetry.NewCatalog())
	if !errors.Is(err, telemetry.ErrNoPipelines) {
		t.Fatalf("Compile() error = %v, want ErrNoPipelines", err)
	}
}

func TestCompileUsesDeterministicComponentIDs(t *testing.T) {
	p := policyWithFileHostAndPrometheus()
	p.Sources[0], p.Sources[2] = p.Sources[2], p.Sources[0]
	cfg, err := telemetry.Compile(p, telemetry.NewCatalog())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if got := cfg.ReceiverIDs(); !reflect.DeepEqual(got, []string{"file_log/app", "host_metrics/base", "prometheus/custom"}) {
		t.Errorf("ReceiverIDs() = %v", got)
	}
}

func validPolicy(sources ...policy.Source) policy.Policy {
	return policy.Policy{
		AgentID: "agent-1", Version: 1,
		IssuedAt: time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC),
		Sources: sources, Limits: policy.Limits{MaxSpoolBytes: 4 << 20, MaxBatchBytes: 1 << 20, MaxEventsPerSec: 100},
	}
}

func policyWithFileHostAndPrometheus() policy.Policy {
	return validPolicy(
		policy.Source{ID: "custom", Kind: policy.SourcePrometheus, Endpoint: "https://metrics.example.test/metrics", Interval: 10 * time.Second},
		policy.Source{ID: "app", Kind: policy.SourceFileLog, Path: "/var/log/app/current.log", Interval: 5 * time.Second},
		policy.Source{ID: "base", Kind: policy.SourceHostMetrics, Interval: 5 * time.Second},
	)
}

func assertElementsMatch(t *testing.T, want, got []string) {
	t.Helper()
	wantCopy, gotCopy := append([]string(nil), want...), append([]string(nil), got...)
	for len(wantCopy) > 0 {
		found := -1
		for index, candidate := range gotCopy {
			if candidate == wantCopy[0] {
				found = index
				break
			}
		}
		if found < 0 {
			t.Fatalf("elements = %v, want %v", got, want)
		}
		wantCopy, gotCopy = wantCopy[1:], append(gotCopy[:found], gotCopy[found+1:]...)
	}
	if len(gotCopy) != 0 {
		t.Fatalf("elements = %v, want %v", got, want)
	}
}
