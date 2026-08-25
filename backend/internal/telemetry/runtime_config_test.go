package telemetry

import (
	"os"
	"reflect"
	"testing"
	"time"

	"dbpilot.local/platform/internal/policy"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/hostmetricsreceiver"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/journaldreceiver"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver"
	promconfig "github.com/prometheus/prometheus/config"
	"go.opentelemetry.io/collector/processor/batchprocessor"
	"go.opentelemetry.io/collector/processor/memorylimiterprocessor"
)

func TestCompileConfiguresConcreteCollectorComponents(t *testing.T) {
	tlsDirectory := t.TempDir()
	caFile := tlsDirectory + "/ca.pem"
	certFile := tlsDirectory + "/client.pem"
	keyFile := tlsDirectory + "/client.key"
	for _, filename := range []string{caFile, certFile, keyFile} {
		if err := os.WriteFile(filename, []byte("test"), 0o600); err != nil {
			t.Fatalf("write TLS fixture: %v", err)
		}
	}

	p := runtimeTestPolicy([]policy.Source{
		{ID: "app", Kind: policy.SourceFileLog, Path: "/var/log/app/current.log", Interval: 5 * time.Second, Params: map[string]string{
			"start_at": "beginning", "encoding": "utf-8", "multiline_line_start_pattern": `^START`, "multiline_line_end_pattern": `^END$`,
		}},
		{ID: "journal", Kind: policy.SourceJournald, Interval: 5 * time.Second, Params: map[string]string{"unit": "sshd.service", "match": "_SYSTEMD_IDENTIFIER=sshd"}},
		{ID: "host", Kind: policy.SourceHostMetrics, Interval: 15 * time.Second, Params: map[string]string{"collectors": "cpu,memory"}},
		{ID: "prom", Kind: policy.SourcePrometheus, Endpoint: "https://metrics.example.test:9443/metrics", Interval: 20 * time.Second, Labels: map[string]string{"service.name": "billing"}, Params: map[string]string{
			"tls_ca_file": caFile, "tls_cert_file": certFile, "tls_key_file": keyFile, "username": "reader", "password": "secret", "scrape_timeout": "10s",
		}},
	})
	p.Limits = policy.Limits{MaxSpoolBytes: 8 << 20, MaxBatchBytes: 2 << 20, MaxEventsPerSec: 100}

	cfg, err := Compile(p, NewCatalog())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	fileConfig, ok := cfg.receivers["file_log/app"].config.(*filelogreceiver.FileLogConfig)
	if !ok {
		t.Fatalf("filelog config type = %T", cfg.receivers["file_log/app"].config)
	}
	if !reflect.DeepEqual(fileConfig.InputConfig.Include, []string{"/var/log/app/current.log"}) || fileConfig.InputConfig.StartAt != "beginning" || fileConfig.InputConfig.Encoding != "utf-8" {
		t.Errorf("filelog config = include=%v start=%q encoding=%q", fileConfig.InputConfig.Include, fileConfig.InputConfig.StartAt, fileConfig.InputConfig.Encoding)
	}
	if fileConfig.InputConfig.SplitConfig.LineStartPattern != "^START" || fileConfig.InputConfig.SplitConfig.LineEndPattern != "^END$" {
		t.Errorf("filelog multiline = %#v", fileConfig.InputConfig.SplitConfig)
	}

	journalConfig, ok := cfg.receivers["journald/journal"].config.(*journaldreceiver.JournaldConfig)
	if !ok {
		t.Fatalf("journald config type = %T", cfg.receivers["journald/journal"].config)
	}
	if !reflect.DeepEqual(journalConfig.InputConfig.Units, []string{"sshd.service"}) || journalConfig.BaseConfig.StorageID == nil {
		t.Errorf("journald config = units=%v storage=%v", journalConfig.InputConfig.Units, journalConfig.BaseConfig.StorageID)
	}
	if len(journalConfig.InputConfig.Matches) != 1 || journalConfig.InputConfig.Matches[0]["_SYSTEMD_IDENTIFIER"] != "sshd" {
		t.Errorf("journald matches = %v", journalConfig.InputConfig.Matches)
	}

	hostConfig, ok := cfg.receivers["host_metrics/host"].config.(*hostmetricsreceiver.Config)
	if !ok {
		t.Fatalf("hostmetrics config type = %T", cfg.receivers["host_metrics/host"].config)
	}
	if hostConfig.ControllerConfig.CollectionInterval != 15*time.Second || len(hostConfig.Scrapers) != 2 {
		t.Errorf("hostmetrics config = interval=%s scrapers=%d", hostConfig.ControllerConfig.CollectionInterval, len(hostConfig.Scrapers))
	}
	if err := hostConfig.Validate(); err != nil {
		t.Errorf("hostmetrics Validate() error = %v", err)
	}

	promConfig, ok := cfg.receivers["prometheus/prom"].config.(*prometheusreceiver.Config)
	if !ok {
		t.Fatalf("prometheus config type = %T", cfg.receivers["prometheus/prom"].config)
	}
	if err := promConfig.Validate(); err != nil {
		t.Errorf("prometheus Validate() error = %v", err)
	}
	if !promConfig.PrometheusConfig.ContainsScrapeConfigs() {
		t.Fatal("prometheus config has no scrape configuration")
	}
	promRuntimeConfig := (*promconfig.Config)(promConfig.PrometheusConfig)
	scrapeConfig := promRuntimeConfig.ScrapeConfigs[0]
	if scrapeConfig.MetricsPath != "/metrics" || scrapeConfig.Scheme != "https" || scrapeConfig.HTTPClientConfig.TLSConfig.CAFile != caFile || scrapeConfig.HTTPClientConfig.TLSConfig.CertFile != certFile || scrapeConfig.HTTPClientConfig.TLSConfig.KeyFile != keyFile {
		t.Errorf("prometheus scrape TLS/endpoint config = %#v", scrapeConfig)
	}
	if scrapeConfig.HTTPClientConfig.BasicAuth == nil || scrapeConfig.HTTPClientConfig.BasicAuth.Username != "reader" || string(scrapeConfig.HTTPClientConfig.BasicAuth.Password) != "secret" {
		t.Errorf("prometheus basic auth config = %#v", scrapeConfig.HTTPClientConfig.BasicAuth)
	}

	memoryConfig, ok := cfg.processors["memory_limiter"].config.(*memorylimiterprocessor.Config)
	if !ok {
		t.Fatalf("memory limiter config type = %T", cfg.processors["memory_limiter"].config)
	}
	if memoryConfig.MemoryLimitMiB != 8 || memoryConfig.MemorySpikeLimitMiB >= memoryConfig.MemoryLimitMiB {
		t.Errorf("memory limiter config = limit=%d spike=%d", memoryConfig.MemoryLimitMiB, memoryConfig.MemorySpikeLimitMiB)
	}
	if err := memoryConfig.Validate(); err != nil {
		t.Errorf("memory limiter Validate() error = %v", err)
	}

	batchConfig, ok := cfg.processors["batch"].config.(*batchprocessor.Config)
	if !ok {
		t.Fatalf("batch config type = %T", cfg.processors["batch"].config)
	}
	if batchConfig.SendBatchMaxSize != 2<<20 || batchConfig.SendBatchSize == 0 {
		t.Errorf("batch config = max=%d size=%d", batchConfig.SendBatchMaxSize, batchConfig.SendBatchSize)
	}
	if err := batchConfig.Validate(); err != nil {
		t.Errorf("batch Validate() error = %v", err)
	}

	storageConfig, ok := cfg.extensions["file_storage"].config.(*filestorage.Config)
	if !ok {
		t.Fatalf("file storage config type = %T", cfg.extensions["file_storage"].config)
	}
	if storageConfig.MaxSize != 8<<20 || !storageConfig.CreateDirectory || storageConfig.Directory == "" {
		t.Errorf("file storage config = directory=%q max=%d create=%t", storageConfig.Directory, storageConfig.MaxSize, storageConfig.CreateDirectory)
	}
	if err := storageConfig.Validate(); err != nil {
		t.Errorf("file storage Validate() error = %v", err)
	}

	if got := cfg.exporters["dbpilot"].resourceAttributes["service.name"]; got != "billing" {
		t.Errorf("exporter resource service.name = %q", got)
	}
}

func TestCompileRejectsInvalidConcreteConfig(t *testing.T) {
	p := runtimeTestPolicy([]policy.Source{{
		ID: "host", Kind: policy.SourceHostMetrics, Interval: 5 * time.Second,
		Params: map[string]string{"collectors": "cpu,shell"},
	}})
	if _, err := Compile(p, NewCatalog()); err == nil {
		t.Fatal("Compile() error = nil, want invalid host collector rejection")
	}
}

func runtimeTestPolicy(sources []policy.Source) policy.Policy {
	return policy.Policy{
		AgentID: "agent-runtime", Version: 1,
		IssuedAt: time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC),
		Sources: sources, Limits: policy.Limits{MaxSpoolBytes: 4 << 20, MaxBatchBytes: 1 << 20, MaxEventsPerSec: 100},
	}
}
