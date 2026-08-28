package agent

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"testing"
	"time"

	"dbpilot.local/platform/internal/spool"
	"dbpilot.local/platform/internal/telemetry"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestHostSnapshotCollectorAppendsBoundedCanonicalOTLPMetrics(t *testing.T) {
	now := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	store, err := spool.Open(t.TempDir(), spool.Limits{MaxBytes: 4 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	require.NoError(t, store.Append(context.Background(), spool.Log, spool.Batch{ID: "existing-log", SourceID: "logs", CreatedAt: now, Payload: make([]byte, 256)}))
	snapshot := completeHostSnapshot(now)
	collector := &HostSnapshotCollector{
		AgentID: "agent-a", Store: store, Reader: staticHostReader{snapshot: snapshot},
		Logs: staticLogSummaryProvider{summaries: []LogSummary{
			{SourceID: "source-b", Severity: "warning", Category: "general", Count: 2, ObservedAt: now},
			{SourceID: "source-a", Severity: "error", Category: "oom", Count: 1, ObservedAt: now},
			{SourceID: "source-c", Severity: "critical", Category: "general", Count: 3, ObservedAt: now},
		}},
		BatchLimits: &mutableBatchLimit{value: 1 << 20}, ProcessNames: []string{"postgres", "mysqld"}, Now: func() time.Time { return now },
	}

	require.NoError(t, collector.Collect(context.Background(), CollectionRequest{Kinds: []string{"host"}}))
	batches, err := store.Pending(context.Background(), spool.Metric, 0)
	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Equal(t, hostSnapshotSourceID, batches[0].SourceID)
	require.LessOrEqual(t, len(batches[0].Payload), 1<<20)
	decoded, err := (&pmetric.ProtoUnmarshaler{}).UnmarshalMetrics(batches[0].Payload)
	require.NoError(t, err)
	resource := decoded.ResourceMetrics().At(0).Resource().Attributes()
	requireResourceString(t, resource, "agent.id", "agent-a")
	requireResourceString(t, resource, "dbpilot.agent.id", "agent-a")
	requireResourceString(t, resource, "host.name", "db-a")
	requireResourceString(t, resource, "os.type", "linux")
	requireResourceString(t, resource, "inspection.snapshot_at", now.Format(time.RFC3339Nano))

	points := decodedMetricPoints(t, decoded)
	requireMetricValue(t, points, "system.cpu.utilization", 82.5)
	requireMetricValue(t, points, "system.cpu.load_average.1m_per_cpu", 1)
	requireMetricValue(t, points, "system.memory.utilization", 81)
	requireMetricValue(t, points, "system.swap.utilization", 26)
	requireMetricValue(t, points, "dbpilot.inspection.host.agent.heartbeat_age_seconds", 0)
	requireMetricValue(t, points, "dbpilot.inspection.host.metric.age_seconds", 0)
	requireMetricValue(t, points, "dbpilot.inspection.host.database.required_process_count", 2)
	requireMetricValue(t, points, "dbpilot.inspection.host.time.synchronization_available", 1)
	requireMetricValue(t, points, "dbpilot.inspection.host.time.synchronized", 1)
	requireMetricValue(t, points, "dbpilot.inspection.host.log.warning_count", 2)
	requireMetricValue(t, points, "dbpilot.inspection.host.log.error_count", 1)
	requireMetricValue(t, points, "dbpilot.inspection.host.log.critical_count", 3)
	requireMetricValue(t, points, "dbpilot.inspection.host.oom.count", 1)
	requireMetricValue(t, points, "system.uptime", 7200)
	require.Greater(t, firstMetricValue(t, points, "dbpilot.inspection.host.spool.utilization"), float64(0))
	t.Logf("decoded metric evidence: batch=%s payload_bytes=%d cpu=%.1f memory=%.1f load_per_cpu=%.1f required_processes=%.0f filesystems=%d",
		batches[0].ID, len(batches[0].Payload), firstMetricValue(t, points, "system.cpu.utilization"),
		firstMetricValue(t, points, "system.memory.utilization"), firstMetricValue(t, points, "system.cpu.load_average.1m_per_cpu"),
		firstMetricValue(t, points, "dbpilot.inspection.host.database.required_process_count"), len(points["system.filesystem.utilization"]))

	filesystemPoints := points["system.filesystem.utilization"]
	require.Len(t, filesystemPoints, MaxHostFilesystems)
	require.Equal(t, "/mnt/00", filesystemPoints[0].attributes["mountpoint"])
	require.Equal(t, "/mnt/63", filesystemPoints[len(filesystemPoints)-1].attributes["mountpoint"])
	require.Len(t, points["system.disk.io"], MaxHostDisks*2)
	require.Len(t, points["system.network.io"], MaxHostInterfaces*2)
	for _, values := range points {
		for _, point := range values {
			require.Equal(t, now, point.timestamp)
			require.False(t, math.IsNaN(point.value))
			require.False(t, math.IsInf(point.value, 0))
		}
	}

	require.NoError(t, collector.Collect(context.Background(), CollectionRequest{Kinds: []string{"host"}}))
	batches, err = store.Pending(context.Background(), spool.Metric, 0)
	require.NoError(t, err)
	require.Len(t, batches, 2)
	require.NotEqual(t, batches[0].ID, batches[1].ID)
}

func TestHostSnapshotCollectorEmptyLogWindowEmitsAvailabilityNotHealthyZeros(t *testing.T) {
	now := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	store := &capturingHostStore{stats: spool.Stats{MaxBytes: 1024}}
	collector := &HostSnapshotCollector{AgentID: "agent-a", Store: store, Reader: staticHostReader{snapshot: completeHostSnapshot(now)}, Logs: staticLogSummaryProvider{observerFailures: 2}, BatchLimits: &mutableBatchLimit{value: 1 << 20}, Now: func() time.Time { return now }}

	require.NoError(t, collector.Collect(context.Background(), CollectionRequest{Kinds: []string{"host"}}))
	decoded, err := (&pmetric.ProtoUnmarshaler{}).UnmarshalMetrics(store.batches[0].Payload)
	require.NoError(t, err)
	points := decodedMetricPoints(t, decoded)
	requireMetricValue(t, points, "dbpilot.inspection.host.log.summary_available", 0)
	requireMetricValue(t, points, "dbpilot.inspection.host.log.observer_failure_count", 2)
	require.NotContains(t, points, "dbpilot.inspection.host.log.warning_count")
	require.NotContains(t, points, "dbpilot.inspection.host.log.error_count")
	require.NotContains(t, points, "dbpilot.inspection.host.log.critical_count")
	require.NotContains(t, points, "dbpilot.inspection.host.oom.count")
}

func TestHostSnapshotCollectorAggregatesEveryValidatedLogSummaryBeforeDimensionalCap(t *testing.T) {
	now := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	index := telemetry.NewLogSummaryIndex(func() time.Time { return now })
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	resourceLogs.Resource().Attributes().PutStr("dbpilot.source.id", "a-source")
	records := resourceLogs.ScopeLogs().AppendEmpty().LogRecords()
	for _, severity := range []plog.SeverityNumber{plog.SeverityNumberDebug, plog.SeverityNumberInfo, plog.SeverityNumberWarn, plog.SeverityNumberError, plog.SeverityNumberFatal} {
		for category := 0; category < 15; category++ {
			record := records.AppendEmpty()
			record.SetTimestamp(pcommon.NewTimestampFromTime(now))
			record.SetSeverityNumber(severity)
			if category < 14 {
				record.Attributes().PutStr("dbpilot.log.category", fmt.Sprintf("category-%02d", category))
			}
		}
	}
	oomResource := logs.ResourceLogs().AppendEmpty()
	oomResource.Resource().Attributes().PutStr("dbpilot.source.id", "z-source")
	oom := oomResource.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	oom.SetTimestamp(pcommon.NewTimestampFromTime(now))
	oom.SetSeverityNumber(plog.SeverityNumberError)
	oom.Body().SetStr("Out of memory: Killed process 99")
	require.NoError(t, index.Observe(context.Background(), logs))
	require.Len(t, index.Snapshot(now, time.Hour), 76)

	store := &capturingHostStore{stats: spool.Stats{MaxBytes: 1 << 20}}
	collector := &HostSnapshotCollector{
		AgentID: "agent-a", Store: store, Reader: staticHostReader{snapshot: completeHostSnapshot(now)}, Logs: index,
		BatchLimits: &mutableBatchLimit{value: 1 << 20}, ProcessNames: []string{"postgres"}, Now: func() time.Time { return now },
	}
	require.NoError(t, collector.Collect(context.Background(), CollectionRequest{Kinds: []string{"host"}}))
	decoded, err := (&pmetric.ProtoUnmarshaler{}).UnmarshalMetrics(store.batches[0].Payload)
	require.NoError(t, err)
	points := decodedMetricPoints(t, decoded)

	requireMetricValue(t, points, "dbpilot.inspection.host.log.warning_count", 15)
	requireMetricValue(t, points, "dbpilot.inspection.host.log.error_count", 16)
	requireMetricValue(t, points, "dbpilot.inspection.host.log.critical_count", 15)
	requireMetricValue(t, points, "dbpilot.inspection.host.oom.count", 1)
	require.Len(t, points["dbpilot.inspection.host.log.source_count"], maxHostLogSummaryDataPoints)
}

func TestHostSnapshotCollectorRejectsCancellationInvalidNumbersAndOversizedPayload(t *testing.T) {
	now := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		mutate    func(*HostSnapshot)
		maxBytes  int64
		cancelled bool
	}{
		{name: "cancelled", cancelled: true},
		{name: "NaN", mutate: func(snapshot *HostSnapshot) { snapshot.CPUUtilization = math.NaN() }},
		{name: "infinity", mutate: func(snapshot *HostSnapshot) { snapshot.Filesystems[0].UsedPercent = math.Inf(1) }},
		{name: "CPU percent out of range", mutate: func(snapshot *HostSnapshot) { snapshot.CPUUtilization = 101 }},
		{name: "negative load", mutate: func(snapshot *HostSnapshot) { snapshot.Load1 = -1 }},
		{name: "oversized", maxBytes: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := completeHostSnapshot(now)
			if test.mutate != nil {
				test.mutate(&value)
			}
			store := &capturingHostStore{stats: spool.Stats{MaxBytes: 1024}}
			limit := test.maxBytes
			if limit == 0 {
				limit = 1 << 20
			}
			collector := &HostSnapshotCollector{AgentID: "agent-a", Store: store, Reader: staticHostReader{snapshot: value}, BatchLimits: &mutableBatchLimit{value: limit}, Now: func() time.Time { return now }}
			ctx := context.Background()
			if test.cancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			err := collector.Collect(ctx, CollectionRequest{Kinds: []string{"host"}})

			require.Error(t, err)
			require.Empty(t, store.batches)
		})
	}
}

func TestHostSnapshotCollectorReturnsAppendFailure(t *testing.T) {
	now := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	appendErr := errors.New("durable spool unavailable")
	store := &capturingHostStore{stats: spool.Stats{MaxBytes: 1024}, appendErr: appendErr}
	collector := &HostSnapshotCollector{AgentID: "agent-a", Store: store, Reader: staticHostReader{snapshot: completeHostSnapshot(now)}, BatchLimits: &mutableBatchLimit{value: 1 << 20}, Now: func() time.Time { return now }}
	require.ErrorIs(t, collector.Collect(context.Background(), CollectionRequest{Kinds: []string{"host"}}), appendErr)
}

func TestHostSnapshotCollectorRequiresActiveDynamicBatchLimitBeforeRead(t *testing.T) {
	now := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	reader := &countingHostReader{snapshot: completeHostSnapshot(now)}
	store := &capturingHostStore{stats: spool.Stats{MaxBytes: 1 << 20}}
	collector := &HostSnapshotCollector{
		AgentID: "agent-a", Store: store, Reader: reader, BatchLimits: &mutableBatchLimit{}, Now: func() time.Time { return now },
	}

	err := collector.Collect(context.Background(), CollectionRequest{Kinds: []string{"host"}})

	require.ErrorContains(t, err, "active telemetry batch limit")
	require.Zero(t, reader.calls)
	require.Empty(t, store.batches)
}

func TestHostSnapshotCollectorReadsDynamicLimitEachCollectionWithoutPoisoningSpoolHead(t *testing.T) {
	now := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	store, err := spool.Open(t.TempDir(), spool.Limits{MaxBytes: 4 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	head := spool.Batch{ID: "existing-head", SourceID: "existing", CreatedAt: now, Payload: []byte("existing payload")}
	require.NoError(t, store.Append(context.Background(), spool.Metric, head))
	limits := &mutableBatchLimit{value: 1 << 20}
	collector := &HostSnapshotCollector{
		AgentID: "agent-a", Store: store, Reader: staticHostReader{snapshot: completeHostSnapshot(now)}, BatchLimits: limits,
		ProcessNames: []string{"postgres"}, Now: func() time.Time { return now },
	}

	require.NoError(t, collector.Collect(context.Background(), CollectionRequest{Kinds: []string{"host"}}))
	pending, err := store.Pending(context.Background(), spool.Metric, 0)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	require.Equal(t, head.ID, pending[0].ID)
	require.Equal(t, head.Payload, pending[0].Payload)
	beforeSmallerPolicy := pending

	limits.value = 1
	require.ErrorContains(t, collector.Collect(context.Background(), CollectionRequest{Kinds: []string{"host"}}), "exporter limit")
	pending, err = store.Pending(context.Background(), spool.Metric, 0)
	require.NoError(t, err)
	require.Equal(t, beforeSmallerPolicy, pending, "smaller active policy must not append an oversized spool head")
}

func TestHostSnapshotCollectorCountsAndMatchesProcessesBeyondDetailLimit(t *testing.T) {
	now := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	snapshot := completeHostSnapshot(now)
	snapshot.Processes = make([]ProcessObservation, 0, MaxHostProcesses+1)
	for index := 0; index < MaxHostProcesses; index++ {
		snapshot.Processes = append(snapshot.Processes, ProcessObservation{Name: fmt.Sprintf("process-%04d", index), Status: "running"})
	}
	snapshot.Processes = append(snapshot.Processes, ProcessObservation{Name: "postgres", Status: "running"})
	store := &capturingHostStore{stats: spool.Stats{MaxBytes: 1 << 20}}
	collector := &HostSnapshotCollector{
		AgentID: "agent-a", Store: store, Reader: staticHostReader{snapshot: snapshot}, ProcessNames: []string{"postgres"},
		BatchLimits: &mutableBatchLimit{value: 1 << 20}, Now: func() time.Time { return now },
	}

	require.NoError(t, collector.Collect(context.Background(), CollectionRequest{Kinds: []string{"host"}}))
	decoded, err := (&pmetric.ProtoUnmarshaler{}).UnmarshalMetrics(store.batches[0].Payload)
	require.NoError(t, err)
	points := decodedMetricPoints(t, decoded)
	requireMetricValue(t, points, "system.processes.count", MaxHostProcesses+1)
	requireMetricValue(t, points, "dbpilot.inspection.host.database.required_process_count", 1)
}

func completeHostSnapshot(now time.Time) HostSnapshot {
	filesystems := make([]FilesystemObservation, 0, MaxHostFilesystems+2)
	disks := make([]DiskObservation, 0, MaxHostDisks+2)
	networks := make([]NetworkObservation, 0, MaxHostInterfaces+2)
	for index := MaxHostFilesystems + 1; index >= 0; index-- {
		filesystems = append(filesystems, FilesystemObservation{Device: fmt.Sprintf("/dev/sd%02d", index), Mountpoint: fmt.Sprintf("/mnt/%02d", index), Type: "xfs", UsedBytes: 800, TotalBytes: 1000, UsedPercent: 80, InodesUsedPercent: 40})
	}
	for index := MaxHostDisks + 1; index >= 0; index-- {
		disks = append(disks, DiskObservation{Name: fmt.Sprintf("sd%02d", index), ReadBytes: uint64(index + 1), WriteBytes: uint64(index + 2)})
	}
	for index := MaxHostInterfaces + 1; index >= 0; index-- {
		networks = append(networks, NetworkObservation{Name: fmt.Sprintf("eth%02d", index), ReceiveBytes: uint64(index + 3), TransmitBytes: uint64(index + 4)})
	}
	return HostSnapshot{
		Hostname: "db-a", OSType: "linux", CPUUtilization: 82.5, LogicalCPUs: 4, Load1: 4,
		MemoryUsedPercent: 81, SwapUsedPercent: 26, Filesystems: filesystems, Disks: disks, Networks: networks,
		Processes: []ProcessObservation{{Name: "postgres", Status: "running"}, {Name: "other", Status: "running"}, {Name: "postgres", Status: "sleeping"}},
		BootTime:  now.Add(-2 * time.Hour), TimeSync: TimeSyncObservation{Available: true, Synchronized: true},
	}
}

type staticHostReader struct {
	snapshot HostSnapshot
	err      error
}

func (reader staticHostReader) Read(context.Context) (HostSnapshot, error) {
	return reader.snapshot, reader.err
}

type countingHostReader struct {
	snapshot HostSnapshot
	calls    int
}

func (reader *countingHostReader) Read(context.Context) (HostSnapshot, error) {
	reader.calls++
	return reader.snapshot, nil
}

type mutableBatchLimit struct{ value int64 }

func (limit *mutableBatchLimit) BatchMaxBytes() int64 { return limit.value }

type staticLogSummaryProvider struct {
	summaries        []LogSummary
	observerFailures uint64
}

func (provider staticLogSummaryProvider) Snapshot(time.Time, time.Duration) []LogSummary {
	return append([]LogSummary(nil), provider.summaries...)
}

func (provider staticLogSummaryProvider) ObserverFailureCount() uint64 {
	return provider.observerFailures
}

type capturingHostStore struct {
	stats     spool.Stats
	statsErr  error
	appendErr error
	batches   []spool.Batch
}

func (store *capturingHostStore) Stats() (spool.Stats, error) { return store.stats, store.statsErr }
func (store *capturingHostStore) Append(_ context.Context, class spool.DataClass, batch spool.Batch) error {
	if store.appendErr != nil {
		return store.appendErr
	}
	if class != spool.Metric {
		return errors.New("unexpected data class")
	}
	store.batches = append(store.batches, batch)
	return nil
}

type decodedPoint struct {
	value      float64
	timestamp  time.Time
	attributes map[string]string
}

func decodedMetricPoints(t *testing.T, metrics pmetric.Metrics) map[string][]decodedPoint {
	t.Helper()
	result := make(map[string][]decodedPoint)
	for resourceIndex := 0; resourceIndex < metrics.ResourceMetrics().Len(); resourceIndex++ {
		resourceMetrics := metrics.ResourceMetrics().At(resourceIndex)
		for scopeIndex := 0; scopeIndex < resourceMetrics.ScopeMetrics().Len(); scopeIndex++ {
			values := resourceMetrics.ScopeMetrics().At(scopeIndex).Metrics()
			for metricIndex := 0; metricIndex < values.Len(); metricIndex++ {
				metric := values.At(metricIndex)
				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					for pointIndex := 0; pointIndex < metric.Gauge().DataPoints().Len(); pointIndex++ {
						point := metric.Gauge().DataPoints().At(pointIndex)
						result[metric.Name()] = append(result[metric.Name()], decodedNumberPoint(point))
					}
				case pmetric.MetricTypeSum:
					for pointIndex := 0; pointIndex < metric.Sum().DataPoints().Len(); pointIndex++ {
						point := metric.Sum().DataPoints().At(pointIndex)
						result[metric.Name()] = append(result[metric.Name()], decodedNumberPoint(point))
					}
				default:
					t.Fatalf("metric %q has unsupported type %s", metric.Name(), metric.Type())
				}
			}
		}
	}
	for name := range result {
		sort.Slice(result[name], func(i, j int) bool {
			return fmt.Sprint(result[name][i].attributes) < fmt.Sprint(result[name][j].attributes)
		})
	}
	return result
}

func decodedNumberPoint(point pmetric.NumberDataPoint) decodedPoint {
	value := point.DoubleValue()
	if point.ValueType() == pmetric.NumberDataPointValueTypeInt {
		value = float64(point.IntValue())
	}
	attributes := make(map[string]string)
	point.Attributes().Range(func(key string, value pcommon.Value) bool {
		attributes[key] = value.AsString()
		return true
	})
	return decodedPoint{value: value, timestamp: point.Timestamp().AsTime(), attributes: attributes}
}

func requireResourceString(t *testing.T, attributes pcommon.Map, key, want string) {
	t.Helper()
	value, ok := attributes.Get(key)
	require.True(t, ok, "missing resource attribute %q", key)
	require.Equal(t, want, value.Str())
}

func requireMetricValue(t *testing.T, points map[string][]decodedPoint, name string, want float64) {
	t.Helper()
	require.InDelta(t, want, firstMetricValue(t, points, name), 0.000001, name)
}

func firstMetricValue(t *testing.T, points map[string][]decodedPoint, name string) float64 {
	t.Helper()
	require.NotEmpty(t, points[name], "missing metric %q", name)
	return points[name][0].value
}
