package telemetry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestLogSummaryIndexKeepsOnlyBoundedNormalizedCounters(t *testing.T) {
	now := time.Date(2026, 8, 29, 8, 30, 0, 0, time.UTC)
	index := NewLogSummaryIndex(func() time.Time { return now })
	logs := plog.NewLogs()
	appendTestLog(logs, "db/source name", plog.SeverityNumberWarn, "", now, "ordinary warning password=do-not-retain")
	appendTestLog(logs, "db/source name", plog.SeverityNumberError, "", now, "kernel: Out of memory: Killed process 42 secret")
	appendTestLog(logs, "db/source name", plog.SeverityNumberUnspecified, "CRITICAL", now, "critical but bounded")

	require.NoError(t, index.Observe(context.Background(), logs))
	require.Equal(t, []LogSummary{
		{SourceID: "db_source_name", Severity: "critical", Category: "general", Count: 1, ObservedAt: now},
		{SourceID: "db_source_name", Severity: "error", Category: "oom", Count: 1, ObservedAt: now},
		{SourceID: "db_source_name", Severity: "warning", Category: "general", Count: 1, ObservedAt: now},
	}, index.Snapshot(now, time.Hour))
	require.NotContains(t, fmt.Sprintf("%#v", index), "do-not-retain")
	require.NotContains(t, fmt.Sprintf("%#v", index), "secret")
}

func TestLogSummaryIndexClassifiesCanonicalFileLogSeverityPrefix(t *testing.T) {
	now := time.Date(2026, 8, 29, 8, 30, 0, 0, time.UTC)
	index := NewLogSummaryIndex(func() time.Time { return now })
	logs := plog.NewLogs()
	appendTestLog(logs, "acceptance-filelog", plog.SeverityNumberUnspecified, "", now, "WARN controlled acceptance log")

	require.NoError(t, index.Observe(context.Background(), logs))
	require.Equal(t, []LogSummary{{SourceID: "acceptance-filelog", Severity: "warning", Category: "general", Count: 1, ObservedAt: now}}, index.Snapshot(now, time.Hour))
	require.NotContains(t, fmt.Sprintf("%#v", index), "controlled acceptance log")
}

func TestLogSummaryIndexBoundsSourcesWindowAndInvalidMetadata(t *testing.T) {
	now := time.Date(2026, 8, 29, 8, 30, 0, 0, time.UTC)
	clock := now.Add(-2 * time.Hour)
	index := NewLogSummaryIndex(func() time.Time { return clock })
	logs := plog.NewLogs()
	appendTestLog(logs, "old", plog.SeverityNumberError, "", now.Add(-61*time.Minute), "old")
	for source := 0; source < MaxLogSummarySources+1; source++ {
		appendTestLog(logs, fmt.Sprintf("source-%03d", source), plog.SeverityNumberWarn, "", now, "warning")
	}
	appendTestLog(logs, "invalid-severity", plog.SeverityNumberUnspecified, "verbose-ish", now, "ignored")
	clock = now

	require.NoError(t, index.Observe(context.Background(), logs))
	summaries := index.Snapshot(now, time.Hour)
	require.Len(t, summaries, MaxLogSummarySources)
	require.Equal(t, "source-000", summaries[0].SourceID)
	require.Equal(t, "source-063", summaries[len(summaries)-1].SourceID)
	require.Equal(t, uint64(3), index.InvalidMetadataCount())
}

func TestLogSummaryIndexEmptyPostStartWindowStaysEmpty(t *testing.T) {
	now := time.Date(2026, 8, 29, 8, 30, 0, 0, time.UTC)
	index := NewLogSummaryIndex(func() time.Time { return now })
	require.Empty(t, index.Snapshot(now, 5*time.Minute))
}

func TestLogSummaryIndexCapsCustomCategoryCardinality(t *testing.T) {
	now := time.Date(2026, 8, 29, 8, 30, 0, 0, time.UTC)
	index := NewLogSummaryIndex(func() time.Time { return now })
	logs := plog.NewLogs()
	for category := 0; category < MaxLogSummaryCategories; category++ {
		resourceLogs := logs.ResourceLogs().AppendEmpty()
		resourceLogs.Resource().Attributes().PutStr("dbpilot.source.id", "source-a")
		record := resourceLogs.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
		record.SetTimestamp(pcommon.NewTimestampFromTime(now))
		record.SetSeverityNumber(plog.SeverityNumberWarn)
		record.Attributes().PutStr("dbpilot.log.category", fmt.Sprintf("category-%02d", category))
	}
	appendTestLog(logs, "source-a", plog.SeverityNumberError, "", now, "Out of memory")
	appendTestLog(logs, "source-a", plog.SeverityNumberInfo, "", now, "general")

	require.NoError(t, index.Observe(context.Background(), logs))
	summaries := index.Snapshot(now, time.Hour)
	require.LessOrEqual(t, len(summaries), MaxLogSummaryCategories)
	require.Contains(t, summaries, LogSummary{SourceID: "source-a", Severity: "error", Category: "oom", Count: 1, ObservedAt: now})
	require.Contains(t, summaries, LogSummary{SourceID: "source-a", Severity: "info", Category: "general", Count: 1, ObservedAt: now})
	require.Equal(t, uint64(2), index.InvalidMetadataCount())
}

func TestSpoolLogsConsumerObserverFailureCannotDropOrMutateOriginalBatch(t *testing.T) {
	store := &capturingLogStore{}
	observer := &mutatingFailingObserver{err: errors.New("observer unavailable")}
	consumer, err := newSpoolLogsConsumer(store, ExporterConfig{MaxBatchBytes: 1 << 20}, observer)
	require.NoError(t, err)
	logs := plog.NewLogs()
	appendTestLog(logs, "source-a", plog.SeverityNumberError, "", time.Now().UTC(), "original body")

	require.NoError(t, consumer.ConsumeLogs(context.Background(), logs))
	require.Len(t, store.batches, 1)
	decoded, err := (&plog.ProtoUnmarshaler{}).UnmarshalLogs(store.batches[0].Payload)
	require.NoError(t, err)
	body := decoded.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Str()
	require.Equal(t, "original body", body)
	require.Equal(t, uint64(1), observer.failures)
}

func TestSpoolLogsConsumerObserverAndFailureRecorderPanicsCannotDropOriginalBatch(t *testing.T) {
	tests := []struct {
		name     string
		observer *panickingHealthObserver
	}{
		{name: "observer panic", observer: &panickingHealthObserver{panicInObserve: true}},
		{name: "failure recorder panic", observer: &panickingHealthObserver{panicInRecord: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &capturingLogStore{}
			consumer, err := newSpoolLogsConsumer(store, ExporterConfig{MaxBatchBytes: 1 << 20}, test.observer)
			require.NoError(t, err)
			logs := plog.NewLogs()
			appendTestLog(logs, "source-a", plog.SeverityNumberError, "", time.Now().UTC(), "original body")

			require.NotPanics(t, func() {
				require.NoError(t, consumer.ConsumeLogs(context.Background(), logs))
			})
			require.Len(t, store.batches, 1)
			decoded, err := (&plog.ProtoUnmarshaler{}).UnmarshalLogs(store.batches[0].Payload)
			require.NoError(t, err)
			require.Equal(t, "original body", decoded.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Str())
		})
	}
}

func appendTestLog(logs plog.Logs, source string, severity plog.SeverityNumber, severityText string, timestamp time.Time, body string) {
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	resourceLogs.Resource().Attributes().PutStr("dbpilot.source.id", source)
	record := resourceLogs.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	record.SetTimestamp(pcommon.NewTimestampFromTime(timestamp))
	record.SetSeverityNumber(severity)
	record.SetSeverityText(severityText)
	record.Body().SetStr(body)
}

type capturingLogStore struct{ batches []spool.Batch }

func (store *capturingLogStore) Append(_ context.Context, class spool.DataClass, batch spool.Batch) error {
	if class != spool.Log {
		return errors.New("unexpected data class")
	}
	store.batches = append(store.batches, batch)
	return nil
}

type mutatingFailingObserver struct {
	err      error
	failures uint64
}

func (observer *mutatingFailingObserver) Observe(_ context.Context, logs plog.Logs) error {
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().SetStr(strings.Repeat("mutated", 10))
	return observer.err
}

func (observer *mutatingFailingObserver) RecordObserverFailure() { observer.failures++ }

type panickingHealthObserver struct {
	panicInObserve bool
	panicInRecord  bool
}

func (observer *panickingHealthObserver) Observe(_ context.Context, logs plog.Logs) error {
	logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().SetStr("observer mutation")
	if observer.panicInObserve {
		panic("observer panic")
	}
	return errors.New("observer failure")
}

func (observer *panickingHealthObserver) RecordObserverFailure() {
	if observer.panicInRecord {
		panic("failure recorder panic")
	}
}
