package telemetry

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

const (
	MaxLogSummarySources    = 64
	MaxLogSummaryCategories = 16
	maximumLogSummaryWindow = time.Hour
)

var unsafeSummaryIdentifier = regexp.MustCompile(`[^A-Za-z0-9_.:-]+`)

type LogSummary struct {
	SourceID   string
	Severity   string
	Category   string
	Count      uint64
	ObservedAt time.Time
}

type LogObserver interface {
	Observe(context.Context, plog.Logs) error
}

type logSummaryKey struct {
	second   int64
	source   string
	severity string
	category string
}

type logSummaryCounter struct {
	count      uint64
	observedAt time.Time
}

// LogSummaryIndex retains counters only. Log bodies are inspected transiently
// for OOM markers and are never copied into index state.
type LogSummaryIndex struct {
	mu               sync.Mutex
	now              func() time.Time
	startedAt        time.Time
	counters         map[logSummaryKey]logSummaryCounter
	invalidMetadata  uint64
	observerFailures uint64
}

func NewLogSummaryIndex(clocks ...func() time.Time) *LogSummaryIndex {
	now := time.Now
	if len(clocks) > 0 && clocks[0] != nil {
		now = clocks[0]
	}
	startedAt := now().UTC()
	return &LogSummaryIndex{now: now, startedAt: startedAt, counters: make(map[logSummaryKey]logSummaryCounter)}
}

func (index *LogSummaryIndex) Observe(ctx context.Context, logs plog.Logs) error {
	if index == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := index.currentTime()
	index.mu.Lock()
	defer index.mu.Unlock()
	index.pruneLocked(now.Add(-maximumLogSummaryWindow))
	knownSources := index.sourcesLocked()

	for resourceIndex := 0; resourceIndex < logs.ResourceLogs().Len(); resourceIndex++ {
		resourceLogs := logs.ResourceLogs().At(resourceIndex)
		source, valid := summaryAttribute(resourceLogs.Resource().Attributes(), "dbpilot.source.id")
		source = sanitizeSummaryIdentifier(source, 64)
		if !valid || source == "" {
			index.invalidMetadata += uint64(resourceLogRecordCount(resourceLogs))
			continue
		}
		_, knownSource := knownSources[source]
		if !knownSource && len(knownSources) >= MaxLogSummarySources {
			index.invalidMetadata += uint64(resourceLogRecordCount(resourceLogs))
			continue
		}
		knownCategories := index.categoriesLocked(source)
		for scopeIndex := 0; scopeIndex < resourceLogs.ScopeLogs().Len(); scopeIndex++ {
			records := resourceLogs.ScopeLogs().At(scopeIndex).LogRecords()
			for recordIndex := 0; recordIndex < records.Len(); recordIndex++ {
				record := records.At(recordIndex)
				severity, ok := normalizedSeverity(record.SeverityNumber(), record.SeverityText())
				observedAt := logObservedAt(record, now)
				if !ok || observedAt.Before(index.startedAt) || observedAt.Before(now.Add(-maximumLogSummaryWindow)) || observedAt.After(now.Add(time.Minute)) {
					index.invalidMetadata++
					continue
				}
				if !knownSource {
					knownSources[source] = struct{}{}
					knownSource = true
				}
				category := logCategory(record)
				if category != "general" && category != "oom" {
					if _, known := knownCategories[category]; !known && len(knownCategories) >= MaxLogSummaryCategories-2 {
						index.invalidMetadata++
						continue
					}
					knownCategories[category] = struct{}{}
				}
				key := logSummaryKey{second: observedAt.Unix(), source: source, severity: severity, category: category}
				counter := index.counters[key]
				counter.count++
				if observedAt.After(counter.observedAt) {
					counter.observedAt = observedAt
				}
				index.counters[key] = counter
			}
		}
	}
	return nil
}

func resourceLogRecordCount(resourceLogs plog.ResourceLogs) int {
	count := 0
	for index := 0; index < resourceLogs.ScopeLogs().Len(); index++ {
		count += resourceLogs.ScopeLogs().At(index).LogRecords().Len()
	}
	return count
}

func (index *LogSummaryIndex) Snapshot(now time.Time, window time.Duration) []LogSummary {
	if index == nil || window <= 0 {
		return nil
	}
	now = now.UTC()
	if window > maximumLogSummaryWindow {
		window = maximumLogSummaryWindow
	}
	from := now.Add(-window)
	index.mu.Lock()
	defer index.mu.Unlock()
	index.pruneLocked(now.Add(-maximumLogSummaryWindow))
	aggregated := make(map[struct{ source, severity, category string }]LogSummary)
	for key, counter := range index.counters {
		if counter.observedAt.Before(from) || counter.observedAt.After(now) || counter.observedAt.Before(index.startedAt) {
			continue
		}
		aggregateKey := struct{ source, severity, category string }{key.source, key.severity, key.category}
		summary := aggregated[aggregateKey]
		summary.SourceID, summary.Severity, summary.Category = key.source, key.severity, key.category
		summary.Count += counter.count
		if counter.observedAt.After(summary.ObservedAt) {
			summary.ObservedAt = counter.observedAt
		}
		aggregated[aggregateKey] = summary
	}
	result := make([]LogSummary, 0, len(aggregated))
	for _, summary := range aggregated {
		result = append(result, summary)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].SourceID != result[j].SourceID {
			return result[i].SourceID < result[j].SourceID
		}
		if result[i].Severity != result[j].Severity {
			return result[i].Severity < result[j].Severity
		}
		return result[i].Category < result[j].Category
	})
	return result
}

func (index *LogSummaryIndex) InvalidMetadataCount() uint64 {
	if index == nil {
		return 0
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	return index.invalidMetadata
}

func (index *LogSummaryIndex) RecordObserverFailure() {
	if index == nil {
		return
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	index.observerFailures++
}

func (index *LogSummaryIndex) ObserverFailureCount() uint64 {
	if index == nil {
		return 0
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	return index.observerFailures
}

func (index *LogSummaryIndex) currentTime() time.Time {
	if index.now == nil {
		return time.Now().UTC()
	}
	return index.now().UTC()
}

func (index *LogSummaryIndex) pruneLocked(cutoff time.Time) {
	for key, counter := range index.counters {
		if counter.observedAt.Before(cutoff) {
			delete(index.counters, key)
		}
	}
}

func (index *LogSummaryIndex) sourcesLocked() map[string]struct{} {
	result := make(map[string]struct{})
	for key := range index.counters {
		result[key.source] = struct{}{}
	}
	return result
}

func (index *LogSummaryIndex) categoriesLocked(source string) map[string]struct{} {
	result := make(map[string]struct{})
	for key := range index.counters {
		if key.source == source && key.category != "general" && key.category != "oom" {
			result[key.category] = struct{}{}
		}
	}
	return result
}

func normalizedSeverity(number plog.SeverityNumber, text string) (string, bool) {
	switch {
	case number >= plog.SeverityNumberFatal && number <= plog.SeverityNumberFatal4:
		return "critical", true
	case number >= plog.SeverityNumberError && number <= plog.SeverityNumberError4:
		return "error", true
	case number >= plog.SeverityNumberWarn && number <= plog.SeverityNumberWarn4:
		return "warning", true
	case number >= plog.SeverityNumberInfo && number <= plog.SeverityNumberInfo4:
		return "info", true
	case number >= plog.SeverityNumberTrace && number <= plog.SeverityNumberDebug4:
		return "debug", true
	case number != plog.SeverityNumberUnspecified:
		return "", false
	}
	value := strings.ToLower(strings.TrimSpace(text))
	switch {
	case strings.HasPrefix(value, "fatal"), strings.HasPrefix(value, "critical"), strings.HasPrefix(value, "emerg"), strings.HasPrefix(value, "alert"):
		return "critical", true
	case strings.HasPrefix(value, "err"):
		return "error", true
	case strings.HasPrefix(value, "warn"):
		return "warning", true
	case strings.HasPrefix(value, "info"), strings.HasPrefix(value, "notice"):
		return "info", true
	case strings.HasPrefix(value, "debug"), strings.HasPrefix(value, "trace"):
		return "debug", true
	default:
		return "", false
	}
}

func logObservedAt(record plog.LogRecord, fallback time.Time) time.Time {
	if record.Timestamp() != 0 {
		return record.Timestamp().AsTime().UTC()
	}
	if record.ObservedTimestamp() != 0 {
		return record.ObservedTimestamp().AsTime().UTC()
	}
	return fallback.UTC()
}

func logCategory(record plog.LogRecord) string {
	if record.Body().Type() == pcommon.ValueTypeStr {
		body := strings.ToLower(record.Body().Str())
		for _, marker := range []string{"out of memory", "oom-killer", "oom killer", "killed process"} {
			if strings.Contains(body, marker) {
				return "oom"
			}
		}
	}
	for _, key := range []string{"dbpilot.log.category", "event.category"} {
		if value, ok := summaryAttribute(record.Attributes(), key); ok {
			if sanitized := sanitizeSummaryIdentifier(strings.ToLower(value), 32); sanitized != "" {
				return sanitized
			}
		}
	}
	return "general"
}

func summaryAttribute(attributes pcommon.Map, key string) (string, bool) {
	value, ok := attributes.Get(key)
	if !ok || value.Type() != pcommon.ValueTypeStr || strings.TrimSpace(value.Str()) == "" {
		return "", false
	}
	return value.Str(), true
}

func sanitizeSummaryIdentifier(value string, maximum int) string {
	value = unsafeSummaryIdentifier.ReplaceAllString(strings.TrimSpace(value), "_")
	value = strings.Trim(value, "_")
	if len(value) > maximum {
		value = value[:maximum]
	}
	return value
}

var _ LogObserver = (*LogSummaryIndex)(nil)
