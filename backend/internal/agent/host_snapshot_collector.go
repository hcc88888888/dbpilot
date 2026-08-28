package agent

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"dbpilot.local/platform/internal/spool"
	"dbpilot.local/platform/internal/telemetry"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gopsutilnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

const (
	hostSnapshotSourceID        = "inspection-host-snapshot"
	defaultHostBatchBytes       = 1 << 20
	MaxHostFilesystems          = 64
	MaxHostDisks                = 64
	MaxHostInterfaces           = 64
	MaxHostProcesses            = 4096
	MaxDatabaseProcessNames     = 64
	maxHostLogSummaryDataPoints = 64
)

var trustedExecutableName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type FilesystemObservation struct {
	Device            string
	Mountpoint        string
	Type              string
	UsedBytes         uint64
	TotalBytes        uint64
	UsedPercent       float64
	InodesUsedPercent float64
}

type DiskObservation struct {
	Name       string
	ReadBytes  uint64
	WriteBytes uint64
}

type NetworkObservation struct {
	Name          string
	ReceiveBytes  uint64
	TransmitBytes uint64
}

type ProcessObservation struct {
	Name   string
	Status string
}

type TimeSyncObservation struct {
	Available    bool
	Synchronized bool
}

type HostSnapshot struct {
	Hostname          string
	OSType            string
	CPUUtilization    float64
	LogicalCPUs       int
	Load1             float64
	MemoryUsedPercent float64
	SwapUsedPercent   float64
	Filesystems       []FilesystemObservation
	Disks             []DiskObservation
	Networks          []NetworkObservation
	Processes         []ProcessObservation
	BootTime          time.Time
	TimeSync          TimeSyncObservation
}

type HostReader interface {
	Read(context.Context) (HostSnapshot, error)
}

type GopsutilHostReader struct{}

func NewGopsutilHostReader() HostReader { return GopsutilHostReader{} }

func (GopsutilHostReader) Read(ctx context.Context) (HostSnapshot, error) {
	if ctx == nil {
		return HostSnapshot{}, errors.New("host reader context is required")
	}
	hostname, err := host.InfoWithContext(ctx)
	if err != nil {
		return HostSnapshot{}, err
	}
	cpuPercent, err := cpu.PercentWithContext(ctx, 100*time.Millisecond, false)
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("read CPU utilization: %w", err)
	}
	if len(cpuPercent) != 1 {
		return HostSnapshot{}, errors.New("read CPU utilization: unexpected aggregate count")
	}
	logicalCPUs, err := cpu.CountsWithContext(ctx, true)
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("read logical CPU count: %w", err)
	}
	if logicalCPUs <= 0 {
		return HostSnapshot{}, errors.New("read logical CPU count: non-positive result")
	}
	loadAverage, err := load.AvgWithContext(ctx)
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("read load average: %w", err)
	}
	memory, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("read memory utilization: %w", err)
	}
	swap, err := mem.SwapMemoryWithContext(ctx)
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("read Swap utilization: %w", err)
	}
	partitions, err := disk.PartitionsWithContext(ctx, false)
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("read filesystem partitions: %w", err)
	}
	filesystems := make([]FilesystemObservation, 0, len(partitions))
	for _, partition := range partitions {
		usage, usageErr := disk.UsageWithContext(ctx, partition.Mountpoint)
		if usageErr != nil || usage.Total == 0 {
			continue
		}
		filesystems = append(filesystems, FilesystemObservation{
			Device: partition.Device, Mountpoint: partition.Mountpoint, Type: partition.Fstype,
			UsedBytes: usage.Used, TotalBytes: usage.Total, UsedPercent: usage.UsedPercent, InodesUsedPercent: usage.InodesUsedPercent,
		})
	}
	diskCounters, err := disk.IOCountersWithContext(ctx)
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("read disk counters: %w", err)
	}
	disks := make([]DiskObservation, 0, len(diskCounters))
	for name, counter := range diskCounters {
		disks = append(disks, DiskObservation{Name: name, ReadBytes: counter.ReadBytes, WriteBytes: counter.WriteBytes})
	}
	networkCounters, err := gopsutilnet.IOCountersWithContext(ctx, true)
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("read network counters: %w", err)
	}
	networks := make([]NetworkObservation, 0, len(networkCounters))
	for _, counter := range networkCounters {
		networks = append(networks, NetworkObservation{Name: counter.Name, ReceiveBytes: counter.BytesRecv, TransmitBytes: counter.BytesSent})
	}
	processes, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return HostSnapshot{}, fmt.Errorf("read processes: %w", err)
	}
	sort.Slice(processes, func(i, j int) bool { return processes[i].Pid < processes[j].Pid })
	processObservations := make([]ProcessObservation, 0, min(len(processes), MaxHostProcesses))
	for _, current := range processes {
		if len(processObservations) >= MaxHostProcesses {
			break
		}
		name, nameErr := current.NameWithContext(ctx)
		if nameErr != nil || normalizeExecutableName(name) == "" {
			continue
		}
		status := "unknown"
		if values, statusErr := current.StatusWithContext(ctx); statusErr == nil && len(values) > 0 {
			status = values[0]
		}
		processObservations = append(processObservations, ProcessObservation{Name: normalizeExecutableName(name), Status: status})
	}
	return HostSnapshot{
		Hostname: hostname.Hostname, OSType: runtime.GOOS, CPUUtilization: cpuPercent[0], LogicalCPUs: logicalCPUs, Load1: loadAverage.Load1,
		MemoryUsedPercent: memory.UsedPercent, SwapUsedPercent: swap.UsedPercent, Filesystems: filesystems, Disks: disks, Networks: networks,
		Processes: processObservations, BootTime: time.Unix(int64(hostname.BootTime), 0).UTC(), TimeSync: readTimeSync(ctx),
	}, nil
}

type HostSnapshotStore interface {
	Append(context.Context, spool.DataClass, spool.Batch) error
	Stats() (spool.Stats, error)
}

type LogSummary = telemetry.LogSummary

type LogSummaryProvider interface {
	Snapshot(time.Time, time.Duration) []LogSummary
}

type HostSnapshotCollector struct {
	AgentID       string
	Store         HostSnapshotStore
	Reader        HostReader
	Logs          LogSummaryProvider
	ProcessNames  []string
	Now           func() time.Time
	MaxBatchBytes int64
}

func (c *HostSnapshotCollector) Collect(ctx context.Context, request CollectionRequest) error {
	if c == nil || ctx == nil || strings.TrimSpace(c.AgentID) == "" || isNilDependencyBoundary(c.Store) || isNilDependencyBoundary(c.Reader) {
		return errors.New("invalid host snapshot collector configuration")
	}
	normalized, err := normalizeCollectionRequest(request)
	if err != nil || !containsCollectionKind(normalized.Kinds, CollectionKindHost) {
		return errors.New("host collection was not requested")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	processNames, err := normalizeProcessNames(c.ProcessNames)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	snapshot, err := c.Reader.Read(ctx)
	if err != nil {
		return fmt.Errorf("read host snapshot: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stats, err := c.Store.Stats()
	if err != nil {
		return fmt.Errorf("read durable spool statistics: %w", err)
	}
	metrics, err := c.buildMetrics(snapshot, stats, processNames, now)
	if err != nil {
		return err
	}
	payload, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(metrics)
	if err != nil {
		return fmt.Errorf("marshal host snapshot metrics: %w", err)
	}
	maximum := c.MaxBatchBytes
	if maximum == 0 {
		maximum = defaultHostBatchBytes
	}
	if maximum < 0 || int64(len(payload)) > maximum {
		return fmt.Errorf("host snapshot batch exceeds exporter limit: %d > %d", len(payload), maximum)
	}
	id, err := newHostSnapshotBatchID()
	if err != nil {
		return err
	}
	if err := c.Store.Append(ctx, spool.Metric, spool.Batch{ID: id, SourceID: hostSnapshotSourceID, CreatedAt: now, Priority: 1, Payload: payload}); err != nil {
		return fmt.Errorf("append host snapshot metrics: %w", err)
	}
	return nil
}

func (c *HostSnapshotCollector) buildMetrics(snapshot HostSnapshot, stats spool.Stats, processNames []string, now time.Time) (pmetric.Metrics, error) {
	if strings.TrimSpace(snapshot.Hostname) == "" || strings.TrimSpace(snapshot.OSType) == "" || snapshot.LogicalCPUs <= 0 || snapshot.BootTime.IsZero() || snapshot.BootTime.After(now) || stats.MaxBytes <= 0 || stats.UsedBytes < 0 || stats.UsedBytes > stats.MaxBytes || stats.PendingBatches < 0 {
		return pmetric.Metrics{}, errors.New("invalid host snapshot metadata")
	}
	if !validHostPercent(snapshot.CPUUtilization) || !validHostPercent(snapshot.MemoryUsedPercent) || !validHostPercent(snapshot.SwapUsedPercent) || !finiteHostValue(snapshot.Load1) || snapshot.Load1 < 0 {
		return pmetric.Metrics{}, errors.New("invalid host utilization observation")
	}
	observations := make([]hostMetricObservation, 0, 64)
	addFloat := func(name, unit string, value float64, attributes map[string]string) error {
		if !finiteHostValue(value) {
			return fmt.Errorf("host metric %q is not finite", name)
		}
		observations = append(observations, hostMetricObservation{name: name, unit: unit, floatValue: value, attributes: attributes})
		return nil
	}
	addInt := func(name, unit string, value int64, cumulative bool, attributes map[string]string) {
		observations = append(observations, hostMetricObservation{name: name, unit: unit, intValue: value, integer: true, cumulative: cumulative, attributes: attributes})
	}
	for _, value := range []struct {
		name, unit string
		value      float64
		attributes map[string]string
	}{
		{"system.cpu.utilization", "%", snapshot.CPUUtilization, map[string]string{"state": "used"}},
		{"system.cpu.load_average.1m_per_cpu", "1", snapshot.Load1 / float64(snapshot.LogicalCPUs), nil},
		{"system.memory.utilization", "%", snapshot.MemoryUsedPercent, map[string]string{"state": "used"}},
		{"system.swap.utilization", "%", snapshot.SwapUsedPercent, map[string]string{"state": "used"}},
		{"dbpilot.inspection.host.agent.heartbeat_age_seconds", "s", 0, nil},
		{"dbpilot.inspection.host.metric.age_seconds", "s", 0, nil},
		{"dbpilot.inspection.host.spool.utilization", "%", float64(stats.UsedBytes) * 100 / float64(stats.MaxBytes), nil},
		{"system.uptime", "s", now.Sub(snapshot.BootTime.UTC()).Seconds(), nil},
	} {
		if err := addFloat(value.name, value.unit, value.value, value.attributes); err != nil {
			return pmetric.Metrics{}, err
		}
	}
	addInt("dbpilot.inspection.host.spool.used_bytes", "By", stats.UsedBytes, false, nil)
	addInt("dbpilot.inspection.host.spool.capacity_bytes", "By", stats.MaxBytes, false, nil)
	addInt("dbpilot.inspection.host.spool.pending_batch_count", "{batches}", int64(stats.PendingBatches), false, nil)
	addInt("dbpilot.inspection.host.boot_time_unix_seconds", "s", snapshot.BootTime.UTC().Unix(), false, nil)

	filesystems := append([]FilesystemObservation(nil), snapshot.Filesystems...)
	for _, filesystem := range filesystems {
		if filesystem.TotalBytes == 0 || filesystem.UsedBytes > filesystem.TotalBytes || !validHostPercent(filesystem.UsedPercent) || !validHostPercent(filesystem.InodesUsedPercent) {
			return pmetric.Metrics{}, errors.New("invalid filesystem observation")
		}
	}
	sort.Slice(filesystems, func(i, j int) bool {
		if filesystems[i].Mountpoint != filesystems[j].Mountpoint {
			return filesystems[i].Mountpoint < filesystems[j].Mountpoint
		}
		return filesystems[i].Device < filesystems[j].Device
	})
	if len(filesystems) > MaxHostFilesystems {
		filesystems = filesystems[:MaxHostFilesystems]
	}
	for _, filesystem := range filesystems {
		attributes := boundedHostAttributes(map[string]string{"device": filesystem.Device, "mountpoint": filesystem.Mountpoint, "type": filesystem.Type})
		if err := addFloat("system.filesystem.utilization", "%", filesystem.UsedPercent, attributes); err != nil {
			return pmetric.Metrics{}, err
		}
		if err := addFloat("system.filesystem.inode_utilization", "%", filesystem.InodesUsedPercent, attributes); err != nil {
			return pmetric.Metrics{}, err
		}
		usedAttributes := cloneStringMap(attributes)
		usedAttributes["state"] = "used"
		freeAttributes := cloneStringMap(attributes)
		freeAttributes["state"] = "free"
		addInt("system.filesystem.usage", "By", uint64ToInt64(filesystem.UsedBytes), false, usedAttributes)
		addInt("system.filesystem.usage", "By", uint64ToInt64(filesystem.TotalBytes-filesystem.UsedBytes), false, freeAttributes)
	}

	disks := append([]DiskObservation(nil), snapshot.Disks...)
	sort.Slice(disks, func(i, j int) bool { return disks[i].Name < disks[j].Name })
	if len(disks) > MaxHostDisks {
		disks = disks[:MaxHostDisks]
	}
	for _, disk := range disks {
		for _, direction := range []struct {
			name  string
			value uint64
		}{{"read", disk.ReadBytes}, {"write", disk.WriteBytes}} {
			addInt("system.disk.io", "By", uint64ToInt64(direction.value), true, boundedHostAttributes(map[string]string{"device": disk.Name, "direction": direction.name}))
		}
	}

	networks := append([]NetworkObservation(nil), snapshot.Networks...)
	sort.Slice(networks, func(i, j int) bool { return networks[i].Name < networks[j].Name })
	if len(networks) > MaxHostInterfaces {
		networks = networks[:MaxHostInterfaces]
	}
	for _, network := range networks {
		for _, direction := range []struct {
			name  string
			value uint64
		}{{"receive", network.ReceiveBytes}, {"transmit", network.TransmitBytes}} {
			addInt("system.network.io", "By", uint64ToInt64(direction.value), true, boundedHostAttributes(map[string]string{"device": network.Name, "direction": direction.name}))
		}
	}

	processes := append([]ProcessObservation(nil), snapshot.Processes...)
	sort.Slice(processes, func(i, j int) bool {
		if normalizeExecutableName(processes[i].Name) != normalizeExecutableName(processes[j].Name) {
			return normalizeExecutableName(processes[i].Name) < normalizeExecutableName(processes[j].Name)
		}
		return processes[i].Status < processes[j].Status
	})
	if len(processes) > MaxHostProcesses {
		processes = processes[:MaxHostProcesses]
	}
	statusCounts := make(map[string]int64)
	processAllowlist := make(map[string]struct{}, len(processNames))
	for _, name := range processNames {
		processAllowlist[name] = struct{}{}
	}
	var requiredProcesses int64
	for _, process := range processes {
		status := normalizedProcessStatus(process.Status)
		statusCounts[status]++
		if _, ok := processAllowlist[normalizeExecutableName(process.Name)]; ok {
			requiredProcesses++
		}
	}
	statuses := make([]string, 0, len(statusCounts))
	for status := range statusCounts {
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	for _, status := range statuses {
		addInt("system.processes.count", "{processes}", statusCounts[status], false, map[string]string{"status": status})
	}
	if len(processNames) == 0 {
		addInt("dbpilot.inspection.host.database.process_allowlist_available", "1", 0, false, nil)
	} else {
		addInt("dbpilot.inspection.host.database.process_allowlist_available", "1", 1, false, nil)
		addInt("dbpilot.inspection.host.database.required_process_count", "{processes}", requiredProcesses, false, nil)
	}
	if snapshot.TimeSync.Available {
		addInt("dbpilot.inspection.host.time.synchronization_available", "1", 1, false, nil)
		addInt("dbpilot.inspection.host.time.synchronized", "1", boolToInt64(snapshot.TimeSync.Synchronized), false, nil)
	} else {
		addInt("dbpilot.inspection.host.time.synchronization_available", "1", 0, false, nil)
	}

	summaries := []LogSummary(nil)
	if !isNilDependencyBoundary(c.Logs) {
		summaries = append(summaries, c.Logs.Snapshot(now, time.Hour)...)
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].SourceID != summaries[j].SourceID {
			return summaries[i].SourceID < summaries[j].SourceID
		}
		if summaries[i].Severity != summaries[j].Severity {
			return summaries[i].Severity < summaries[j].Severity
		}
		return summaries[i].Category < summaries[j].Category
	})
	if len(summaries) > maxHostLogSummaryDataPoints {
		summaries = summaries[:maxHostLogSummaryDataPoints]
	}
	if len(summaries) == 0 {
		addInt("dbpilot.inspection.host.log.summary_available", "1", 0, false, nil)
	} else {
		addInt("dbpilot.inspection.host.log.summary_available", "1", 1, false, nil)
		counts := map[string]int64{"warning": 0, "error": 0, "critical": 0, "oom": 0}
		for _, summary := range summaries {
			if summary.Count > math.MaxInt64 {
				return pmetric.Metrics{}, errors.New("log summary count exceeds metric range")
			}
			if _, ok := counts[summary.Severity]; ok {
				counts[summary.Severity] += int64(summary.Count)
			}
			if summary.Category == "oom" {
				counts["oom"] += int64(summary.Count)
			}
			addInt("dbpilot.inspection.host.log.source_count", "{events}", int64(summary.Count), false, boundedHostAttributes(map[string]string{"source.id": summary.SourceID, "severity": summary.Severity, "category": summary.Category}))
		}
		for _, severity := range []string{"warning", "error", "critical"} {
			addInt("dbpilot.inspection.host.log."+severity+"_count", "{events}", counts[severity], false, nil)
		}
		addInt("dbpilot.inspection.host.oom.count", "{events}", counts["oom"], false, nil)
	}
	if health, ok := c.Logs.(interface{ InvalidMetadataCount() uint64 }); ok {
		addInt("dbpilot.inspection.host.log.invalid_metadata_count", "{events}", uint64ToInt64(health.InvalidMetadataCount()), false, nil)
	}
	if health, ok := c.Logs.(interface{ ObserverFailureCount() uint64 }); ok {
		addInt("dbpilot.inspection.host.log.observer_failure_count", "{events}", uint64ToInt64(health.ObserverFailureCount()), false, nil)
	}

	return encodeHostMetrics(observations, c.AgentID, snapshot, now)
}

type hostMetricObservation struct {
	name       string
	unit       string
	floatValue float64
	intValue   int64
	integer    bool
	cumulative bool
	attributes map[string]string
}

func encodeHostMetrics(observations []hostMetricObservation, agentID string, snapshot HostSnapshot, now time.Time) (pmetric.Metrics, error) {
	sort.Slice(observations, func(i, j int) bool {
		if observations[i].name != observations[j].name {
			return observations[i].name < observations[j].name
		}
		return canonicalAttributes(observations[i].attributes) < canonicalAttributes(observations[j].attributes)
	})
	metrics := pmetric.NewMetrics()
	resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
	resource := resourceMetrics.Resource().Attributes()
	resource.PutStr("agent.id", agentID)
	resource.PutStr("dbpilot.agent.id", agentID)
	resource.PutStr("dbpilot.source.id", hostSnapshotSourceID)
	resource.PutStr("host.name", snapshot.Hostname)
	resource.PutStr("os.type", strings.ToLower(snapshot.OSType))
	resource.PutStr("inspection.snapshot_at", now.Format(time.RFC3339Nano))
	scope := resourceMetrics.ScopeMetrics().AppendEmpty()
	scope.Scope().SetName("dbpilot.host-inspection")
	var metric pmetric.Metric
	currentName := ""
	for _, observation := range observations {
		if observation.name == "" || observation.unit == "" {
			return pmetric.Metrics{}, errors.New("invalid host metric identity")
		}
		if observation.name != currentName {
			metric = scope.Metrics().AppendEmpty()
			metric.SetName(observation.name)
			metric.SetUnit(observation.unit)
			if observation.cumulative {
				metric.SetEmptySum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
				metric.Sum().SetIsMonotonic(true)
			} else {
				metric.SetEmptyGauge()
			}
			currentName = observation.name
		}
		var point pmetric.NumberDataPoint
		if observation.cumulative {
			point = metric.Sum().DataPoints().AppendEmpty()
		} else {
			point = metric.Gauge().DataPoints().AppendEmpty()
		}
		point.SetTimestamp(pcommon.NewTimestampFromTime(now))
		if observation.integer {
			point.SetIntValue(observation.intValue)
		} else {
			point.SetDoubleValue(observation.floatValue)
		}
		for key, value := range observation.attributes {
			point.Attributes().PutStr(key, value)
		}
	}
	return metrics, nil
}

func normalizeProcessNames(values []string) ([]string, error) {
	if len(values) > MaxDatabaseProcessNames {
		return nil, fmt.Errorf("database process-name allowlist exceeds %d", MaxDatabaseProcessNames)
	}
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		if strings.ContainsAny(raw, "\x00\r\n/\\") {
			return nil, fmt.Errorf("invalid database process name %q", raw)
		}
		name := normalizeExecutableName(raw)
		if !trustedExecutableName.MatchString(name) {
			return nil, fmt.Errorf("invalid database process name %q", raw)
		}
		seen[name] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

func NormalizeDatabaseProcessNames(values []string) ([]string, error) {
	return normalizeProcessNames(values)
}

func normalizeExecutableName(value string) string {
	return strings.ToLower(strings.TrimSpace(filepath.Base(value)))
}

func normalizedProcessStatus(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, allowed := range []string{"blocked", "daemon", "detached", "idle", "locked", "orphan", "paging", "running", "sleeping", "stopped", "system", "zombies"} {
		if value == allowed || (value == "zombie" && allowed == "zombies") {
			return allowed
		}
	}
	return "unknown"
}

func containsCollectionKind(kinds []string, target string) bool {
	for _, kind := range kinds {
		if kind == target {
			return true
		}
	}
	return false
}

func boundedHostAttributes(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		value = strings.TrimSpace(value)
		if len(value) > 128 {
			value = value[:128]
		}
		result[key] = value
	}
	return result
}

func cloneStringMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values)+1)
	for key, value := range values {
		result[key] = value
	}
	return result
}

func canonicalAttributes(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result strings.Builder
	for _, key := range keys {
		result.WriteString(key)
		result.WriteByte('=')
		result.WriteString(values[key])
		result.WriteByte(0)
	}
	return result.String()
}

func finiteHostValue(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
func validHostPercent(value float64) bool {
	return finiteHostValue(value) && value >= 0 && value <= 100
}
func boolToInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
func uint64ToInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}

func newHostSnapshotBatchID() (string, error) {
	var value [16]byte
	if _, err := cryptorand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate host snapshot batch ID: %w", err)
	}
	return fmt.Sprintf("%x", value[:]), nil
}

var _ Collector = (*HostSnapshotCollector)(nil)
