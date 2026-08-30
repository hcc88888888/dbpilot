package hostinventory

import (
	"math"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestClassifyHostRequiresRealHeartbeat(t *testing.T) {
	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	got := ClassifyHost(now, Host{LastHelloAt: now, LastHeartbeatAt: time.Time{}}, time.Minute, 5*time.Minute)
	require.Equal(t, HostOffline, got)
}

func TestClassifyHostUsesStaleAndOfflineWindows(t *testing.T) {
	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		heartbeat time.Time
		want      HostStatus
	}{
		{name: "fresh heartbeat", heartbeat: now.Add(-time.Minute), want: HostOnline},
		{name: "past stale window", heartbeat: now.Add(-2 * time.Minute), want: HostStale},
		{name: "past offline window", heartbeat: now.Add(-6 * time.Minute), want: HostOffline},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			host := Host{LastHeartbeatAt: test.heartbeat}
			require.Equal(t, test.want, ClassifyHost(now, host, time.Minute, 5*time.Minute))
		})
	}
}

func TestClassifyHostPreservesDecommissionedState(t *testing.T) {
	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	host := Host{Status: HostDecommissioned, LastHeartbeatAt: now}
	require.Equal(t, HostDecommissioned, ClassifyHost(now, host, time.Minute, 5*time.Minute))
}

func TestClassifyHostPreservesPreHeartbeatEnrollmentStates(t *testing.T) {
	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	for _, status := range []HostStatus{HostPending, HostEnrolling} {
		require.Equal(t, status, ClassifyHost(now, Host{Status: status}, time.Minute, 5*time.Minute))
	}
}

func TestHostStatusTransitionsAllowRecoveryAndKeepDecommissionTerminal(t *testing.T) {
	allowed := [][2]HostStatus{
		{HostPending, HostEnrolling},
		{HostEnrolling, HostOnline},
		{HostOnline, HostStale},
		{HostStale, HostOffline},
		{HostStale, HostOnline},
		{HostOffline, HostOnline},
		{HostPending, HostDecommissioned},
		{HostOffline, HostDecommissioned},
	}
	for _, transition := range allowed {
		require.True(t, CanTransitionHostStatus(transition[0], transition[1]), "%s -> %s", transition[0], transition[1])
	}
	for _, next := range []HostStatus{HostPending, HostEnrolling, HostOnline, HostStale, HostOffline} {
		require.False(t, CanTransitionHostStatus(HostDecommissioned, next), "decommissioned -> %s", next)
	}
	require.False(t, CanTransitionHostStatus(HostOnline, HostPending))
}

func TestHostValidationEnforcesScopeIdentityAndInventoryBounds(t *testing.T) {
	valid := validHostFixture()
	require.NoError(t, valid.Validate())

	tests := []struct {
		name   string
		mutate func(*Host)
	}{
		{name: "missing tenant", mutate: func(host *Host) { host.Scope.TenantID = "" }},
		{name: "noncanonical project", mutate: func(host *Host) { host.Scope.ProjectID = " project-1" }},
		{name: "oversized display name", mutate: func(host *Host) { host.DisplayName = stringOfLength(121) }},
		{name: "oversized hostname", mutate: func(host *Host) { host.Hostname = stringOfLength(254) }},
		{name: "oversized operating system", mutate: func(host *Host) { host.OperatingSystem = stringOfLength(65) }},
		{name: "oversized architecture", mutate: func(host *Host) { host.Architecture = stringOfLength(33) }},
		{name: "too many addresses", mutate: func(host *Host) { host.NetworkAddresses = repeatedStrings(33, "10.0.0.1") }},
		{name: "duplicate address", mutate: func(host *Host) { host.NetworkAddresses = []string{"10.0.0.1", "10.0.0.1"} }},
		{name: "too many labels", mutate: func(host *Host) { host.Labels = numberedMap(33) }},
		{name: "oversized label value", mutate: func(host *Host) { host.Labels = map[string]string{"role": stringOfLength(129)} }},
		{name: "too many filesystems", mutate: func(host *Host) { host.Filesystems = repeatedFilesystems(129) }},
		{name: "filesystem available exceeds capacity", mutate: func(host *Host) {
			host.Filesystems = []FilesystemSummary{{MountPoint: "/", CapacityBytes: 10, AvailableBytes: 11}}
		}},
		{name: "too many capabilities", mutate: func(host *Host) { host.Capabilities = repeatedCapabilities(65) }},
		{name: "zero enrollment revision", mutate: func(host *Host) { host.EnrollmentRevision = 0 }},
		{name: "invalid etag version", mutate: func(host *Host) { host.Version = 0 }},
		{name: "etag version exceeds PostgreSQL bigint", mutate: func(host *Host) { host.Version = math.MaxUint64 }},
		{name: "resource capacity exceeds PostgreSQL bigint", mutate: func(host *Host) { host.Memory.Capacity = math.MaxUint64 }},
		{name: "filesystem capacity exceeds PostgreSQL bigint", mutate: func(host *Host) { host.Filesystems[0].CapacityBytes = math.MaxUint64 }},
		{name: "non UTC enrolled timestamp", mutate: func(host *Host) { host.EnrolledAt = host.EnrolledAt.In(time.FixedZone("offset", 3600)) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host := validHostFixture()
			test.mutate(&host)
			require.ErrorIs(t, host.Validate(), ErrInvalid)
		})
	}
}

func TestObservationValidationRequiresMonotonicRevisionShapeAndBounds(t *testing.T) {
	valid := validObservationFixture()
	require.NoError(t, valid.Validate())

	tests := []struct {
		name   string
		mutate func(*Observation)
	}{
		{name: "missing host", mutate: func(value *Observation) { value.HostID = "" }},
		{name: "missing agent", mutate: func(value *Observation) { value.AgentID = "" }},
		{name: "zero revision", mutate: func(value *Observation) { value.Revision = 0 }},
		{name: "revision exceeds PostgreSQL bigint", mutate: func(value *Observation) { value.Revision = math.MaxUint64 }},
		{name: "memory capacity exceeds PostgreSQL bigint", mutate: func(value *Observation) { value.MemoryCapacityBytes = math.MaxUint64 }},
		{name: "oversized hostname", mutate: func(value *Observation) { value.Hostname = stringOfLength(254) }},
		{name: "oversized agent version", mutate: func(value *Observation) { value.AgentVersion = stringOfLength(65) }},
		{name: "duplicate capability", mutate: func(value *Observation) { value.Capabilities = []string{"host.collect", "host.collect"} }},
		{name: "zero observed timestamp", mutate: func(value *Observation) { value.ObservedAt = time.Time{} }},
		{name: "non UTC observed timestamp", mutate: func(value *Observation) { value.ObservedAt = value.ObservedAt.In(time.FixedZone("offset", 3600)) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := validObservationFixture()
			test.mutate(&observation)
			require.ErrorIs(t, observation.Validate(), ErrInvalid)
		})
	}
}

func TestMigrationDefinesScopedUniqueHostsAndAppendOnlyObservations(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/0001_host_inventory.sql")
	require.NoError(t, err)
	schema := string(content)
	for _, required := range []string{
		"CREATE TABLE managed_hosts",
		"CREATE TABLE host_observations",
		"UNIQUE (tenant_id, project_id, host_id)",
		"UNIQUE (tenant_id, project_id, agent_id)",
		"UNIQUE (tenant_id, project_id, host_id, agent_id)",
		"UNIQUE (agent_id)",
		"PRIMARY KEY (tenant_id, project_id, host_id, observation_revision)",
		"FOREIGN KEY (tenant_id, project_id, host_id)",
		"FOREIGN KEY (tenant_id, project_id, host_id, agent_id)",
		"observation_revision BIGINT NOT NULL CHECK (observation_revision >= 0)",
		"CHECK (status IN ('pending', 'enrolling', 'online', 'stale', 'offline', 'decommissioned'))",
		"host_observations_append_only",
		"BEFORE UPDATE OR DELETE ON host_observations",
	} {
		require.Contains(t, schema, required)
	}
}

func validHostFixture() Host {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	return Host{
		Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		ID:    "host-1", AgentID: "agent-1", DisplayName: "DB host", Hostname: "db-1.example",
		OperatingSystem: "linux", OperatingSystemVersion: "kylin-v10", KernelVersion: "5.10", Architecture: "amd64",
		CPU: ResourceSummary{Capacity: 8, Available: 2}, Memory: ResourceSummary{Capacity: 1024, Available: 512},
		Filesystems:      []FilesystemSummary{{MountPoint: "/", CapacityBytes: 1024, AvailableBytes: 512}},
		NetworkAddresses: []string{"10.0.0.1"}, Labels: map[string]string{"role": "database"}, ContainerRuntime: ContainerRuntimeNone,
		Capabilities: []Capability{{Name: "host.collect", Available: true}}, AgentVersion: "1.0.0",
		EnrollmentRevision: 1, ObservationRevision: 2, EnrolledAt: now.Add(-time.Hour), LastHelloAt: now.Add(-time.Minute), LastHeartbeatAt: now.Add(-time.Minute),
		Status: HostOnline, Version: 2,
	}
}

func validObservationFixture() Observation {
	return Observation{
		HostID: "host-1", AgentID: "agent-1", Revision: 2, AgentVersion: "1.0.0", Hostname: "db-1.example",
		OS: "linux", OSVersion: "kylin-v10", Kernel: "5.10", Architecture: "amd64",
		LogicalCPUCount: 8, MemoryCapacityBytes: 1024,
		Filesystems:      []FilesystemSummary{{MountPoint: "/", CapacityBytes: 1024, AvailableBytes: 512}},
		NetworkAddresses: []string{"10.0.0.1"}, Capabilities: []string{"host.collect"},
		ObservedAt: time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC),
	}
}

func stringOfLength(length int) string {
	value := make([]byte, length)
	for index := range value {
		value[index] = 'a'
	}
	return string(value)
}

func repeatedStrings(count int, value string) []string {
	items := make([]string, count)
	for index := range items {
		items[index] = value + string(rune('A'+index))
	}
	return items
}

func numberedMap(count int) map[string]string {
	items := make(map[string]string, count)
	for index := 0; index < count; index++ {
		items[string(rune('a'+index/26))+string(rune('a'+index%26))] = "value"
	}
	return items
}

func repeatedFilesystems(count int) []FilesystemSummary {
	items := make([]FilesystemSummary, count)
	for index := range items {
		items[index] = FilesystemSummary{MountPoint: "/mount/" + string(rune('a'+index%26)), CapacityBytes: 10, AvailableBytes: 5}
	}
	return items
}

func repeatedCapabilities(count int) []Capability {
	items := make([]Capability, count)
	for index := range items {
		items[index] = Capability{Name: "capability." + string(rune('a'+index%26)), Available: true}
	}
	return items
}
