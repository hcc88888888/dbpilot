package rediscovery

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	discoverydomain "dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestRediscoveryCreatesOneScopedTypedJobFromCurrentPolicyAndLiveCapabilities(t *testing.T) {
	fixture := newRediscoveryFixture()

	created, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", RediscoveryRequest{Actor: "operator-a", IdempotencyKey: "rediscover-a", RequestFingerprint: "sha256:" + repeatHex("a"), RequestID: "request-a", TraceID: "trace-a"})

	require.NoError(t, err)
	require.Equal(t, job.StatusQueued, created.Status)
	require.Equal(t, int64(1), created.Version)
	require.Equal(t, fixture.scope, created.Scope)
	require.Equal(t, "host.rediscover", created.Type)
	require.Equal(t, []string{"agent-a"}, created.TargetResourceIDs)
	require.Equal(t, "host", created.SourceResource.ResourceType)
	require.Equal(t, "host-a", created.SourceResource.ResourceID)
	require.Len(t, fixture.jobs.messages, 1)
	envelope := new(agentv1.CommandEnvelope)
	require.NoError(t, proto.Unmarshal(fixture.jobs.messages[0].Payload, envelope))
	require.Equal(t, "agent-a", envelope.GetAgentId())
	require.Equal(t, "host-a", envelope.GetDiscoverDatabases().GetHostId())
	require.Equal(t, uint64(7), envelope.GetDiscoverDatabases().GetRuleRevision())
	require.True(t, envelope.GetDiscoverDatabases().GetIncludeNative())
	require.True(t, envelope.GetDiscoverDatabases().GetIncludeDocker())
	require.NotContains(t, string(fixture.jobs.messages[0].Payload), "secret")
}

func TestRediscoveryRecoversUnknownCommitAndRejectsOfflineOrUnnegotiatedHost(t *testing.T) {
	fixture := newRediscoveryFixture()
	request := RediscoveryRequest{Actor: "operator-a", IdempotencyKey: "rediscover-a", RequestFingerprint: "sha256:" + repeatHex("a"), RequestID: "request-a", TraceID: "trace-a"}
	fixture.jobs.failAfterCreate = errors.New("connection lost after commit")

	first, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
	require.NoError(t, err)
	second, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
	require.NoError(t, err)
	require.Equal(t, first.ID, second.ID)
	require.Equal(t, 1, fixture.jobs.created, "lost response replay must not create a second Job")

	fixture = newRediscoveryFixture()
	fixture.hosts.value.Status = hostinventory.HostOffline
	_, err = fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
	require.ErrorIs(t, err, ErrHostNotOnline)
	require.Zero(t, fixture.jobs.created)

	fixture = newRediscoveryFixture()
	delete(fixture.capabilities.allowed, "discovery_report_ack_v1")
	_, err = fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
	require.ErrorIs(t, err, ErrRediscoveryUnavailable)
	require.Zero(t, fixture.jobs.created)
}

type rediscoveryFixture struct {
	scope        platformscope.Scope
	hosts        *memoryRediscoveryHosts
	jobs         *memoryRediscoveryJobs
	capabilities *memoryRediscoveryCapabilities
	service      *RediscoveryCoordinator
}

func newRediscoveryFixture() rediscoveryFixture {
	now := time.Date(2026, 9, 4, 3, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	host := hostinventory.Host{Scope: scope, ID: "host-a", AgentID: "agent-a", DisplayName: "Host A", Hostname: "host-a", OperatingSystem: "linux", Architecture: "amd64", NetworkAddresses: []string{}, Labels: map[string]string{}, ContainerRuntime: hostinventory.ContainerRuntimeDocker, Capabilities: []hostinventory.Capability{{Name: "native_discovery_v1", Available: true}, {Name: "docker_discovery_v1", Available: true}}, EnrollmentRevision: 1, ObservationRevision: 1, EnrolledAt: now.Add(-time.Hour), LastHeartbeatAt: now.Add(-time.Second), Status: hostinventory.HostOnline, Version: 2}
	jobs := &memoryRediscoveryJobs{values: map[string]job.Job{}}
	capabilities := &memoryRediscoveryCapabilities{allowed: map[string]bool{"discover_databases": true, "native_discovery_v1": true, "docker_discovery_v1": true, "discovery_source_results_v1": true, "discovery_policy_attestation_v1": true, "discovery_report_ack_v1": true}}
	policy := discoverydomain.RuleAttestation{Version: discoverydomain.RuleAttestationVersion, Algorithm: discoverydomain.RuleAttestationAlgorithm, KeyID: "key-a", Revision: 7, Digest: sha256.Sum256([]byte("rules")), IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), DisappearanceGrace: 10 * time.Minute}
	hosts := &memoryRediscoveryHosts{value: host}
	service := &RediscoveryCoordinator{Hosts: hosts, Jobs: jobs, Capabilities: capabilities, Policies: []discoverydomain.RuleAttestation{policy}, RuleKeys: map[string]ed25519.PublicKey{"key-a": make(ed25519.PublicKey, ed25519.PublicKeySize)}, Now: func() time.Time { return now }}
	return rediscoveryFixture{scope: scope, hosts: hosts, jobs: jobs, capabilities: capabilities, service: service}
}

type memoryRediscoveryHosts struct{ value hostinventory.Host }

func (hosts *memoryRediscoveryHosts) Get(_ context.Context, scope platformscope.Scope, hostID string) (hostinventory.Host, error) {
	if hosts.value.Scope != scope || hosts.value.ID != hostID {
		return hostinventory.Host{}, hostinventory.ErrNotFound
	}
	return hosts.value, nil
}

type memoryRediscoveryCapabilities struct{ allowed map[string]bool }

func (source *memoryRediscoveryCapabilities) Supports(_ string, required ...string) bool {
	for _, capability := range required {
		if !source.allowed[capability] {
			return false
		}
	}
	return true
}

type memoryRediscoveryJobs struct {
	values          map[string]job.Job
	messages        []job.OutboxMessage
	created         int
	failAfterCreate error
}

func (store *memoryRediscoveryJobs) CreateWithOutbox(_ context.Context, value job.Job, messages []job.OutboxMessage) error {
	if _, exists := store.values[value.ID]; exists {
		return job.ErrConflict
	}
	store.values[value.ID] = value
	store.messages = append([]job.OutboxMessage(nil), messages...)
	store.created++
	return store.failAfterCreate
}
func (store *memoryRediscoveryJobs) Get(_ context.Context, scope platformscope.Scope, id string) (job.Job, error) {
	value, ok := store.values[id]
	if !ok || value.Scope != scope {
		return job.Job{}, job.ErrNotFound
	}
	return value, nil
}

func repeatHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result[:64]
}
