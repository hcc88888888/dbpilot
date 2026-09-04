package rediscovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
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
	request := RediscoveryRequest{Actor: "operator-a", IdempotencyKey: "rediscover-a", RequestFingerprint: "sha256:" + repeatHex("a"), RequestID: "request-a", TraceID: "trace-a"}
	for name, mutate := range map[string]func(*rediscoveryFixture){
		"host offline": func(fixture *rediscoveryFixture) { fixture.hosts.value.Status = hostinventory.HostOffline },
		"policy changed": func(fixture *rediscoveryFixture) {
			fixture.service.Policies = nil
			fixture.service.RuleKeys = nil
		},
		"capability disappeared": func(fixture *rediscoveryFixture) { delete(fixture.capabilities.allowed, "discovery_report_ack_v1") },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRediscoveryFixture()
			fixture.jobs.failAfterCreate = errors.New("connection lost after commit")
			first, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
			require.NoError(t, err)
			mutate(&fixture)
			second, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
			require.NoError(t, err)
			require.Equal(t, first.ID, second.ID)
			require.Equal(t, 1, fixture.jobs.created, "lost response replay must not create a second Job")
		})
	}

	fixture := newRediscoveryFixture()
	fixture.hosts.value.Status = hostinventory.HostOffline
	_, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
	require.ErrorIs(t, err, ErrHostNotOnline)
	require.Zero(t, fixture.jobs.created)

	fixture = newRediscoveryFixture()
	delete(fixture.capabilities.allowed, "discovery_report_ack_v1")
	_, err = fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
	require.ErrorIs(t, err, ErrRediscoveryUnavailable)
	require.Zero(t, fixture.jobs.created)
}

func TestRediscoveryAcceptsBoundedGlobalSubjectAndOpenAPIIdempotencyKey(t *testing.T) {
	fixture := newRediscoveryFixture()
	key := "rediscover /?=+_"
	for len(key) < 128 {
		key += "x"
	}
	request := RediscoveryRequest{Actor: "https://issuer.example/subjects/user|tenant@example.com", IdempotencyKey: key, RequestFingerprint: "sha256:" + repeatHex("b"), RequestID: "request-global-subject", TraceID: "trace-global-subject"}

	created, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)

	require.NoError(t, err)
	require.Equal(t, request.Actor, created.InitiatedBy)
}

func TestRediscoveryReplayRejectsJobWithoutExactImmutableOutboxCorrelation(t *testing.T) {
	fixture := newRediscoveryFixture()
	request := RediscoveryRequest{Actor: "operator-a", IdempotencyKey: "rediscover-corrupt", RequestFingerprint: "sha256:" + repeatHex("c"), RequestID: "request-corrupt", TraceID: "trace-corrupt"}
	created, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
	require.NoError(t, err)
	require.Len(t, fixture.jobs.messages, 1)
	fixture.jobs.messages[0].JobID = "job-other"

	_, err = fixture.service.Start(context.Background(), fixture.scope, "host-a", request)

	require.ErrorIs(t, err, ErrRediscoveryUnavailable)
	require.Equal(t, 1, fixture.jobs.created)
	require.NotEmpty(t, created.ID)
}

func TestRediscoveryUpgradesUnversionedDigestReplayAndIncrementsJobVersionOnce(t *testing.T) {
	request := RediscoveryRequest{Actor: "operator-a", IdempotencyKey: "rediscover-legacy", RequestFingerprint: "sha256:" + repeatHex("e"), RequestID: "request-legacy", TraceID: "trace-legacy"}
	fixture := newRediscoveryFixture()
	created, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
	require.NoError(t, err)
	stored := fixture.jobs.values[created.ID]
	digest := sha256.Sum256(fixture.jobs.messages[0].Payload)
	legacyKey := "host-rediscover-" + strings.TrimPrefix(created.ID, "job-host-rediscover-") + "-command-sha256-" + hex.EncodeToString(digest[:])
	stored.IdempotencyKey = legacyKey
	fixture.jobs.values[created.ID] = stored
	fixture.hosts.value.Status = hostinventory.HostOffline
	fixture.service.Policies = nil
	fixture.service.RuleKeys = nil
	fixture.capabilities.allowed = map[string]bool{}

	replayed, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)

	require.NoError(t, err)
	require.Equal(t, created.ID, replayed.ID)
	require.True(t, strings.HasPrefix(replayed.IdempotencyKey, "host-rediscover-v2-"), replayed.IdempotencyKey)
	require.NotEqual(t, legacyKey, replayed.IdempotencyKey)
	require.Equal(t, created.Version+1, replayed.Version)
	replayedAgain, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
	require.NoError(t, err)
	require.Equal(t, replayed.IdempotencyKey, replayedAgain.IdempotencyKey)
	require.Equal(t, replayed.Version, replayedAgain.Version)
	require.Equal(t, 1, fixture.jobs.upgrades, "legacy upgrade must be one-way")
}

func TestRediscoveryPreDigestReplayFailsClosedWithoutIndependentEvidence(t *testing.T) {
	request := RediscoveryRequest{Actor: "operator-a", IdempotencyKey: "rediscover-legacy-corrupt", RequestFingerprint: "sha256:" + repeatHex("f"), RequestID: "request-legacy-corrupt", TraceID: "trace-legacy-corrupt"}
	for name, corrupt := range map[string]func(*rediscoveryFixture){
		"canonical": func(*rediscoveryFixture) {},
		"unknown field": func(fixture *rediscoveryFixture) {
			fixture.jobs.messages[0].Payload = append(fixture.jobs.messages[0].Payload, 0xa0, 0x06, 0x01)
		},
		"changed lease": func(fixture *rediscoveryFixture) {
			mutateRediscoveryEnvelope(t, fixture.jobs, func(envelope *agentv1.CommandEnvelope) { envelope.LeaseSeconds++ })
		},
		"changed rule": func(fixture *rediscoveryFixture) {
			mutateRediscoveryEnvelope(t, fixture.jobs, func(envelope *agentv1.CommandEnvelope) { envelope.GetDiscoverDatabases().RuleRevision++ })
		},
		"changed include": func(fixture *rediscoveryFixture) {
			mutateRediscoveryEnvelope(t, fixture.jobs, func(envelope *agentv1.CommandEnvelope) { envelope.GetDiscoverDatabases().IncludeDocker = false })
		},
		"changed agent and target": func(fixture *rediscoveryFixture) {
			mutateRediscoveryEnvelope(t, fixture.jobs, func(envelope *agentv1.CommandEnvelope) { envelope.AgentId = "agent-b" })
			message := fixture.jobs.messages[0]
			message.TargetID = "agent-b"
			fixture.jobs.messages[0] = message
			stored := fixture.jobs.values[message.JobID]
			stored.TargetResourceIDs = []string{"agent-b"}
			fixture.jobs.values[message.JobID] = stored
		},
		"envelope authority": func(fixture *rediscoveryFixture) {
			mutateRediscoveryEnvelope(t, fixture.jobs, func(envelope *agentv1.CommandEnvelope) { envelope.CommandId = "payload-command" })
		},
		"second outbox": func(fixture *rediscoveryFixture) {
			duplicate := fixture.jobs.messages[0]
			duplicate.ID = "command-extra"
			fixture.jobs.messages = append(fixture.jobs.messages, duplicate)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRediscoveryFixture()
			created, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
			require.NoError(t, err)
			stored := fixture.jobs.values[created.ID]
			stored.IdempotencyKey = "host-rediscover-" + strings.TrimPrefix(created.ID, "job-host-rediscover-")
			fixture.jobs.values[created.ID] = stored
			corrupt(&fixture)

			_, err = fixture.service.Start(context.Background(), fixture.scope, "host-a", request)

			require.ErrorIs(t, err, ErrRediscoveryUnavailable)
			require.Equal(t, 0, fixture.jobs.upgrades)
		})
	}
}

func TestRediscoveryUnversionedDigestUpgradeRejectsPayloadTOCTOU(t *testing.T) {
	fixture := newRediscoveryFixture()
	request := RediscoveryRequest{Actor: "operator-a", IdempotencyKey: "rediscover-legacy-race", RequestFingerprint: "sha256:" + repeatHex("1"), RequestID: "request-legacy-race", TraceID: "trace-legacy-race"}
	created, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
	require.NoError(t, err)
	stored := fixture.jobs.values[created.ID]
	digest := sha256.Sum256(fixture.jobs.messages[0].Payload)
	stored.IdempotencyKey = "host-rediscover-" + strings.TrimPrefix(created.ID, "job-host-rediscover-") + "-command-sha256-" + hex.EncodeToString(digest[:])
	fixture.jobs.values[created.ID] = stored
	fixture.jobs.beforeUpgrade = func() {
		fixture.jobs.messages[0].Payload = append(fixture.jobs.messages[0].Payload, 0xa0, 0x06, 0x01)
	}

	_, err = fixture.service.Start(context.Background(), fixture.scope, "host-a", request)

	require.ErrorIs(t, err, ErrRediscoveryUnavailable)
	require.Equal(t, 0, fixture.jobs.upgrades)
	require.Equal(t, stored.IdempotencyKey, fixture.jobs.values[created.ID].IdempotencyKey)
}

func TestRediscoveryReplayRejectsNoncanonicalChangedOrMultipleOutbox(t *testing.T) {
	request := RediscoveryRequest{Actor: "operator-a", IdempotencyKey: "rediscover-integrity", RequestFingerprint: "sha256:" + repeatHex("d"), RequestID: "request-integrity", TraceID: "trace-integrity"}
	for name, corrupt := range map[string]func(*memoryRediscoveryJobs){
		"unknown field": func(store *memoryRediscoveryJobs) {
			store.messages[0].Payload = append(store.messages[0].Payload, 0xa0, 0x06, 0x01)
		},
		"changed lease": func(store *memoryRediscoveryJobs) {
			mutateRediscoveryEnvelope(t, store, func(envelope *agentv1.CommandEnvelope) { envelope.LeaseSeconds++ })
		},
		"changed rule": func(store *memoryRediscoveryJobs) {
			mutateRediscoveryEnvelope(t, store, func(envelope *agentv1.CommandEnvelope) { envelope.GetDiscoverDatabases().RuleRevision++ })
		},
		"changed include": func(store *memoryRediscoveryJobs) {
			mutateRediscoveryEnvelope(t, store, func(envelope *agentv1.CommandEnvelope) { envelope.GetDiscoverDatabases().IncludeDocker = false })
		},
		"envelope authority": func(store *memoryRediscoveryJobs) {
			mutateRediscoveryEnvelope(t, store, func(envelope *agentv1.CommandEnvelope) { envelope.CommandId = "payload-command" })
		},
		"second outbox": func(store *memoryRediscoveryJobs) {
			duplicate := store.messages[0]
			duplicate.ID = "command-extra"
			store.messages = append(store.messages, duplicate)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRediscoveryFixture()
			_, err := fixture.service.Start(context.Background(), fixture.scope, "host-a", request)
			require.NoError(t, err)
			corrupt(fixture.jobs)

			_, err = fixture.service.Start(context.Background(), fixture.scope, "host-a", request)

			require.ErrorIs(t, err, ErrRediscoveryUnavailable)
			require.Equal(t, 1, fixture.jobs.created)
		})
	}
}

func mutateRediscoveryEnvelope(t *testing.T, store *memoryRediscoveryJobs, mutate func(*agentv1.CommandEnvelope)) {
	t.Helper()
	envelope := new(agentv1.CommandEnvelope)
	require.NoError(t, proto.Unmarshal(store.messages[0].Payload, envelope))
	mutate(envelope)
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	require.NoError(t, err)
	store.messages[0].Payload = payload
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
	upgrades        int
	failAfterCreate error
	beforeUpgrade   func()
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
func (store *memoryRediscoveryJobs) GetOperation(ctx context.Context, scope platformscope.Scope, jobID, commandID string) (job.Job, job.OutboxMessage, error) {
	value, err := store.Get(ctx, scope, jobID)
	if err != nil {
		return job.Job{}, job.OutboxMessage{}, err
	}
	correlated := 0
	var found job.OutboxMessage
	for _, message := range store.messages {
		if message.Scope == scope && message.JobID == jobID {
			correlated++
		}
		if message.ID == commandID && message.Scope == scope && message.JobID == jobID {
			found = message
		}
	}
	if correlated == 1 && found.ID != "" {
		return value, found, nil
	}
	return job.Job{}, job.OutboxMessage{}, job.ErrConflict
}

func (store *memoryRediscoveryJobs) UpgradeOperationIdempotencyKey(ctx context.Context, expected job.Job, expectedMessage job.OutboxMessage, currentKey string) (job.Job, job.OutboxMessage, error) {
	if store.beforeUpgrade != nil {
		store.beforeUpgrade()
	}
	value, message, err := store.GetOperation(ctx, expected.Scope, expected.ID, expectedMessage.ID)
	if err != nil {
		return job.Job{}, job.OutboxMessage{}, err
	}
	if value.Type != expected.Type || value.InitiatedBy != expected.InitiatedBy || value.SourceResource != expected.SourceResource || value.RequestID != expected.RequestID || value.TraceID != expected.TraceID || value.IdempotencyKey != expected.IdempotencyKey && value.IdempotencyKey != currentKey || message.TargetID != expectedMessage.TargetID || message.Type != expectedMessage.Type || !bytes.Equal(message.Payload, expectedMessage.Payload) {
		return job.Job{}, job.OutboxMessage{}, job.ErrConflict
	}
	if value.IdempotencyKey != currentKey {
		if value.Version != expected.Version {
			return job.Job{}, job.OutboxMessage{}, job.ErrConflict
		}
		value.IdempotencyKey = currentKey
		value.Version++
		store.values[value.ID] = value
		store.upgrades++
	} else if value.Version != expected.Version+1 {
		return job.Job{}, job.OutboxMessage{}, job.ErrConflict
	}
	return value, message, nil
}

func repeatHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result[:64]
}
