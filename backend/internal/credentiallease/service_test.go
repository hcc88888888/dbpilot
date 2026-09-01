package credentiallease

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestLeaseAuthorizesBeforeResolveAndIsConcurrentNonceIdempotent(t *testing.T) {
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	authorizer := &testAuthorizer{grant: validGrant(now)}
	provider := &testProvider{credential: Credential{Username: "monitor", SecretBytes: []byte("fixture-password"), Revision: 11}}
	auditor := &testAudit{}
	service, err := NewService(Config{Authorizer: authorizer, Provider: provider, Clock: testClock{now: now}, Audit: auditor, TTL: time.Minute, Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 128))})
	require.NoError(t, err)

	request := validRequest()
	agent := AuthenticatedAgent{AgentID: "agent-1", SessionID: "session-1"}
	const callers = 8
	results := make(chan Lease, callers)
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			lease, leaseErr := service.Lease(context.Background(), agent, request)
			results <- lease
			errorsSeen <- leaseErr
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for leaseErr := range errorsSeen {
		require.NoError(t, leaseErr)
	}
	var leaseID string
	for lease := range results {
		if leaseID == "" {
			leaseID = lease.ID
		}
		require.Equal(t, leaseID, lease.ID)
		require.Equal(t, uint64(11), lease.CredentialRevision)
		require.Equal(t, now.Add(time.Minute), lease.ExpiresAt)
		require.Equal(t, []byte("fixture-password"), lease.SecretBytes)
		lease.Release()
	}
	require.Equal(t, 1, provider.calls)
	require.GreaterOrEqual(t, authorizer.calls, 1)
	require.NotEmpty(t, auditor.records)
}

func TestLeaseRejectsNonceConflictAndProviderDetailsAreRedacted(t *testing.T) {
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	authorizer := &testAuthorizer{grant: validGrant(now)}
	provider := &testProvider{credential: Credential{Username: "monitor", SecretBytes: []byte("fixture-password"), Revision: 11}}
	service, err := NewService(Config{Authorizer: authorizer, Provider: provider, Clock: testClock{now: now}, Audit: &testAudit{}, TTL: time.Minute, Random: bytes.NewReader(bytes.Repeat([]byte{0x11}, 128))})
	require.NoError(t, err)
	agent := AuthenticatedAgent{AgentID: "agent-1", SessionID: "session-1"}
	_, err = service.Lease(context.Background(), agent, validRequest())
	require.NoError(t, err)
	conflict := validRequest()
	conflict.InstanceID = "instance-2"
	_, err = service.Lease(context.Background(), agent, conflict)
	require.ErrorIs(t, err, ErrLeaseRejected)

	provider.err = errors.New("vault secret fixture-password at internal/path")
	request := validRequest()
	request.Nonce = bytes.Repeat([]byte{0x22}, 32)
	_, err = service.Lease(context.Background(), agent, request)
	require.ErrorIs(t, err, ErrLeaseRejected)
	require.NotContains(t, err.Error(), "fixture-password")
	require.NotContains(t, err.Error(), "internal/path")
}

func TestLeaseRejectsNonSecretReferenceAndChangedAuthorizationFence(t *testing.T) {
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	grant := validGrant(now)
	grant.CredentialRef = "env://password"
	provider := &testProvider{credential: Credential{Username: "monitor", SecretBytes: []byte("fixture-password"), Revision: 11}}
	service, err := NewService(Config{Authorizer: &testAuthorizer{grant: grant}, Provider: provider, Clock: testClock{now: now}, Audit: &testAudit{}, TTL: time.Minute, Random: bytes.NewReader(bytes.Repeat([]byte{0x33}, 64))})
	require.NoError(t, err)
	_, err = service.Lease(context.Background(), AuthenticatedAgent{AgentID: "agent-1", SessionID: "session-1"}, validRequest())
	require.ErrorIs(t, err, ErrLeaseRejected)
	require.Zero(t, provider.calls)
}

func TestLeaseReauthorizesAfterBlockedProviderAndUsesFreshDatabaseTime(t *testing.T) {
	initial := time.Now().UTC().Add(10 * time.Second)
	clock := &mutableClock{now: initial}
	authorizer := &testAuthorizer{grant: validGrant(initial)}
	provider := &blockingProvider{started: make(chan struct{}), release: make(chan struct{}), credential: Credential{Username: "monitor", SecretBytes: []byte("blocked-provider-secret"), Revision: 11}}
	service, err := NewService(Config{Authorizer: authorizer, Provider: provider, Clock: clock, Audit: &testAudit{}, TTL: time.Minute, Random: bytes.NewReader(bytes.Repeat([]byte{0x55}, 64))})
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() {
		_, leaseErr := service.Lease(context.Background(), AuthenticatedAgent{AgentID: "agent-1", SessionID: "session-1"}, validRequest())
		result <- leaseErr
	}()
	<-provider.started
	authorizer.mu.Lock()
	authorizer.grant.OperationRevision++
	authorizer.mu.Unlock()
	clock.mu.Lock()
	clock.now = initial.Add(30 * time.Second)
	clock.mu.Unlock()
	close(provider.release)
	require.ErrorIs(t, <-result, ErrLeaseRejected)
	require.Equal(t, make([]byte, len(provider.returned)), provider.returned)
	require.Equal(t, 2, authorizer.calls)
}

func TestNonceConflictPreservesExactReplayAndExpiredNonceIsTombstoned(t *testing.T) {
	now := time.Now().UTC().Add(10 * time.Second)
	service, err := NewService(Config{Authorizer: &testAuthorizer{grant: validGrant(now)}, Provider: &testProvider{credential: Credential{Username: "monitor", SecretBytes: []byte("nonce-secret"), Revision: 11}}, Clock: testClock{now: now}, Audit: &testAudit{}, TTL: 5 * time.Second, Random: bytes.NewReader(bytes.Repeat([]byte{0x66}, 64))})
	require.NoError(t, err)
	agent := AuthenticatedAgent{AgentID: "agent-1", SessionID: "session-1"}
	first, err := service.Lease(context.Background(), agent, validRequest())
	require.NoError(t, err)
	conflict := validRequest()
	conflict.InstanceID = "instance-2"
	_, err = service.Lease(context.Background(), agent, conflict)
	require.ErrorIs(t, err, ErrLeaseRejected)
	replayed, err := service.Lease(context.Background(), agent, validRequest())
	require.NoError(t, err)
	require.Equal(t, first.ID, replayed.ID)
	service.mu.Lock()
	record := service.leases[agent.SessionID+"\x00"+string(validRequest().Nonce)]
	record.lease.Release()
	record.expired = true
	service.mu.Unlock()
	_, err = service.Lease(context.Background(), agent, validRequest())
	require.ErrorIs(t, err, ErrLeaseRejected)
	first.Release()
	replayed.Release()
}

func TestServiceCloseZerosReadyAndBlockedProviderLeases(t *testing.T) {
	now := time.Now().UTC().Add(10 * time.Second)
	provider := &blockingProvider{started: make(chan struct{}), release: make(chan struct{}), credential: Credential{Username: "monitor", SecretBytes: []byte("close-secret"), Revision: 11}}
	service, err := NewService(Config{Authorizer: &testAuthorizer{grant: validGrant(now)}, Provider: provider, Clock: testClock{now: now}, Audit: &testAudit{}, TTL: time.Minute, Random: bytes.NewReader(bytes.Repeat([]byte{0x77}, 64))})
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, leaseErr := service.Lease(context.Background(), AuthenticatedAgent{AgentID: "agent-1", SessionID: "session-1"}, validRequest())
		done <- leaseErr
	}()
	<-provider.started
	service.Close()
	close(provider.release)
	require.ErrorIs(t, <-done, ErrLeaseRejected)
	require.Equal(t, make([]byte, len(provider.returned)), provider.returned)
}

func TestSubsequentNonceUsesDurableRenewalAuthorization(t *testing.T) {
	now := time.Now().UTC().Add(10 * time.Second)
	initial := &testAuthorizer{grant: validGrant(now)}
	renewal := &testRenewalAuthorizer{grant: validGrant(now)}
	service, err := NewService(Config{Authorizer: initial, Renewals: renewal, Provider: &testProvider{credential: Credential{Username: "monitor", SecretBytes: []byte("renewal-secret"), Revision: 11}}, Clock: testClock{now: now}, Audit: &testAudit{}, TTL: time.Minute, Random: bytes.NewReader(bytes.Repeat([]byte{0x78}, 64))})
	require.NoError(t, err)
	agent := AuthenticatedAgent{AgentID: "agent-1", SessionID: "session-1"}
	first, err := service.Lease(context.Background(), agent, validRequest())
	require.NoError(t, err)
	first.Release()
	renewRequest := validRequest()
	renewRequest.Nonce = bytes.Repeat([]byte{0x79}, 32)
	second, err := service.Lease(context.Background(), agent, renewRequest)
	require.NoError(t, err)
	second.Release()
	require.Equal(t, 2, initial.calls)
	require.Equal(t, 2, renewal.calls)
}

func TestTombstoneEvictionNeverDeletesNewGenerationOrConsumesLiveCapacity(t *testing.T) {
	now := time.Now().UTC()
	service, err := NewService(Config{Authorizer: &testAuthorizer{grant: validGrant(now)}, Provider: &testProvider{credential: Credential{Username: "monitor", SecretBytes: []byte("capacity-secret"), Revision: 11}}, Clock: testClock{now: now}, Audit: &testAudit{}, TTL: time.Minute, MaximumLive: 1, Random: bytes.NewReader(bytes.Repeat([]byte{0x7a}, 64))})
	require.NoError(t, err)
	service.mu.Lock()
	service.addTombstoneLocked("nonce-reused", now.Add(time.Minute), now)
	first := service.tombstones["nonce-reused"].generation
	service.addTombstoneLocked("nonce-reused", now.Add(2*time.Minute), now)
	second := service.tombstones["nonce-reused"].generation
	for index := 0; index < 3; index++ {
		service.addTombstoneLocked(fmt.Sprintf("nonce-%d", index), now.Add(time.Minute), now)
	}
	current, exists := service.tombstones["nonce-reused"]
	for index := 3; index < 20; index++ {
		service.addTombstoneLocked(fmt.Sprintf("nonce-%d", index), now.Add(time.Minute), now)
	}
	service.mu.Unlock()
	require.NotEqual(t, first, second)
	require.True(t, exists)
	require.Equal(t, second, current.generation)
	_, err = service.Lease(context.Background(), AuthenticatedAgent{AgentID: "agent-1", SessionID: "session-1"}, validRequest())
	require.ErrorIs(t, err, ErrLeaseRejected, "full live tombstone capacity must reject without eviction")
	service.mu.Lock()
	for key, tombstone := range service.tombstones {
		tombstone.until = now.Add(-time.Second)
		service.tombstones[key] = tombstone
	}
	service.pruneLocked(now)
	service.mu.Unlock()
	lease, err := service.Lease(context.Background(), AuthenticatedAgent{AgentID: "agent-1", SessionID: "session-1"}, validRequest())
	require.NoError(t, err, "expired tombstones must prune and release capacity")
	lease.Release()
}

func TestAdmissionReservesFutureFenceForEveryActiveNonce(t *testing.T) {
	now := time.Now().UTC()
	service, err := NewService(Config{Authorizer: &testAuthorizer{grant: validGrant(now)}, Provider: &testProvider{credential: Credential{Username: "monitor", SecretBytes: []byte("reserved-fence-secret"), Revision: 11}}, Clock: testClock{now: now}, Audit: &testAudit{}, TTL: time.Minute, MaximumLive: 2, Random: bytes.NewReader(bytes.Repeat([]byte{0x7b}, 128))})
	require.NoError(t, err)
	service.mu.Lock()
	for index := 0; index < service.totalFenceCapacity()-2; index++ {
		require.True(t, service.addTombstoneLocked(fmt.Sprintf("old-%d", index), now.Add(10*time.Minute), now))
	}
	service.mu.Unlock()
	agent := AuthenticatedAgent{AgentID: "agent-1", SessionID: "session-1"}
	firstRequest := validRequest()
	secondRequest := validRequest()
	secondRequest.Nonce = bytes.Repeat([]byte{0x7c}, 32)
	first, err := service.Lease(context.Background(), agent, firstRequest)
	require.NoError(t, err)
	second, err := service.Lease(context.Background(), agent, secondRequest)
	require.NoError(t, err)
	third := validRequest()
	third.Nonce = bytes.Repeat([]byte{0x7d}, 32)
	_, err = service.Lease(context.Background(), agent, third)
	require.ErrorIs(t, err, ErrLeaseRejected)
	service.mu.Lock()
	service.pruneLocked(now.Add(2 * time.Minute))
	active, tombstones := len(service.leases), len(service.tombstones)
	service.mu.Unlock()
	require.Zero(t, active)
	require.Equal(t, service.totalFenceCapacity(), tombstones)
	_, err = service.Lease(context.Background(), agent, firstRequest)
	require.ErrorIs(t, err, ErrLeaseRejected)
	conflict := firstRequest
	conflict.InstanceID = "instance-2"
	_, err = service.Lease(context.Background(), agent, conflict)
	require.ErrorIs(t, err, ErrLeaseRejected)
	first.Release()
	second.Release()
	service.mu.Lock()
	service.pruneLocked(now.Add(20 * time.Minute))
	require.Empty(t, service.tombstones)
	service.mu.Unlock()
}

func validRequest() LeaseRequest {
	return LeaseRequest{Nonce: bytes.Repeat([]byte{0x01}, 32), InstanceID: "instance-1", AssignmentID: "assignment-1", DatabaseFamily: "mysql", ConfigurationRevision: 5, OperationRevision: 7}
}

func validGrant(now time.Time) Authorization {
	return Authorization{Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, HostID: "host-1", AgentID: "agent-1", AssignmentID: "assignment-1", DatabaseFamily: "mysql", ConfigurationRevision: 5, OperationRevision: 7, InstanceID: "instance-1", InstanceRevision: 9, CredentialRef: "secret://database/instance-1", TLSRef: "secret://tls/instance-1", ManagementStatus: "monitoring", AuthorizedAt: now}
}

type testAuthorizer struct {
	mu    sync.Mutex
	grant Authorization
	err   error
	calls int
}

func (value *testAuthorizer) Authorize(context.Context, AuthenticatedAgent, LeaseRequest) (Authorization, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.calls++
	return value.grant, value.err
}

type testProvider struct {
	mu         sync.Mutex
	credential Credential
	err        error
	calls      int
}

type testRenewalAuthorizer struct {
	grant Authorization
	calls int
}

func (value *testRenewalAuthorizer) AuthorizeRenewal(context.Context, AuthenticatedAgent, LeaseRequest) (Authorization, error) {
	value.calls++
	return value.grant, nil
}

func (value *testProvider) Resolve(context.Context, string) (Credential, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.calls++
	credential := value.credential.Clone()
	return credential, value.err
}

type testClock struct{ now time.Time }

func (value testClock) Now(context.Context) (time.Time, error) { return value.now, nil }

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (value *mutableClock) Now(context.Context) (time.Time, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.now, nil
}

type blockingProvider struct {
	started    chan struct{}
	release    chan struct{}
	credential Credential
	returned   []byte
}

func (value *blockingProvider) Resolve(context.Context, string) (Credential, error) {
	close(value.started)
	<-value.release
	credential := value.credential.Clone()
	value.returned = credential.SecretBytes
	return credential, nil
}

type testAudit struct {
	mu      sync.Mutex
	records []AuditRecord
}

func (value *testAudit) Record(_ context.Context, record AuditRecord) error {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.records = append(value.records, record)
	return nil
}
