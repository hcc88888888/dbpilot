package credentiallease

import (
	"bytes"
	"context"
	"errors"
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

func validRequest() LeaseRequest {
	return LeaseRequest{Nonce: bytes.Repeat([]byte{0x01}, 32), InstanceID: "instance-1", AssignmentID: "assignment-1", ConfigurationRevision: 5}
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

func (value *testProvider) Resolve(context.Context, string) (Credential, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.calls++
	credential := value.credential.Clone()
	return credential, value.err
}

type testClock struct{ now time.Time }

func (value testClock) Now(context.Context) (time.Time, error) { return value.now, nil }

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
