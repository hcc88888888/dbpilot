package enrollment

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestWrongAgentDoesNotBurnTokenAndCorrectAgentCanRetry(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	raw := []byte("0123456789abcdef0123456789abcdef")
	store := newAttemptMemoryStore(validEnrollmentToken(HashToken(raw), now).Grant())
	issuer := &sequenceIssuer{}
	service := ApplicationService{Tokens: store, Certificates: issuer, Now: func() time.Time { return now }}

	_, err := service.Enroll(context.Background(), signedEnrollRequest(t, raw, "agent-other", now))
	require.ErrorIs(t, err, ErrEnrollmentTokenInvalid)
	require.Zero(t, store.completeCalls)
	require.Zero(t, issuer.calls)

	result, err := service.Enroll(context.Background(), signedEnrollRequest(t, raw, "agent-1", now))
	require.NoError(t, err)
	require.Equal(t, []byte("certificate-1"), result.CertificatePEM)
	require.Equal(t, 1, store.completeCalls)
}

func TestIssuerAndHostFailureDoNotBurnToken(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	raw := []byte("abcdef0123456789abcdef0123456789")
	request := signedEnrollRequest(t, raw, "agent-1", now)
	store := newAttemptMemoryStore(validEnrollmentToken(HashToken(raw), now).Grant())
	issuer := &sequenceIssuer{errors: []error{errors.New("issuer unavailable")}}
	service := ApplicationService{Tokens: store, Certificates: issuer, Now: func() time.Time { return now }}

	_, err := service.Enroll(context.Background(), request)
	require.Error(t, err)
	require.Zero(t, store.completeCalls)

	store.completeErrors = []error{errors.New("Host insert failed")}
	_, err = service.Enroll(context.Background(), request)
	require.Error(t, err)
	require.Equal(t, 1, store.completeCalls)

	result, err := service.Enroll(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, []byte("certificate-3"), result.CertificatePEM)
	require.Equal(t, 2, store.completeCalls)
}

func TestLostResponseRetryReturnsExactStoredPublicIssuance(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	raw := []byte("fedcba9876543210fedcba9876543210")
	request := signedEnrollRequest(t, raw, "agent-1", now)
	store := newAttemptMemoryStore(validEnrollmentToken(HashToken(raw), now).Grant())
	store.commitThenError = true
	issuer := &sequenceIssuer{}
	service := ApplicationService{Tokens: store, Certificates: issuer, Now: func() time.Time { return now }}

	first, err := service.Enroll(context.Background(), request)
	require.NoError(t, err, "unknown commit outcome must resolve the durable issuance")
	require.Equal(t, []byte("certificate-1"), first.CertificatePEM)
	require.Equal(t, 1, issuer.calls)

	second, err := service.Enroll(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, first, second, "same token and CSR retry must return byte-identical public response")
	require.Equal(t, 1, issuer.calls, "durable replay must not issue a second certificate")
}

type attemptMemoryStore struct {
	mu              sync.Mutex
	grant           EnrollmentGrant
	stored          map[EnrollmentAttemptKey]EnrollResult
	completeCalls   int
	completeErrors  []error
	commitThenError bool
	resolveErr      error
}

func newAttemptMemoryStore(grant EnrollmentGrant) *attemptMemoryStore {
	return &attemptMemoryStore{grant: grant, stored: make(map[EnrollmentAttemptKey]EnrollResult)}
}

func (store *attemptMemoryStore) Create(context.Context, EnrollmentToken) (EnrollmentTokenCreation, error) {
	return EnrollmentTokenCreation{Generation: 1}, nil
}

func (store *attemptMemoryStore) Replace(_ context.Context, _ EnrollmentToken, expected uint64) (EnrollmentTokenCreation, error) {
	return EnrollmentTokenCreation{Generation: expected + 1, Replaced: true}, nil
}

func (store *attemptMemoryStore) ResolveReplacement(context.Context, platformscope.Scope, ReplacementLookup) (ReplacementState, error) {
	return ReplacementState{}, ErrEnrollmentNotFound
}

func (store *attemptMemoryStore) Resolve(_ context.Context, key EnrollmentAttemptKey) (EnrollmentResolution, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.resolveErr != nil {
		return EnrollmentResolution{}, store.resolveErr
	}
	if key.AgentID != store.grant.AgentID || (key.HostID != "" && key.HostID != store.grant.HostID) {
		return EnrollmentResolution{}, ErrEnrollmentTokenInvalid
	}
	key.HostID = store.grant.HostID
	if response, exists := store.stored[key]; exists {
		copy := response
		return EnrollmentResolution{Grant: store.grant, Response: &copy}, nil
	}
	return EnrollmentResolution{Grant: store.grant}, nil
}

func (store *attemptMemoryStore) Complete(_ context.Context, completion EnrollmentCompletion) (EnrollResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.completeCalls++
	if len(store.completeErrors) > 0 {
		err := store.completeErrors[0]
		store.completeErrors = store.completeErrors[1:]
		return EnrollResult{}, err
	}
	key := completion.Key
	key.HostID = completion.Grant.HostID
	if existing, ok := store.stored[key]; ok {
		return existing, nil
	}
	store.stored[key] = completion.Result
	if store.commitThenError {
		store.commitThenError = false
		return EnrollResult{}, errors.New("commit outcome unknown")
	}
	return completion.Result, nil
}

type sequenceIssuer struct {
	calls  int
	errors []error
}

func (issuer *sequenceIssuer) SignAgentCSR(_ context.Context, _ EnrollmentGrant, _ []byte) ([]byte, []byte, time.Time, error) {
	issuer.calls++
	if len(issuer.errors) > 0 {
		err := issuer.errors[0]
		issuer.errors = issuer.errors[1:]
		return nil, nil, time.Time{}, err
	}
	return []byte("certificate-" + string(rune('0'+issuer.calls))), []byte("chain"), time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC), nil
}

var _ EnrollmentStore = (*attemptMemoryStore)(nil)
