package idempotency

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestServiceClaimsCompletesAndReplaysExactResponse(t *testing.T) {
	store := newSynchronizedStore()
	service := NewService(store)
	service.now = func() time.Time { return time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC) }
	key := validKey()
	fingerprint := "sha256:0a9896a42ff3a8f7c9edfe3c97cc1e9d2b6bc06122f89876a49ea3bc4cc51b59"

	claim, err := service.Begin(context.Background(), key, fingerprint, successfulReconcile)
	require.NoError(t, err)
	require.True(t, claim.Claimed)
	require.Regexp(t, `^owner-[0-9a-f]{64}$`, claim.OwnerToken)
	require.Nil(t, claim.Response)

	want := Response{
		Status: http.StatusAccepted,
		Header: http.Header{"Content-Type": {"application/json"}, "ETag": {`"8"`}, "Location": {"/jobs/job-1"}},
		Body:   []byte(`{"id":"job-1","version":8}`),
	}
	completed, err := service.Complete(context.Background(), key, fingerprint, claim.OwnerToken, want, reconciliationFixture(), successfulReconcile)
	require.NoError(t, err)
	require.Equal(t, want, completed)

	completed.Header.Set("ETag", `"mutated"`)
	completed.Body[0] = '['
	replay, err := service.Begin(context.Background(), key, fingerprint, successfulReconcile)
	require.NoError(t, err)
	require.False(t, replay.Claimed)
	require.Empty(t, replay.OwnerToken)
	require.Equal(t, want, *replay.Response)

	replay.Response.Header.Set("ETag", `"mutated-again"`)
	replay.Response.Body[0] = '['
	replayAgain, err := service.Begin(context.Background(), key, fingerprint, successfulReconcile)
	require.NoError(t, err)
	require.Equal(t, want, *replayAgain.Response)
}

func TestServiceRejectsSameKeyWithDifferentFingerprint(t *testing.T) {
	service := NewService(newSynchronizedStore())
	key := validKey()
	_, err := service.Begin(context.Background(), key, "sha256:0a9896a42ff3a8f7c9edfe3c97cc1e9d2b6bc06122f89876a49ea3bc4cc51b59", successfulReconcile)
	require.NoError(t, err)

	_, err = service.Begin(context.Background(), key, "sha256:70b9d78842924a3f00599c8298f0e6786ea68aa7b6ea5f5f74335c7d26d0579d", successfulReconcile)
	require.ErrorIs(t, err, ErrKeyConflict)
}

func TestServiceAllowsOnlyOneConcurrentClaim(t *testing.T) {
	service := NewService(newSynchronizedStore())
	key := validKey()
	fingerprint := "sha256:0a9896a42ff3a8f7c9edfe3c97cc1e9d2b6bc06122f89876a49ea3bc4cc51b59"
	start := make(chan struct{})
	results := make(chan error, 2)
	claims := make(chan Claim, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			claim, err := service.Begin(context.Background(), key, fingerprint, successfulReconcile)
			claims <- claim
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	close(claims)

	claimed, inProgress := 0, 0
	owners := make(map[string]struct{})
	for claim := range claims {
		if claim.Claimed {
			claimed++
			owners[claim.OwnerToken] = struct{}{}
		}
	}
	for err := range results {
		switch {
		case err == nil:
		case err == ErrInProgress:
			inProgress++
		default:
			t.Fatalf("unexpected concurrent claim error: %v", err)
		}
	}
	require.Equal(t, 1, claimed)
	require.Len(t, owners, 1)
	require.Equal(t, 1, inProgress)
}

func TestServiceRejectsInvalidKeysFingerprintsAndResponsesBeforeStore(t *testing.T) {
	store := newSynchronizedStore()
	service := NewService(store)
	key := validKey()

	invalidKeys := []Key{
		{},
		{Scope: key.Scope, Actor: "", OperationID: key.OperationID, IdempotencyKey: key.IdempotencyKey},
		{Scope: key.Scope, Actor: key.Actor, OperationID: " operation", IdempotencyKey: key.IdempotencyKey},
		{Scope: key.Scope, Actor: key.Actor, OperationID: key.OperationID, IdempotencyKey: " "},
	}
	for _, invalid := range invalidKeys {
		_, err := service.Begin(context.Background(), invalid, "sha256:0a9896a42ff3a8f7c9edfe3c97cc1e9d2b6bc06122f89876a49ea3bc4cc51b59", successfulReconcile)
		require.ErrorIs(t, err, ErrInvalid)
	}
	_, err := service.Begin(context.Background(), key, "not-a-fingerprint", successfulReconcile)
	require.ErrorIs(t, err, ErrInvalid)
	require.Zero(t, store.claimCalls)

	validFingerprint := "sha256:0a9896a42ff3a8f7c9edfe3c97cc1e9d2b6bc06122f89876a49ea3bc4cc51b59"
	claim, err := service.Begin(context.Background(), key, validFingerprint, successfulReconcile)
	require.NoError(t, err)
	for _, response := range []Response{
		{Status: 99, Body: []byte(`{}`)},
		{Status: 200, Body: []byte(`not-json`)},
		{Status: 200, Header: http.Header{"X-Test": {"unsafe\r\nvalue"}}, Body: []byte(`{}`)},
	} {
		_, err := service.Complete(context.Background(), key, validFingerprint, claim.OwnerToken, response, reconciliationFixture(), successfulReconcile)
		require.ErrorIs(t, err, ErrInvalid)
	}
	require.Zero(t, store.completeCalls)
}

func validKey() Key {
	return Key{
		Scope: platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"},
		Actor: "operator-1", OperationID: "cancelJob", IdempotencyKey: "cancel-job-1",
	}
}

func successfulReconcile(context.Context, Response, []byte) error { return nil }

func reconciliationFixture() []byte { return []byte(`{"audit":"fixture"}`) }

type synchronizedStore struct {
	mu            sync.Mutex
	records       map[string]synchronizedRecord
	claimCalls    int
	completeCalls int
}

type synchronizedRecord struct {
	fingerprint    string
	owner          string
	state          State
	response       Response
	reconciliation []byte
}

func newSynchronizedStore() *synchronizedStore {
	return &synchronizedStore{records: make(map[string]synchronizedRecord)}
}

func (store *synchronizedStore) Claim(_ context.Context, key Key, fingerprint, owner string, _, _ time.Time) (Claim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.claimCalls++
	mapKey := key.Scope.Key() + "\x00" + key.Actor + "\x00" + key.OperationID + "\x00" + key.IdempotencyKey
	record, ok := store.records[mapKey]
	if !ok {
		store.records[mapKey] = synchronizedRecord{fingerprint: fingerprint, owner: owner, state: StateProcessing}
		return Claim{Claimed: true, OwnerToken: owner, State: StateProcessing}, nil
	}
	if record.fingerprint != fingerprint {
		return Claim{}, ErrKeyConflict
	}
	if record.state == StateProcessing {
		return Claim{}, ErrInProgress
	}
	response := cloneResponse(record.response)
	ownerToken := record.owner
	reconciliation := append([]byte(nil), record.reconciliation...)
	if record.state == StateCompleted {
		ownerToken = ""
		reconciliation = nil
	}
	return Claim{OwnerToken: ownerToken, State: record.state, Response: &response, Reconciliation: reconciliation}, nil
}

func (store *synchronizedStore) CommitSideEffect(_ context.Context, key Key, fingerprint, owner string, response Response, reconciliation []byte, _ time.Time) (Response, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.completeCalls++
	mapKey := key.Scope.Key() + "\x00" + key.Actor + "\x00" + key.OperationID + "\x00" + key.IdempotencyKey
	record := store.records[mapKey]
	if record.fingerprint != fingerprint || record.owner != owner || record.state != StateProcessing {
		return Response{}, ErrOwnershipConflict
	}
	record.state = StateSideEffectCommitted
	record.response = cloneResponse(response)
	record.reconciliation = append([]byte(nil), reconciliation...)
	store.records[mapKey] = record
	return cloneResponse(record.response), nil
}

func (store *synchronizedStore) MarkAudited(_ context.Context, key Key, fingerprint, owner string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	mapKey := key.Scope.Key() + "\x00" + key.Actor + "\x00" + key.OperationID + "\x00" + key.IdempotencyKey
	record := store.records[mapKey]
	if record.fingerprint != fingerprint || record.owner != owner || record.state != StateSideEffectCommitted {
		return ErrOwnershipConflict
	}
	record.state = StateAudited
	store.records[mapKey] = record
	return nil
}

func (store *synchronizedStore) Complete(_ context.Context, key Key, fingerprint, owner string, response Response, _ time.Time) (Response, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	mapKey := key.Scope.Key() + "\x00" + key.Actor + "\x00" + key.OperationID + "\x00" + key.IdempotencyKey
	record := store.records[mapKey]
	if record.fingerprint != fingerprint || record.owner != owner || record.state != StateAudited {
		return Response{}, ErrOwnershipConflict
	}
	record.state = StateCompleted
	store.records[mapKey] = record
	return cloneResponse(response), nil
}

func (store *synchronizedStore) Abort(_ context.Context, key Key, fingerprint, owner string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	mapKey := key.Scope.Key() + "\x00" + key.Actor + "\x00" + key.OperationID + "\x00" + key.IdempotencyKey
	if record, ok := store.records[mapKey]; ok && record.fingerprint == fingerprint && record.owner == owner && record.state == StateProcessing {
		delete(store.records, mapKey)
	}
	return nil
}
