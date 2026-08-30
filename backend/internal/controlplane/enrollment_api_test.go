package controlplane

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestCreateHostEnrollmentUsesGeneratedPermissionTrustedScopeAndReturnsTokenOnce(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	raw := bytes.Repeat([]byte{0x42}, enrollment.EnrollmentTokenBytes)
	encodedToken := base64.RawURLEncoding.EncodeToString(raw)
	service := &recordingEnrollmentService{created: enrollment.CreatedEnrollment{
		HostID: "host-1", AgentID: "agent-1", Token: raw, ExpiresAt: now.Add(10 * time.Minute), EnrollmentRevision: 1, Generation: 1,
	}}
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/host-enrollments", bytes.NewBufferString(`{
		"host_id":"host-1","agent_id":"agent-1","display_name":"Primary database host",
		"labels":{"role":"database"},"expires_in_seconds":600
	}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "enroll-host-1")
	principal := principalWith(platformTestScope, openapi.PermissionCreateHostEnrollment)

	response := servePlatformRequest(Services{Enrollment: service, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}, principal, request)

	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	require.Equal(t, platformTestScope, service.scope)
	require.Equal(t, "trusted-user", service.request.IssuedBy)
	require.Equal(t, "enroll-host-1", service.request.IdempotencyKey)
	require.Regexp(t, `^sha256:[0-9a-f]{64}$`, service.request.RequestFingerprint)
	require.Equal(t, "createHostEnrollment", service.request.Audit.OperationID)
	require.Equal(t, "trusted-user", service.request.Audit.Actor)
	require.Equal(t, 10*time.Minute, service.request.ExpiresIn)
	var body openapi.HostEnrollment
	require.NoError(t, decodeJSONBytes(response.Body.Bytes(), &body))
	require.Equal(t, encodedToken, body.EnrollmentToken)
	require.Equal(t, int64(1), body.EnrollmentRevision)
	require.Equal(t, int64(1), body.Generation)
	requireOpenAPIResponse(t, request, response)

	denied := httptest.NewRequest(http.MethodPost, platformBasePath+"/host-enrollments", bytes.NewBufferString(`{"host_id":"host-1","agent_id":"agent-1","display_name":"Primary","expires_in_seconds":600}`))
	denied.Header.Set("Content-Type", "application/json")
	denied.Header.Set("Idempotency-Key", "enroll-denied")
	deniedResponse := servePlatformRequest(Services{Enrollment: service, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}, principalWith(platformTestScope, openapi.PermissionListHosts), denied)
	requireProblem(t, deniedResponse, http.StatusForbidden, "forbidden", deniedResponse.Header().Get("X-Request-ID"))
	require.Equal(t, 1, service.calls)
}

func TestCreateHostEnrollmentRejectsInvalidIdempotencyBeforeTokenCreation(t *testing.T) {
	service := &recordingEnrollmentService{}
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/host-enrollments", bytes.NewBufferString(`{"host_id":"host-1","agent_id":"agent-1","display_name":"Primary","expires_in_seconds":600}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "bad\tkey")

	response := servePlatformRequest(Services{Enrollment: service, Idempotency: idempotency.NewService(newHTTPIdempotencyStore()), Audit: &recordingAuditService{}}, principalWith(platformTestScope, openapi.PermissionCreateHostEnrollment), request)

	requireProblem(t, response, http.StatusBadRequest, "invalid_request", response.Header().Get("X-Request-ID"))
	require.Zero(t, service.calls)
}

func TestCreateHostEnrollmentExactRetryIsNonReplayableAndExplicitReplacementIsGenerationFenced(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	firstToken := bytes.Repeat([]byte{0x31}, enrollment.EnrollmentTokenBytes)
	secondToken := bytes.Repeat([]byte{0x32}, enrollment.EnrollmentTokenBytes)
	service := &recordingEnrollmentService{createdValues: []enrollment.CreatedEnrollment{
		{HostID: "host-1", AgentID: "agent-1", Token: firstToken, ExpiresAt: now.Add(10 * time.Minute), EnrollmentRevision: 1, Generation: 1},
		{HostID: "host-1", AgentID: "agent-1", Token: secondToken, ExpiresAt: now.Add(10 * time.Minute), EnrollmentRevision: 1, Generation: 2, Replaced: true},
	}}
	store := newHTTPIdempotencyStore()
	services := Services{Enrollment: service, Idempotency: idempotency.NewService(store)}
	principal := principalWith(platformTestScope, openapi.PermissionCreateHostEnrollment)

	first := servePlatformRequest(services, principal, newEnrollmentAPIRequest("enroll-retry", "Primary"))
	require.Len(t, store.records, 1)
	second := servePlatformRequest(services, principal, newEnrollmentAPIRequest("enroll-retry", "Primary"))
	conflict := servePlatformRequest(services, principal, newEnrollmentAPIRequest("enroll-retry", "Different"))
	replacement := servePlatformRequest(services, principal, newEnrollmentReplacementRequest("replace-1", `"1"`, "Primary"))

	require.Equal(t, http.StatusCreated, first.Code, first.Body.String())
	requireProblem(t, second, http.StatusConflict, "enrollment_token_not_replayable", second.Header().Get("X-Request-ID"))
	require.Equal(t, `"1"`, second.Header().Get("ETag"))
	var firstBody, replacementBody openapi.HostEnrollment
	require.NoError(t, decodeJSONBytes(first.Body.Bytes(), &firstBody))
	require.Equal(t, http.StatusCreated, replacement.Code, replacement.Body.String())
	require.NoError(t, decodeJSONBytes(replacement.Body.Bytes(), &replacementBody))
	require.NotEqual(t, firstBody.EnrollmentToken, replacementBody.EnrollmentToken)
	require.Equal(t, int64(2), replacementBody.Generation)
	require.Equal(t, `"2"`, replacement.Header().Get("ETag"))
	requireProblem(t, conflict, http.StatusConflict, "idempotency_conflict", conflict.Header().Get("X-Request-ID"))
	require.Equal(t, 2, service.calls)
}

func TestCreateHostEnrollmentRecoversUnreturnedTokenAfterMarkerFailureOrUnknownCommit(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		fail    func(*httpIdempotencyStore)
		release func(*httpIdempotencyStore)
	}{
		{
			name:    "commit failed before marker persistence",
			fail:    func(store *httpIdempotencyStore) { store.completeErr = errors.New("marker unavailable") },
			release: func(store *httpIdempotencyStore) { store.completeErr = nil },
		},
		{
			name: "marker commit outcome was unknown",
			fail: func(store *httpIdempotencyStore) {
				store.commitUnknownErr = errors.New("connection lost after marker commit")
			},
			release: func(store *httpIdempotencyStore) { store.commitUnknownErr = nil },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &recordingEnrollmentService{createdValues: []enrollment.CreatedEnrollment{
				{HostID: "host-1", AgentID: "agent-1", Token: bytes.Repeat([]byte{0x41}, enrollment.EnrollmentTokenBytes), ExpiresAt: now.Add(10 * time.Minute), EnrollmentRevision: 1, Generation: 1},
				{HostID: "host-1", AgentID: "agent-1", Token: bytes.Repeat([]byte{0x42}, enrollment.EnrollmentTokenBytes), ExpiresAt: now.Add(10 * time.Minute), EnrollmentRevision: 1, Generation: 2, Replaced: true},
			}}
			store := newHTTPIdempotencyStore()
			test.fail(store)
			services := Services{Enrollment: service, Idempotency: idempotency.NewService(store)}
			principal := principalWith(platformTestScope, openapi.PermissionCreateHostEnrollment)

			failed := servePlatformRequest(services, principal, newEnrollmentAPIRequest("recover-create", "Primary"))
			requireProblem(t, failed, http.StatusInternalServerError, "internal_error", failed.Header().Get("X-Request-ID"))
			test.release(store)
			recovered := servePlatformRequest(services, principal, newEnrollmentAPIRequest("recover-create", "Primary"))
			require.Equal(t, http.StatusCreated, recovered.Code, recovered.Body.String())
			var body openapi.HostEnrollment
			require.NoError(t, decodeJSONBytes(recovered.Body.Bytes(), &body))
			require.Equal(t, int64(2), body.Generation)
			require.Equal(t, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, enrollment.EnrollmentTokenBytes)), body.EnrollmentToken)

			replayed := servePlatformRequest(services, principal, newEnrollmentAPIRequest("recover-create", "Primary"))
			requireProblem(t, replayed, http.StatusConflict, "enrollment_token_not_replayable", replayed.Header().Get("X-Request-ID"))
			require.Equal(t, `"2"`, replayed.Header().Get("ETag"))
			require.Equal(t, 2, service.calls, "recovery may fence the unreachable token only once")
		})
	}
}

func TestConcurrentExactRecoveryReturnsAtMostOneReplacementToken(t *testing.T) {
	service := &generationFencedEnrollmentService{now: time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)}
	store := newHTTPIdempotencyStore()
	store.completeErr = errors.New("marker unavailable")
	services := Services{Enrollment: service, Idempotency: idempotency.NewService(store)}
	principal := principalWith(platformTestScope, openapi.PermissionCreateHostEnrollment)
	failed := servePlatformRequest(services, principal, newEnrollmentAPIRequest("recover-concurrent", "Primary"))
	requireProblem(t, failed, http.StatusInternalServerError, "internal_error", failed.Header().Get("X-Request-ID"))
	store.completeErr = nil

	const consumers = 16
	responses := make(chan *httptest.ResponseRecorder, consumers)
	var wait sync.WaitGroup
	for index := 0; index < consumers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses <- servePlatformRequest(services, principal, newEnrollmentAPIRequest("recover-concurrent", "Primary"))
		}()
	}
	wait.Wait()
	close(responses)
	created := 0
	for response := range responses {
		switch response.Code {
		case http.StatusCreated:
			created++
			var body openapi.HostEnrollment
			require.NoError(t, decodeJSONBytes(response.Body.Bytes(), &body))
			require.Equal(t, int64(2), body.Generation)
			require.True(t, service.validToken(body.EnrollmentToken), "the sole returned token must remain the active generation")
		case http.StatusConflict:
			var problem openapi.Problem
			require.NoError(t, decodeJSONBytes(response.Body.Bytes(), &problem))
			require.Contains(t, []string{"conflict", "enrollment_token_not_replayable", "idempotency_in_progress"}, problem.Code)
		default:
			t.Fatalf("unexpected concurrent recovery response %d: %s", response.Code, response.Body.String())
		}
	}
	require.Equal(t, 1, created)
	require.Equal(t, uint64(2), service.currentGeneration())
}

func TestReplaceHostEnrollmentFinalizesCommittedGenerationAfterMarkerFailureOrUnknownOutcome(t *testing.T) {
	for _, test := range []struct {
		name    string
		fail    func(*httpIdempotencyStore)
		release func(*httpIdempotencyStore)
	}{
		{
			name:    "marker failed before persistence",
			fail:    func(store *httpIdempotencyStore) { store.completeErr = errors.New("marker unavailable") },
			release: func(store *httpIdempotencyStore) { store.completeErr = nil },
		},
		{
			name: "marker commit outcome was unknown",
			fail: func(store *httpIdempotencyStore) {
				store.commitUnknownErr = errors.New("connection lost after marker commit")
			},
			release: func(store *httpIdempotencyStore) { store.commitUnknownErr = nil },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := newGenerationFencedEnrollmentService(1)
			store := newHTTPIdempotencyStore()
			test.fail(store)
			services := Services{Enrollment: service, Idempotency: idempotency.NewService(store)}
			principal := principalWith(platformTestScope, openapi.PermissionCreateHostEnrollment)

			failed := servePlatformRequest(services, principal, newEnrollmentReplacementRequest("replace-recover", `"1"`, "Primary"))
			requireProblem(t, failed, http.StatusInternalServerError, "internal_error", failed.Header().Get("X-Request-ID"))
			require.Equal(t, uint64(2), service.currentGeneration(), "token and Audit commit precedes public marker persistence")
			test.release(store)

			recovered := servePlatformRequest(services, principal, newEnrollmentReplacementRequest("replace-recover", `"1"`, "Primary"))
			requireProblem(t, recovered, http.StatusConflict, "enrollment_token_not_replayable", recovered.Header().Get("X-Request-ID"))
			require.Equal(t, `"2"`, recovered.Header().Get("ETag"))
			require.Equal(t, uint64(2), service.currentGeneration(), "marker recovery must not rotate the committed replacement")
			require.Equal(t, 1, service.replacementCallCount())
		})
	}
}

func TestConcurrentExactReplacementRecoveryConvergesWithoutInvalidatingTheCommittedToken(t *testing.T) {
	service := newGenerationFencedEnrollmentService(1)
	store := newHTTPIdempotencyStore()
	store.completeErr = errors.New("marker unavailable")
	services := Services{Enrollment: service, Idempotency: idempotency.NewService(store)}
	principal := principalWith(platformTestScope, openapi.PermissionCreateHostEnrollment)
	failed := servePlatformRequest(services, principal, newEnrollmentReplacementRequest("replace-concurrent", `"1"`, "Primary"))
	requireProblem(t, failed, http.StatusInternalServerError, "internal_error", failed.Header().Get("X-Request-ID"))
	activeToken := service.activeToken()
	store.completeErr = nil

	const consumers = 16
	responses := make(chan *httptest.ResponseRecorder, consumers)
	var wait sync.WaitGroup
	for index := 0; index < consumers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses <- servePlatformRequest(services, principal, newEnrollmentReplacementRequest("replace-concurrent", `"1"`, "Primary"))
		}()
	}
	wait.Wait()
	close(responses)
	for response := range responses {
		requireProblem(t, response, http.StatusConflict, "enrollment_token_not_replayable", response.Header().Get("X-Request-ID"))
		require.Equal(t, `"2"`, response.Header().Get("ETag"))
	}
	require.Equal(t, uint64(2), service.currentGeneration())
	require.Equal(t, 1, service.replacementCallCount())
	require.Equal(t, activeToken, service.activeToken(), "exact recovery may not invalidate the committed replacement token")
}

func newEnrollmentAPIRequest(idempotencyKey, displayName string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/host-enrollments", bytes.NewBufferString(`{"host_id":"host-1","agent_id":"agent-1","display_name":"`+displayName+`","expires_in_seconds":600}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	return request
}

func newEnrollmentReplacementRequest(idempotencyKey, ifMatch, displayName string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/host-enrollments/host-1/actions/replace", bytes.NewBufferString(`{"agent_id":"agent-1","display_name":"`+displayName+`","expires_in_seconds":600}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("If-Match", ifMatch)
	return request
}

type recordingEnrollmentService struct {
	scope            platformscope.Scope
	request          enrollment.CreateRequest
	created          enrollment.CreatedEnrollment
	createdValues    []enrollment.CreatedEnrollment
	err              error
	calls            int
	replacementState enrollment.ReplacementState
}

type generationFencedEnrollmentService struct {
	mu           sync.Mutex
	now          time.Time
	generation   uint64
	token        []byte
	replacements int
	scope        platformscope.Scope
	request      enrollment.CreateRequest
}

func newGenerationFencedEnrollmentService(generation uint64) *generationFencedEnrollmentService {
	service := &generationFencedEnrollmentService{now: time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC), generation: generation}
	if generation > 0 {
		service.token = bytes.Repeat([]byte{byte(0x50 + generation)}, enrollment.EnrollmentTokenBytes)
	}
	return service
}

func (service *generationFencedEnrollmentService) Create(_ context.Context, _ platformscope.Scope, _ enrollment.CreateRequest) (enrollment.CreatedEnrollment, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.generation != 0 {
		return enrollment.CreatedEnrollment{}, enrollment.ErrEnrollmentConflict
	}
	service.generation = 1
	service.token = bytes.Repeat([]byte{0x51}, enrollment.EnrollmentTokenBytes)
	return service.createdLocked(false), nil
}

func (service *generationFencedEnrollmentService) Replace(_ context.Context, scope platformscope.Scope, request enrollment.CreateRequest, expected uint64) (enrollment.CreatedEnrollment, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if expected != service.generation {
		return enrollment.CreatedEnrollment{}, enrollment.ErrEnrollmentGenerationConflict
	}
	service.replacements++
	service.generation++
	service.token = bytes.Repeat([]byte{byte(0x50 + service.generation)}, enrollment.EnrollmentTokenBytes)
	service.scope, service.request = scope, request
	return service.createdLocked(true), nil
}

func (service *generationFencedEnrollmentService) ResolveReplacement(_ context.Context, scope platformscope.Scope, request enrollment.ReplacementLookup) (enrollment.ReplacementState, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if scope != service.scope || request.HostID != service.request.HostID || request.AgentID != service.request.AgentID || request.IssuedBy != service.request.IssuedBy ||
		request.IdempotencyKey != service.request.IdempotencyKey || request.RequestFingerprint != service.request.RequestFingerprint {
		return enrollment.ReplacementState{}, enrollment.ErrEnrollmentNotFound
	}
	return enrollment.ReplacementState{HostID: request.HostID, AgentID: request.AgentID, EnrollmentRevision: 1, Generation: service.generation}, nil
}

func (service *generationFencedEnrollmentService) createdLocked(replaced bool) enrollment.CreatedEnrollment {
	return enrollment.CreatedEnrollment{HostID: "host-1", AgentID: "agent-1", Token: append([]byte(nil), service.token...), ExpiresAt: service.now.Add(10 * time.Minute), EnrollmentRevision: 1, Generation: service.generation, Replaced: replaced}
}

func (service *generationFencedEnrollmentService) validToken(encoded string) bool {
	service.mu.Lock()
	defer service.mu.Unlock()
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && bytes.Equal(decoded, service.token)
}

func (service *generationFencedEnrollmentService) currentGeneration() uint64 {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.generation
}

func (service *generationFencedEnrollmentService) replacementCallCount() int {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.replacements
}

func (service *generationFencedEnrollmentService) activeToken() string {
	service.mu.Lock()
	defer service.mu.Unlock()
	return base64.RawURLEncoding.EncodeToString(service.token)
}

func (service *recordingEnrollmentService) Create(_ context.Context, scope platformscope.Scope, request enrollment.CreateRequest) (enrollment.CreatedEnrollment, error) {
	service.calls++
	service.scope, service.request = scope, request
	if len(service.createdValues) > 0 {
		created := service.createdValues[0]
		service.createdValues = service.createdValues[1:]
		return created, service.err
	}
	return service.created, service.err
}

func (service *recordingEnrollmentService) Replace(_ context.Context, scope platformscope.Scope, request enrollment.CreateRequest, expected uint64) (enrollment.CreatedEnrollment, error) {
	service.calls++
	service.scope, service.request = scope, request
	if len(service.createdValues) > 0 {
		created := service.createdValues[0]
		service.createdValues = service.createdValues[1:]
		return created, service.err
	}
	created := service.created
	created.Generation = expected + 1
	created.Replaced = true
	return created, service.err
}

func (service *recordingEnrollmentService) ResolveReplacement(_ context.Context, _ platformscope.Scope, request enrollment.ReplacementLookup) (enrollment.ReplacementState, error) {
	if service.replacementState.Generation == 0 {
		return enrollment.ReplacementState{}, enrollment.ErrEnrollmentNotFound
	}
	state := service.replacementState
	state.HostID, state.AgentID = request.HostID, request.AgentID
	return state, nil
}
