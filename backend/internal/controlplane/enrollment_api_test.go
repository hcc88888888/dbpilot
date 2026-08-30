package controlplane

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestCreateHostEnrollmentUsesGeneratedPermissionTrustedScopeAndReturnsTokenOnce(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	raw := bytes.Repeat([]byte{0x42}, enrollment.EnrollmentTokenBytes)
	encodedToken := base64.RawURLEncoding.EncodeToString(raw)
	service := &recordingEnrollmentService{created: enrollment.CreatedEnrollment{
		HostID: "host-1", AgentID: "agent-1", Token: raw, ExpiresAt: now.Add(10 * time.Minute), EnrollmentRevision: 1,
	}}
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/host-enrollments", bytes.NewBufferString(`{
		"host_id":"host-1","agent_id":"agent-1","display_name":"Primary database host",
		"labels":{"role":"database"},"expires_in_seconds":600
	}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "enroll-host-1")
	principal := principalWith(platformTestScope, openapi.PermissionCreateHostEnrollment)

	response := servePlatformRequest(Services{Enrollment: service}, principal, request)

	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	require.Equal(t, platformTestScope, service.scope)
	require.Equal(t, "trusted-user", service.request.IssuedBy)
	require.Equal(t, "enroll-host-1", service.request.IdempotencyKey)
	require.Equal(t, 10*time.Minute, service.request.ExpiresIn)
	var body openapi.HostEnrollment
	require.NoError(t, decodeJSONBytes(response.Body.Bytes(), &body))
	require.Equal(t, encodedToken, body.EnrollmentToken)
	require.Equal(t, int64(1), body.EnrollmentRevision)
	requireOpenAPIResponse(t, request, response)

	denied := httptest.NewRequest(http.MethodPost, platformBasePath+"/host-enrollments", bytes.NewBufferString(`{"host_id":"host-1","agent_id":"agent-1","display_name":"Primary","expires_in_seconds":600}`))
	denied.Header.Set("Content-Type", "application/json")
	denied.Header.Set("Idempotency-Key", "enroll-denied")
	deniedResponse := servePlatformRequest(Services{Enrollment: service}, principalWith(platformTestScope, openapi.PermissionListHosts), denied)
	requireProblem(t, deniedResponse, http.StatusForbidden, "forbidden", deniedResponse.Header().Get("X-Request-ID"))
	require.Equal(t, 1, service.calls)
}

func TestCreateHostEnrollmentRejectsInvalidIdempotencyBeforeTokenCreation(t *testing.T) {
	service := &recordingEnrollmentService{}
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/host-enrollments", bytes.NewBufferString(`{"host_id":"host-1","agent_id":"agent-1","display_name":"Primary","expires_in_seconds":600}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "bad\tkey")

	response := servePlatformRequest(Services{Enrollment: service}, principalWith(platformTestScope, openapi.PermissionCreateHostEnrollment), request)

	requireProblem(t, response, http.StatusBadRequest, "invalid_request", response.Header().Get("X-Request-ID"))
	require.Zero(t, service.calls)
}

type recordingEnrollmentService struct {
	scope   platformscope.Scope
	request enrollment.CreateRequest
	created enrollment.CreatedEnrollment
	err     error
	calls   int
}

func (service *recordingEnrollmentService) Create(_ context.Context, scope platformscope.Scope, request enrollment.CreateRequest) (enrollment.CreatedEnrollment, error) {
	service.calls++
	service.scope, service.request = scope, request
	return service.created, service.err
}
