package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/capability"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"
	"github.com/stretchr/testify/require"
)

const platformBasePath = "/api/v1/tenants/tenant-a/projects/project-a"

var platformTestScope = platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}

func TestGeneratedGetJobReturnsScopedContractEntityWithETag(t *testing.T) {
	jobs := &recordingJobService{getValue: validPlatformJob()}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/jobs/job-1", nil)
	request.Header.Set("X-Request-ID", "request-http-1")
	response := servePlatformRequest(Services{Jobs: jobs}, principalWith(platformTestScope, openapi.PermissionGetJob), request)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, `"7"`, response.Header().Get("ETag"))
	require.Equal(t, "request-http-1", response.Header().Get("X-Request-ID"))
	require.Equal(t, platformTestScope, jobs.getScope)
	require.Equal(t, "job-1", jobs.getID)
	require.JSONEq(t, `{
		"id":"job-1","type":"inspection.run","status":"running","outcome":"none",
		"tenant_id":"tenant-a","project_id":"project-a","instance_id":"instance-1",
		"target_resource_ids":["instance-1"],"initiated_by":"trusted-user",
		"source_resource":{"resource_type":"inspection","resource_id":"inspection-1"},
		"idempotency_key":"create-job-1","version":7,
		"progress":{"total_targets":1,"completed_targets":0,"failed_targets":0,"skipped_targets":0},
		"artifacts":[],"created_at":"2026-08-28T04:00:00Z","request_id":"request-job-1","trace_id":"trace-job-1"
	}`, response.Body.String())
	requireOpenAPIResponse(t, request, response)
}

func TestGeneratedCancelUsesURLScopeAuthenticatedActorAndConditionalVersion(t *testing.T) {
	jobs := &recordingJobService{transitionValue: func() job.Job {
		value := validPlatformJob()
		value.Status = job.StatusCancelling
		value.Version = 8
		return value
	}()}
	audits := &recordingAuditService{}
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/jobs/job-1/actions/cancel", nil)
	request.Header.Set("Idempotency-Key", "cancel-job-1")
	request.Header.Set("If-Match", `"7"`)
	request.Header.Set("X-Request-ID", "request-cancel-1")
	request.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	response := servePlatformRequest(Services{Jobs: jobs, Audit: audits, Idempotency: idempotency.NewService(newHTTPIdempotencyStore()), Now: func() time.Time { return time.Date(2026, 8, 28, 5, 0, 0, 0, time.UTC) }}, principalWith(platformTestScope, openapi.PermissionCancelJob), request)

	require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
	require.Equal(t, `"8"`, response.Header().Get("ETag"))
	require.Equal(t, platformBasePath+"/jobs/job-1", response.Header().Get("Location"))
	require.Len(t, jobs.transitions, 1)
	require.Equal(t, platformTestScope, jobs.transitions[0].Scope)
	require.Equal(t, "job-1", jobs.transitions[0].JobID)
	require.Equal(t, int64(7), jobs.transitions[0].CurrentVersion)
	require.Equal(t, job.StatusCancelling, jobs.transitions[0].To)
	require.Equal(t, "trusted-user", jobs.transitions[0].Actor)
	require.Equal(t, time.Date(2026, 8, 28, 5, 0, 0, 0, time.UTC), jobs.transitions[0].At)
	require.Equal(t, request.Header.Get("traceparent"), response.Header().Get("traceparent"))
	require.Len(t, audits.records, 1)
	require.Equal(t, audit.Event{
		Scope: platformTestScope, Action: "job.cancel_requested", Actor: audit.Actor{Type: "user", ID: "trusted-user"},
		Resource: audit.Resource{Type: "job", ID: "job-1"}, Result: "success", RequestID: "request-cancel-1",
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", DedupeKey: audits.records[0].DedupeKey,
		Detail: map[string]any{"operation_id": "cancelJob"},
	}, audits.records[0])
	requireOpenAPIResponse(t, request, response)
}

func TestPlatformRequestValidationRejectsUnexpectedBodyQueryAndHeaderBeforeServices(t *testing.T) {
	t.Run("unexpected body", func(t *testing.T) {
		jobs := &recordingJobService{}
		services := Services{Jobs: jobs, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
		request := httptest.NewRequest(http.MethodPost, platformBasePath+"/jobs/job-1/actions/cancel", strings.NewReader(`{"actor":"attacker","tenant_id":"tenant-b","project_id":"project-b"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "cancel-job-1")
		request.Header.Set("If-Match", `"7"`)

		response := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionCancelJob), request)

		requireProblem(t, response, http.StatusBadRequest, "invalid_request", response.Header().Get("X-Request-ID"))
		require.Empty(t, jobs.transitions)
	})

	t.Run("query maximum", func(t *testing.T) {
		audits := &recordingAuditService{}
		request := httptest.NewRequest(http.MethodGet, platformBasePath+"/audit-events?limit=101", nil)

		response := servePlatformRequest(Services{Audit: audits}, principalWith(platformTestScope, openapi.PermissionListAuditEvents), request)

		requireProblem(t, response, http.StatusBadRequest, "invalid_request", response.Header().Get("X-Request-ID"))
		require.Zero(t, audits.calls)
	})

	t.Run("empty required header", func(t *testing.T) {
		artifacts := &recordingArtifactService{}
		request := httptest.NewRequest(http.MethodPost, platformBasePath+"/artifacts/artifact-1/actions/download", nil)
		request.Header["Idempotency-Key"] = []string{""}

		response := servePlatformRequest(Services{Artifacts: artifacts, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}, principalWith(platformTestScope, openapi.PermissionCreateArtifactDownload), request)

		requireProblem(t, response, http.StatusBadRequest, "invalid_request", response.Header().Get("X-Request-ID"))
		require.Zero(t, artifacts.downloadCalls)
	})
}

func TestPlatformMethodGateRejectsHEADAndUnsupportedMethodsBeforeServices(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		permission string
		allow      string
		services   func() (Services, func() int)
	}{
		{name: "head get job", method: http.MethodHead, path: platformBasePath + "/jobs/job-1", permission: openapi.PermissionGetJob, allow: http.MethodGet, services: func() (Services, func() int) {
			jobs := &recordingJobService{getValue: validPlatformJob()}
			return Services{Jobs: jobs}, func() int { return jobs.getCalls }
		}},
		{name: "post get job", method: http.MethodPost, path: platformBasePath + "/jobs/job-1", permission: openapi.PermissionGetJob, allow: http.MethodGet, services: func() (Services, func() int) {
			jobs := &recordingJobService{getValue: validPlatformJob()}
			return Services{Jobs: jobs}, func() int { return jobs.getCalls }
		}},
		{name: "put artifact download", method: http.MethodPut, path: platformBasePath + "/artifacts/artifact-1/actions/download", permission: openapi.PermissionCreateArtifactDownload, allow: http.MethodPost, services: func() (Services, func() int) {
			artifacts := &recordingArtifactService{}
			return Services{Artifacts: artifacts, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}, func() int { return artifacts.downloadCalls }
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			services, calls := test.services()
			request := httptest.NewRequest(test.method, test.path, nil)

			response := servePlatformRequest(services, principalWith(platformTestScope, test.permission), request)

			requireProblem(t, response, http.StatusMethodNotAllowed, "method_not_allowed", response.Header().Get("X-Request-ID"))
			require.Equal(t, test.allow, response.Header().Get("Allow"))
			require.Zero(t, calls())
		})
	}
}

func TestGeneratedCancelRequiresIdempotencyKeyAndIfMatch(t *testing.T) {
	tests := map[string]func(*http.Request){
		"missing idempotency key": func(request *http.Request) { request.Header.Set("If-Match", `"7"`) },
		"missing if match":        func(request *http.Request) { request.Header.Set("Idempotency-Key", "cancel-job-1") },
		"invalid if match": func(request *http.Request) {
			request.Header.Set("Idempotency-Key", "cancel-job-1")
			request.Header.Set("If-Match", "W/\"7\"")
		},
	}
	for name, configure := range tests {
		t.Run(name, func(t *testing.T) {
			jobs := &recordingJobService{}
			request := httptest.NewRequest(http.MethodPost, platformBasePath+"/jobs/job-1/actions/cancel", nil)
			request.Header.Set("X-Request-ID", "request-invalid-1")
			configure(request)

			response := servePlatformRequest(Services{Jobs: jobs, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}, principalWith(platformTestScope, openapi.PermissionCancelJob), request)

			requireProblem(t, response, http.StatusBadRequest, "invalid_request", "request-invalid-1")
			require.Empty(t, jobs.transitions)
			requireOpenAPIResponse(t, request, response)
		})
	}
}

func TestGeneratedCancelReturnsPreconditionFailedForStaleETag(t *testing.T) {
	jobs := &recordingJobService{transitionErr: job.ErrConflict}
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/jobs/job-1/actions/cancel", nil)
	request.Header.Set("Idempotency-Key", "cancel-job-1")
	request.Header.Set("If-Match", `"6"`)
	response := servePlatformRequest(Services{Jobs: jobs, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}, principalWith(platformTestScope, openapi.PermissionCancelJob), request)

	requireProblem(t, response, http.StatusPreconditionFailed, "precondition_failed", response.Header().Get("X-Request-ID"))
	requireOpenAPIResponse(t, request, response)
}

func TestGeneratedCancelReplaysCompletedResponseWithOriginalStaleETag(t *testing.T) {
	jobs := &recordingJobService{transitionValue: func() job.Job {
		value := validPlatformJob()
		value.Status = job.StatusCancelling
		value.Version = 8
		return value
	}()}
	idempotencyService := idempotency.NewService(newHTTPIdempotencyStore())
	services := Services{Jobs: jobs, Idempotency: idempotencyService, Now: func() time.Time { return time.Date(2026, 8, 28, 5, 0, 0, 0, time.UTC) }}

	firstRequest := newCancelRequest(`"7"`, "cancel-job-1")
	first := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionCancelJob), firstRequest)
	secondRequest := newCancelRequest(`"7"`, "cancel-job-1")
	second := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionCancelJob), secondRequest)

	require.Equal(t, http.StatusAccepted, first.Code, first.Body.String())
	require.Equal(t, first.Code, second.Code)
	require.Equal(t, first.Body.Bytes(), second.Body.Bytes())
	require.Equal(t, first.Header().Get("ETag"), second.Header().Get("ETag"))
	require.Equal(t, first.Header().Get("Location"), second.Header().Get("Location"))
	require.Len(t, jobs.transitions, 1)
	requireOpenAPIResponse(t, firstRequest, first)
	requireOpenAPIResponse(t, secondRequest, second)
}

func TestGeneratedArtifactDownloadReplaysDescriptorWithoutSecondSignerCall(t *testing.T) {
	artifacts := &recordingArtifactService{downloadValue: artifact.Download{
		URL:       "https://downloads.example/artifact-1?signature=safe",
		ExpiresAt: time.Date(2026, 8, 28, 5, 5, 0, 0, time.UTC),
	}}
	services := Services{Artifacts: artifacts, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
	principal := principalWith(platformTestScope, openapi.PermissionCreateArtifactDownload)

	firstRequest := newDownloadRequest("download-artifact-1")
	first := servePlatformRequest(services, principal, firstRequest)
	secondRequest := newDownloadRequest("download-artifact-1")
	second := servePlatformRequest(services, principal, secondRequest)

	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.Equal(t, first.Code, second.Code)
	require.Equal(t, first.Body.Bytes(), second.Body.Bytes())
	require.Equal(t, 1, artifacts.downloadCalls)
	requireOpenAPIResponse(t, firstRequest, first)
	requireOpenAPIResponse(t, secondRequest, second)
}

func TestGeneratedExpiredArtifactDownloadReturnsDocumentedConflict(t *testing.T) {
	artifacts := &recordingArtifactService{downloadErr: artifact.ErrExpired}
	services := Services{Artifacts: artifacts, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
	request := newDownloadRequest("download-expired-1")

	response := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionCreateArtifactDownload), request)

	requireProblem(t, response, http.StatusConflict, "conflict", response.Header().Get("X-Request-ID"))
	require.Equal(t, 1, artifacts.downloadCalls)
	requireOpenAPIResponse(t, request, response)
}

func TestGeneratedIdempotencyKeyFingerprintCollisionReturnsConflict(t *testing.T) {
	jobs := &recordingJobService{transitionValue: func() job.Job {
		value := validPlatformJob()
		value.Status = job.StatusCancelling
		value.Version = 8
		return value
	}()}
	services := Services{Jobs: jobs, Audit: &recordingAuditService{}, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
	principal := principalWith(platformTestScope, openapi.PermissionCancelJob)
	first := servePlatformRequest(services, principal, newCancelRequest(`"7"`, "cancel-job-1"))
	require.Equal(t, http.StatusAccepted, first.Code, first.Body.String())

	collision := servePlatformRequest(services, principal, newCancelRequest(`"6"`, "cancel-job-1"))

	requireProblem(t, collision, http.StatusConflict, "idempotency_conflict", collision.Header().Get("X-Request-ID"))
	require.Len(t, jobs.transitions, 1)
}

func TestGeneratedConcurrentDuplicateReturnsRetryableConflictWithoutSecondExecution(t *testing.T) {
	jobs := newBlockingJobService()
	services := Services{Jobs: jobs, Audit: &recordingAuditService{}, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
	principal := principalWith(platformTestScope, openapi.PermissionCancelJob)
	handler := NewHTTPHandler(services, platformStaticPrincipalResolver{principal: principal})
	first := httptest.NewRecorder()
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		handler.ServeHTTP(first, newCancelRequest(`"7"`, "cancel-job-1"))
	}()
	<-jobs.started

	duplicate := httptest.NewRecorder()
	handler.ServeHTTP(duplicate, newCancelRequest(`"7"`, "cancel-job-1"))
	close(jobs.proceed)
	<-firstDone

	requireProblem(t, duplicate, http.StatusConflict, "idempotency_in_progress", duplicate.Header().Get("X-Request-ID"))
	require.Equal(t, "1", duplicate.Header().Get("Retry-After"))
	require.Equal(t, 1, jobs.calls())
	require.Equal(t, http.StatusAccepted, first.Code, first.Body.String())
	require.Equal(t, 1, jobs.calls())
}

func TestReconcileCancelAuditFailureFromStoredSideEffectWithoutSecondCancel(t *testing.T) {
	jobs := &recordingJobService{transitionValue: func() job.Job {
		value := validPlatformJob()
		value.Status = job.StatusCancelling
		value.Version = 8
		return value
	}()}
	audits := &recordingAuditService{err: errors.New("audit unavailable")}
	store := newHTTPIdempotencyStore()
	services := Services{Jobs: jobs, Audit: audits, Idempotency: idempotency.NewService(store)}
	principal := principalWith(platformTestScope, openapi.PermissionCancelJob)

	first := servePlatformRequest(services, principal, newCancelRequest(`"7"`, "cancel-audit-repair-1"))
	requireProblem(t, first, http.StatusInternalServerError, "internal_error", first.Header().Get("X-Request-ID"))
	require.Len(t, jobs.transitions, 1)
	require.Equal(t, 1, audits.recordCalls)

	audits.err = nil
	retryRequest := newCancelRequest(`"7"`, "cancel-audit-repair-1")
	retry := servePlatformRequest(services, principal, retryRequest)

	require.Equal(t, http.StatusAccepted, retry.Code, retry.Body.String())
	require.Equal(t, `"8"`, retry.Header().Get("ETag"))
	require.Len(t, jobs.transitions, 1, "reconciliation must not repeat the cancellation")
	require.Equal(t, 2, audits.recordCalls)
	requireOpenAPIResponse(t, retryRequest, retry)
}

func TestReconcileArtifactAuditFailureFromStoredDescriptorWithoutSecondSigning(t *testing.T) {
	artifacts := &recordingArtifactService{downloadValue: artifact.Download{
		URL:       "https://downloads.example/signed-once?signature=safe",
		ExpiresAt: time.Date(2026, 8, 28, 5, 5, 0, 0, time.UTC),
	}}
	audits := &recordingAuditService{err: errors.New("audit unavailable")}
	store := newHTTPIdempotencyStore()
	services := Services{Artifacts: artifacts, Audit: audits, Idempotency: idempotency.NewService(store)}
	principal := principalWith(platformTestScope, openapi.PermissionCreateArtifactDownload)

	first := servePlatformRequest(services, principal, newDownloadRequest("download-audit-repair-1"))
	requireProblem(t, first, http.StatusInternalServerError, "internal_error", first.Header().Get("X-Request-ID"))
	require.Equal(t, 1, artifacts.downloadCalls)
	require.Equal(t, 1, audits.recordCalls)

	audits.err = nil
	retryRequest := newDownloadRequest("download-audit-repair-1")
	retry := servePlatformRequest(services, principal, retryRequest)

	require.Equal(t, http.StatusOK, retry.Code, retry.Body.String())
	require.Contains(t, retry.Body.String(), "signed-once")
	require.Equal(t, 1, artifacts.downloadCalls, "reconciliation must not sign a second descriptor")
	require.Equal(t, 2, audits.recordCalls)
	requireOpenAPIResponse(t, retryRequest, retry)
}

func TestAmbiguousJobCommitLeavesClaimProcessingAndRetryDoesNotTransitionAgain(t *testing.T) {
	jobs := &recordingJobService{transitionErr: job.ErrAmbiguousCommit}
	store := newHTTPIdempotencyStore()
	services := Services{Jobs: jobs, Idempotency: idempotency.NewService(store)}
	principal := principalWith(platformTestScope, openapi.PermissionCancelJob)

	first := servePlatformRequest(services, principal, newCancelRequest(`"7"`, "cancel-ambiguous-1"))
	requireProblem(t, first, http.StatusInternalServerError, "internal_error", first.Header().Get("X-Request-ID"))
	require.Len(t, jobs.transitions, 1)
	require.Zero(t, store.abortCalls)

	retry := servePlatformRequest(services, principal, newCancelRequest(`"7"`, "cancel-ambiguous-1"))
	requireProblem(t, retry, http.StatusConflict, "idempotency_in_progress", retry.Header().Get("X-Request-ID"))
	require.Len(t, jobs.transitions, 1)
}

func TestDownloadCompleteFailureLeavesClaimProcessingAndRetryDoesNotResign(t *testing.T) {
	artifacts := &recordingArtifactService{downloadValue: artifact.Download{
		URL:       "https://downloads.example/artifact-1?signature=safe",
		ExpiresAt: time.Date(2026, 8, 28, 5, 5, 0, 0, time.UTC),
	}}
	store := newHTTPIdempotencyStore()
	store.completeErr = errors.New("idempotency completion unavailable")
	services := Services{Artifacts: artifacts, Idempotency: idempotency.NewService(store)}
	principal := principalWith(platformTestScope, openapi.PermissionCreateArtifactDownload)

	first := servePlatformRequest(services, principal, newDownloadRequest("download-complete-failure-1"))
	requireProblem(t, first, http.StatusInternalServerError, "internal_error", first.Header().Get("X-Request-ID"))
	require.Equal(t, 1, artifacts.downloadCalls)
	require.Zero(t, store.abortCalls)

	retry := servePlatformRequest(services, principal, newDownloadRequest("download-complete-failure-1"))
	requireProblem(t, retry, http.StatusConflict, "idempotency_in_progress", retry.Header().Get("X-Request-ID"))
	require.Equal(t, 1, artifacts.downloadCalls)
}

func TestDownloadSafePreSideEffectFailureAbortsByOwnerAndCanRetry(t *testing.T) {
	artifacts := &sequencedArtifactService{
		errors: []error{errors.Join(artifact.ErrBeforeDownloadSideEffect, artifact.ErrNotFound), nil},
		value:  artifact.Download{URL: "https://downloads.example/artifact-1?signature=safe", ExpiresAt: time.Date(2026, 8, 28, 5, 5, 0, 0, time.UTC)},
	}
	store := newHTTPIdempotencyStore()
	services := Services{Artifacts: artifacts, Idempotency: idempotency.NewService(store)}
	principal := principalWith(platformTestScope, openapi.PermissionCreateArtifactDownload)

	first := servePlatformRequest(services, principal, newDownloadRequest("download-safe-retry-1"))
	requireProblem(t, first, http.StatusNotFound, "not_found", first.Header().Get("X-Request-ID"))
	require.Equal(t, 1, store.abortCalls)
	require.Len(t, store.claimedOwners, 1)
	require.Equal(t, store.claimedOwners[0], store.abortedOwners[0])

	retry := servePlatformRequest(services, principal, newDownloadRequest("download-safe-retry-1"))
	require.Equal(t, http.StatusOK, retry.Code, retry.Body.String())
	require.Equal(t, 2, artifacts.calls)
	require.Len(t, store.claimedOwners, 2)
	require.NotEqual(t, store.claimedOwners[0], store.claimedOwners[1])
}

func TestDownloadUnknownServiceErrorLeavesClaimProcessing(t *testing.T) {
	artifacts := &recordingArtifactService{downloadErr: errors.New("signer outcome unknown")}
	store := newHTTPIdempotencyStore()
	services := Services{Artifacts: artifacts, Idempotency: idempotency.NewService(store)}
	principal := principalWith(platformTestScope, openapi.PermissionCreateArtifactDownload)

	first := servePlatformRequest(services, principal, newDownloadRequest("download-unknown-1"))
	requireProblem(t, first, http.StatusInternalServerError, "internal_error", first.Header().Get("X-Request-ID"))
	require.Zero(t, store.abortCalls)

	retry := servePlatformRequest(services, principal, newDownloadRequest("download-unknown-1"))
	requireProblem(t, retry, http.StatusConflict, "idempotency_in_progress", retry.Header().Get("X-Request-ID"))
	require.Equal(t, 1, artifacts.downloadCalls)
}

func TestGeneratedArtifactMetadataAndDownloadDescriptor(t *testing.T) {
	created := time.Date(2026, 8, 28, 4, 0, 0, 0, time.UTC)
	expires := created.Add(time.Hour)
	artifacts := &recordingArtifactService{
		getValue:      artifact.Artifact{ID: "artifact-1", Scope: platformTestScope, Kind: "inspection-report", ContentType: "application/json", SizeBytes: 37, Checksum: "sha256:abc", CreatedBy: "trusted-user", CreatedAt: created, ExpiresAt: &expires},
		downloadValue: artifact.Download{URL: "https://downloads.example/artifact-1?signature=safe", ExpiresAt: created.Add(5 * time.Minute)},
	}
	actionAudits := &recordingAuditService{}

	metadataRequest := httptest.NewRequest(http.MethodGet, platformBasePath+"/artifacts/artifact-1", nil)
	metadataResponse := servePlatformRequest(Services{Artifacts: artifacts}, principalWith(platformTestScope, openapi.PermissionGetArtifact), metadataRequest)
	require.Equal(t, http.StatusOK, metadataResponse.Code, metadataResponse.Body.String())
	require.Equal(t, platformTestScope, artifacts.getScope)
	require.NotContains(t, metadataResponse.Body.String(), "storage_reference")
	requireOpenAPIResponse(t, metadataRequest, metadataResponse)

	downloadRequest := httptest.NewRequest(http.MethodPost, platformBasePath+"/artifacts/artifact-1/actions/download", nil)
	downloadRequest.Header.Set("Idempotency-Key", "download-artifact-1")
	downloadRequest.Header.Set("X-Request-ID", "request-download-1")
	downloadRequest.Header.Set("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
	downloadResponse := servePlatformRequest(Services{Artifacts: artifacts, Audit: actionAudits, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}, principalWith(platformTestScope, openapi.PermissionCreateArtifactDownload), downloadRequest)
	require.Equal(t, http.StatusOK, downloadResponse.Code, downloadResponse.Body.String())
	require.Equal(t, platformTestScope, artifacts.downloadScope)
	require.Equal(t, "artifact-1", artifacts.downloadID)
	require.Equal(t, artifact.MaximumDownloadTTL, artifacts.downloadTTL)
	require.Len(t, actionAudits.records, 1)
	require.Equal(t, "artifact.download_authorized", actionAudits.records[0].Action)
	require.Equal(t, audit.Resource{Type: "artifact", ID: "artifact-1"}, actionAudits.records[0].Resource)
	require.Equal(t, "request-download-1", actionAudits.records[0].RequestID)
	require.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", actionAudits.records[0].TraceID)
	requireOpenAPIResponse(t, downloadRequest, downloadResponse)
}

func TestSpecialArtifactIDRemainsValidAcrossMetadataRouteAndResponseContract(t *testing.T) {
	id := "legacy/id with space?#%中文"
	created := time.Date(2026, 8, 28, 4, 0, 0, 0, time.UTC)
	artifacts := &recordingArtifactService{getValue: artifact.Artifact{
		ID: id, Scope: platformTestScope, Kind: "inspection-report", ContentType: "application/json",
		SizeBytes: 37, Checksum: "sha256:abc", CreatedAt: created,
	}}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/artifacts/"+url.PathEscape(id), nil)
	response := servePlatformRequest(Services{Artifacts: artifacts}, principalWith(platformTestScope, openapi.PermissionGetArtifact), request)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), `"id":"legacy/id with space?#%中文"`)
	requireOpenAPIResponse(t, request, response)
}

func TestGeneratedAuditListUsesOnlyURLScopeAndOpaqueCursor(t *testing.T) {
	occurred := time.Date(2026, 8, 28, 4, 0, 0, 0, time.UTC)
	audits := &recordingAuditService{page: audit.Page{Items: []audit.Event{{
		ID: "audit-1", Scope: platformTestScope, OccurredAt: occurred, Action: "inspection.started",
		Actor: audit.Actor{Type: "user", ID: "trusted-user"}, Result: "success", RequestID: "request-job-1", CommandID: "command-1", Detail: map[string]any{"result": "accepted"},
	}}, NextCursor: "next-cursor"}}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/audit-events?cursor=opaque-cursor&limit=1", nil)
	response := servePlatformRequest(Services{Audit: audits}, principalWith(platformTestScope, openapi.PermissionListAuditEvents), request)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, platformTestScope, audits.scope)
	require.Equal(t, audit.ListQuery{Cursor: "opaque-cursor", Limit: 1}, audits.query)
	require.JSONEq(t, `{"items":[{"id":"audit-1","occurred_at":"2026-08-28T04:00:00Z","action":"inspection.started","tenant_id":"tenant-a","project_id":"project-a","actor":{"type":"user","id":"trusted-user"},"result":"success","request_id":"request-job-1","command_id":"command-1","detail":{"result":"accepted"}}],"page":{"limit":1,"next_cursor":"next-cursor","has_more":true}}`, response.Body.String())
	requireOpenAPIResponse(t, request, response)
}

func TestGeneratedCapabilitiesIntersectAuthenticatedPermissions(t *testing.T) {
	capabilities := &recordingCapabilityService{values: []capability.Capability{{Name: "job.read", Enabled: true, RequiredPermission: openapi.PermissionGetJob, DatabaseTypes: []string{"postgresql"}, AgentCapabilities: []string{"inspect_instance"}}}}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/capabilities", nil)
	principal := principalWith(platformTestScope, openapi.PermissionGetCapabilities, openapi.PermissionGetJob)
	response := servePlatformRequest(Services{
		Capabilities: capabilities,
		CapabilityInput: func(context.Context, platformscope.Scope) capability.Input {
			return capability.Input{DatabaseType: "postgresql", AgentCapabilities: map[string]bool{"inspect_instance": true}}
		},
	}, principal, request)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.True(t, capabilities.input.Permissions[openapi.PermissionGetCapabilities])
	require.True(t, capabilities.input.Permissions[openapi.PermissionGetJob])
	require.Equal(t, "postgresql", capabilities.input.DatabaseType)
	requireOpenAPIResponse(t, request, response)
}

func TestGeneratedRoutesRejectMissingOrWrongActionBeforeServiceExecution(t *testing.T) {
	tests := []struct {
		name      string
		principal Principal
		status    int
		code      string
	}{
		{name: "unauthenticated", status: http.StatusUnauthorized, code: "unauthenticated"},
		{name: "wrong action", principal: principalWith(platformTestScope, openapi.PermissionCancelJob), status: http.StatusForbidden, code: "forbidden"},
		{name: "wrong scope", principal: principalWith(platformscope.Scope{TenantID: "tenant-b", ProjectID: "project-b"}, openapi.PermissionGetJob), status: http.StatusForbidden, code: "forbidden"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			jobs := &recordingJobService{getValue: validPlatformJob()}
			request := httptest.NewRequest(http.MethodGet, platformBasePath+"/jobs/job-1", nil)
			var resolver PrincipalResolver = platformStaticPrincipalResolver{principal: test.principal}
			if test.status == http.StatusUnauthorized {
				resolver = platformStaticPrincipalResolver{err: ErrUnauthenticated}
			}
			response := httptest.NewRecorder()

			NewHTTPHandler(Services{Jobs: jobs}, resolver).ServeHTTP(response, request)

			requireProblem(t, response, test.status, test.code, response.Header().Get("X-Request-ID"))
			require.Zero(t, jobs.getCalls)
			requireOpenAPIResponse(t, request, response)
		})
	}
}

func TestProblemMappingsAreStableAndNeverExposeInternalErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "validation", err: artifact.ErrInvalid, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "not found", err: job.ErrNotFound, status: http.StatusNotFound, code: "not_found"},
		{name: "conflict", err: job.ErrInvalidTransition, status: http.StatusConflict, code: "conflict"},
		{name: "precondition", err: ErrPreconditionFailed, status: http.StatusPreconditionFailed, code: "precondition_failed"},
		{name: "ownership conflict", err: idempotency.ErrOwnershipConflict, status: http.StatusConflict, code: "idempotency_ownership_conflict"},
		{name: "forbidden", err: ErrForbidden, status: http.StatusForbidden, code: "forbidden"},
		{name: "timeout", err: context.DeadlineExceeded, status: http.StatusGatewayTimeout, code: "timeout"},
		{name: "internal", err: errors.New("postgres password=top-secret"), status: http.StatusInternalServerError, code: "internal_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			problem := problemForError(test.err, "request-problem-1", "/safe-instance")
			require.Equal(t, test.status, problem.Status)
			require.Equal(t, test.code, problem.Code)
			require.NotContains(t, problem.Title, "top-secret")
			if problem.Detail != nil {
				require.NotContains(t, *problem.Detail, "top-secret")
			}
			requireProblemSchema(t, problem)
		})
	}
}

func TestPlatformIdempotencyFingerprintBindsRequestInputsAndExcludesIdentityToken(t *testing.T) {
	metadata := platformRequestMetadata{
		Method: http.MethodPost, Path: platformBasePath + "/jobs/job-1/actions/cancel",
		RawQuery: "", IfMatch: `"7"`, Body: []byte(`{"reason":"operator"}`),
	}
	baseContext := context.WithValue(context.Background(), platformRequestMetadataContextKey{}, metadata)
	base, err := platformIdempotencyFingerprint(baseContext, "cancelJob", "job-1", `"7"`)
	require.NoError(t, err)

	mutations := []struct {
		name       string
		metadata   platformRequestMetadata
		operation  string
		resourceID string
		ifMatch    string
	}{
		{name: "path", metadata: func() platformRequestMetadata { value := metadata; value.Path += "-other"; return value }(), operation: "cancelJob", resourceID: "job-1", ifMatch: `"7"`},
		{name: "body", metadata: func() platformRequestMetadata {
			value := metadata
			value.Body = []byte(`{"reason":"other"}`)
			return value
		}(), operation: "cancelJob", resourceID: "job-1", ifMatch: `"7"`},
		{name: "resource", metadata: metadata, operation: "cancelJob", resourceID: "job-2", ifMatch: `"7"`},
		{name: "if match", metadata: func() platformRequestMetadata { value := metadata; value.IfMatch = `"8"`; return value }(), operation: "cancelJob", resourceID: "job-1", ifMatch: `"8"`},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), platformRequestMetadataContextKey{}, mutation.metadata)
			got, err := platformIdempotencyFingerprint(ctx, mutation.operation, mutation.resourceID, mutation.ifMatch)
			require.NoError(t, err)
			require.NotEqual(t, base, got)
		})
	}

	identityContext := context.WithValue(baseContext, principalContextKey{}, Principal{Subject: "different-user"})
	withDifferentIdentity, err := platformIdempotencyFingerprint(identityContext, "cancelJob", "job-1", `"7"`)
	require.NoError(t, err)
	require.Equal(t, base, withDifferentIdentity, "identity and bearer token material belong in the durable key, never the request fingerprint")
}

func servePlatformRequest(services Services, principal Principal, request *http.Request) *httptest.ResponseRecorder {
	if services.Audit == nil {
		services.Audit = &recordingAuditService{}
	}
	response := httptest.NewRecorder()
	NewHTTPHandler(services, platformStaticPrincipalResolver{principal: principal}).ServeHTTP(response, request)
	return response
}

func newCancelRequest(ifMatch, idempotencyKey string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/jobs/job-1/actions/cancel", nil)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("If-Match", ifMatch)
	return request
}

func newDownloadRequest(idempotencyKey string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/artifacts/artifact-1/actions/download", nil)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	return request
}

func requireProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code, requestID string) openapi.Problem {
	t.Helper()
	require.Equal(t, status, response.Code, response.Body.String())
	require.Equal(t, "application/problem+json", response.Header().Get("Content-Type"))
	var problem openapi.Problem
	require.NoError(t, decodeJSONBytes(response.Body.Bytes(), &problem))
	require.Equal(t, code, problem.Code)
	require.NotEmpty(t, problem.Type)
	require.NotEmpty(t, problem.Title)
	require.Equal(t, requestID, problem.RequestId)
	requireProblemSchema(t, problem)
	return problem
}

func requireProblemSchema(t *testing.T, problem openapi.Problem) {
	t.Helper()
	spec, err := openapi.GetSpec()
	require.NoError(t, err)
	encoded := new(bytes.Buffer)
	require.NoError(t, json.NewEncoder(encoded).Encode(problem))
	var value any
	require.NoError(t, decodeJSONBytes(encoded.Bytes(), &value))
	require.NoError(t, spec.Components.Schemas["Problem"].Value.VisitJSON(value))
}

func requireOpenAPIResponse(t *testing.T, request *http.Request, response *httptest.ResponseRecorder) {
	t.Helper()
	spec, err := openapi.GetSpec()
	require.NoError(t, err)
	router, err := legacy.NewRouter(spec)
	require.NoError(t, err)
	route, pathParams, err := router.FindRoute(request)
	require.NoError(t, err)
	input := &openapi3filter.RequestValidationInput{Request: request, PathParams: pathParams, Route: route}
	validation := (&openapi3filter.ResponseValidationInput{RequestValidationInput: input, Status: response.Code, Header: response.Header()}).SetBodyBytes(response.Body.Bytes())
	require.NoError(t, openapi3filter.ValidateResponse(context.Background(), validation))
}

func decodeJSONBytes(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

type platformStaticPrincipalResolver struct {
	principal Principal
	err       error
}

func (resolver platformStaticPrincipalResolver) ResolvePrincipal(*http.Request) (Principal, error) {
	return resolver.principal, resolver.err
}

func principalWith(scope platformscope.Scope, permissions ...string) Principal {
	return Principal{Subject: "trusted-user", Projects: map[string]struct{}{scope.Key(): {}}, Grants: scopedGrants(scope, permissions...)}
}

func validPlatformJob() job.Job {
	return job.Job{
		ID: "job-1", Type: "inspection.run", Scope: platformTestScope, Status: job.StatusRunning, Outcome: job.OutcomeNone,
		InstanceID: "instance-1", TargetResourceIDs: []string{"instance-1"}, InitiatedBy: "trusted-user",
		SourceResource: job.ResourceReference{ResourceType: "inspection", ResourceID: "inspection-1"}, IdempotencyKey: "create-job-1", Version: 7,
		Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: time.Date(2026, 8, 28, 4, 0, 0, 0, time.UTC),
		RequestID: "request-job-1", TraceID: "trace-job-1",
	}
}

type recordingJobService struct {
	getValue        job.Job
	getErr          error
	getScope        platformscope.Scope
	getID           string
	getCalls        int
	transitionValue job.Job
	transitionErr   error
	transitions     []job.Transition
}

func (service *recordingJobService) Get(_ context.Context, scope platformscope.Scope, id string) (job.Job, error) {
	service.getCalls++
	service.getScope, service.getID = scope, id
	return service.getValue, service.getErr
}

func (service *recordingJobService) RequestCancel(_ context.Context, scope platformscope.Scope, id, actor string, version int64, at time.Time) (job.Job, error) {
	transition := job.Transition{Scope: scope, JobID: id, Actor: actor, CurrentVersion: version, To: job.StatusCancelling, At: at}
	service.transitions = append(service.transitions, transition)
	return service.transitionValue, service.transitionErr
}

func TestPlatformTraceparentRejectsMalformedInputAndGeneratesValidContext(t *testing.T) {
	jobs := &recordingJobService{getValue: validPlatformJob()}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/jobs/job-1", nil)
	request.Header.Set("traceparent", "00-not-a-trace-secret-value")
	response := servePlatformRequest(Services{Jobs: jobs}, principalWith(platformTestScope, openapi.PermissionGetJob), request)

	require.Equal(t, http.StatusOK, response.Code)
	generated := response.Header().Get("traceparent")
	require.NotEqual(t, request.Header.Get("traceparent"), generated)
	canonical, traceID := validTraceparent([]string{generated})
	require.Equal(t, generated, canonical)
	require.Len(t, traceID, 32)
}

func TestBearerUnauthorizedResponseAdvertisesBearerChallenge(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/jobs/job-1", nil)
	request.Header.Set("Authorization", "Bearer expired-token")
	response := httptest.NewRecorder()
	NewHTTPHandler(Services{Jobs: &recordingJobService{}}, BearerPrincipalResolver{Verifier: &recordingTokenVerifier{err: errors.New("expired")}}).ServeHTTP(response, request)

	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Equal(t, "Bearer", response.Header().Get("WWW-Authenticate"))
}

type recordingArtifactService struct {
	getCalls      int
	getValue      artifact.Artifact
	getErr        error
	getScope      platformscope.Scope
	downloadValue artifact.Download
	downloadErr   error
	downloadScope platformscope.Scope
	downloadID    string
	downloadTTL   time.Duration
	downloadCalls int
}

func (service *recordingArtifactService) Get(_ context.Context, scope platformscope.Scope, _ string) (artifact.Artifact, error) {
	service.getCalls++
	service.getScope = scope
	return service.getValue, service.getErr
}

func (service *recordingArtifactService) CreateDownload(_ context.Context, scope platformscope.Scope, id string, ttl time.Duration) (artifact.Download, error) {
	service.downloadScope, service.downloadID, service.downloadTTL = scope, id, ttl
	service.downloadCalls++
	return service.downloadValue, service.downloadErr
}

type recordingAuditService struct {
	page        audit.Page
	err         error
	scope       platformscope.Scope
	query       audit.ListQuery
	calls       int
	recordCalls int
	records     []audit.Event
}

func (service *recordingAuditService) RecordOnce(_ context.Context, event audit.Event) (audit.Event, error) {
	service.recordCalls++
	for _, existing := range service.records {
		if existing.DedupeKey == event.DedupeKey {
			return existing, nil
		}
	}
	service.records = append(service.records, event)
	return event, service.err
}

func (service *recordingAuditService) List(_ context.Context, scope platformscope.Scope, query audit.ListQuery) (audit.Page, error) {
	service.calls++
	service.scope, service.query = scope, query
	return service.page, service.err
}

type recordingCapabilityService struct {
	values []capability.Capability
	input  capability.Input
}

func (service *recordingCapabilityService) Resolve(input capability.Input) []capability.Capability {
	service.input = input
	return service.values
}

type httpIdempotencyStore struct {
	mu            sync.Mutex
	records       map[string]httpIdempotencyRecord
	completeErr   error
	abortCalls    int
	claimedOwners []string
	abortedOwners []string
}

type httpIdempotencyRecord struct {
	fingerprint string
	owner       string
	state       idempotency.State
	response    idempotency.Response
}

func newHTTPIdempotencyStore() *httpIdempotencyStore {
	return &httpIdempotencyStore{records: make(map[string]httpIdempotencyRecord)}
}

func (store *httpIdempotencyStore) Claim(_ context.Context, key idempotency.Key, fingerprint, owner string, _, _ time.Time) (idempotency.Claim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	mapKey := key.Scope.Key() + "\x00" + key.Actor + "\x00" + key.OperationID + "\x00" + key.IdempotencyKey
	record, exists := store.records[mapKey]
	if !exists {
		store.records[mapKey] = httpIdempotencyRecord{fingerprint: fingerprint, owner: owner, state: idempotency.StateProcessing}
		store.claimedOwners = append(store.claimedOwners, owner)
		return idempotency.Claim{Claimed: true, OwnerToken: owner, State: idempotency.StateProcessing}, nil
	}
	if record.fingerprint != fingerprint {
		return idempotency.Claim{}, idempotency.ErrKeyConflict
	}
	if record.state == idempotency.StateProcessing {
		return idempotency.Claim{}, idempotency.ErrInProgress
	}
	response := cloneIdempotencyResponse(record.response)
	ownerToken := record.owner
	if record.state == idempotency.StateCompleted {
		ownerToken = ""
	}
	return idempotency.Claim{OwnerToken: ownerToken, State: record.state, Response: &response}, nil
}

func (store *httpIdempotencyStore) CommitSideEffect(_ context.Context, key idempotency.Key, fingerprint, owner string, response idempotency.Response, _ time.Time) (idempotency.Response, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.completeErr != nil {
		return idempotency.Response{}, store.completeErr
	}
	mapKey := key.Scope.Key() + "\x00" + key.Actor + "\x00" + key.OperationID + "\x00" + key.IdempotencyKey
	record, exists := store.records[mapKey]
	if !exists || record.fingerprint != fingerprint || record.owner != owner || record.state != idempotency.StateProcessing {
		return idempotency.Response{}, idempotency.ErrOwnershipConflict
	}
	record.state = idempotency.StateSideEffectCommitted
	record.response = cloneIdempotencyResponse(response)
	store.records[mapKey] = record
	return cloneIdempotencyResponse(record.response), nil
}

func (store *httpIdempotencyStore) MarkAudited(_ context.Context, key idempotency.Key, fingerprint, owner string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	mapKey := key.Scope.Key() + "\x00" + key.Actor + "\x00" + key.OperationID + "\x00" + key.IdempotencyKey
	record, exists := store.records[mapKey]
	if !exists || record.fingerprint != fingerprint || record.owner != owner || record.state != idempotency.StateSideEffectCommitted {
		return idempotency.ErrOwnershipConflict
	}
	record.state = idempotency.StateAudited
	store.records[mapKey] = record
	return nil
}

func (store *httpIdempotencyStore) Complete(_ context.Context, key idempotency.Key, fingerprint, owner string, response idempotency.Response, _ time.Time) (idempotency.Response, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.completeErr != nil {
		return idempotency.Response{}, store.completeErr
	}
	mapKey := key.Scope.Key() + "\x00" + key.Actor + "\x00" + key.OperationID + "\x00" + key.IdempotencyKey
	record, exists := store.records[mapKey]
	if !exists || record.fingerprint != fingerprint || record.owner != owner || record.state != idempotency.StateAudited {
		return idempotency.Response{}, idempotency.ErrOwnershipConflict
	}
	record.state = idempotency.StateCompleted
	store.records[mapKey] = record
	return cloneIdempotencyResponse(response), nil
}

func (store *httpIdempotencyStore) Abort(_ context.Context, key idempotency.Key, fingerprint, owner string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.abortCalls++
	store.abortedOwners = append(store.abortedOwners, owner)
	mapKey := key.Scope.Key() + "\x00" + key.Actor + "\x00" + key.OperationID + "\x00" + key.IdempotencyKey
	if record, exists := store.records[mapKey]; exists && record.fingerprint == fingerprint && record.owner == owner && record.state == idempotency.StateProcessing {
		delete(store.records, mapKey)
		return nil
	}
	return idempotency.ErrOwnershipConflict
}

func cloneIdempotencyResponse(response idempotency.Response) idempotency.Response {
	response.Header = response.Header.Clone()
	response.Body = append([]byte(nil), response.Body...)
	return response
}

type sequencedArtifactService struct {
	errors []error
	value  artifact.Download
	calls  int
}

func (service *sequencedArtifactService) Get(context.Context, platformscope.Scope, string) (artifact.Artifact, error) {
	return artifact.Artifact{}, nil
}

func (service *sequencedArtifactService) CreateDownload(context.Context, platformscope.Scope, string, time.Duration) (artifact.Download, error) {
	index := service.calls
	service.calls++
	if index < len(service.errors) && service.errors[index] != nil {
		return artifact.Download{}, service.errors[index]
	}
	return service.value, nil
}

type blockingJobService struct {
	mu      sync.Mutex
	count   int
	started chan struct{}
	proceed chan struct{}
}

func newBlockingJobService() *blockingJobService {
	return &blockingJobService{started: make(chan struct{}), proceed: make(chan struct{})}
}

func (service *blockingJobService) Get(context.Context, platformscope.Scope, string) (job.Job, error) {
	return validPlatformJob(), nil
}

func (service *blockingJobService) RequestCancel(_ context.Context, _ platformscope.Scope, _ string, _ string, _ int64, _ time.Time) (job.Job, error) {
	service.mu.Lock()
	service.count++
	if service.count == 1 {
		close(service.started)
	}
	service.mu.Unlock()
	<-service.proceed
	value := validPlatformJob()
	value.Status = job.StatusCancelling
	value.Version = 8
	return value, nil
}

func (service *blockingJobService) calls() int {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.count
}
