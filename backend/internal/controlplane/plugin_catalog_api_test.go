package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/plugincatalog"
	"github.com/stretchr/testify/require"
)

func TestPluginUploadStreamsBeyondJSONLimitAndReplaysIdempotentlyWithAudit(t *testing.T) {
	// Break caught: buffering the gzip through the JSON middleware rejects valid
	// packages, while an unbound idempotency key can replay different bytes.
	body := bytes.Repeat([]byte("bounded-stream-chunk"), 96*1024)
	service := &recordingPluginCatalogService{uploadValue: validCatalogVersion(plugincatalog.StatusVerified, 1)}
	audits := &recordingAuditService{}
	services := Services{PluginCatalog: service, Audit: audits, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
	principal := principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage)

	request := newPluginUploadRequest(body, "upload-key-1")
	response := servePlatformRequest(services, principal, request)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	require.Equal(t, `"1"`, response.Header().Get("ETag"))
	require.Equal(t, 1, service.uploadCalls)
	require.Equal(t, body, service.uploadBodies[0])
	require.Equal(t, int64(len(body)), service.uploadMetadata[0].ContentLength)
	require.Equal(t, "trusted-user", service.uploadMetadata[0].Actor)
	require.Equal(t, platformTestScope, service.uploadScopes[0])
	require.Equal(t, 1, audits.recordCalls)
	require.Equal(t, "plugin.version_uploaded", audits.records[0].Action)
	bodyDigest := sha256.Sum256(body)
	require.Equal(t, hex.EncodeToString(bodyDigest[:]), audits.records[0].Detail["package_sha256"])
	require.NotContains(t, fmt.Sprint(audits.records[0].Detail), "bounded-stream-chunk")
	requireOpenAPIResponse(t, request, response)

	replayRequest := newPluginUploadRequest(body, "upload-key-1")
	replay := servePlatformRequest(services, principal, replayRequest)
	require.Equal(t, response.Code, replay.Code)
	require.JSONEq(t, response.Body.String(), replay.Body.String())
	require.Equal(t, 1, service.uploadCalls, "exact replay must use the durable response")
	require.Equal(t, 1, audits.recordCalls, "audit is deduplicated with the response")

	conflictBody := append([]byte(nil), body...)
	conflictBody[len(conflictBody)-1] ^= 1
	conflictRequest := newPluginUploadRequest(conflictBody, "upload-key-1")
	conflict := servePlatformRequest(services, principal, conflictRequest)
	requireProblem(t, conflict, http.StatusConflict, "idempotency_conflict", conflict.Header().Get("X-Request-ID"))
	require.Equal(t, 1, service.uploadCalls)
}

func TestPluginUploadProcessingRecoveryReplaysImmutableOriginalSnapshotAfterApproval(t *testing.T) {
	// Break caught: a crash after verified revision 1 must not replay a later
	// approved row as the original upload response or Audit event.
	body := []byte("durable-upload-body")
	service := newRecordingDurableCatalog(validCatalogVersion(plugincatalog.StatusVerified, 1))
	audits := &recordingAuditService{}
	store := newHTTPIdempotencyStore()
	store.completeErr = errors.New("simulated crash after catalog commit")
	services := Services{PluginCatalog: service, Audit: audits, Idempotency: idempotency.NewService(store)}
	principal := principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage)

	first := servePlatformRequest(services, principal, newPluginUploadRequest(body, "upload-crash-key"))
	require.Equal(t, http.StatusInternalServerError, first.Code)
	require.Equal(t, 1, service.uploadOperationCalls)
	service.uploadValue = validCatalogVersion(plugincatalog.StatusApproved, 2)
	store.completeErr = nil

	retry := servePlatformRequest(services, principal, newPluginUploadRequest(body, "upload-crash-key"))
	require.Equal(t, http.StatusCreated, retry.Code, retry.Body.String())
	require.Equal(t, `"1"`, retry.Header().Get("ETag"))
	require.Contains(t, retry.Body.String(), `"status":"verified"`)
	require.Equal(t, 1, service.uploadOperationCalls, "recovery must use the immutable operation snapshot")
	require.Equal(t, 1, service.recoverOperationCalls)
	require.Equal(t, 1, audits.recordCalls)
}

func TestPluginApproveProcessingRecoveryReplaysApprovedSnapshotAfterPublish(t *testing.T) {
	// Break caught: a later available revision cannot make the original approve
	// idempotency key unrecoverable or change its ETag/body.
	service := newRecordingDurableCatalog(validCatalogVersion(plugincatalog.StatusVerified, 7))
	service.approveValue = validCatalogVersion(plugincatalog.StatusApproved, 8)
	audits := &recordingAuditService{}
	store := newHTTPIdempotencyStore()
	store.completeErr = errors.New("simulated crash after approve commit")
	services := Services{PluginCatalog: service, Audit: audits, Idempotency: idempotency.NewService(store)}
	principal := principalWith(platformTestScope, openapi.PermissionApprovePluginVersion)
	request := func() *http.Request {
		value := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-versions/plugin-version-1/actions/approve", bytes.NewBufferString(`{}`))
		value.Header.Set("Content-Type", "application/json")
		value.Header.Set("Idempotency-Key", "approve-crash-key")
		value.Header.Set("If-Match", `"7"`)
		return value
	}

	first := servePlatformRequest(services, principal, request())
	require.Equal(t, http.StatusInternalServerError, first.Code)
	require.Equal(t, 1, service.approveOperationCalls)
	service.approveValue = validCatalogVersion(plugincatalog.StatusAvailable, 9)
	store.completeErr = nil

	retry := servePlatformRequest(services, principal, request())
	require.Equal(t, http.StatusOK, retry.Code, retry.Body.String())
	require.Equal(t, `"8"`, retry.Header().Get("ETag"))
	require.Contains(t, retry.Body.String(), `"status":"approved"`)
	require.Equal(t, 1, service.approveOperationCalls)
	require.Equal(t, 1, service.recoverOperationCalls)
	require.Equal(t, 1, audits.recordCalls)
}

func TestPluginLifecycleProcessingRecoveryCreatesMissingOperationSnapshot(t *testing.T) {
	tests := []struct {
		name, path, body, key, etag, failureName string
		permission                               string
		status                                   plugincatalog.Status
		revision                                 uint64
	}{
		{name: "approve", path: "/plugin-versions/plugin-version-1/actions/approve", body: `{}`, key: "approve-pre-operation", etag: `"7"`, failureName: "approve", permission: openapi.PermissionApprovePluginVersion, status: plugincatalog.StatusApproved, revision: 8},
		{name: "publish", path: "/plugin-versions/plugin-version-1/actions/publish", body: `{}`, key: "publish-pre-operation", etag: `"8"`, failureName: "publish", permission: openapi.PermissionPublishPluginVersion, status: plugincatalog.StatusAvailable, revision: 9},
		{name: "revoke", path: "/plugin-versions/plugin-version-1/actions/revoke", body: `{"reason_code":"publisher_compromise"}`, key: "revoke-pre-operation", etag: `"9"`, failureName: "revoke", permission: openapi.PermissionRevokePluginVersion, status: plugincatalog.StatusRevoked, revision: 10},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newRecordingDurableCatalog(validCatalogVersion(plugincatalog.StatusVerified, 7))
			service.approveValue = validCatalogVersion(test.status, test.revision)
			service.publishValue = validCatalogVersion(test.status, test.revision)
			service.revokeValue = validCatalogVersion(test.status, test.revision)
			service.operationFailures = map[string]int{test.failureName: 1}
			audits := &recordingAuditService{}
			services := Services{PluginCatalog: service, Audit: audits, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
			request := func() *http.Request {
				value := httptest.NewRequest(http.MethodPost, platformBasePath+test.path, bytes.NewBufferString(test.body))
				value.Header.Set("Content-Type", "application/json")
				value.Header.Set("Idempotency-Key", test.key)
				value.Header.Set("If-Match", test.etag)
				return value
			}
			first := servePlatformRequest(services, principalWith(platformTestScope, test.permission), request())
			require.Equal(t, http.StatusInternalServerError, first.Code)
			require.Empty(t, service.operations)
			retry := servePlatformRequest(services, principalWith(platformTestScope, test.permission), request())
			require.Equal(t, http.StatusOK, retry.Code, retry.Body.String())
			require.Equal(t, `"`+fmt.Sprint(test.revision)+`"`, retry.Header().Get("ETag"))
			require.Contains(t, retry.Body.String(), `"status":"`+string(test.status)+`"`)
			require.Len(t, service.operations, 1)
			require.Len(t, audits.records, 1)
		})
	}
}

func TestPluginLifecycleAPIsEnforceETagAndReturnPublicMetadataOnly(t *testing.T) {
	// Break caught: lifecycle mutations without If-Match can overwrite a newer
	// decision; responses must never expose storage paths or signature bytes.
	service := &recordingPluginCatalogService{
		approveValue: validCatalogVersion(plugincatalog.StatusApproved, 8),
		publishValue: validCatalogVersion(plugincatalog.StatusAvailable, 9),
		revokeValue:  validCatalogVersion(plugincatalog.StatusRevoked, 10),
	}
	audits := &recordingAuditService{}
	services := Services{PluginCatalog: service, Audit: audits, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
	principal := principalWith(platformTestScope,
		openapi.PermissionApprovePluginVersion, openapi.PermissionPublishPluginVersion, openapi.PermissionRevokePluginVersion,
	)

	tests := []struct {
		name, path, body, key, etag string
		wantStatus                  plugincatalog.Status
		wantRevision                uint64
	}{
		{name: "approve", path: "/plugin-versions/plugin-version-1/actions/approve", body: `{}`, key: "approve-key", etag: `"7"`, wantStatus: plugincatalog.StatusApproved, wantRevision: 8},
		{name: "publish", path: "/plugin-versions/plugin-version-1/actions/publish", body: `{}`, key: "publish-key", etag: `"8"`, wantStatus: plugincatalog.StatusAvailable, wantRevision: 9},
		{name: "revoke", path: "/plugin-versions/plugin-version-1/actions/revoke", body: `{"reason_code":"publisher_compromise"}`, key: "revoke-key", etag: `"9"`, wantStatus: plugincatalog.StatusRevoked, wantRevision: 10},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, platformBasePath+test.path, bytes.NewBufferString(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", test.key)
			request.Header.Set("If-Match", test.etag)
			response := servePlatformRequest(services, principal, request)
			require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			require.Equal(t, `"`+fmt.Sprint(test.wantRevision)+`"`, response.Header().Get("ETag"))
			require.Contains(t, response.Body.String(), `"status":"`+string(test.wantStatus)+`"`)
			require.NotContains(t, response.Body.String(), "SIGNATURE")
			require.NotContains(t, response.Body.String(), "storage")
			requireOpenAPIResponse(t, request, response)
		})
	}
	require.Equal(t, []uint64{7}, service.approveRevisions)
	require.Equal(t, []uint64{8}, service.publishRevisions)
	require.Equal(t, []uint64{9}, service.revokeRevisions)
	require.Equal(t, []string{"publisher_compromise"}, service.revokeReasons)
	require.Equal(t, 3, audits.recordCalls)
	require.Equal(t, float64(7), audits.records[0].Detail["expected_revision"])
}

func TestPluginCatalogListsVersionsAndDefinitionsWithinAuthenticatedScope(t *testing.T) {
	// Break caught: list filters must be supplied to the scoped application
	// service and public pages expose only contract fields.
	version := validCatalogVersion(plugincatalog.StatusAvailable, 9)
	definition := plugincatalog.PluginDefinition{
		Scope: platformTestScope, PluginID: "mysql", Name: "mysql", DatabaseFamily: "mysql", ProtocolVersion: "v1",
		SupportedVariants: []string{"mysql"}, Capabilities: []string{"metrics.collect"}, LatestAvailableVersion: "1.0.0",
	}
	service := &recordingPluginCatalogService{
		versionPage:    plugincatalog.VersionPage{Items: []plugincatalog.PluginVersion{version}},
		definitionPage: plugincatalog.DefinitionPage{Items: []plugincatalog.PluginDefinition{definition}},
	}
	services := Services{PluginCatalog: service}
	principal := principalWith(platformTestScope, openapi.PermissionListPluginVersions, openapi.PermissionListPluginDefinitions)

	versionsRequest := httptest.NewRequest(http.MethodGet, platformBasePath+"/plugin-versions?plugin_id=mysql&status=available&limit=25", nil)
	versions := servePlatformRequest(services, principal, versionsRequest)
	require.Equal(t, http.StatusOK, versions.Code, versions.Body.String())
	require.Contains(t, versions.Body.String(), `"artifact_id":"plugin-package-1"`)
	requireOpenAPIResponse(t, versionsRequest, versions)
	require.Equal(t, platformTestScope, service.listVersionScopes[0])
	require.Equal(t, plugincatalog.VersionFilter{PluginID: "mysql", Status: plugincatalog.StatusAvailable, Limit: 25}, service.versionFilters[0])

	definitionsRequest := httptest.NewRequest(http.MethodGet, platformBasePath+"/plugin-definitions?database_family=mysql&limit=25", nil)
	definitions := servePlatformRequest(services, principal, definitionsRequest)
	require.Equal(t, http.StatusOK, definitions.Code, definitions.Body.String())
	requireOpenAPIResponse(t, definitionsRequest, definitions)
	require.Equal(t, platformTestScope, service.listDefinitionScopes[0])
	require.Equal(t, plugincatalog.DefinitionFilter{DatabaseFamily: "mysql", Limit: 25}, service.definitionFilters[0])
}

func TestPluginDefinitionListEncodesRequiredNullLatestVersion(t *testing.T) {
	// Break caught: the generated pointer uses omitempty even though Task 1 made
	// latest_available_version required and nullable.
	definition := plugincatalog.PluginDefinition{
		Scope: platformTestScope, PluginID: "mysql", Name: "mysql", DatabaseFamily: "mysql", ProtocolVersion: "v1",
		SupportedVariants: []string{"mysql"}, Capabilities: []string{"metrics.collect"},
	}
	service := &recordingPluginCatalogService{definitionPage: plugincatalog.DefinitionPage{Items: []plugincatalog.PluginDefinition{definition}}}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/plugin-definitions", nil)
	response := servePlatformRequest(Services{PluginCatalog: service}, principalWith(platformTestScope, openapi.PermissionListPluginDefinitions), request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), `"latest_available_version":null`)
	requireOpenAPIResponse(t, request, response)
}

func TestPluginUploadRejectsOutOfScopeApplicationResult(t *testing.T) {
	// Break caught: handlers must distrust service results even though scope is
	// absent from the public DTO, or cross-project Artifact IDs can leak.
	body := []byte("small gzip-shaped body")
	value := validCatalogVersion(plugincatalog.StatusVerified, 1)
	value.Scope = platformscope.Scope{TenantID: "tenant-other", ProjectID: "project-other"}
	service := &recordingPluginCatalogService{uploadValue: value}
	request := newPluginUploadRequest(body, "out-of-scope-upload")
	response := servePlatformRequest(Services{PluginCatalog: service, Audit: &recordingAuditService{}, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}, principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage), request)
	requireProblem(t, response, http.StatusInternalServerError, "internal_error", response.Header().Get("X-Request-ID"))
}

func TestPluginUploadAdmissionRejectsBeforeReadingBody(t *testing.T) {
	// Break caught: permission and cheap contract failures must not consume or
	// stage an attacker-controlled upload.
	tests := []struct {
		name          string
		principal     Principal
		contentType   string
		keyValues     []string
		contentLength int64
		wantStatus    int
	}{
		{name: "forbidden", principal: principalWith(platformTestScope, openapi.PermissionListPluginVersions), contentType: "application/gzip", keyValues: []string{"upload-key"}, wantStatus: http.StatusForbidden},
		{name: "wrong media type", principal: principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage), contentType: "application/octet-stream", keyValues: []string{"upload-key"}, wantStatus: http.StatusBadRequest},
		{name: "129 byte key", principal: principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage), contentType: "application/gzip", keyValues: []string{repeatString("k", 129)}, wantStatus: http.StatusBadRequest},
		{name: "duplicate key", principal: principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage), contentType: "application/gzip", keyValues: []string{"one", "two"}, wantStatus: http.StatusBadRequest},
		{name: "missing key", principal: principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage), contentType: "application/gzip", wantStatus: http.StatusBadRequest},
		{name: "oversized content length", principal: principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage), contentType: "application/gzip", keyValues: []string{"upload-key"}, contentLength: maximumPluginUploadBytes + 1, wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &countingRequestBody{contents: []byte("must-not-be-read")}
			request := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-versions", body)
			request.ContentLength = int64(len(body.contents))
			if test.contentLength != 0 {
				request.ContentLength = test.contentLength
			}
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Del("Idempotency-Key")
			for _, value := range test.keyValues {
				request.Header.Add("Idempotency-Key", value)
			}
			response := servePlatformRequest(Services{PluginCatalog: &recordingPluginCatalogService{}}, test.principal, request)
			require.Equal(t, test.wantStatus, response.Code, response.Body.String())
			require.Zero(t, body.reads)
		})
	}
}

func TestUploadAdmissionEnforcesAggregateBytesAndConcurrency(t *testing.T) {
	admission := newUploadAdmission(100, 2)
	releaseFirst, err := admission.Acquire(60)
	require.NoError(t, err)
	defer releaseFirst()
	_, err = admission.Acquire(50)
	require.ErrorIs(t, err, ErrServiceUnavailable)
	releaseSecond, err := admission.Acquire(40)
	require.NoError(t, err)
	releaseSecond()
}

func TestDisabledPluginCatalogRejectsBeforeReadingUpload(t *testing.T) {
	body := &countingRequestBody{contents: []byte("disabled-must-not-stage")}
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-versions", body)
	request.ContentLength = int64(len(body.contents))
	request.Header.Set("Content-Type", "application/gzip")
	request.Header.Set("Idempotency-Key", "disabled-upload")
	response := servePlatformRequest(Services{}, principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage), request)
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.Zero(t, body.reads)
}

func TestNonUploadRoutesRejectGzipWithoutReadingOrStaging(t *testing.T) {
	tests := []struct {
		name, method, path, permission string
	}{
		{name: "GET list", method: http.MethodGet, path: "/plugin-definitions", permission: openapi.PermissionListPluginDefinitions},
		{name: "JSON lifecycle", method: http.MethodPost, path: "/plugin-versions/plugin-version-1/actions/approve", permission: openapi.PermissionApprovePluginVersion},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &countingRequestBody{contents: bytes.Repeat([]byte("gzip-shaped"), 1024)}
			request := httptest.NewRequest(test.method, platformBasePath+test.path, body)
			request.ContentLength = int64(len(body.contents))
			request.Header.Set("Content-Type", "application/gzip")
			request.Header.Set("Idempotency-Key", "wrong-route")
			request.Header.Set("If-Match", `"7"`)
			response := servePlatformRequest(Services{PluginCatalog: newRecordingDurableCatalog(validCatalogVersion(plugincatalog.StatusVerified, 7))}, principalWith(platformTestScope, test.permission), request)
			require.Equal(t, http.StatusBadRequest, response.Code)
			require.Zero(t, body.reads)
		})
	}
}

func TestPluginUploadStagingReportsCleanupFailure(t *testing.T) {
	body := []byte("cleanup-observed-upload")
	service := newRecordingDurableCatalog(validCatalogVersion(plugincatalog.StatusVerified, 1))
	cleanupFailures := 0
	services := Services{
		PluginCatalog: service, Audit: &recordingAuditService{}, Idempotency: idempotency.NewService(newHTTPIdempotencyStore()),
		PluginUploadRemove: func(path string) error {
			_ = os.Remove(path)
			return errors.New("injected HTTP upload cleanup failure")
		},
		PluginUploadCleanupFailure: func(error) { cleanupFailures++ },
	}
	response := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage), newPluginUploadRequest(body, "cleanup-observed"))
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	require.Equal(t, 1, cleanupFailures)
}

func TestPluginCatalogProblemMappingsAreFixedAndRedacted(t *testing.T) {
	// Break caught: wrapping publisher/storage errors must not place filesystem,
	// signature, or key material in public Problems.
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{err: fmt.Errorf("publisher key /secret/path: %w", plugincatalog.ErrSignatureRejected), status: http.StatusUnprocessableEntity, code: "plugin_signature_rejected"},
		{err: fmt.Errorf("manifest password=top-secret: %w", plugincatalog.ErrManifestRejected), status: http.StatusUnprocessableEntity, code: "plugin_manifest_rejected"},
		{err: plugincatalog.ErrPlatformMismatch, status: http.StatusUnprocessableEntity, code: "plugin_platform_mismatch"},
		{err: fmt.Errorf("C:/artifact/root: %w", plugincatalog.ErrArtifactUnavailable), status: http.StatusServiceUnavailable, code: "plugin_artifact_unavailable"},
		{err: plugincatalog.ErrRevisionConflict, status: http.StatusPreconditionFailed, code: "state_revision_conflict"},
		{err: plugincatalog.ErrInvalid, status: http.StatusBadRequest, code: "invalid_request"},
		{err: plugincatalog.ErrPackageTooLarge, status: http.StatusUnprocessableEntity, code: "plugin_manifest_rejected"},
	}
	for _, test := range tests {
		problem := problemForError(test.err, "request-plugin-problem", "/plugin-versions/plugin-version-1")
		require.Equal(t, test.status, problem.Status)
		require.Equal(t, test.code, problem.Code)
		require.NotContains(t, problem.Title, "secret")
		require.Nil(t, problem.Detail)
	}
}

func TestPluginFailuresAuditExactlyOnceWithoutPublishingState(t *testing.T) {
	// Break caught: rejected signatures/manifests and stale lifecycle attempts
	// need a fixed deduplicated failure Audit even though no state is published.
	t.Run("invalid signature", func(t *testing.T) {
		service := newRecordingDurableCatalog(plugincatalog.PluginVersion{})
		service.uploadErr = fmt.Errorf("%w: SIGNATURE bytes /private/path: %w", plugincatalog.ErrBeforeSideEffect, plugincatalog.ErrSignatureRejected)
		audits := &recordingAuditService{}
		services := Services{PluginCatalog: service, Audit: audits, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
		principal := principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage)
		for range 2 {
			response := servePlatformRequest(services, principal, newPluginUploadRequest([]byte("invalid-signed-package"), "invalid-signature-key"))
			require.Equal(t, http.StatusUnprocessableEntity, response.Code)
		}
		require.Len(t, audits.records, 1)
		require.Equal(t, "plugin.version_verification_failed", audits.records[0].Action)
		require.Equal(t, "failure", audits.records[0].Result)
		require.NotContains(t, fmt.Sprint(audits.records[0].Detail), "SIGNATURE")
		require.NotContains(t, fmt.Sprint(audits.records[0].Detail), "private")
		require.Empty(t, service.operations)
	})

	t.Run("stale approval", func(t *testing.T) {
		service := newRecordingDurableCatalog(validCatalogVersion(plugincatalog.StatusVerified, 7))
		service.approveErr = plugincatalog.ErrRevisionConflict
		audits := &recordingAuditService{}
		services := Services{PluginCatalog: service, Audit: audits, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
		principal := principalWith(platformTestScope, openapi.PermissionApprovePluginVersion)
		for range 2 {
			request := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-versions/plugin-version-1/actions/approve", bytes.NewBufferString(`{}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "stale-approve-key")
			request.Header.Set("If-Match", `"7"`)
			response := servePlatformRequest(services, principal, request)
			require.Equal(t, http.StatusPreconditionFailed, response.Code)
		}
		require.Len(t, audits.records, 1)
		require.Equal(t, "plugin.version_transition_failed", audits.records[0].Action)
		require.Equal(t, "state_revision_conflict", audits.records[0].Detail["error_code"])
	})
}

func TestPluginAuditDedupeAllowsFailureThenSuccessWithSameKey(t *testing.T) {
	t.Run("unknown publisher then configured", func(t *testing.T) {
		service := newRecordingDurableCatalog(validCatalogVersion(plugincatalog.StatusVerified, 1))
		service.uploadErr = fmt.Errorf("%w: %w", plugincatalog.ErrBeforeSideEffect, plugincatalog.ErrUnknownPublisher)
		audits := &recordingAuditService{}
		services := Services{PluginCatalog: service, Audit: audits, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
		principal := principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage)
		body := []byte("publisher-becomes-trusted")
		failure := servePlatformRequest(services, principal, newPluginUploadRequest(body, "failure-success-upload"))
		require.Equal(t, http.StatusUnprocessableEntity, failure.Code)
		service.uploadErr = nil
		success := servePlatformRequest(services, principal, newPluginUploadRequest(body, "failure-success-upload"))
		require.Equal(t, http.StatusCreated, success.Code, success.Body.String())
		replay := servePlatformRequest(services, principal, newPluginUploadRequest(body, "failure-success-upload"))
		require.Equal(t, http.StatusCreated, replay.Code)
		require.Len(t, audits.records, 2)
		require.NotEqual(t, audits.records[0].DedupeKey, audits.records[1].DedupeKey)
		require.Equal(t, []string{"failure", "success"}, []string{audits.records[0].Result, audits.records[1].Result})
	})

	t.Run("not found then created version", func(t *testing.T) {
		service := newRecordingDurableCatalog(validCatalogVersion(plugincatalog.StatusVerified, 7))
		service.approveValue = validCatalogVersion(plugincatalog.StatusApproved, 8)
		service.approveErr = plugincatalog.ErrNotFound
		audits := &recordingAuditService{}
		services := Services{PluginCatalog: service, Audit: audits, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
		principal := principalWith(platformTestScope, openapi.PermissionApprovePluginVersion)
		request := func() *http.Request {
			value := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-versions/plugin-version-1/actions/approve", bytes.NewBufferString(`{}`))
			value.Header.Set("Content-Type", "application/json")
			value.Header.Set("Idempotency-Key", "failure-success-approve")
			value.Header.Set("If-Match", `"7"`)
			return value
		}
		require.Equal(t, http.StatusNotFound, servePlatformRequest(services, principal, request()).Code)
		service.approveErr = nil
		require.Equal(t, http.StatusOK, servePlatformRequest(services, principal, request()).Code)
		require.Equal(t, http.StatusOK, servePlatformRequest(services, principal, request()).Code)
		require.Len(t, audits.records, 2)
		require.NotEqual(t, audits.records[0].DedupeKey, audits.records[1].DedupeKey)
	})
}

func newPluginUploadRequest(body []byte, key string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-versions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/gzip")
	request.Header.Set("Idempotency-Key", key)
	return request
}

func validCatalogVersion(status plugincatalog.Status, revision uint64) plugincatalog.PluginVersion {
	return plugincatalog.PluginVersion{
		ID: "plugin-version-1", Scope: platformTestScope, PluginID: "mysql", Version: "1.0.0", Status: status,
		ArtifactID: "plugin-package-1", PackageSHA256: repeatString("0", 64), ManifestDigest: repeatString("1", 64),
		PublisherID: "publisher-1", SigningKeyID: "key-1", ProtocolVersion: "v1",
		MinimumAgentProtocolVersion: "v1", MaximumAgentProtocolVersion: "v1",
		SupportedVariants: []string{"mysql"}, DatabaseVersionRange: ">=8 <9", Capabilities: []string{"metrics.collect"},
		MetricTemplateSchemaVersion: 1,
		Platforms:                   []plugincatalog.Platform{{OperatingSystem: "linux", Architecture: "amd64", SHA256: repeatString("2", 64), SizeBytes: 24}},
		Revision:                    revision, CreatedAt: time.Date(2026, 8, 30, 4, 0, 0, 0, time.UTC),
	}
}

func repeatString(value string, count int) string { return string(bytes.Repeat([]byte(value), count)) }

type recordingPluginCatalogService struct {
	uploadValue           plugincatalog.PluginVersion
	uploadErr             error
	uploadCalls           int
	uploadScopes          []platformscope.Scope
	uploadMetadata        []plugincatalog.UploadMetadata
	uploadBodies          [][]byte
	approveValue          plugincatalog.PluginVersion
	approveErr            error
	publishValue          plugincatalog.PluginVersion
	revokeValue           plugincatalog.PluginVersion
	approveRevisions      []uint64
	publishRevisions      []uint64
	revokeRevisions       []uint64
	revokeReasons         []string
	versionPage           plugincatalog.VersionPage
	definitionPage        plugincatalog.DefinitionPage
	listVersionScopes     []platformscope.Scope
	versionFilters        []plugincatalog.VersionFilter
	listDefinitionScopes  []platformscope.Scope
	definitionFilters     []plugincatalog.DefinitionFilter
	operations            map[string]plugincatalog.OperationSnapshot
	operationFailures     map[string]int
	uploadOperationCalls  int
	approveOperationCalls int
	recoverOperationCalls int
}

func newRecordingDurableCatalog(value plugincatalog.PluginVersion) *recordingPluginCatalogService {
	return &recordingPluginCatalogService{uploadValue: value, operations: make(map[string]plugincatalog.OperationSnapshot)}
}

type countingRequestBody struct {
	contents []byte
	reads    int
}

func (body *countingRequestBody) Read(buffer []byte) (int, error) {
	body.reads++
	if len(body.contents) == 0 {
		return 0, io.EOF
	}
	read := copy(buffer, body.contents)
	body.contents = body.contents[read:]
	return read, nil
}

func (*countingRequestBody) Close() error { return nil }

func (service *recordingPluginCatalogService) Upload(_ context.Context, scope platformscope.Scope, metadata plugincatalog.UploadMetadata, reader io.Reader) (plugincatalog.PluginVersion, error) {
	service.uploadCalls++
	service.uploadScopes = append(service.uploadScopes, scope)
	service.uploadMetadata = append(service.uploadMetadata, metadata)
	body, err := io.ReadAll(reader)
	if err != nil {
		return plugincatalog.PluginVersion{}, err
	}
	service.uploadBodies = append(service.uploadBodies, body)
	return service.uploadValue, service.uploadErr
}

func (service *recordingPluginCatalogService) Approve(_ context.Context, _ platformscope.Scope, _ string, revision uint64) (plugincatalog.PluginVersion, error) {
	service.approveRevisions = append(service.approveRevisions, revision)
	return service.approveValue, service.approveErr
}

func (service *recordingPluginCatalogService) UploadOperation(_ context.Context, scope platformscope.Scope, metadata plugincatalog.UploadMetadata, key plugincatalog.OperationKey, auditJSON []byte, builder plugincatalog.OperationResponseBuilder, reader io.Reader) (plugincatalog.OperationSnapshot, error) {
	service.uploadOperationCalls++
	service.uploadCalls++
	if service.uploadErr != nil {
		return plugincatalog.OperationSnapshot{}, service.uploadErr
	}
	if snapshot, ok := service.operations[key.Identity()]; ok {
		return snapshot, nil
	}
	if service.operations == nil {
		service.operations = make(map[string]plugincatalog.OperationSnapshot)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return plugincatalog.OperationSnapshot{}, err
	}
	service.uploadBodies = append(service.uploadBodies, body)
	service.uploadScopes = append(service.uploadScopes, scope)
	service.uploadMetadata = append(service.uploadMetadata, metadata)
	response, err := builder(service.uploadValue)
	if err != nil {
		return plugincatalog.OperationSnapshot{}, err
	}
	snapshot := plugincatalog.OperationSnapshot{Key: key, State: plugincatalog.OperationCommitted, Version: service.uploadValue, Response: response, AuditEventJSON: append([]byte(nil), auditJSON...)}
	service.operations[key.Identity()] = snapshot
	return snapshot, nil
}

func (service *recordingPluginCatalogService) ApproveOperation(_ context.Context, _ platformscope.Scope, _ string, revision uint64, key plugincatalog.OperationKey, auditJSON []byte, builder plugincatalog.OperationResponseBuilder) (plugincatalog.OperationSnapshot, error) {
	service.approveOperationCalls++
	if service.consumeOperationFailure("approve") {
		return plugincatalog.OperationSnapshot{}, errors.New("crash before approve operation snapshot")
	}
	service.approveRevisions = append(service.approveRevisions, revision)
	if service.approveErr != nil {
		return plugincatalog.OperationSnapshot{}, service.approveErr
	}
	response, err := builder(service.approveValue)
	if err != nil {
		return plugincatalog.OperationSnapshot{}, err
	}
	snapshot := plugincatalog.OperationSnapshot{Key: key, State: plugincatalog.OperationCommitted, Version: service.approveValue, Response: response, AuditEventJSON: append([]byte(nil), auditJSON...)}
	if service.operations == nil {
		service.operations = make(map[string]plugincatalog.OperationSnapshot)
	}
	service.operations[key.Identity()] = snapshot
	return snapshot, nil
}

func (service *recordingPluginCatalogService) PublishOperation(ctx context.Context, scope platformscope.Scope, id string, revision uint64, key plugincatalog.OperationKey, auditJSON []byte, builder plugincatalog.OperationResponseBuilder) (plugincatalog.OperationSnapshot, error) {
	if service.consumeOperationFailure("publish") {
		return plugincatalog.OperationSnapshot{}, errors.New("crash before publish operation snapshot")
	}
	value, err := service.Publish(ctx, scope, id, revision)
	if err != nil {
		return plugincatalog.OperationSnapshot{}, err
	}
	response, err := builder(value)
	if err != nil {
		return plugincatalog.OperationSnapshot{}, err
	}
	snapshot := plugincatalog.OperationSnapshot{Key: key, State: plugincatalog.OperationCommitted, Version: value, Response: response, AuditEventJSON: append([]byte(nil), auditJSON...)}
	if service.operations == nil {
		service.operations = make(map[string]plugincatalog.OperationSnapshot)
	}
	service.operations[key.Identity()] = snapshot
	return snapshot, nil
}

func (service *recordingPluginCatalogService) RevokeOperation(ctx context.Context, scope platformscope.Scope, id string, revision uint64, reason string, key plugincatalog.OperationKey, auditJSON []byte, builder plugincatalog.OperationResponseBuilder) (plugincatalog.OperationSnapshot, error) {
	if service.consumeOperationFailure("revoke") {
		return plugincatalog.OperationSnapshot{}, errors.New("crash before revoke operation snapshot")
	}
	value, err := service.Revoke(ctx, scope, id, revision, reason)
	if err != nil {
		return plugincatalog.OperationSnapshot{}, err
	}
	response, err := builder(value)
	if err != nil {
		return plugincatalog.OperationSnapshot{}, err
	}
	snapshot := plugincatalog.OperationSnapshot{Key: key, State: plugincatalog.OperationCommitted, Version: value, Response: response, AuditEventJSON: append([]byte(nil), auditJSON...)}
	if service.operations == nil {
		service.operations = make(map[string]plugincatalog.OperationSnapshot)
	}
	service.operations[key.Identity()] = snapshot
	return snapshot, nil
}

func (service *recordingPluginCatalogService) consumeOperationFailure(name string) bool {
	if service.operationFailures[name] <= 0 {
		return false
	}
	service.operationFailures[name]--
	return true
}

func (service *recordingPluginCatalogService) RecoverOperation(_ context.Context, key plugincatalog.OperationKey) (plugincatalog.OperationSnapshot, error) {
	service.recoverOperationCalls++
	snapshot, ok := service.operations[key.Identity()]
	if !ok {
		return plugincatalog.OperationSnapshot{}, plugincatalog.ErrNotFound
	}
	return snapshot, nil
}

func (service *recordingPluginCatalogService) Publish(_ context.Context, _ platformscope.Scope, _ string, revision uint64) (plugincatalog.PluginVersion, error) {
	service.publishRevisions = append(service.publishRevisions, revision)
	return service.publishValue, nil
}

func (service *recordingPluginCatalogService) Revoke(_ context.Context, _ platformscope.Scope, _ string, revision uint64, reason string) (plugincatalog.PluginVersion, error) {
	service.revokeRevisions = append(service.revokeRevisions, revision)
	service.revokeReasons = append(service.revokeReasons, reason)
	return service.revokeValue, nil
}

func (service *recordingPluginCatalogService) ListVersions(_ context.Context, scope platformscope.Scope, filter plugincatalog.VersionFilter) (plugincatalog.VersionPage, error) {
	service.listVersionScopes = append(service.listVersionScopes, scope)
	service.versionFilters = append(service.versionFilters, filter)
	return service.versionPage, nil
}

func (service *recordingPluginCatalogService) ListDefinitions(_ context.Context, scope platformscope.Scope, filter plugincatalog.DefinitionFilter) (plugincatalog.DefinitionPage, error) {
	service.listDefinitionScopes = append(service.listDefinitionScopes, scope)
	service.definitionFilters = append(service.definitionFilters, filter)
	return service.definitionPage, nil
}

var _ plugincatalog.CatalogService = (*recordingPluginCatalogService)(nil)
