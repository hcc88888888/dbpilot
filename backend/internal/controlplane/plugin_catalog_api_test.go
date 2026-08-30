package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	uploadValue          plugincatalog.PluginVersion
	uploadErr            error
	uploadCalls          int
	uploadScopes         []platformscope.Scope
	uploadMetadata       []plugincatalog.UploadMetadata
	uploadBodies         [][]byte
	approveValue         plugincatalog.PluginVersion
	publishValue         plugincatalog.PluginVersion
	revokeValue          plugincatalog.PluginVersion
	approveRevisions     []uint64
	publishRevisions     []uint64
	revokeRevisions      []uint64
	revokeReasons        []string
	versionPage          plugincatalog.VersionPage
	definitionPage       plugincatalog.DefinitionPage
	listVersionScopes    []platformscope.Scope
	versionFilters       []plugincatalog.VersionFilter
	listDefinitionScopes []platformscope.Scope
	definitionFilters    []plugincatalog.DefinitionFilter
}

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
	return service.approveValue, nil
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
