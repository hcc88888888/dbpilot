package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/plugincatalog"
)

func (api platformAPI) ListPluginDefinitions(ctx context.Context, request openapi.ListPluginDefinitionsRequestObject) (openapi.ListPluginDefinitionsResponseObject, error) {
	if api.services.PluginCatalog == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := plugincatalog.DefinitionFilter{}
	if request.Params.DatabaseFamily != nil {
		filter.DatabaseFamily = string(*request.Params.DatabaseFamily)
	}
	if request.Params.Cursor != nil {
		filter.Cursor = *request.Params.Cursor
	}
	if request.Params.Limit != nil {
		filter.Limit = *request.Params.Limit
	}
	page, err := api.services.PluginCatalog.ListDefinitions(ctx, scope, filter)
	if err != nil {
		return nil, err
	}
	items := make([]openapi.PluginDefinition, len(page.Items))
	for index, value := range page.Items {
		if value.Scope != scope {
			return nil, errors.New("plugin catalog returned an out-of-scope definition")
		}
		items[index], err = openAPIPluginDefinition(value)
		if err != nil {
			return nil, err
		}
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 50
	}
	return openapi.ListPluginDefinitions200JSONResponse{Items: items, Page: openAPIPage(limit, page.More, page.NextCursor)}, nil
}

func (api platformAPI) ListPluginVersions(ctx context.Context, request openapi.ListPluginVersionsRequestObject) (openapi.ListPluginVersionsResponseObject, error) {
	if api.services.PluginCatalog == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := plugincatalog.VersionFilter{}
	if request.Params.PluginId != nil {
		filter.PluginID = *request.Params.PluginId
	}
	if request.Params.Status != nil {
		filter.Status = plugincatalog.Status(*request.Params.Status)
	}
	if request.Params.Cursor != nil {
		filter.Cursor = *request.Params.Cursor
	}
	if request.Params.Limit != nil {
		filter.Limit = *request.Params.Limit
	}
	page, err := api.services.PluginCatalog.ListVersions(ctx, scope, filter)
	if err != nil {
		return nil, err
	}
	items := make([]openapi.PluginVersion, len(page.Items))
	for index, value := range page.Items {
		if value.Scope != scope {
			return nil, errors.New("plugin catalog returned an out-of-scope version")
		}
		items[index], err = openAPIPluginVersion(value)
		if err != nil {
			return nil, err
		}
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 50
	}
	return openapi.ListPluginVersions200JSONResponse{Items: items, Page: openAPIPage(limit, page.More, page.NextCursor)}, nil
}

func (api platformAPI) UploadPluginVersionPackage(ctx context.Context, request openapi.UploadPluginVersionPackageRequestObject) (openapi.UploadPluginVersionPackageResponseObject, error) {
	if api.services.PluginCatalog == nil || api.services.Idempotency == nil || api.services.Audit == nil {
		return nil, ErrServiceUnavailable
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) || request.Params.ContentLength <= 0 || request.Body == nil {
		return nil, ErrInvalidRequest
	}
	metadata, ok := ctx.Value(platformRequestMetadataContextKey{}).(platformRequestMetadata)
	if !ok || !validPluginBodyDigest(metadata.BodyDigest) || metadata.ContentLength != request.Params.ContentLength {
		return nil, ErrInvalidRequest
	}
	resourceID := "plugin-version-" + strings.TrimPrefix(metadata.BodyDigest, "sha256:")[:32]
	key := idempotency.Key{Scope: scope, Actor: principal.Subject, OperationID: "uploadPluginVersionPackage", IdempotencyKey: request.Params.IdempotencyKey}
	fingerprint, err := platformIdempotencyFingerprint(ctx, key.OperationID, resourceID, "")
	if err != nil {
		return nil, err
	}
	auditPayload, reconcile, err := pluginAuditReconciliation(ctx, api.services.Audit, scope, principal, "plugin.version_uploaded", "plugin_version", resourceID, "success", key.OperationID, key.IdempotencyKey, map[string]any{
		"package_sha256": strings.TrimPrefix(metadata.BodyDigest, "sha256:"),
	})
	if err != nil {
		return nil, err
	}
	operationKey := func(owner string) plugincatalog.OperationKey {
		return plugincatalog.OperationKey{Scope: scope, Actor: principal.Subject, OperationID: key.OperationID, IdempotencyKey: key.IdempotencyKey, Fingerprint: fingerprint, OwnerToken: owner}
	}
	upload := func(operationContext context.Context, durableKey plugincatalog.OperationKey, storedAudit []byte) (plugincatalog.OperationSnapshot, error) {
		return api.services.PluginCatalog.UploadOperation(operationContext, scope, plugincatalog.UploadMetadata{Actor: principal.Subject, ContentLength: request.Params.ContentLength}, durableKey, storedAudit, pluginOperationResponseBuilder, request.Body)
	}
	claim, err := api.services.Idempotency.BeginRecoverable(ctx, key, fingerprint, auditPayload, reconcile, func(recoveryContext context.Context, processing idempotency.ProcessingClaim) (idempotency.Response, error) {
		durableKey := operationKey(processing.OwnerToken)
		snapshot, recoveryErr := api.services.PluginCatalog.RecoverOperation(recoveryContext, durableKey)
		if errors.Is(recoveryErr, plugincatalog.ErrOperationPending) || errors.Is(recoveryErr, plugincatalog.ErrNotFound) {
			snapshot, recoveryErr = upload(recoveryContext, durableKey, processing.Reconciliation)
		}
		if recoveryErr != nil {
			return idempotency.Response{}, recoveryErr
		}
		if snapshot.Version.Scope != scope || !bytes.Equal(snapshot.AuditEventJSON, processing.Reconciliation) {
			return idempotency.Response{}, errors.New("plugin catalog returned an out-of-scope version")
		}
		return idempotencyResponseFromOperation(snapshot.Response)
	})
	if err != nil {
		return nil, err
	}
	if claim.Response != nil {
		return uploadPluginVersionIdempotentResponse{response: *claim.Response}, nil
	}
	snapshot, err := upload(ctx, operationKey(claim.OwnerToken), auditPayload)
	if err != nil {
		if errors.Is(err, plugincatalog.ErrBeforeSideEffect) {
			if auditErr := recordPluginFailureAudit(ctx, api.services.Audit, scope, principal, "plugin.version_verification_failed", "plugin_package", resourceID, key.OperationID, key.IdempotencyKey, pluginFailureCode(err), map[string]any{"package_sha256": strings.TrimPrefix(metadata.BodyDigest, "sha256:")}); auditErr != nil {
				return nil, auditErr
			}
			if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, claim.OwnerToken); abortErr != nil {
				return nil, abortErr
			}
		}
		return nil, err
	}
	if snapshot.Version.Scope != scope || !bytes.Equal(snapshot.AuditEventJSON, auditPayload) {
		return nil, errors.New("plugin catalog returned an out-of-scope version")
	}
	stored, err := idempotencyResponseFromOperation(snapshot.Response)
	if err != nil {
		return nil, err
	}
	completed, err := api.services.Idempotency.Complete(ctx, key, fingerprint, claim.OwnerToken, stored, auditPayload, reconcile)
	if err != nil {
		return nil, err
	}
	return uploadPluginVersionIdempotentResponse{response: completed}, nil
}

func validPluginBodyDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32
}

func (api platformAPI) ApprovePluginVersion(ctx context.Context, request openapi.ApprovePluginVersionRequestObject) (openapi.ApprovePluginVersionResponseObject, error) {
	response, err := api.mutatePluginVersion(ctx, "approvePluginVersion", "plugin.version_approved", request.VersionId, request.Params.IdempotencyKey, request.Params.IfMatch, plugincatalog.StatusApproved, func(callContext context.Context, scope platformscope.Scope, revision uint64, key plugincatalog.OperationKey, auditJSON []byte) (plugincatalog.OperationSnapshot, error) {
		return api.services.PluginCatalog.ApproveOperation(callContext, scope, request.VersionId, revision, key, auditJSON, pluginOperationResponseBuilder)
	})
	if err != nil {
		return nil, err
	}
	return approvePluginVersionIdempotentResponse{response: response}, nil
}

func (api platformAPI) PublishPluginVersion(ctx context.Context, request openapi.PublishPluginVersionRequestObject) (openapi.PublishPluginVersionResponseObject, error) {
	response, err := api.mutatePluginVersion(ctx, "publishPluginVersion", "plugin.version_published", request.VersionId, request.Params.IdempotencyKey, request.Params.IfMatch, plugincatalog.StatusAvailable, func(callContext context.Context, scope platformscope.Scope, revision uint64, key plugincatalog.OperationKey, auditJSON []byte) (plugincatalog.OperationSnapshot, error) {
		return api.services.PluginCatalog.PublishOperation(callContext, scope, request.VersionId, revision, key, auditJSON, pluginOperationResponseBuilder)
	})
	if err != nil {
		return nil, err
	}
	return publishPluginVersionIdempotentResponse{response: response}, nil
}

func (api platformAPI) RevokePluginVersion(ctx context.Context, request openapi.RevokePluginVersionRequestObject) (openapi.RevokePluginVersionResponseObject, error) {
	if request.Body == nil {
		return nil, ErrInvalidRequest
	}
	reason := request.Body.ReasonCode
	response, err := api.mutatePluginVersion(ctx, "revokePluginVersion", "plugin.version_revoked", request.VersionId, request.Params.IdempotencyKey, request.Params.IfMatch, plugincatalog.StatusRevoked, func(callContext context.Context, scope platformscope.Scope, revision uint64, key plugincatalog.OperationKey, auditJSON []byte) (plugincatalog.OperationSnapshot, error) {
		return api.services.PluginCatalog.RevokeOperation(callContext, scope, request.VersionId, revision, reason, key, auditJSON, pluginOperationResponseBuilder)
	})
	if err != nil {
		return nil, err
	}
	return revokePluginVersionIdempotentResponse{response: response}, nil
}

type pluginMutationFunc func(context.Context, platformscope.Scope, uint64, plugincatalog.OperationKey, []byte) (plugincatalog.OperationSnapshot, error)

func (api platformAPI) mutatePluginVersion(ctx context.Context, operationID, action, versionID, idempotencyKey, ifMatch string, target plugincatalog.Status, mutate pluginMutationFunc) (idempotency.Response, error) {
	if api.services.PluginCatalog == nil || api.services.Idempotency == nil || api.services.Audit == nil || mutate == nil {
		return idempotency.Response{}, ErrServiceUnavailable
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return idempotency.Response{}, err
	}
	if !validIdempotencyKey(idempotencyKey) {
		return idempotency.Response{}, ErrInvalidRequest
	}
	revision, err := parseEntityTag(ifMatch)
	if err != nil {
		return idempotency.Response{}, ErrInvalidRequest
	}
	key := idempotency.Key{Scope: scope, Actor: principal.Subject, OperationID: operationID, IdempotencyKey: idempotencyKey}
	fingerprint, err := platformIdempotencyFingerprint(ctx, operationID, versionID, ifMatch)
	if err != nil {
		return idempotency.Response{}, err
	}
	auditPayload, reconcile, err := pluginAuditReconciliation(ctx, api.services.Audit, scope, principal, action, "plugin_version", versionID, "success", operationID, idempotencyKey, map[string]any{
		"expected_revision": uint64(revision), "target_status": string(target),
	})
	if err != nil {
		return idempotency.Response{}, err
	}
	operationKey := func(owner string) plugincatalog.OperationKey {
		return plugincatalog.OperationKey{Scope: scope, Actor: principal.Subject, OperationID: operationID, IdempotencyKey: idempotencyKey, Fingerprint: fingerprint, OwnerToken: owner}
	}
	claim, err := api.services.Idempotency.BeginRecoverable(ctx, key, fingerprint, auditPayload, reconcile, func(recoveryContext context.Context, processing idempotency.ProcessingClaim) (idempotency.Response, error) {
		durableKey := operationKey(processing.OwnerToken)
		snapshot, recoveryErr := api.services.PluginCatalog.RecoverOperation(recoveryContext, durableKey)
		if errors.Is(recoveryErr, plugincatalog.ErrNotFound) {
			snapshot, recoveryErr = mutate(recoveryContext, scope, uint64(revision), durableKey, processing.Reconciliation)
		}
		if recoveryErr != nil {
			return idempotency.Response{}, recoveryErr
		}
		if snapshot.Version.Scope != scope || snapshot.Version.ID != versionID || !bytes.Equal(snapshot.AuditEventJSON, processing.Reconciliation) {
			return idempotency.Response{}, errors.New("plugin catalog returned an out-of-scope version")
		}
		return idempotencyResponseFromOperation(snapshot.Response)
	})
	if err != nil {
		return idempotency.Response{}, err
	}
	if claim.Response != nil {
		return *claim.Response, nil
	}
	snapshot, err := mutate(ctx, scope, uint64(revision), operationKey(claim.OwnerToken), auditPayload)
	if err != nil {
		if errors.Is(err, plugincatalog.ErrInvalid) || errors.Is(err, plugincatalog.ErrNotFound) || errors.Is(err, plugincatalog.ErrRevisionConflict) {
			if auditErr := recordPluginFailureAudit(ctx, api.services.Audit, scope, principal, "plugin.version_transition_failed", "plugin_version", versionID, operationID, idempotencyKey, pluginFailureCode(err), map[string]any{"expected_revision": uint64(revision), "target_status": string(target)}); auditErr != nil {
				return idempotency.Response{}, auditErr
			}
			if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, claim.OwnerToken); abortErr != nil {
				return idempotency.Response{}, abortErr
			}
		}
		return idempotency.Response{}, err
	}
	if snapshot.Version.Scope != scope || snapshot.Version.ID != versionID || !bytes.Equal(snapshot.AuditEventJSON, auditPayload) {
		return idempotency.Response{}, errors.New("plugin catalog returned an out-of-scope version")
	}
	stored, err := idempotencyResponseFromOperation(snapshot.Response)
	if err != nil {
		return idempotency.Response{}, err
	}
	return api.services.Idempotency.Complete(ctx, key, fingerprint, claim.OwnerToken, stored, auditPayload, reconcile)
}

func pluginFailureCode(err error) string {
	switch {
	case errors.Is(err, plugincatalog.ErrSignatureRejected), errors.Is(err, plugincatalog.ErrUnknownPublisher):
		return "plugin_signature_rejected"
	case errors.Is(err, plugincatalog.ErrManifestRejected), errors.Is(err, plugincatalog.ErrPackageTooLarge):
		return "plugin_manifest_rejected"
	case errors.Is(err, plugincatalog.ErrPlatformMismatch):
		return "plugin_platform_mismatch"
	case errors.Is(err, plugincatalog.ErrRevisionConflict):
		return "state_revision_conflict"
	case errors.Is(err, plugincatalog.ErrNotFound):
		return "not_found"
	default:
		return "invalid_request"
	}
}

func recordPluginFailureAudit(ctx context.Context, service AuditService, scope platformscope.Scope, principal Principal, action, resourceType, resourceID, operationID, idempotencyKey, errorCode string, detail map[string]any) error {
	if service == nil {
		return ErrServiceUnavailable
	}
	event := httpActionAuditEvent(ctx, scope, principal, action, resourceType, resourceID, "failure", operationID, idempotencyKey)
	digest := sha256.Sum256([]byte(event.DedupeKey))
	event.RequestID = "plugin-failure-" + hex.EncodeToString(digest[:16])
	event.TraceID = ""
	event.Detail["error_code"] = errorCode
	for key, value := range detail {
		event.Detail[key] = value
	}
	_, err := service.RecordOnce(ctx, event)
	return err
}

func storedPluginVersionResponse(value plugincatalog.PluginVersion, status int) (idempotency.Response, error) {
	response, err := openAPIPluginVersion(value)
	if err != nil {
		return idempotency.Response{}, err
	}
	body, err := json.Marshal(response)
	if err != nil {
		return idempotency.Response{}, err
	}
	stored := idempotency.Response{Status: status, Header: make(http.Header), Body: body}
	stored.Header.Set("Content-Type", "application/json")
	stored.Header.Set("ETag", value.ETag())
	return stored, nil
}

func pluginOperationResponseBuilder(value plugincatalog.PluginVersion) (plugincatalog.OperationResponse, error) {
	stored, err := storedPluginVersionResponse(value, map[plugincatalog.Status]int{plugincatalog.StatusVerified: http.StatusCreated}[value.Status])
	if err != nil {
		return plugincatalog.OperationResponse{}, err
	}
	if stored.Status == 0 {
		stored.Status = http.StatusOK
	}
	return plugincatalog.OperationResponse{Status: stored.Status, ETag: stored.Header.Get("ETag"), Body: append([]byte(nil), stored.Body...)}, nil
}

func idempotencyResponseFromOperation(value plugincatalog.OperationResponse) (idempotency.Response, error) {
	if value.Validate() != nil {
		return idempotency.Response{}, errors.New("stored plugin operation response is invalid")
	}
	response := idempotency.Response{Status: value.Status, Header: make(http.Header), Body: append([]byte(nil), value.Body...)}
	response.Header.Set("Content-Type", "application/json")
	response.Header.Set("ETag", value.ETag)
	return response, nil
}

func pluginAuditReconciliation(ctx context.Context, service AuditService, scope platformscope.Scope, principal Principal, action, resourceType, resourceID, result, operationID, idempotencyKey string, detail map[string]any) ([]byte, idempotency.ReconcileFunc, error) {
	expected := httpActionAuditEvent(ctx, scope, principal, action, resourceType, resourceID, result, operationID, idempotencyKey)
	for key, value := range detail {
		expected.Detail[key] = value
	}
	encodedDetail, err := json.Marshal(expected.Detail)
	if err != nil {
		return nil, nil, err
	}
	if json.Unmarshal(encodedDetail, &expected.Detail) != nil {
		return nil, nil, errors.New("plugin audit detail is invalid")
	}
	payload := httpActionAuditPayload{Scope: expected.Scope, Action: expected.Action, Actor: expected.Actor, Resource: expected.Resource, Result: expected.Result, RequestID: expected.RequestID, TraceID: expected.TraceID, DedupeKey: expected.DedupeKey, Detail: expected.Detail}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	reconcile := func(callbackContext context.Context, _ idempotency.Response, storedJSON []byte) error {
		var stored httpActionAuditPayload
		if json.Unmarshal(storedJSON, &stored) != nil || stored.Scope != expected.Scope || stored.Action != expected.Action || stored.Actor != expected.Actor || stored.Resource != expected.Resource || stored.Result != expected.Result || stored.DedupeKey != expected.DedupeKey || !reflect.DeepEqual(stored.Detail, expected.Detail) || !canonicalAuditIdentity(stored.RequestID) || stored.TraceID != "" && !canonicalAuditIdentity(stored.TraceID) {
			return errors.New("stored plugin audit payload is invalid")
		}
		_, recordErr := service.RecordOnce(callbackContext, audit.Event{Scope: stored.Scope, Action: stored.Action, Actor: stored.Actor, Resource: stored.Resource, Result: stored.Result, RequestID: stored.RequestID, TraceID: stored.TraceID, DedupeKey: stored.DedupeKey, Detail: stored.Detail})
		return recordErr
	}
	return encoded, reconcile, nil
}

func openAPIPluginVersion(value plugincatalog.PluginVersion) (openapi.PluginVersion, error) {
	if value.Validate() != nil {
		return openapi.PluginVersion{}, errors.New("plugin version cannot be represented by the platform contract")
	}
	platforms := make([]openapi.PluginPlatform, len(value.Platforms))
	for index, platform := range value.Platforms {
		platforms[index] = openapi.PluginPlatform{OperatingSystem: openapi.PluginOperatingSystem(platform.OperatingSystem), Architecture: openapi.PluginArchitecture(platform.Architecture), Sha256: platform.SHA256, SizeBytes: platform.SizeBytes}
	}
	variants := make([]openapi.DatabaseVariant, len(value.SupportedVariants))
	for index, variant := range value.SupportedVariants {
		variants[index] = openapi.DatabaseVariant(variant)
	}
	response := openapi.PluginVersion{
		VersionId: value.ID, PluginId: value.PluginID, Version: value.Version, Status: openapi.PluginVersionStatus(value.Status),
		ArtifactId: value.ArtifactID, PackageSha256: value.PackageSHA256, ManifestDigest: value.ManifestDigest,
		PublisherId: value.PublisherID, SupportedVariants: variants, DatabaseVersionRange: value.DatabaseVersionRange,
		Capabilities: append([]string(nil), value.Capabilities...), MetricTemplateSchemaVersion: value.MetricTemplateSchemaVersion,
		Platforms: platforms, CreatedAt: value.CreatedAt.UTC(), Etag: value.ETag(),
	}
	response.SigningKeyId = &value.SigningKeyID
	response.MinimumAgentProtocolVersion = &value.MinimumAgentProtocolVersion
	response.MaximumAgentProtocolVersion = &value.MaximumAgentProtocolVersion
	if value.ApprovedAt != nil {
		at := value.ApprovedAt.UTC()
		response.ApprovedAt = &at
	}
	return response, nil
}

func openAPIPluginDefinition(value plugincatalog.PluginDefinition) (openapi.PluginDefinition, error) {
	if value.Validate() != nil {
		return openapi.PluginDefinition{}, errors.New("plugin definition cannot be represented by the platform contract")
	}
	variants := make([]openapi.DatabaseVariant, len(value.SupportedVariants))
	for index, variant := range value.SupportedVariants {
		variants[index] = openapi.DatabaseVariant(variant)
	}
	response := openapi.PluginDefinition{
		PluginId: value.PluginID, Name: value.Name, DatabaseFamily: openapi.DatabaseFamily(value.DatabaseFamily), ProtocolVersion: value.ProtocolVersion,
		Capabilities: append([]string(nil), value.Capabilities...), SupportedVariants: &variants,
	}
	if value.LatestAvailableVersion != "" {
		latest := value.LatestAvailableVersion
		response.LatestAvailableVersion = &latest
	}
	return response, nil
}

func openAPIPage(limit int, more bool, cursor string) openapi.Page {
	var next *string
	if cursor != "" {
		next = &cursor
	}
	return openapi.Page{Limit: limit, HasMore: more, NextCursor: next}
}

type uploadPluginVersionIdempotentResponse struct{ response idempotency.Response }

func (value uploadPluginVersionIdempotentResponse) VisitUploadPluginVersionPackageResponse(writer http.ResponseWriter) error {
	return writeIdempotencyResponse(writer, value.response)
}

type approvePluginVersionIdempotentResponse struct{ response idempotency.Response }

func (value approvePluginVersionIdempotentResponse) VisitApprovePluginVersionResponse(writer http.ResponseWriter) error {
	return writeIdempotencyResponse(writer, value.response)
}

type publishPluginVersionIdempotentResponse struct{ response idempotency.Response }

func (value publishPluginVersionIdempotentResponse) VisitPublishPluginVersionResponse(writer http.ResponseWriter) error {
	return writeIdempotencyResponse(writer, value.response)
}

type revokePluginVersionIdempotentResponse struct{ response idempotency.Response }

func (value revokePluginVersionIdempotentResponse) VisitRevokePluginVersionResponse(writer http.ResponseWriter) error {
	return writeIdempotencyResponse(writer, value.response)
}
