package controlplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"dbpilot.local/platform/gen/openapi"
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
	auditPayload, reconcile, err := httpActionAuditReconciliationWithDetail(ctx, api.services.Audit, scope, principal, "plugin.version_uploaded", "plugin_version", resourceID, "success", key.OperationID, key.IdempotencyKey, map[string]any{
		"package_sha256": strings.TrimPrefix(metadata.BodyDigest, "sha256:"),
	})
	if err != nil {
		return nil, err
	}
	upload := func(operationContext context.Context) (plugincatalog.PluginVersion, error) {
		return api.services.PluginCatalog.Upload(operationContext, scope, plugincatalog.UploadMetadata{Actor: principal.Subject, ContentLength: request.Params.ContentLength}, request.Body)
	}
	claim, err := api.services.Idempotency.BeginRecoverable(ctx, key, fingerprint, auditPayload, reconcile, func(recoveryContext context.Context, _ idempotency.ProcessingClaim) (idempotency.Response, error) {
		value, recoveryErr := upload(recoveryContext)
		if recoveryErr != nil {
			return idempotency.Response{}, recoveryErr
		}
		if value.Scope != scope {
			return idempotency.Response{}, errors.New("plugin catalog returned an out-of-scope version")
		}
		return storedPluginVersionResponse(value, http.StatusCreated)
	})
	if err != nil {
		return nil, err
	}
	if claim.Response != nil {
		return uploadPluginVersionIdempotentResponse{response: *claim.Response}, nil
	}
	value, err := upload(ctx)
	if err != nil {
		if errors.Is(err, plugincatalog.ErrBeforeSideEffect) {
			if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, claim.OwnerToken); abortErr != nil {
				return nil, abortErr
			}
		}
		return nil, err
	}
	if value.Scope != scope {
		return nil, errors.New("plugin catalog returned an out-of-scope version")
	}
	stored, err := storedPluginVersionResponse(value, http.StatusCreated)
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
	response, err := api.mutatePluginVersion(ctx, "approvePluginVersion", "plugin.version_approved", request.VersionId, request.Params.IdempotencyKey, request.Params.IfMatch, plugincatalog.StatusApproved, func(callContext context.Context, revision uint64) (plugincatalog.PluginVersion, error) {
		return api.services.PluginCatalog.Approve(callContext, mustPlatformScope(ctx), request.VersionId, revision)
	})
	if err != nil {
		return nil, err
	}
	return approvePluginVersionIdempotentResponse{response: response}, nil
}

func (api platformAPI) PublishPluginVersion(ctx context.Context, request openapi.PublishPluginVersionRequestObject) (openapi.PublishPluginVersionResponseObject, error) {
	response, err := api.mutatePluginVersion(ctx, "publishPluginVersion", "plugin.version_published", request.VersionId, request.Params.IdempotencyKey, request.Params.IfMatch, plugincatalog.StatusAvailable, func(callContext context.Context, revision uint64) (plugincatalog.PluginVersion, error) {
		return api.services.PluginCatalog.Publish(callContext, mustPlatformScope(ctx), request.VersionId, revision)
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
	response, err := api.mutatePluginVersion(ctx, "revokePluginVersion", "plugin.version_revoked", request.VersionId, request.Params.IdempotencyKey, request.Params.IfMatch, plugincatalog.StatusRevoked, func(callContext context.Context, revision uint64) (plugincatalog.PluginVersion, error) {
		return api.services.PluginCatalog.Revoke(callContext, mustPlatformScope(ctx), request.VersionId, revision, reason)
	})
	if err != nil {
		return nil, err
	}
	return revokePluginVersionIdempotentResponse{response: response}, nil
}

type pluginMutationFunc func(context.Context, uint64) (plugincatalog.PluginVersion, error)

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
	auditPayload, reconcile, err := httpActionAuditReconciliationWithDetail(ctx, api.services.Audit, scope, principal, action, "plugin_version", versionID, "success", operationID, idempotencyKey, map[string]any{
		"expected_revision": uint64(revision), "target_status": string(target),
	})
	if err != nil {
		return idempotency.Response{}, err
	}
	claim, err := api.services.Idempotency.BeginRecoverable(ctx, key, fingerprint, auditPayload, reconcile, func(recoveryContext context.Context, _ idempotency.ProcessingClaim) (idempotency.Response, error) {
		value, recoveryErr := mutate(recoveryContext, uint64(revision))
		if errors.Is(recoveryErr, plugincatalog.ErrRevisionConflict) {
			page, listErr := api.services.PluginCatalog.ListVersions(recoveryContext, scope, plugincatalog.VersionFilter{VersionID: versionID, Limit: 1})
			if listErr != nil || len(page.Items) != 1 || page.Items[0].Status != target || page.Items[0].Revision != uint64(revision)+1 {
				return idempotency.Response{}, recoveryErr
			}
			value = page.Items[0]
			recoveryErr = nil
		}
		if recoveryErr != nil {
			return idempotency.Response{}, recoveryErr
		}
		if value.Scope != scope || value.ID != versionID {
			return idempotency.Response{}, errors.New("plugin catalog returned an out-of-scope version")
		}
		return storedPluginVersionResponse(value, http.StatusOK)
	})
	if err != nil {
		return idempotency.Response{}, err
	}
	if claim.Response != nil {
		return *claim.Response, nil
	}
	value, err := mutate(ctx, uint64(revision))
	if err != nil {
		if errors.Is(err, plugincatalog.ErrInvalid) || errors.Is(err, plugincatalog.ErrNotFound) || errors.Is(err, plugincatalog.ErrRevisionConflict) {
			if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, claim.OwnerToken); abortErr != nil {
				return idempotency.Response{}, abortErr
			}
		}
		return idempotency.Response{}, err
	}
	if value.Scope != scope || value.ID != versionID {
		return idempotency.Response{}, errors.New("plugin catalog returned an out-of-scope version")
	}
	stored, err := storedPluginVersionResponse(value, http.StatusOK)
	if err != nil {
		return idempotency.Response{}, err
	}
	return api.services.Idempotency.Complete(ctx, key, fingerprint, claim.OwnerToken, stored, auditPayload, reconcile)
}

func mustPlatformScope(ctx context.Context) platformscope.Scope {
	scope, _, _ := platformRequestIdentity(ctx)
	return scope
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
