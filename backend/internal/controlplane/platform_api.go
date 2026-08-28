package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/capability"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
)

type platformScopeContextKey struct{}

type platformAPI struct{ services Services }

var _ openapi.StrictServerInterface = platformAPI{}

func (api platformAPI) GetJob(ctx context.Context, request openapi.GetJobRequestObject) (openapi.GetJobResponseObject, error) {
	if api.services.Jobs == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	value, err := api.services.Jobs.Get(ctx, scope, request.JobId)
	if err != nil {
		return nil, err
	}
	if value.ID != request.JobId || value.Scope != scope {
		return nil, errors.New("job service returned an out-of-scope entity")
	}
	response, err := openAPIJob(value)
	if err != nil {
		return nil, err
	}
	return getJobOKResponse{Body: response, ETag: entityTag(value.Version)}, nil
}

func (api platformAPI) CancelJob(ctx context.Context, request openapi.CancelJobRequestObject) (openapi.CancelJobResponseObject, error) {
	if api.services.Jobs == nil || api.services.Idempotency == nil || api.services.Audit == nil {
		return nil, ErrServiceUnavailable
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	version, err := parseEntityTag(request.Params.IfMatch)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	key := idempotency.Key{Scope: scope, Actor: principal.Subject, OperationID: "cancelJob", IdempotencyKey: request.Params.IdempotencyKey}
	fingerprint, err := platformIdempotencyFingerprint(ctx, key.OperationID, request.JobId, request.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	reconcile := func(callbackContext context.Context, _ idempotency.Response) error {
		_, auditErr := api.services.Audit.RecordOnce(callbackContext, httpActionAuditEvent(callbackContext, scope, principal, "job.cancel_requested", "job", request.JobId, "success", "cancelJob", request.Params.IdempotencyKey))
		return auditErr
	}
	claim, err := api.services.Idempotency.Begin(ctx, key, fingerprint, reconcile)
	if err != nil {
		return nil, err
	}
	if claim.Response != nil {
		if claim.Response.Status != http.StatusAccepted {
			return nil, errors.New("stored cancellation response has an invalid status")
		}
		return cancelJobIdempotentResponse{response: *claim.Response}, nil
	}
	owner := claim.OwnerToken
	now := time.Now
	if api.services.Now != nil {
		now = api.services.Now
	}
	value, err := api.services.Jobs.RequestCancel(ctx, scope, request.JobId, principal.Subject, version, now().UTC())
	if errors.Is(err, job.ErrConflict) {
		if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, owner); abortErr != nil {
			return nil, abortErr
		}
		return nil, ErrPreconditionFailed
	}
	if err != nil {
		if jobTransitionFailedBeforeSideEffect(err) {
			if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, owner); abortErr != nil {
				return nil, abortErr
			}
		}
		return nil, err
	}
	if value.ID != request.JobId || value.Scope != scope {
		return nil, errors.New("job service returned an out-of-scope entity")
	}
	response, err := openAPIJob(value)
	if err != nil {
		return nil, err
	}
	responseBody, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	stored := idempotency.Response{Status: http.StatusAccepted, Header: make(http.Header), Body: responseBody}
	stored.Header.Set("Content-Type", "application/json")
	stored.Header.Set("ETag", entityTag(value.Version))
	stored.Header.Set("Location", "/api/v1/tenants/"+url.PathEscape(scope.TenantID)+"/projects/"+url.PathEscape(scope.ProjectID)+"/jobs/"+url.PathEscape(value.ID))
	completed, err := api.services.Idempotency.Complete(ctx, key, fingerprint, owner, stored, reconcile)
	if err != nil {
		return nil, err
	}
	return cancelJobIdempotentResponse{response: completed}, nil
}

func (api platformAPI) GetArtifact(ctx context.Context, request openapi.GetArtifactRequestObject) (openapi.GetArtifactResponseObject, error) {
	if api.services.Artifacts == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	value, err := api.services.Artifacts.Get(ctx, scope, request.ArtifactId)
	if err != nil {
		return nil, err
	}
	if value.ID != request.ArtifactId || value.Scope != scope {
		return nil, errors.New("artifact service returned an out-of-scope entity")
	}
	response, err := openAPIArtifact(value)
	if err != nil {
		return nil, err
	}
	return openapi.GetArtifact200JSONResponse(response), nil
}

func (api platformAPI) CreateArtifactDownload(ctx context.Context, request openapi.CreateArtifactDownloadRequestObject) (openapi.CreateArtifactDownloadResponseObject, error) {
	if api.services.Artifacts == nil || api.services.Idempotency == nil || api.services.Audit == nil {
		return nil, ErrServiceUnavailable
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	key := idempotency.Key{Scope: scope, Actor: principal.Subject, OperationID: "createArtifactDownload", IdempotencyKey: request.Params.IdempotencyKey}
	fingerprint, err := platformIdempotencyFingerprint(ctx, key.OperationID, request.ArtifactId, "")
	if err != nil {
		return nil, err
	}
	reconcile := func(callbackContext context.Context, _ idempotency.Response) error {
		_, auditErr := api.services.Audit.RecordOnce(callbackContext, httpActionAuditEvent(callbackContext, scope, principal, "artifact.download_authorized", "artifact", request.ArtifactId, "success", "createArtifactDownload", request.Params.IdempotencyKey))
		return auditErr
	}
	claim, err := api.services.Idempotency.Begin(ctx, key, fingerprint, reconcile)
	if err != nil {
		return nil, err
	}
	if claim.Response != nil {
		if claim.Response.Status != http.StatusOK {
			return nil, errors.New("stored artifact download response has an invalid status")
		}
		return artifactDownloadIdempotentResponse{response: *claim.Response}, nil
	}
	owner := claim.OwnerToken
	value, err := api.services.Artifacts.CreateDownload(ctx, scope, request.ArtifactId, artifact.MaximumDownloadTTL)
	if err != nil {
		if errors.Is(err, artifact.ErrBeforeDownloadSideEffect) {
			if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, owner); abortErr != nil {
				return nil, abortErr
			}
		}
		return nil, err
	}
	var headers *map[string]string
	if len(value.Headers) > 0 {
		copyHeaders := make(map[string]string, len(value.Headers))
		for name, headerValue := range value.Headers {
			copyHeaders[name] = headerValue
		}
		headers = &copyHeaders
	}
	descriptor := openapi.DownloadDescriptor{
		Url: value.URL, ExpiresAt: value.ExpiresAt.UTC(), Headers: headers,
	}
	responseBody, err := json.Marshal(descriptor)
	if err != nil {
		return nil, err
	}
	stored := idempotency.Response{Status: http.StatusOK, Header: make(http.Header), Body: responseBody}
	stored.Header.Set("Content-Type", "application/json")
	completed, err := api.services.Idempotency.Complete(ctx, key, fingerprint, owner, stored, reconcile)
	if err != nil {
		return nil, err
	}
	return artifactDownloadIdempotentResponse{response: completed}, nil
}

func (api platformAPI) ListAuditEvents(ctx context.Context, request openapi.ListAuditEventsRequestObject) (openapi.ListAuditEventsResponseObject, error) {
	if api.services.Audit == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	query := audit.ListQuery{}
	if request.Params.Cursor != nil {
		if *request.Params.Cursor == "" || *request.Params.Cursor != strings.TrimSpace(*request.Params.Cursor) {
			return nil, ErrInvalidRequest
		}
		query.Cursor = *request.Params.Cursor
	}
	if request.Params.Limit != nil {
		if *request.Params.Limit < 1 || *request.Params.Limit > audit.MaximumListLimit {
			return nil, ErrInvalidRequest
		}
		query.Limit = *request.Params.Limit
	}
	page, err := api.services.Audit.List(ctx, scope, query)
	if err != nil {
		return nil, err
	}
	items := make([]openapi.AuditEvent, len(page.Items))
	for index, value := range page.Items {
		if value.Scope != scope {
			return nil, errors.New("audit service returned an out-of-scope entity")
		}
		items[index] = openAPIAuditEvent(value)
	}
	limit := query.Limit
	if limit == 0 {
		limit = audit.DefaultListLimit
	}
	var nextCursor *string
	if page.NextCursor != "" {
		next := page.NextCursor
		nextCursor = &next
	}
	return openapi.ListAuditEvents200JSONResponse{
		Items: items,
		Page:  openapi.Page{Limit: limit, HasMore: nextCursor != nil, NextCursor: nextCursor},
	}, nil
}

func (api platformAPI) GetCapabilities(ctx context.Context, _ openapi.GetCapabilitiesRequestObject) (openapi.GetCapabilitiesResponseObject, error) {
	if api.services.Capabilities == nil {
		return nil, ErrServiceUnavailable
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	input := capability.Input{}
	if api.services.CapabilityInput != nil {
		input = api.services.CapabilityInput(ctx, scope)
	}
	input.Permissions = effectivePermissions(principal, scope)
	values := api.services.Capabilities.Resolve(input)
	responses := make([]openapi.Capability, len(values))
	for index, value := range values {
		responses[index] = openAPICapability(value)
	}
	return openapi.GetCapabilities200JSONResponse{Capabilities: responses}, nil
}

func platformRequestIdentity(ctx context.Context) (platformscope.Scope, Principal, error) {
	if ctx == nil {
		return platformscope.Scope{}, Principal{}, ErrUnauthenticated
	}
	scope, scopeOK := ctx.Value(platformScopeContextKey{}).(platformscope.Scope)
	principal, principalOK := ctx.Value(principalContextKey{}).(Principal)
	if !scopeOK || scope.Validate() != nil || !principalOK || strings.TrimSpace(principal.Subject) == "" {
		return platformscope.Scope{}, Principal{}, ErrUnauthenticated
	}
	return scope, principal, nil
}

func effectivePermissions(principal Principal, scope platformscope.Scope) map[string]bool {
	permissions := make(map[string]bool)
	if principal.PlatformAdmin {
		for _, permission := range openapi.OperationPermissions {
			permissions[permission] = true
		}
		return permissions
	}
	for permission := range principal.Grants[scope.Key()] {
		permissions[permission] = true
	}
	return permissions
}

func validIdempotencyKey(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\t")
}

func parseEntityTag(value string) (int64, error) {
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, ErrInvalidRequest
	}
	version, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || version < 1 || entityTag(version) != value {
		return 0, ErrInvalidRequest
	}
	return version, nil
}

func entityTag(version int64) string { return `"` + strconv.FormatInt(version, 10) + `"` }

type getJobOKResponse struct {
	Body openapi.Job
	ETag string
}

type cancelJobIdempotentResponse struct{ response idempotency.Response }

func (response cancelJobIdempotentResponse) VisitCancelJobResponse(writer http.ResponseWriter) error {
	return writeIdempotencyResponse(writer, response.response)
}

type artifactDownloadIdempotentResponse struct{ response idempotency.Response }

func (response artifactDownloadIdempotentResponse) VisitCreateArtifactDownloadResponse(writer http.ResponseWriter) error {
	return writeIdempotencyResponse(writer, response.response)
}

func writeIdempotencyResponse(writer http.ResponseWriter, response idempotency.Response) error {
	for name, values := range response.Header {
		writer.Header()[name] = append([]string(nil), values...)
	}
	writer.WriteHeader(response.Status)
	_, err := writer.Write(response.Body)
	return err
}

func platformIdempotencyFingerprint(ctx context.Context, operationID, resourceID, ifMatch string) (string, error) {
	metadata, ok := ctx.Value(platformRequestMetadataContextKey{}).(platformRequestMetadata)
	if !ok || metadata.Path == "" || metadata.Method == "" || metadata.IfMatch != ifMatch {
		return "", ErrInvalidRequest
	}
	var input bytes.Buffer
	for _, value := range []string{operationID, metadata.Method, metadata.Path, resourceID, metadata.RawQuery, string(metadata.Body), ifMatch} {
		input.WriteString(strconv.Itoa(len(value)))
		input.WriteByte(':')
		input.WriteString(value)
	}
	digest := sha256.Sum256(input.Bytes())
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func jobTransitionFailedBeforeSideEffect(err error) bool {
	return errors.Is(err, job.ErrNotFound) || errors.Is(err, job.ErrInvalidTransition)
}

func httpActionAuditEvent(ctx context.Context, scope platformscope.Scope, principal Principal, action, resourceType, resourceID, result, operationID, idempotencyKey string) audit.Event {
	digest := sha256.Sum256([]byte(scope.Key() + "\x00" + principal.Subject + "\x00" + operationID + "\x00" + resourceID + "\x00" + idempotencyKey))
	return audit.Event{
		Scope: scope, Action: action, Actor: audit.Actor{Type: "user", ID: principal.Subject},
		Resource: audit.Resource{Type: resourceType, ID: resourceID}, Result: result,
		RequestID: requestIDFromContext(ctx), TraceID: traceIDFromContext(ctx),
		DedupeKey: "http.action:" + hex.EncodeToString(digest[:]),
		Detail:    map[string]any{"operation_id": operationID},
	}
}

func (response getJobOKResponse) VisitGetJobResponse(writer http.ResponseWriter) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(response.Body); err != nil {
		return err
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("ETag", response.ETag)
	writer.WriteHeader(http.StatusOK)
	_, err := body.WriteTo(writer)
	return err
}

func openAPIJob(value job.Job) (openapi.Job, error) {
	status := openapi.JobStatus(value.Status)
	outcome := openapi.JobOutcome(value.Outcome)
	if value.Scope.Validate() != nil || value.ID == "" || value.Type == "" || value.Version < 1 || value.CreatedAt.IsZero() || value.RequestID == "" || value.TraceID == "" || value.SourceResource.ResourceType == "" || value.SourceResource.ResourceID == "" || !status.Valid() || !outcome.Valid() {
		return openapi.Job{}, errors.New("job cannot be represented by the platform contract")
	}
	artifacts := make([]openapi.ArtifactReference, len(value.Artifacts))
	for index, reference := range value.Artifacts {
		artifacts[index] = openapi.ArtifactReference{ArtifactId: reference.ArtifactID, Kind: reference.Kind}
	}
	response := openapi.Job{
		Id: value.ID, Type: value.Type, Status: status, Outcome: outcome,
		TenantId: value.Scope.TenantID, ProjectId: value.Scope.ProjectID, Version: int(value.Version),
		Progress:       openapi.JobProgress{TotalTargets: value.Progress.TotalTargets, CompletedTargets: value.Progress.CompletedTargets, FailedTargets: value.Progress.FailedTargets, SkippedTargets: value.Progress.SkippedTargets},
		SourceResource: openapi.ResourceReference{ResourceType: value.SourceResource.ResourceType, ResourceId: value.SourceResource.ResourceID},
		CreatedAt:      value.CreatedAt.UTC(), RequestId: value.RequestID, TraceId: value.TraceID, Artifacts: artifacts,
		DispatchedAt: utcTimePointer(value.DispatchedAt), StartedAt: utcTimePointer(value.StartedAt), FinishedAt: utcTimePointer(value.FinishedAt), TimeoutAt: utcTimePointer(value.TimeoutAt),
	}
	if value.InstanceID != "" {
		instanceID := openapi.InstanceId(value.InstanceID)
		response.InstanceId = &instanceID
	}
	if len(value.TargetResourceIDs) > 0 {
		targets := append([]string(nil), value.TargetResourceIDs...)
		response.TargetResourceIds = &targets
	}
	if value.InitiatedBy != "" {
		initiatedBy := value.InitiatedBy
		response.InitiatedBy = &initiatedBy
	}
	if value.IdempotencyKey != "" {
		idempotencyKey := value.IdempotencyKey
		response.IdempotencyKey = &idempotencyKey
	}
	if value.ErrorSummary != "" {
		errorSummary := value.ErrorSummary
		response.ErrorSummary = &errorSummary
	}
	if value.ResultSummary != "" {
		resultSummary := value.ResultSummary
		response.ResultSummary = &resultSummary
	}
	return response, nil
}

func openAPIArtifact(value artifact.Artifact) (openapi.Artifact, error) {
	if value.Scope.Validate() != nil || value.ID == "" || value.Kind == "" || value.ContentType == "" || value.SizeBytes < 0 || value.SizeBytes > int64(^uint(0)>>1) || value.Checksum == "" || value.CreatedAt.IsZero() {
		return openapi.Artifact{}, errors.New("artifact cannot be represented by the platform contract")
	}
	response := openapi.Artifact{
		Id: value.ID, Kind: value.Kind, ContentType: value.ContentType, SizeBytes: int(value.SizeBytes), Checksum: value.Checksum,
		TenantId: value.Scope.TenantID, ProjectId: value.Scope.ProjectID, CreatedAt: value.CreatedAt.UTC(), ExpiresAt: utcTimePointer(value.ExpiresAt),
	}
	if value.SourceResource.ResourceType != "" && value.SourceResource.ResourceID != "" {
		response.SourceResource = &openapi.ResourceReference{ResourceType: value.SourceResource.ResourceType, ResourceId: value.SourceResource.ResourceID}
	}
	if value.JobID != "" {
		jobID := openapi.JobId(value.JobID)
		response.JobId = &jobID
	}
	if value.CreatedBy != "" {
		createdBy := value.CreatedBy
		response.CreatedBy = &createdBy
	}
	return response, nil
}

func openAPIAuditEvent(value audit.Event) openapi.AuditEvent {
	response := openapi.AuditEvent{
		Id: value.ID, OccurredAt: value.OccurredAt.UTC(), Action: value.Action,
		TenantId: value.Scope.TenantID, ProjectId: value.Scope.ProjectID,
		Actor: openapi.AuditActor{Type: value.Actor.Type, Id: value.Actor.ID}, Result: value.Result, RequestId: value.RequestID,
	}
	if value.Resource.Type != "" && value.Resource.ID != "" {
		response.SourceResource = &openapi.ResourceReference{ResourceType: value.Resource.Type, ResourceId: value.Resource.ID}
	}
	if value.JobID != "" {
		jobID := openapi.JobId(value.JobID)
		response.JobId = &jobID
	}
	if value.CommandID != "" {
		commandID := openapi.CommandId(value.CommandID)
		response.CommandId = &commandID
	}
	if value.TraceID != "" {
		traceID := openapi.TraceId(value.TraceID)
		response.TraceId = &traceID
	}
	if value.Detail != nil {
		detail := make(map[string]any, len(value.Detail))
		for key, item := range value.Detail {
			detail[key] = item
		}
		response.Detail = &detail
	}
	return response
}

func openAPICapability(value capability.Capability) openapi.Capability {
	response := openapi.Capability{
		Name: value.Name, Enabled: value.Enabled,
		DatabaseTypes: append([]string{}, value.DatabaseTypes...), AgentCapabilities: append([]string{}, value.AgentCapabilities...),
		RequiredPermission: value.RequiredPermission,
	}
	if value.ReasonCode != "" {
		reason := string(value.ReasonCode)
		response.ReasonCode = &reason
	}
	return response
}

func utcTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	utc := value.UTC()
	return &utc
}
