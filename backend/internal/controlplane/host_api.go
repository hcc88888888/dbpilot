package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/rediscovery"
)

func (api platformAPI) ListHosts(ctx context.Context, request openapi.ListHostsRequestObject) (openapi.ListHostsResponseObject, error) {
	if api.services.Hosts == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := hostinventory.Filter{}
	if request.Params.Status != nil {
		filter.Status = hostinventory.HostStatus(*request.Params.Status)
	}
	if request.Params.Cursor != nil {
		filter.Cursor = *request.Params.Cursor
	}
	if request.Params.Limit != nil {
		filter.Limit = *request.Params.Limit
	}
	page, err := api.services.Hosts.List(ctx, scope, filter)
	if err != nil {
		return nil, err
	}
	items := make([]openapi.ManagedHost, len(page.Items))
	for index, value := range page.Items {
		if value.Scope != scope {
			return nil, errors.New("host service returned an out-of-scope entity")
		}
		value, err = hostWithDiscoverySourceHealth(ctx, api.services, value)
		if err != nil {
			return nil, err
		}
		items[index], err = openAPIManagedHost(value)
		if err != nil {
			return nil, err
		}
	}
	limit := filter.Limit
	if limit == 0 {
		limit = hostinventory.DefaultListLimit
	}
	var nextCursor *string
	if page.NextCursor != "" {
		if page.NextCursor != strings.TrimSpace(page.NextCursor) || len(page.NextCursor) > 512 {
			return nil, errors.New("host service returned an invalid cursor")
		}
		next := page.NextCursor
		nextCursor = &next
	}
	return openapi.ListHosts200JSONResponse{
		Items: items,
		Page:  openapi.Page{Limit: limit, HasMore: nextCursor != nil, NextCursor: nextCursor},
	}, nil
}

func (api platformAPI) GetHost(ctx context.Context, request openapi.GetHostRequestObject) (openapi.GetHostResponseObject, error) {
	if api.services.Hosts == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	host, err := api.services.Hosts.Get(ctx, scope, request.HostId)
	if err != nil {
		return nil, err
	}
	if host.Scope != scope || host.ID != request.HostId {
		return nil, errors.New("host service returned an out-of-scope entity")
	}
	host, err = hostWithDiscoverySourceHealth(ctx, api.services, host)
	if err != nil {
		return nil, err
	}
	body, err := openAPIManagedHost(host)
	if err != nil {
		return nil, err
	}
	etag := entityTag(int64(host.Version))
	return openapi.GetHost200JSONResponse{Body: body, Headers: openapi.GetHost200ResponseHeaders{ETag: etag}}, nil
}

func hostWithDiscoverySourceHealth(ctx context.Context, services Services, host hostinventory.Host) (hostinventory.Host, error) {
	reader, ok := services.Discovery.(interface {
		SourceResults(context.Context, platformscope.Scope, string) ([]discovery.SourceResult, error)
	})
	if !ok {
		return host, nil
	}
	results, err := reader.SourceResults(ctx, host.Scope, host.ID)
	if err != nil {
		return hostinventory.Host{}, err
	}
	if len(results) == 0 {
		return host, nil
	}
	filtered := make([]hostinventory.Capability, 0, len(host.Capabilities)+2)
	for _, capability := range host.Capabilities {
		if capability.Name != "native_discovery_v1" && capability.Name != "docker_discovery_v1" {
			filtered = append(filtered, capability)
		}
	}
	for _, result := range results {
		if result.Status == discovery.SourceNotRequested {
			continue
		}
		capability := hostinventory.Capability{Name: string(result.Source) + "_discovery_v1", Available: result.Status == discovery.SourceCompleted}
		if !capability.Available {
			if result.Reason == discovery.SourcePermissionDenied {
				capability.Reason = "permission_denied"
			} else if result.Source == discovery.SourceDocker {
				capability.Reason = "docker_discovery_unavailable"
			} else {
				capability.Reason = "agent_unsupported"
			}
		}
		filtered = append(filtered, capability)
	}
	host.Capabilities = filtered
	if host.Validate() != nil {
		return hostinventory.Host{}, hostinventory.ErrInvalid
	}
	return host, nil
}

func (api platformAPI) DecommissionHost(ctx context.Context, request openapi.DecommissionHostRequestObject) (openapi.DecommissionHostResponseObject, error) {
	if api.services.Hosts == nil || api.services.Idempotency == nil || api.services.Audit == nil {
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
	key := idempotency.Key{Scope: scope, Actor: principal.Subject, OperationID: "decommissionHost", IdempotencyKey: request.Params.IdempotencyKey}
	fingerprint, err := platformIdempotencyFingerprint(ctx, key.OperationID, request.HostId, request.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	auditPayload, reconcile, err := httpActionAuditReconciliation(ctx, api.services.Audit, scope, principal, "host.decommissioned", "host", request.HostId, "success", key.OperationID, key.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	claim, err := api.services.Idempotency.BeginRecoverable(ctx, key, fingerprint, auditPayload, reconcile, func(recoveryContext context.Context, processing idempotency.ProcessingClaim) (idempotency.Response, error) {
		current, recoveryErr := api.services.Hosts.Get(recoveryContext, scope, request.HostId)
		if recoveryErr != nil {
			return idempotency.Response{}, recoveryErr
		}
		expectedTransition := hostDecommissionTransition(key, fingerprint, processing.OwnerToken)
		if current.Status != hostinventory.HostDecommissioned || current.Version != uint64(version)+1 || current.DecommissionTransition == nil || !current.DecommissionTransition.Matches(expectedTransition) {
			return idempotency.Response{}, idempotency.ErrInProgress
		}
		if api.services.AgentSessions != nil {
			api.services.AgentSessions.Terminate(current.AgentID)
		}
		return storedHostDecommissionResponse(current, scope, request.HostId, expectedTransition)
	})
	if err != nil {
		return nil, err
	}
	if claim.Response != nil {
		if claim.Response.Status != http.StatusOK {
			return nil, errors.New("stored host decommission response has an invalid status")
		}
		return hostDecommissionIdempotentResponse{response: *claim.Response}, nil
	}
	owner := claim.OwnerToken
	transition := hostDecommissionTransition(key, fingerprint, owner)
	decommissionContext := hostinventory.WithDecommissionTransition(ctx, transition)
	host, err := api.services.Hosts.Decommission(decommissionContext, scope, request.HostId, uint64(version))
	if errors.Is(err, hostinventory.ErrConflict) {
		if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, owner); abortErr != nil {
			return nil, abortErr
		}
		return nil, ErrPreconditionFailed
	}
	if err != nil {
		if errors.Is(err, hostinventory.ErrNotFound) {
			if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, owner); abortErr != nil {
				return nil, abortErr
			}
		}
		return nil, err
	}
	if api.services.AgentSessions != nil {
		api.services.AgentSessions.Terminate(host.AgentID)
	}
	stored, err := storedHostDecommissionResponse(host, scope, request.HostId, transition)
	if err != nil {
		return nil, err
	}
	completed, err := api.services.Idempotency.Complete(ctx, key, fingerprint, owner, stored, auditPayload, reconcile)
	if err != nil {
		return nil, err
	}
	return hostDecommissionIdempotentResponse{response: completed}, nil
}

func (api platformAPI) RediscoverHost(ctx context.Context, request openapi.RediscoverHostRequestObject) (openapi.RediscoverHostResponseObject, error) {
	if api.services.HostRediscovery == nil || api.services.Idempotency == nil || api.services.Audit == nil {
		return nil, ErrServiceUnavailable
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	fingerprint, err := platformIdempotencyFingerprint(ctx, "rediscoverHost", request.HostId, "")
	if err != nil {
		return nil, err
	}
	key := idempotency.Key{Scope: scope, Actor: principal.Subject, OperationID: "rediscoverHost", IdempotencyKey: request.Params.IdempotencyKey}
	auditPayload, reconcileAudit, err := httpActionAuditReconciliation(ctx, api.services.Audit, scope, principal, "host.rediscovery_requested", "host", request.HostId, "success", key.OperationID, key.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	recovery := hostRediscoveryRecovery{RequestID: requestIDFromContext(ctx), TraceID: traceIDFromContext(ctx), Audit: append(json.RawMessage(nil), auditPayload...)}
	if metadata, ok := ctx.Value(platformRequestMetadataContextKey{}).(platformRequestMetadata); ok {
		recovery.Instance = metadata.Path
	}
	recoveryJSON, err := json.Marshal(recovery)
	if err != nil {
		return nil, err
	}
	reconcile := func(reconcileContext context.Context, response idempotency.Response, payload []byte) error {
		var original hostRediscoveryRecovery
		if json.Unmarshal(payload, &original) != nil || original.RequestID == "" || original.TraceID == "" || !json.Valid(original.Audit) {
			return idempotency.ErrInvalid
		}
		return reconcileAudit(reconcileContext, response, original.Audit)
	}
	run := func(callContext context.Context, value hostRediscoveryRecovery) (idempotency.Response, error) {
		created, startErr := api.services.HostRediscovery.Start(callContext, scope, request.HostId, rediscovery.RediscoveryRequest{Actor: principal.Subject, IdempotencyKey: request.Params.IdempotencyKey, RequestFingerprint: fingerprint, RequestID: value.RequestID, TraceID: value.TraceID})
		if startErr != nil {
			if errors.Is(startErr, rediscovery.ErrHostNotOnline) || errors.Is(startErr, rediscovery.ErrRediscoveryUnavailable) || errors.Is(startErr, rediscovery.ErrInvalid) || errors.Is(startErr, hostinventory.ErrNotFound) {
				return idempotency.Response{}, hostRediscoveryPreMutationError{err: startErr}
			}
			return idempotency.Response{}, startErr
		}
		return storedHostRediscoveryResponse(created, scope, request.HostId)
	}
	begin := func() (idempotency.Claim, error) {
		return api.services.Idempotency.BeginRecoverable(ctx, key, fingerprint, recoveryJSON, reconcile, func(recoveryContext context.Context, processing idempotency.ProcessingClaim) (idempotency.Response, error) {
			var original hostRediscoveryRecovery
			if json.Unmarshal(processing.Reconciliation, &original) != nil || original.RequestID == "" || original.TraceID == "" {
				return idempotency.Response{}, idempotency.ErrInvalid
			}
			stored, runErr := run(recoveryContext, original)
			var before hostRediscoveryPreMutationError
			if errors.As(runErr, &before) {
				if abortErr := api.services.Idempotency.Abort(recoveryContext, key, fingerprint, processing.OwnerToken); abortErr != nil {
					return idempotency.Response{}, abortErr
				}
				return idempotency.Response{}, before.err
			}
			return stored, runErr
		})
	}
	var claim idempotency.Claim
	for attempt := 0; attempt < 4; attempt++ {
		claim, err = begin()
		if !errors.Is(err, idempotency.ErrOwnershipConflict) {
			break
		}
	}
	if err != nil {
		var before hostRediscoveryPreMutationError
		if errors.As(err, &before) {
			return nil, before.err
		}
		return nil, err
	}
	if claim.Response != nil {
		return hostRediscoveryIdempotentResponse{response: *claim.Response}, nil
	}
	stored, err := run(ctx, recovery)
	if err != nil {
		var before hostRediscoveryPreMutationError
		if errors.As(err, &before) {
			if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, claim.OwnerToken); abortErr != nil {
				return nil, abortErr
			}
			return nil, before.err
		}
		return nil, err
	}
	completed, err := api.services.Idempotency.Complete(ctx, key, fingerprint, claim.OwnerToken, stored, recoveryJSON, reconcile)
	if err != nil {
		return nil, err
	}
	return hostRediscoveryIdempotentResponse{response: completed}, nil
}

type hostRediscoveryRecovery struct {
	RequestID string          `json:"request_id"`
	TraceID   string          `json:"trace_id"`
	Instance  string          `json:"instance,omitempty"`
	Audit     json.RawMessage `json:"audit"`
}

type hostRediscoveryPreMutationError struct{ err error }

func (value hostRediscoveryPreMutationError) Error() string { return value.err.Error() }
func (value hostRediscoveryPreMutationError) Unwrap() error { return value.err }

type hostRediscoveryIdempotentResponse struct{ response idempotency.Response }

func (response hostRediscoveryIdempotentResponse) VisitRediscoverHostResponse(writer http.ResponseWriter) error {
	return writeIdempotencyResponse(writer, response.response)
}

func storedHostRediscoveryResponse(value job.Job, scope platformscope.Scope, hostID string) (idempotency.Response, error) {
	if value.Scope != scope || value.Type != "host.rediscover" || value.SourceResource != (job.ResourceReference{ResourceType: "host", ResourceID: hostID}) || value.Version < 1 {
		return idempotency.Response{}, errors.New("stored host rediscovery Job is invalid")
	}
	body, err := openAPIJob(value)
	if err != nil {
		return idempotency.Response{}, err
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return idempotency.Response{}, err
	}
	location := fmt.Sprintf("/api/v1/tenants/%s/projects/%s/jobs/%s", url.PathEscape(scope.TenantID), url.PathEscape(scope.ProjectID), url.PathEscape(value.ID))
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("ETag", entityTag(value.Version))
	headers.Set("Location", location)
	return idempotency.Response{Status: http.StatusAccepted, Header: headers, Body: encoded}, nil
}

func hostDecommissionTransition(key idempotency.Key, fingerprint, owner string) hostinventory.DecommissionTransition {
	return hostinventory.DecommissionTransition{
		Actor: key.Actor, OperationID: key.OperationID, IdempotencyKey: key.IdempotencyKey,
		Fingerprint: fingerprint, OwnerToken: owner,
	}
}

type hostDecommissionIdempotentResponse struct{ response idempotency.Response }

func (response hostDecommissionIdempotentResponse) VisitDecommissionHostResponse(writer http.ResponseWriter) error {
	return writeIdempotencyResponse(writer, response.response)
}

func storedHostDecommissionResponse(value hostinventory.Host, scope platformscope.Scope, hostID string, expected hostinventory.DecommissionTransition) (idempotency.Response, error) {
	if value.Scope != scope || value.ID != hostID || value.Status != hostinventory.HostDecommissioned || value.DecommissionTransition == nil || !value.DecommissionTransition.Matches(expected) {
		return idempotency.Response{}, errors.New("stored host decommission snapshot is invalid")
	}
	body, err := openAPIManagedHost(value)
	if err != nil {
		return idempotency.Response{}, err
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return idempotency.Response{}, err
	}
	response := idempotency.Response{Status: http.StatusOK, Header: make(http.Header), Body: encoded}
	response.Header.Set("Content-Type", "application/json")
	response.Header.Set("ETag", entityTag(int64(value.Version)))
	return response, nil
}

func openAPIManagedHost(value hostinventory.Host) (openapi.ManagedHost, error) {
	if value.Validate() != nil {
		return openapi.ManagedHost{}, hostinventory.ErrInvalid
	}
	status := openapi.HostStatus(value.Status)
	runtime := openapi.ContainerRuntime(value.ContainerRuntime)
	if !status.Valid() || !runtime.Valid() {
		return openapi.ManagedHost{}, hostinventory.ErrInvalid
	}
	capabilities := make([]openapi.HostCapability, len(value.Capabilities))
	for index, capability := range value.Capabilities {
		mapped := openapi.HostCapability{Name: capability.Name, Available: capability.Available}
		if capability.Reason != "" {
			reason := openapi.HostCapabilityReason(capability.Reason)
			if !reason.Valid() {
				return openapi.ManagedHost{}, hostinventory.ErrInvalid
			}
			mapped.Reason = &reason
		}
		capabilities[index] = mapped
	}
	result := openapi.ManagedHost{
		HostId: value.ID, AgentId: value.AgentID, TenantId: value.Scope.TenantID, ProjectId: value.Scope.ProjectID,
		DisplayName: value.DisplayName, Hostname: value.Hostname, OperatingSystem: value.OperatingSystem, Architecture: value.Architecture,
		NetworkAddresses: append([]string(nil), value.NetworkAddresses...), Labels: cloneHostLabels(value.Labels), ContainerRuntime: runtime,
		Capabilities: capabilities, EnrollmentRevision: int64(value.EnrollmentRevision), EnrolledAt: value.EnrolledAt.UTC(), Status: status,
		Etag: entityTag(int64(value.Version)),
	}
	if value.OperatingSystemVersion != "" {
		result.OperatingSystemVersion = stringPointer(value.OperatingSystemVersion)
	}
	if value.KernelVersion != "" {
		result.KernelVersion = stringPointer(value.KernelVersion)
	}
	if value.AgentVersion != "" {
		result.AgentVersion = stringPointer(value.AgentVersion)
	}
	if value.CPU.Capacity != 0 || value.CPU.Available != 0 {
		result.CpuSummary = &openapi.HostResourceSummary{Capacity: int64(value.CPU.Capacity), Available: int64(value.CPU.Available)}
	}
	if value.Memory.Capacity != 0 || value.Memory.Available != 0 {
		result.MemorySummary = &openapi.HostResourceSummary{Capacity: int64(value.Memory.Capacity), Available: int64(value.Memory.Available)}
	}
	if len(value.Filesystems) > 0 {
		filesystems := make([]openapi.FilesystemSummary, len(value.Filesystems))
		for index, filesystem := range value.Filesystems {
			filesystems[index] = openapi.FilesystemSummary{MountPoint: filesystem.MountPoint, CapacityBytes: int64(filesystem.CapacityBytes), AvailableBytes: int64(filesystem.AvailableBytes)}
		}
		result.FilesystemSummary = &filesystems
	}
	if !value.LastHelloAt.IsZero() {
		at := value.LastHelloAt.UTC()
		result.LastHelloAt = &at
	}
	if !value.LastHeartbeatAt.IsZero() {
		at := value.LastHeartbeatAt.UTC()
		result.LastHeartbeatAt = &at
	}
	return result, nil
}

func cloneHostLabels(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for name, value := range values {
		result[name] = value
	}
	return result
}

func stringPointer(value string) *string { return &value }
