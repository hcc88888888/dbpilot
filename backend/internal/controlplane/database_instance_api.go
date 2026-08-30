package controlplane

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/discovery"
)

func (api platformAPI) AcceptDiscoveryCandidate(ctx context.Context, request openapi.AcceptDiscoveryCandidateRequestObject) (openapi.AcceptDiscoveryCandidateResponseObject, error) {
	if api.services.DatabaseInstances == nil || api.services.Discovery == nil {
		return nil, ErrServiceUnavailable
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	revision, err := parseEntityTag(request.Params.IfMatch)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	candidate, err := api.services.Discovery.Get(ctx, scope, request.CandidateId)
	if err != nil {
		return nil, err
	}
	if candidate.Scope != scope || candidate.ID != request.CandidateId || candidate.ObservationRevision != uint64(revision) {
		return nil, ErrPreconditionFailed
	}
	fingerprint, err := platformIdempotencyFingerprint(ctx, "acceptDiscoveryCandidate", request.CandidateId, request.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	endpoint, socket, tlsRef := candidate.NormalizedEndpoint, candidate.UnixSocket, ""
	if request.Body.NormalizedEndpoint != nil {
		endpoint = *request.Body.NormalizedEndpoint
	}
	if request.Body.UnixSocket != nil {
		socket = *request.Body.UnixSocket
	}
	if request.Body.TlsRef != nil {
		tlsRef = *request.Body.TlsRef
	}
	labels := map[string]string{}
	if request.Body.Labels != nil {
		labels = cloneStringMap(*request.Body.Labels)
	}
	value, err := api.services.DatabaseInstances.AcceptCandidate(ctx, scope, request.CandidateId, databaseinstance.AcceptCandidateRequest{
		DisplayName: request.Body.DisplayName, DatabaseFamily: request.Body.DatabaseFamily, DatabaseVariant: request.Body.DatabaseVariant,
		Endpoint: endpoint, UnixSocket: socket, CredentialRef: request.Body.CredentialRef, TLSRef: tlsRef, Labels: labels,
		ExpectedCandidateRevision: uint64(revision), CandidateFingerprint: candidateFingerprintHex(candidate),
		Audit: instanceMutationAudit(ctx, principal, "acceptDiscoveryCandidate", request.Params.IdempotencyKey, fingerprint),
	})
	if err != nil {
		return nil, mapDatabaseInstancePrecondition(err)
	}
	body, err := openAPIManagedDatabaseInstance(value)
	if err != nil {
		return nil, err
	}
	return openapi.AcceptDiscoveryCandidate202JSONResponse{Body: body, Headers: openapi.AcceptDiscoveryCandidate202ResponseHeaders{ETag: entityTag(int64(value.Revision))}}, nil
}

func (api platformAPI) ListDatabaseInstances(ctx context.Context, request openapi.ListDatabaseInstancesRequestObject) (openapi.ListDatabaseInstancesResponseObject, error) {
	if api.services.DatabaseInstances == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := databaseinstance.Filter{}
	if request.Params.HostId != nil {
		filter.HostID = *request.Params.HostId
	}
	if request.Params.DatabaseFamily != nil {
		filter.DatabaseFamily = *request.Params.DatabaseFamily
	}
	if request.Params.Status != nil {
		filter.Status = databaseinstance.ManagementStatus(*request.Params.Status)
	}
	if request.Params.Cursor != nil {
		filter.Cursor = *request.Params.Cursor
	}
	if request.Params.Limit != nil {
		filter.Limit = *request.Params.Limit
	}
	page, err := api.services.DatabaseInstances.List(ctx, scope, filter)
	if err != nil {
		return nil, err
	}
	items := make([]openapi.ManagedDatabaseInstance, len(page.Items))
	for index, value := range page.Items {
		if value.Scope != scope {
			return nil, errors.New("database instance service returned an out-of-scope entity")
		}
		items[index], err = openAPIManagedDatabaseInstance(value)
		if err != nil {
			return nil, err
		}
	}
	limit := filter.Limit
	if limit == 0 {
		limit = databaseinstance.DefaultListLimit
	}
	var next *string
	if page.NextCursor != "" {
		if strings.TrimSpace(page.NextCursor) != page.NextCursor || len(page.NextCursor) > 512 {
			return nil, errors.New("database instance service returned an invalid cursor")
		}
		cursor := page.NextCursor
		next = &cursor
	}
	return openapi.ListDatabaseInstances200JSONResponse{Items: items, Page: openapi.Page{Limit: limit, HasMore: next != nil, NextCursor: next}}, nil
}

func (api platformAPI) GetDatabaseInstance(ctx context.Context, request openapi.GetDatabaseInstanceRequestObject) (openapi.GetDatabaseInstanceResponseObject, error) {
	if api.services.DatabaseInstances == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	value, err := api.services.DatabaseInstances.Get(ctx, scope, request.InstanceId)
	if err != nil {
		return nil, err
	}
	body, err := openAPIManagedDatabaseInstance(value)
	if err != nil {
		return nil, err
	}
	return openapi.GetDatabaseInstance200JSONResponse{Body: body, Headers: openapi.GetDatabaseInstance200ResponseHeaders{ETag: entityTag(int64(value.Revision))}}, nil
}

func (api platformAPI) UpdateDatabaseInstance(ctx context.Context, request openapi.UpdateDatabaseInstanceRequestObject) (openapi.UpdateDatabaseInstanceResponseObject, error) {
	if api.services.DatabaseInstances == nil {
		return nil, ErrServiceUnavailable
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	revision, err := parseEntityTag(request.Params.IfMatch)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	fingerprint, err := platformIdempotencyFingerprint(ctx, "updateDatabaseInstance", request.InstanceId, request.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	update := databaseinstance.Update{DisplayName: request.Body.DisplayName, CredentialRef: request.Body.CredentialRef, TLSRef: request.Body.TlsRef, DesiredPluginVersion: request.Body.DesiredPluginVersion, TemplateProfileID: request.Body.TemplateProfileId, Labels: request.Body.Labels, Audit: instanceMutationAudit(ctx, principal, "updateDatabaseInstance", request.Params.IdempotencyKey, fingerprint)}
	value, err := api.services.DatabaseInstances.Update(ctx, scope, request.InstanceId, uint64(revision), update)
	if err != nil {
		return nil, mapDatabaseInstancePrecondition(err)
	}
	body, err := openAPIManagedDatabaseInstance(value)
	if err != nil {
		return nil, err
	}
	return openapi.UpdateDatabaseInstance200JSONResponse{Body: body, Headers: openapi.UpdateDatabaseInstance200ResponseHeaders{ETag: entityTag(int64(value.Revision))}}, nil
}

func (api platformAPI) RetireDatabaseInstance(ctx context.Context, request openapi.RetireDatabaseInstanceRequestObject) (openapi.RetireDatabaseInstanceResponseObject, error) {
	if api.services.DatabaseInstances == nil {
		return nil, ErrServiceUnavailable
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	revision, err := parseEntityTag(request.Params.IfMatch)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	fingerprint, err := platformIdempotencyFingerprint(ctx, "retireDatabaseInstance", request.InstanceId, request.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	value, err := api.services.DatabaseInstances.Retire(ctx, scope, request.InstanceId, uint64(revision), instanceMutationAudit(ctx, principal, "retireDatabaseInstance", request.Params.IdempotencyKey, fingerprint))
	if err != nil {
		return nil, mapDatabaseInstancePrecondition(err)
	}
	body, err := openAPIManagedDatabaseInstance(value)
	if err != nil {
		return nil, err
	}
	return openapi.RetireDatabaseInstance200JSONResponse{Body: body, Headers: openapi.RetireDatabaseInstance200ResponseHeaders{ETag: entityTag(int64(value.Revision))}}, nil
}

func (api platformAPI) TestDatabaseInstanceConnection(ctx context.Context, request openapi.TestDatabaseInstanceConnectionRequestObject) (openapi.TestDatabaseInstanceConnectionResponseObject, error) {
	if api.services.DatabaseInstances == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	value, err := api.services.DatabaseInstances.Get(ctx, scope, request.InstanceId)
	if err != nil {
		return nil, err
	}
	if value.CapabilityState == databaseinstance.CapabilityPluginNotInstalled || value.PluginID == "" || value.PluginAssignmentRevision == 0 {
		return nil, databaseinstance.ErrPluginMissing
	}
	return nil, ErrServiceUnavailable
}

func instanceMutationAudit(ctx context.Context, principal Principal, operationID, key, fingerprint string) databaseinstance.MutationAudit {
	return databaseinstance.MutationAudit{Actor: principal.Subject, OperationID: operationID, IdempotencyKey: key, RequestFingerprint: fingerprint, RequestID: requestIDFromContext(ctx), TraceID: traceIDFromContext(ctx)}
}

func mapDatabaseInstancePrecondition(err error) error {
	if errors.Is(err, databaseinstance.ErrPrecondition) {
		return ErrPreconditionFailed
	}
	return err
}

func candidateFingerprintHex(value discovery.Candidate) string {
	return hex.EncodeToString(value.Fingerprint[:])
}

func openAPIManagedDatabaseInstance(value databaseinstance.Instance) (openapi.ManagedDatabaseInstance, error) {
	if value.Validate() != nil {
		return openapi.ManagedDatabaseInstance{}, databaseinstance.ErrInvalid
	}
	status := openapi.DatabaseManagementStatus(value.ManagementStatus)
	connection := openapi.ConnectionTestStatus(value.ConnectionTestStatus)
	if !status.Valid() || !connection.Valid() {
		return openapi.ManagedDatabaseInstance{}, databaseinstance.ErrInvalid
	}
	capabilities := append([]string(nil), value.Capabilities...)
	if value.CapabilityState != "" {
		capabilities = append(capabilities, string(value.CapabilityState))
	}
	result := openapi.ManagedDatabaseInstance{InstanceId: value.ID, TenantId: value.Scope.TenantID, ProjectId: value.Scope.ProjectID, HostId: value.HostID, AgentId: value.AgentID, DatabaseFamily: value.DatabaseFamily, DatabaseVariant: value.DatabaseVariant, DisplayName: value.DisplayName, CredentialRef: value.CredentialRef, Labels: cloneStringMap(value.Labels), Capabilities: capabilities, ConnectionTestStatus: connection, PluginAssignmentRevision: int64(value.PluginAssignmentRevision), ManagementStatus: status, Etag: entityTag(int64(value.Revision))}
	if value.Endpoint != "" {
		result.Endpoint = stringPointer(value.Endpoint)
	}
	if value.UnixSocket != "" {
		result.UnixSocket = stringPointer(value.UnixSocket)
	}
	if value.Version != "" {
		result.Version = stringPointer(value.Version)
	}
	if value.Edition != "" {
		result.Edition = stringPointer(value.Edition)
	}
	if value.Role != "" {
		result.Role = stringPointer(value.Role)
	}
	if value.Topology != "" {
		result.Topology = stringPointer(value.Topology)
	}
	if value.TLSRef != "" {
		result.TlsRef = stringPointer(value.TLSRef)
	}
	if value.PluginID != "" {
		result.PluginId = stringPointer(value.PluginID)
	}
	if value.DesiredPluginVersion != "" {
		result.DesiredPluginVersion = stringPointer(value.DesiredPluginVersion)
	}
	if value.TemplateProfileID != "" {
		result.TemplateProfileId = stringPointer(value.TemplateProfileID)
	}
	if value.ConnectionTestAt != nil {
		at := value.ConnectionTestAt.UTC()
		result.ConnectionTestAt = &at
	}
	return result, nil
}
