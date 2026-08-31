package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/pluginassignment"
)

func (api platformAPI) ListPluginAssignments(ctx context.Context, request openapi.ListPluginAssignmentsRequestObject) (openapi.ListPluginAssignmentsResponseObject, error) {
	if api.services.PluginAssignments == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := pluginassignment.Filter{}
	if request.Params.HostId != nil {
		filter.HostID = string(*request.Params.HostId)
	}
	if request.Params.PluginId != nil {
		filter.PluginID = *request.Params.PluginId
	}
	if request.Params.Cursor != nil {
		filter.Cursor = *request.Params.Cursor
	}
	if request.Params.Limit != nil {
		filter.Limit = *request.Params.Limit
	}
	page, err := api.services.PluginAssignments.List(ctx, scope, filter)
	if err != nil {
		return nil, err
	}
	items := make([]openapi.PluginAssignment, len(page.Items))
	for index, value := range page.Items {
		items[index], err = openAPIPluginAssignment(value)
		if err != nil {
			return nil, err
		}
	}
	limit := filter.Limit
	if limit == 0 {
		limit = pluginassignment.DefaultListLimit
	}
	return openapi.ListPluginAssignments200JSONResponse{Items: items, Page: openAPIPage(limit, page.NextCursor != "", page.NextCursor)}, nil
}

func (api platformAPI) GetPluginAssignment(ctx context.Context, request openapi.GetPluginAssignmentRequestObject) (openapi.GetPluginAssignmentResponseObject, error) {
	if api.services.PluginAssignments == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	value, err := api.services.PluginAssignments.Get(ctx, scope, request.AssignmentId)
	if err != nil {
		return nil, err
	}
	body, err := openAPIPluginAssignment(value)
	if err != nil {
		return nil, err
	}
	return openapi.GetPluginAssignment200JSONResponse{Body: body, Headers: openapi.GetPluginAssignment200ResponseHeaders{ETag: value.ETag()}}, nil
}

func (api platformAPI) UpdatePluginAssignment(ctx context.Context, request openapi.UpdatePluginAssignmentRequestObject) (openapi.UpdatePluginAssignmentResponseObject, error) {
	if api.services.PluginAssignments == nil {
		return nil, ErrServiceUnavailable
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	revision, err := parseEntityTag(request.Params.IfMatch)
	if err != nil || revision < 1 {
		return nil, ErrInvalidRequest
	}
	fingerprint, err := platformIdempotencyFingerprint(ctx, "updatePluginAssignment", request.AssignmentId, request.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	update := pluginassignment.DesiredUpdate{Audit: pluginassignment.MutationAudit{Actor: principal.Subject, OperationID: "updatePluginAssignment", IdempotencyKey: request.Params.IdempotencyKey, RequestFingerprint: fingerprint, RequestID: requestIDFromContext(ctx), TraceID: traceIDFromContext(ctx)}}
	if request.Body.DesiredVersion != nil {
		update.DesiredVersion = request.Body.DesiredVersion
	}
	if request.Body.DesiredState != nil {
		state := pluginassignment.DesiredState(*request.Body.DesiredState)
		update.DesiredState = &state
	}
	if request.Body.RolloutPercentage != nil {
		update.RolloutPercentage = request.Body.RolloutPercentage
	}
	value, err := api.services.PluginAssignments.SetDesiredState(ctx, scope, request.AssignmentId, uint64(revision), update)
	if err != nil {
		return nil, err
	}
	body, err := openAPIPluginAssignment(value)
	if err != nil {
		return nil, err
	}
	return openapi.UpdatePluginAssignment200JSONResponse{Body: body, Headers: openapi.UpdatePluginAssignment200ResponseHeaders{ETag: value.ETag()}}, nil
}

func (api platformAPI) ReconcilePluginAssignment(ctx context.Context, request openapi.ReconcilePluginAssignmentRequestObject) (openapi.ReconcilePluginAssignmentResponseObject, error) {
	if api.services.PluginAssignments == nil || api.services.PluginReconciler == nil {
		return nil, ErrServiceUnavailable
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	fingerprint, err := platformIdempotencyFingerprint(ctx, "reconcilePluginAssignment", request.AssignmentId, "")
	if err != nil {
		return nil, err
	}
	audit := pluginassignment.MutationAudit{Actor: principal.Subject, OperationID: "reconcilePluginAssignment", IdempotencyKey: request.Params.IdempotencyKey, RequestFingerprint: fingerprint, RequestID: requestIDFromContext(ctx), TraceID: traceIDFromContext(ctx)}
	assignment, err := api.services.PluginAssignments.ForceReconcile(ctx, scope, request.AssignmentId, audit)
	if err != nil {
		return nil, err
	}
	value, err := api.services.PluginReconciler.ReconcileAssignment(ctx, assignment, api.now())
	if err != nil {
		return nil, err
	}
	body, err := openAPIJob(value)
	if err != nil {
		return nil, err
	}
	location := fmt.Sprintf("/api/v1/tenants/%s/projects/%s/jobs/%s", scope.TenantID, scope.ProjectID, value.ID)
	return openapi.ReconcilePluginAssignment202JSONResponse{Body: body, Headers: openapi.ReconcilePluginAssignment202ResponseHeaders{Location: location}}, nil
}

func openAPIPluginAssignment(value pluginassignment.Assignment) (openapi.PluginAssignment, error) {
	if value.Validate() != nil {
		return openapi.PluginAssignment{}, errors.New("plugin assignment cannot be represented by the platform contract")
	}
	result := openapi.PluginAssignment{AssignmentId: value.ID, HostId: openapi.HostId(value.HostID), AgentId: openapi.AgentId(value.AgentID), PluginId: value.PluginID, DatabaseFamily: openapi.DatabaseFamily(value.DatabaseFamily), DesiredVersion: value.DesiredVersion, DesiredState: openapi.PluginDesiredState(value.DesiredState), ConfigurationRevision: int64(value.ConfigurationRevision), OperationRevision: int64(value.OperationRevision), RolloutPercentage: value.RolloutPercentage, CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(), Etag: value.ETag()}
	if value.Observed != nil {
		observed := value.Observed
		wire := openapi.PluginObservedState{AssignmentId: observed.AssignmentID, ProcessState: openapi.PluginProcessState(observed.ProcessState), Health: openapi.PluginHealthStatus(observed.Health), CircuitState: openapi.PluginCircuitState(observed.CircuitState), RestartCount: int(observed.RestartCount), BoundInstanceCount: int(observed.BoundInstanceCount), ActiveConfigurationRevision: int64(observed.ActiveConfigurationRevision), ObservedOperationRevision: int64(observed.ObservedOperationRevision), ObservedAt: observed.ObservedAt.UTC()}
		if observed.InstalledVersion != "" {
			wire.InstalledVersion = &observed.InstalledVersion
		}
		slot := openapi.PluginActiveSlot(observed.ActiveSlot)
		wire.ActiveSlot = &slot
		if observed.PID > 0 {
			pid := int(observed.PID)
			wire.Pid = &pid
		}
		wire.StartedAt = observed.StartedAt
		if observed.LastErrorCode != "" {
			wire.LastErrorCode = &observed.LastErrorCode
		}
		result.ObservedState = &wire
	}
	return result, nil
}

func (api platformAPI) now() time.Time {
	if api.services.Now != nil {
		return api.services.Now().UTC()
	}
	return time.Now().UTC()
}
