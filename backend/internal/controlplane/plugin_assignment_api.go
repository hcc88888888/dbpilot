package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
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
	if api.services.PluginAssignments == nil || api.services.PluginReconciler == nil || api.services.Idempotency == nil {
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
	key := idempotency.Key{Scope: scope, Actor: principal.Subject, OperationID: "reconcilePluginAssignment", IdempotencyKey: request.Params.IdempotencyKey}
	recovery := reconcilePluginAssignmentRecovery{RequestID: audit.RequestID}
	if metadata, ok := ctx.Value(platformRequestMetadataContextKey{}).(platformRequestMetadata); ok {
		recovery.Instance = metadata.Path
	}
	recoveryJSON, err := json.Marshal(recovery)
	if err != nil {
		return nil, err
	}
	reconcile := func(context.Context, idempotency.Response, []byte) error { return nil }
	run := func(callContext context.Context, responseContext reconcilePluginAssignmentRecovery) (idempotency.Response, error) {
		assignment, err := api.services.PluginAssignments.ForceReconcile(callContext, scope, request.AssignmentId, audit)
		if err != nil {
			return idempotency.Response{}, reconcilePreMutationError{err: err}
		}
		if current, getErr := api.services.PluginAssignments.Get(callContext, scope, request.AssignmentId); getErr == nil && current.OperationRevision == assignment.OperationRevision {
			if cause, ok := durableReconcileProblem(current); ok {
				return storedPluginReconcileProblem(cause, current, responseContext)
			}
		}
		value, err := api.services.PluginReconciler.ReconcileAssignment(callContext, assignment, api.now())
		if err != nil {
			current, getErr := api.services.PluginAssignments.Get(callContext, scope, request.AssignmentId)
			if getErr == nil {
				if cause, ok := durableReconcileProblem(current); ok {
					return storedPluginReconcileProblem(cause, current, responseContext)
				}
			}
			return idempotency.Response{}, err
		}
		return storedPluginReconcileResponse(value, scope)
	}
	begin := func() (idempotency.Claim, error) {
		return api.services.Idempotency.BeginRecoverable(ctx, key, fingerprint, recoveryJSON, reconcile, func(recoveryContext context.Context, processing idempotency.ProcessingClaim) (idempotency.Response, error) {
			var original reconcilePluginAssignmentRecovery
			if err := json.Unmarshal(processing.Reconciliation, &original); err != nil || original.RequestID == "" {
				return idempotency.Response{}, idempotency.ErrInvalid
			}
			stored, runErr := run(recoveryContext, original)
			var before reconcilePreMutationError
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
		var before reconcilePreMutationError
		if errors.As(err, &before) {
			return nil, before.err
		}
		return nil, err
	}
	if claim.Response != nil {
		return reconcilePluginAssignmentIdempotentResponse{response: *claim.Response}, nil
	}
	stored, err := run(ctx, recovery)
	if err != nil {
		var before reconcilePreMutationError
		if errors.As(err, &before) {
			if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, claim.OwnerToken); abortErr != nil {
				return nil, abortErr
			}
			return nil, before.err
		}
		return nil, err
	}
	completed, err := api.services.Idempotency.Complete(ctx, key, fingerprint, claim.OwnerToken, stored, recoveryJSON, reconcile)
	if errors.Is(err, idempotency.ErrOwnershipConflict) {
		for attempt := 0; attempt < 4; attempt++ {
			replayed, replayErr := begin()
			if replayErr == nil && replayed.Response != nil {
				return reconcilePluginAssignmentIdempotentResponse{response: *replayed.Response}, nil
			}
			if !errors.Is(replayErr, idempotency.ErrOwnershipConflict) {
				if replayErr == nil {
					return nil, idempotency.ErrInProgress
				}
				return nil, replayErr
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return reconcilePluginAssignmentIdempotentResponse{response: completed}, nil
}

type reconcilePreMutationError struct{ err error }

func (value reconcilePreMutationError) Error() string { return value.err.Error() }
func (value reconcilePreMutationError) Unwrap() error { return value.err }

type reconcilePluginAssignmentRecovery struct {
	RequestID string `json:"request_id"`
	Instance  string `json:"instance,omitempty"`
}

func storedPluginReconcileProblem(cause error, assignment pluginassignment.Assignment, responseContext reconcilePluginAssignmentRecovery) (idempotency.Response, error) {
	problem := problemForError(cause, responseContext.RequestID, responseContext.Instance)
	reason := assignment.BlockedReason
	if reason == "" {
		if assignment.ReconcileState == pluginassignment.ReconcileConflict {
			reason = "state_conflict"
		} else if assignment.ReconcileState == pluginassignment.ReconcileConverged {
			reason = "already_converged"
		}
	}
	problem.Detail = &reason
	encoded, err := json.Marshal(problem)
	if err != nil {
		return idempotency.Response{}, err
	}
	return idempotency.Response{Status: problem.Status, Header: http.Header{"Content-Type": []string{"application/problem+json"}, "ETag": []string{assignment.ETag()}, "X-Request-ID": []string{problem.RequestId}}, Body: encoded}, nil
}

func durableReconcileProblem(value pluginassignment.Assignment) (error, bool) {
	switch value.ReconcileState {
	case pluginassignment.ReconcileWaiting:
		if value.BlockedReason != "" {
			return pluginassignment.ErrConflict, true
		}
	case pluginassignment.ReconcileBlocked:
		if value.BlockedReason == "version_revoked" {
			return pluginassignment.ErrVersionRevoked, true
		}
		if value.BlockedReason != "" {
			return pluginassignment.ErrConflict, true
		}
	case pluginassignment.ReconcileConflict:
		return pluginassignment.ErrConflict, true
	case pluginassignment.ReconcileConverged:
		return pluginassignment.ErrConflict, true
	}
	return nil, false
}

func storedPluginReconcileResponse(value job.Job, scope platformscope.Scope) (idempotency.Response, error) {
	body, err := openAPIJob(value)
	if err != nil {
		return idempotency.Response{}, err
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return idempotency.Response{}, err
	}
	location := fmt.Sprintf("/api/v1/tenants/%s/projects/%s/jobs/%s", scope.TenantID, scope.ProjectID, value.ID)
	return idempotency.Response{Status: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}, "Location": []string{location}}, Body: encoded}, nil
}

type reconcilePluginAssignmentIdempotentResponse struct{ response idempotency.Response }

func (value reconcilePluginAssignmentIdempotentResponse) VisitReconcilePluginAssignmentResponse(writer http.ResponseWriter) error {
	for key, items := range value.response.Header {
		writer.Header().Del(key)
		for _, item := range items {
			writer.Header().Add(key, item)
		}
	}
	writer.WriteHeader(value.response.Status)
	_, err := writer.Write(value.response.Body)
	return err
}

func openAPIPluginAssignment(value pluginassignment.Assignment) (openapi.PluginAssignment, error) {
	if value.Validate() != nil {
		return openapi.PluginAssignment{}, errors.New("plugin assignment cannot be represented by the platform contract")
	}
	result := openapi.PluginAssignment{AssignmentId: value.ID, HostId: openapi.HostId(value.HostID), AgentId: openapi.AgentId(value.AgentID), PluginId: value.PluginID, DatabaseFamily: openapi.DatabaseFamily(value.DatabaseFamily), DesiredVersion: value.DesiredVersion, DesiredState: openapi.PluginDesiredState(value.DesiredState), ConfigurationRevision: int64(value.ConfigurationRevision), OperationRevision: int64(value.OperationRevision), RolloutPercentage: value.RolloutPercentage, ReconcileState: openapi.PluginReconcileState(value.ReconcileState), CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC(), Etag: value.ETag()}
	if value.BlockedReason != "" {
		result.ReconcileReason = &value.BlockedReason
	}
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
