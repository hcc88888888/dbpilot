package controlplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/platformscope"
)

func (api platformAPI) ListDiscoveryCandidates(ctx context.Context, request openapi.ListDiscoveryCandidatesRequestObject) (openapi.ListDiscoveryCandidatesResponseObject, error) {
	if api.services.Discovery == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := discovery.Filter{}
	if request.Params.HostId != nil {
		filter.HostID = *request.Params.HostId
	}
	if request.Params.Status != nil {
		filter.Status = discovery.Status(*request.Params.Status)
	}
	if request.Params.Source != nil {
		filter.Source = discovery.Source(*request.Params.Source)
	}
	if request.Params.DatabaseFamily != nil {
		filter.DatabaseFamily = *request.Params.DatabaseFamily
	}
	if request.Params.Cursor != nil {
		filter.Cursor = *request.Params.Cursor
	}
	if request.Params.Limit != nil {
		filter.Limit = *request.Params.Limit
	}
	page, err := api.services.Discovery.List(ctx, scope, filter)
	if err != nil {
		return nil, err
	}
	items := make([]openapi.DiscoveryCandidate, len(page.Items))
	for index, value := range page.Items {
		if value.Scope != scope {
			return nil, errors.New("discovery service returned an out-of-scope entity")
		}
		items[index], err = openAPIDiscoveryCandidate(value)
		if err != nil {
			return nil, err
		}
	}
	limit := filter.Limit
	if limit == 0 {
		limit = discovery.DefaultListLimit
	}
	var next *string
	if page.NextCursor != "" {
		if strings.TrimSpace(page.NextCursor) != page.NextCursor || len(page.NextCursor) > 512 {
			return nil, errors.New("discovery service returned an invalid cursor")
		}
		next = &page.NextCursor
	}
	return openapi.ListDiscoveryCandidates200JSONResponse{Items: items, Page: openapi.Page{Limit: limit, HasMore: next != nil, NextCursor: next}}, nil
}

func (api platformAPI) GetDiscoveryCandidate(ctx context.Context, request openapi.GetDiscoveryCandidateRequestObject) (openapi.GetDiscoveryCandidateResponseObject, error) {
	if api.services.Discovery == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	value, err := api.services.Discovery.Get(ctx, scope, request.CandidateId)
	if err != nil {
		return nil, err
	}
	body, err := openAPIDiscoveryCandidate(value)
	if err != nil {
		return nil, err
	}
	return openapi.GetDiscoveryCandidate200JSONResponse(body), nil
}

func (api platformAPI) IgnoreDiscoveryCandidate(ctx context.Context, request openapi.IgnoreDiscoveryCandidateRequestObject) (openapi.IgnoreDiscoveryCandidateResponseObject, error) {
	if api.services.Discovery == nil || api.services.Idempotency == nil || api.services.Audit == nil {
		return nil, ErrServiceUnavailable
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	reason := request.Body.ReasonCode
	key := idempotency.Key{Scope: scope, Actor: principal.Subject, OperationID: "ignoreDiscoveryCandidate", IdempotencyKey: request.Params.IdempotencyKey}
	fingerprint, err := platformIdempotencyFingerprint(ctx, key.OperationID, request.CandidateId, "")
	if err != nil {
		return nil, err
	}
	auditPayload, reconcile, err := httpActionAuditReconciliation(ctx, api.services.Audit, scope, principal, "discovery.candidate_ignored", "discovery_candidate", request.CandidateId, "success", key.OperationID, key.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	claim, err := api.services.Idempotency.BeginRecoverable(ctx, key, fingerprint, auditPayload, reconcile, func(recoveryContext context.Context, _ idempotency.ProcessingClaim) (idempotency.Response, error) {
		current, getErr := api.services.Discovery.Get(recoveryContext, scope, request.CandidateId)
		if getErr != nil {
			return idempotency.Response{}, getErr
		}
		if current.Status != discovery.StatusIgnored || current.IgnoreReason != reason {
			return idempotency.Response{}, idempotency.ErrInProgress
		}
		return storedDiscoveryResponse(current)
	})
	if err != nil {
		return nil, err
	}
	if claim.Response != nil {
		return discoveryIdempotentResponse{response: *claim.Response}, nil
	}
	value, err := api.services.Discovery.Ignore(ctx, scope, request.CandidateId, reason)
	if err != nil {
		if errors.Is(err, discovery.ErrNotFound) || errors.Is(err, discovery.ErrConflict) {
			if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, claim.OwnerToken); abortErr != nil {
				return nil, abortErr
			}
		}
		return nil, err
	}
	stored, err := storedDiscoveryResponse(value)
	if err != nil {
		return nil, err
	}
	completed, err := api.services.Idempotency.Complete(ctx, key, fingerprint, claim.OwnerToken, stored, auditPayload, reconcile)
	if err != nil {
		return nil, err
	}
	return discoveryIdempotentResponse{response: completed}, nil
}

type discoveryIdempotentResponse struct{ response idempotency.Response }

func (response discoveryIdempotentResponse) VisitIgnoreDiscoveryCandidateResponse(writer http.ResponseWriter) error {
	return writeIdempotencyResponse(writer, response.response)
}
func storedDiscoveryResponse(value discovery.Candidate) (idempotency.Response, error) {
	body, err := openAPIDiscoveryCandidate(value)
	if err != nil {
		return idempotency.Response{}, err
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return idempotency.Response{}, err
	}
	response := idempotency.Response{Status: http.StatusOK, Header: make(http.Header), Body: encoded}
	response.Header.Set("Content-Type", "application/json")
	return response, nil
}

func openAPIDiscoveryCandidate(value discovery.Candidate) (openapi.DiscoveryCandidate, error) {
	if value.Validate() != nil {
		return openapi.DiscoveryCandidate{}, discovery.ErrInvalid
	}
	evidence := make([]openapi.DiscoveryEvidence, len(value.Evidence))
	for index, item := range value.Evidence {
		kind := openapi.DiscoveryEvidenceKind(item.Kind)
		if !kind.Valid() {
			return openapi.DiscoveryCandidate{}, discovery.ErrInvalid
		}
		evidence[index] = openapi.DiscoveryEvidence{Kind: kind, Value: item.Value}
	}
	result := openapi.DiscoveryCandidate{CandidateId: value.ID, TenantId: value.Scope.TenantID, ProjectId: value.Scope.ProjectID, HostId: value.HostID, AgentId: value.AgentID, DiscoverySource: openapi.DiscoverySource(value.Source), DatabaseFamily: value.DatabaseFamily, DatabaseVariant: value.DatabaseVariant, Confidence: float32(value.Confidence), EvidenceSummary: evidence, Fingerprint: hex.EncodeToString(value.Fingerprint[:]), RuleRevision: int64(value.RuleRevision), ObservationRevision: int64(value.ObservationRevision), FirstSeenAt: value.FirstSeenAt.UTC(), LastSeenAt: value.LastSeenAt.UTC(), Status: openapi.DiscoveryCandidateStatus(value.Status), Etag: entityTag(int64(value.ObservationRevision))}
	if value.VersionHint != "" {
		result.VersionHint = stringPointer(value.VersionHint)
	}
	if value.NormalizedEndpoint != "" {
		result.NormalizedEndpoint = stringPointer(value.NormalizedEndpoint)
	}
	if value.UnixSocket != "" {
		result.UnixSocket = stringPointer(value.UnixSocket)
	}
	if value.ProcessIdentity != "" {
		result.ProcessIdentity = stringPointer(value.ProcessIdentity)
	}
	if value.ServiceName != "" {
		result.ServiceName = stringPointer(value.ServiceName)
	}
	if value.ContainerIdentity != "" {
		result.ContainerIdentity = stringPointer(value.ContainerIdentity)
	}
	if value.ContainerImage != "" {
		result.ContainerImage = stringPointer(value.ContainerImage)
	}
	if value.DiscoveredRole != "" {
		result.DiscoveredRole = stringPointer(value.DiscoveredRole)
	}
	return result, nil
}

var _ = platformscope.Scope{}
