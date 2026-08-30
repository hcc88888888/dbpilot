package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/idempotency"
)

func (api platformAPI) CreateHostEnrollment(ctx context.Context, request openapi.CreateHostEnrollmentRequestObject) (openapi.CreateHostEnrollmentResponseObject, error) {
	if api.services.Enrollment == nil || api.services.Idempotency == nil || api.services.Audit == nil {
		return nil, ErrServiceUnavailable
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	key := idempotency.Key{Scope: scope, Actor: principal.Subject, OperationID: "createHostEnrollment", IdempotencyKey: request.Params.IdempotencyKey}
	fingerprint, err := platformIdempotencyFingerprint(ctx, key.OperationID, request.Body.HostId, "")
	if err != nil {
		return nil, err
	}
	auditPayload, reconcile, err := httpActionAuditReconciliation(ctx, api.services.Audit, scope, principal, "host.enrollment_created", "host", request.Body.HostId, "success", key.OperationID, key.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	claim, err := api.services.Idempotency.Begin(ctx, key, fingerprint, reconcile)
	if err != nil {
		return nil, err
	}
	replacing := claim.Response != nil
	labels := map[string]string{}
	if request.Body.Labels != nil {
		labels = cloneHostLabels(*request.Body.Labels)
	}
	created, err := api.services.Enrollment.Create(ctx, scope, enrollment.CreateRequest{
		HostID: request.Body.HostId, AgentID: request.Body.AgentId, DisplayName: request.Body.DisplayName,
		Labels: labels, ExpiresIn: time.Duration(request.Body.ExpiresInSeconds) * time.Second,
		IssuedBy: principal.Subject, IdempotencyKey: request.Params.IdempotencyKey, RequestFingerprint: fingerprint,
	})
	if err != nil {
		if !replacing {
			if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, claim.OwnerToken); abortErr != nil {
				return nil, abortErr
			}
		}
		return nil, err
	}
	defer clearEnrollmentToken(created.Token)
	if created.HostID != request.Body.HostId || created.AgentID != request.Body.AgentId || len(created.Token) != enrollment.EnrollmentTokenBytes ||
		created.EnrollmentRevision == 0 || created.EnrollmentRevision > math.MaxInt64 || created.Generation == 0 || created.ExpiresAt.IsZero() || created.ExpiresAt.Location() != time.UTC || created.Replaced != replacing {
		return nil, errors.New("enrollment service returned an invalid one-time token")
	}
	if replacing {
		replacementOperation := key.OperationID + ".replacement." + stringGeneration(created.Generation)
		event := httpActionAuditEvent(ctx, scope, principal, "host.enrollment_replaced", "host", created.HostID, "success", replacementOperation, key.IdempotencyKey)
		if _, err := api.services.Audit.RecordOnce(ctx, event); err != nil {
			return nil, err
		}
	} else {
		markerBody, err := json.Marshal(map[string]any{
			"host_id": created.HostID, "agent_id": created.AgentID, "enrollment_revision": created.EnrollmentRevision,
			"generation": created.Generation, "token_persisted": false,
		})
		if err != nil {
			return nil, err
		}
		marker := idempotency.Response{Status: http.StatusCreated, Header: make(http.Header), Body: markerBody}
		marker.Header.Set("Content-Type", "application/json")
		if _, err := api.services.Idempotency.Complete(ctx, key, fingerprint, claim.OwnerToken, marker, auditPayload, reconcile); err != nil {
			return nil, err
		}
	}
	return openapi.CreateHostEnrollment201JSONResponse{
		HostId: created.HostID, AgentId: created.AgentID, EnrollmentToken: base64.RawURLEncoding.EncodeToString(created.Token),
		ExpiresAt: created.ExpiresAt, EnrollmentRevision: int64(created.EnrollmentRevision),
	}, nil
}

func stringGeneration(value uint64) string {
	return strconv.FormatUint(value, 10)
}

func clearEnrollmentToken(token []byte) {
	for index := range token {
		token[index] = 0
	}
}
