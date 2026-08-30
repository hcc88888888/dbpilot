package controlplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"reflect"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/idempotency"
)

var ErrEnrollmentTokenNotReplayable = errors.New("one-time enrollment token delivery cannot be replayed")

type enrollmentDeliveryMarker struct {
	HostID             string `json:"host_id"`
	AgentID            string `json:"agent_id"`
	EnrollmentRevision uint64 `json:"enrollment_revision"`
	Generation         uint64 `json:"generation"`
	TokenPersisted     bool   `json:"token_persisted"`
}

type enrollmentRecoveryPayload struct {
	HostID             string            `json:"host_id"`
	AgentID            string            `json:"agent_id"`
	DisplayName        string            `json:"display_name"`
	Labels             map[string]string `json:"labels"`
	ExpiresInSeconds   int               `json:"expires_in_seconds"`
	Actor              string            `json:"actor"`
	RequestID          string            `json:"request_id"`
	TraceID            string            `json:"trace_id,omitempty"`
	IdempotencyKey     string            `json:"idempotency_key"`
	RequestFingerprint string            `json:"request_fingerprint"`
}

func (api platformAPI) CreateHostEnrollment(ctx context.Context, request openapi.CreateHostEnrollmentRequestObject) (openapi.CreateHostEnrollmentResponseObject, error) {
	if api.services.Enrollment == nil || api.services.Idempotency == nil {
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
	payload := enrollmentRecoveryPayload{
		HostID: request.Body.HostId, AgentID: request.Body.AgentId, DisplayName: request.Body.DisplayName,
		Labels: enrollmentLabels(request.Body.Labels), ExpiresInSeconds: request.Body.ExpiresInSeconds,
		Actor: principal.Subject, RequestID: requestIDFromContext(ctx), TraceID: traceIDFromContext(ctx),
		IdempotencyKey: key.IdempotencyKey, RequestFingerprint: fingerprint,
	}
	reconciliation, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var recovered *enrollment.CreatedEnrollment
	claim, err := api.services.Idempotency.BeginUnreturnedRecoverable(ctx, key, fingerprint, reconciliation, validateEnrollmentRecovery(payload), func(recoveryContext context.Context, processing idempotency.ProcessingClaim) (idempotency.Response, error) {
		var stored enrollmentRecoveryPayload
		if json.Unmarshal(processing.Reconciliation, &stored) != nil || !sameEnrollmentRecoveryRequest(stored, payload) {
			return idempotency.Response{}, errors.New("stored enrollment recovery payload is invalid")
		}
		request := enrollmentCreateRequest(stored, "createHostEnrollment.recovery")
		expectedGeneration := uint64(1)
		if processing.Response != nil {
			marker, markerErr := decodeEnrollmentMarker(*processing.Response)
			if markerErr != nil {
				return idempotency.Response{}, markerErr
			}
			expectedGeneration = marker.Generation
		}
		created, replaceErr := api.services.Enrollment.Replace(recoveryContext, scope, request, expectedGeneration)
		if errors.Is(replaceErr, enrollment.ErrEnrollmentNotFound) {
			created, replaceErr = api.services.Enrollment.Create(recoveryContext, scope, request)
		}
		if replaceErr != nil {
			return idempotency.Response{}, replaceErr
		}
		recovered = &created
		return enrollmentMarkerResponse(created)
	})
	if err != nil {
		return nil, err
	}
	if claim.Response != nil {
		marker, markerErr := decodeEnrollmentMarker(*claim.Response)
		if markerErr != nil {
			return nil, markerErr
		}
		if recovered == nil {
			problem := problemForError(ErrEnrollmentTokenNotReplayable, requestIDFromContext(ctx), "")
			etag := entityTag(int64(marker.Generation))
			return openapi.CreateHostEnrollment409ApplicationProblemPlusJSONResponse{
				Body: problem, Headers: openapi.CreateHostEnrollment409ResponseHeaders{ETag: &etag},
			}, nil
		}
		return createEnrollmentResponse(*recovered)
	}
	created, err := api.services.Enrollment.Create(ctx, scope, enrollmentCreateRequest(payload, key.OperationID))
	if err != nil {
		if abortErr := api.services.Idempotency.Abort(ctx, key, fingerprint, claim.OwnerToken); abortErr != nil {
			return nil, abortErr
		}
		return nil, err
	}
	defer clearEnrollmentToken(created.Token)
	marker, err := enrollmentMarkerResponse(created)
	if err != nil {
		return nil, err
	}
	if _, err := api.services.Idempotency.Complete(ctx, key, fingerprint, claim.OwnerToken, marker, reconciliation, validateEnrollmentRecovery(payload)); err != nil {
		return nil, err
	}
	return createEnrollmentResponse(created)
}

func (api platformAPI) ReplaceHostEnrollment(ctx context.Context, request openapi.ReplaceHostEnrollmentRequestObject) (openapi.ReplaceHostEnrollmentResponseObject, error) {
	if api.services.Enrollment == nil || api.services.Idempotency == nil {
		return nil, ErrServiceUnavailable
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	expected, err := parseEntityTag(request.Params.IfMatch)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	key := idempotency.Key{Scope: scope, Actor: principal.Subject, OperationID: "replaceHostEnrollment", IdempotencyKey: request.Params.IdempotencyKey}
	fingerprint, err := platformIdempotencyFingerprint(ctx, key.OperationID, request.HostId, request.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	payload := enrollmentRecoveryPayload{
		HostID: request.HostId, AgentID: request.Body.AgentId, DisplayName: request.Body.DisplayName,
		Labels: enrollmentLabels(request.Body.Labels), ExpiresInSeconds: request.Body.ExpiresInSeconds,
		Actor: principal.Subject, RequestID: requestIDFromContext(ctx), TraceID: traceIDFromContext(ctx),
		IdempotencyKey: key.IdempotencyKey, RequestFingerprint: fingerprint,
	}
	reconciliation, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	claim, err := api.services.Idempotency.Begin(ctx, key, fingerprint, validateEnrollmentRecovery(payload))
	if err != nil {
		return nil, err
	}
	if claim.Response != nil {
		return nil, ErrEnrollmentTokenNotReplayable
	}
	created, err := api.services.Enrollment.Replace(ctx, scope, enrollmentCreateRequest(payload, key.OperationID), uint64(expected))
	if errors.Is(err, enrollment.ErrEnrollmentGenerationConflict) {
		_ = api.services.Idempotency.Abort(ctx, key, fingerprint, claim.OwnerToken)
		return nil, ErrPreconditionFailed
	}
	if err != nil {
		_ = api.services.Idempotency.Abort(ctx, key, fingerprint, claim.OwnerToken)
		return nil, err
	}
	defer clearEnrollmentToken(created.Token)
	marker, err := enrollmentMarkerResponse(created)
	if err != nil {
		return nil, err
	}
	if _, err := api.services.Idempotency.Complete(ctx, key, fingerprint, claim.OwnerToken, marker, reconciliation, validateEnrollmentRecovery(payload)); err != nil {
		return nil, err
	}
	body, err := enrollmentContract(created)
	if err != nil {
		return nil, err
	}
	return openapi.ReplaceHostEnrollment201JSONResponse{
		Body: body, Headers: openapi.ReplaceHostEnrollment201ResponseHeaders{ETag: entityTag(int64(created.Generation))},
	}, nil
}

func enrollmentCreateRequest(payload enrollmentRecoveryPayload, operationID string) enrollment.CreateRequest {
	return enrollment.CreateRequest{
		HostID: payload.HostID, AgentID: payload.AgentID, DisplayName: payload.DisplayName, Labels: cloneHostLabels(payload.Labels),
		ExpiresIn: time.Duration(payload.ExpiresInSeconds) * time.Second, IssuedBy: payload.Actor,
		IdempotencyKey: payload.IdempotencyKey, RequestFingerprint: payload.RequestFingerprint,
		Audit: enrollment.EnrollmentAudit{
			Actor: payload.Actor, RequestID: payload.RequestID, TraceID: payload.TraceID,
			OperationID: operationID, IdempotencyKey: payload.IdempotencyKey,
		},
	}
}

func enrollmentLabels(labels *map[string]string) map[string]string {
	if labels == nil {
		return map[string]string{}
	}
	return cloneHostLabels(*labels)
}

func validateEnrollmentRecovery(expected enrollmentRecoveryPayload) idempotency.ReconcileFunc {
	return func(_ context.Context, _ idempotency.Response, stored []byte) error {
		var decoded enrollmentRecoveryPayload
		if json.Unmarshal(stored, &decoded) != nil || !sameEnrollmentRecoveryRequest(decoded, expected) {
			return errors.New("stored enrollment recovery payload is invalid")
		}
		return nil
	}
}

func sameEnrollmentRecoveryRequest(stored, expected enrollmentRecoveryPayload) bool {
	return stored.HostID == expected.HostID && stored.AgentID == expected.AgentID && stored.DisplayName == expected.DisplayName &&
		reflect.DeepEqual(stored.Labels, expected.Labels) && stored.ExpiresInSeconds == expected.ExpiresInSeconds &&
		stored.Actor == expected.Actor && stored.IdempotencyKey == expected.IdempotencyKey && stored.RequestFingerprint == expected.RequestFingerprint &&
		canonicalAuditIdentity(stored.RequestID) && (stored.TraceID == "" || canonicalAuditIdentity(stored.TraceID))
}

func enrollmentMarkerResponse(created enrollment.CreatedEnrollment) (idempotency.Response, error) {
	if err := validateCreatedEnrollment(created); err != nil {
		return idempotency.Response{}, err
	}
	body, err := json.Marshal(enrollmentDeliveryMarker{
		HostID: created.HostID, AgentID: created.AgentID, EnrollmentRevision: created.EnrollmentRevision,
		Generation: created.Generation, TokenPersisted: false,
	})
	if err != nil {
		return idempotency.Response{}, err
	}
	response := idempotency.Response{Status: http.StatusCreated, Header: make(http.Header), Body: body}
	response.Header.Set("Content-Type", "application/json")
	return response, nil
}

func decodeEnrollmentMarker(response idempotency.Response) (enrollmentDeliveryMarker, error) {
	var marker enrollmentDeliveryMarker
	if response.Status != http.StatusCreated || json.Unmarshal(response.Body, &marker) != nil || marker.HostID == "" || marker.AgentID == "" || marker.EnrollmentRevision == 0 || marker.Generation == 0 || marker.TokenPersisted {
		return enrollmentDeliveryMarker{}, errors.New("stored enrollment delivery marker is invalid")
	}
	return marker, nil
}

func createEnrollmentResponse(created enrollment.CreatedEnrollment) (openapi.CreateHostEnrollmentResponseObject, error) {
	body, err := enrollmentContract(created)
	if err != nil {
		return nil, err
	}
	return openapi.CreateHostEnrollment201JSONResponse(body), nil
}

func enrollmentContract(created enrollment.CreatedEnrollment) (openapi.HostEnrollment, error) {
	if err := validateCreatedEnrollment(created); err != nil {
		return openapi.HostEnrollment{}, err
	}
	return openapi.HostEnrollment{
		HostId: created.HostID, AgentId: created.AgentID, EnrollmentToken: base64.RawURLEncoding.EncodeToString(created.Token),
		ExpiresAt: created.ExpiresAt, EnrollmentRevision: int64(created.EnrollmentRevision), Generation: int64(created.Generation),
	}, nil
}

func validateCreatedEnrollment(created enrollment.CreatedEnrollment) error {
	if created.HostID == "" || created.AgentID == "" || len(created.Token) != enrollment.EnrollmentTokenBytes || created.EnrollmentRevision == 0 || created.EnrollmentRevision > math.MaxInt64 || created.Generation == 0 || created.Generation > math.MaxInt64 || created.ExpiresAt.IsZero() || created.ExpiresAt.Location() != time.UTC {
		return errors.New("enrollment service returned an invalid one-time token")
	}
	return nil
}

func clearEnrollmentToken(token []byte) {
	for index := range token {
		token[index] = 0
	}
}
