package controlplane

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/enrollment"
)

func (api platformAPI) CreateHostEnrollment(ctx context.Context, request openapi.CreateHostEnrollmentRequestObject) (openapi.CreateHostEnrollmentResponseObject, error) {
	if api.services.Enrollment == nil {
		return nil, ErrServiceUnavailable
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	labels := map[string]string{}
	if request.Body.Labels != nil {
		labels = cloneHostLabels(*request.Body.Labels)
	}
	created, err := api.services.Enrollment.Create(ctx, scope, enrollment.CreateRequest{
		HostID: request.Body.HostId, AgentID: request.Body.AgentId, DisplayName: request.Body.DisplayName,
		Labels: labels, ExpiresIn: time.Duration(request.Body.ExpiresInSeconds) * time.Second,
		IssuedBy: principal.Subject, IdempotencyKey: request.Params.IdempotencyKey,
	})
	if err != nil {
		return nil, err
	}
	defer clearEnrollmentToken(created.Token)
	if created.HostID != request.Body.HostId || created.AgentID != request.Body.AgentId || len(created.Token) != enrollment.EnrollmentTokenBytes ||
		created.EnrollmentRevision == 0 || created.EnrollmentRevision > math.MaxInt64 || created.ExpiresAt.IsZero() || created.ExpiresAt.Location() != time.UTC {
		return nil, errors.New("enrollment service returned an invalid one-time token")
	}
	return openapi.CreateHostEnrollment201JSONResponse{
		HostId: created.HostID, AgentId: created.AgentID, EnrollmentToken: base64.RawURLEncoding.EncodeToString(created.Token),
		ExpiresAt: created.ExpiresAt, EnrollmentRevision: int64(created.EnrollmentRevision),
	}, nil
}

func clearEnrollmentToken(token []byte) {
	for index := range token {
		token[index] = 0
	}
}
