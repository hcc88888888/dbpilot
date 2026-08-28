package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/inspection"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
)

var (
	ErrInvalidRequest     = errors.New("invalid platform request")
	ErrMethodNotAllowed   = errors.New("platform method is not allowed")
	ErrPreconditionFailed = errors.New("platform precondition failed")
	ErrServiceUnavailable = errors.New("platform service unavailable")
)

type requestIDContextKey struct{}

func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID := validRequestID(request.Header.Values("X-Request-ID"))
		if requestID == "" {
			requestID = newRequestID()
		}
		writer.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(request.Context(), requestIDContextKey{}, requestID)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	return value
}

func validRequestID(values []string) string {
	if len(values) != 1 || !headerIdentifier.MatchString(values[0]) {
		return ""
	}
	return values[0]
}

func newRequestID() string {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "request-unavailable"
	}
	return "request-" + hex.EncodeToString(random)
}

func problemForError(err error, requestID, instance string) openapi.Problem {
	status, code, title := http.StatusInternalServerError, "internal_error", "Internal server error"
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, artifact.ErrInvalid), errors.Is(err, audit.ErrInvalidEvent), errors.Is(err, audit.ErrInvalidCursor), errors.Is(err, platformscope.ErrInvalid), errors.Is(err, inspection.ErrInvalid), errors.Is(err, inspection.ErrInvalidItem), errors.Is(err, inspection.ErrInvalidSchedule), errors.Is(err, inspection.ErrInvalidReport), errors.Is(err, inspection.ErrUnsafeReport), errors.Is(err, inspection.ErrReportTooLarge), errors.Is(err, inspection.ErrUnknownTarget), errors.Is(err, inspection.ErrNoTargets):
		status, code, title = http.StatusBadRequest, "invalid_request", "Request validation failed"
	case errors.Is(err, ErrUnauthenticated):
		status, code, title = http.StatusUnauthorized, "unauthenticated", "Authentication is required"
	case errors.Is(err, ErrForbidden):
		status, code, title = http.StatusForbidden, "forbidden", "Access is forbidden"
	case errors.Is(err, ErrMethodNotAllowed):
		status, code, title = http.StatusMethodNotAllowed, "method_not_allowed", "Method is not allowed"
	case errors.Is(err, job.ErrNotFound), errors.Is(err, artifact.ErrNotFound), errors.Is(err, inspection.ErrNotFound):
		status, code, title = http.StatusNotFound, "not_found", "Resource was not found"
	case errors.Is(err, ErrPreconditionFailed):
		status, code, title = http.StatusPreconditionFailed, "precondition_failed", "Request precondition failed"
	case errors.Is(err, idempotency.ErrKeyConflict):
		status, code, title = http.StatusConflict, "idempotency_conflict", "Idempotency key conflicts with the request"
	case errors.Is(err, idempotency.ErrInProgress):
		status, code, title = http.StatusConflict, "idempotency_in_progress", "Idempotent request is still processing"
	case errors.Is(err, idempotency.ErrOwnershipConflict):
		status, code, title = http.StatusConflict, "idempotency_ownership_conflict", "Idempotency claim ownership changed"
	case errors.Is(err, job.ErrConflict), errors.Is(err, job.ErrInvalidTransition), errors.Is(err, artifact.ErrExpired), errors.Is(err, inspection.ErrConflict), errors.Is(err, inspection.ErrDuplicate), errors.Is(err, inspection.ErrRunNotRetryable):
		status, code, title = http.StatusConflict, "conflict", "Resource state conflicts with the request"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		status, code, title = http.StatusGatewayTimeout, "timeout", "Operation timed out"
	case errors.Is(err, ErrServiceUnavailable):
		status, code, title = http.StatusServiceUnavailable, "unavailable", "Service is unavailable"
	}
	if requestID == "" {
		requestID = newRequestID()
	}
	if !strings.HasPrefix(instance, "/") {
		instance = ""
	}
	var problemInstance *string
	if instance != "" {
		problemInstance = &instance
	}
	return openapi.Problem{
		Type:      "https://dbpilot.local/problems/" + code,
		Title:     title,
		Status:    status,
		Code:      code,
		RequestId: requestID,
		Instance:  problemInstance,
	}
}

func writePlatformProblem(writer http.ResponseWriter, request *http.Request, err error) {
	requestID, instance := "", ""
	if request != nil {
		requestID = requestIDFromContext(request.Context())
		instance = request.URL.EscapedPath()
	}
	problem := problemForError(err, requestID, instance)
	writer.Header().Set("Content-Type", "application/problem+json")
	if errors.Is(err, idempotency.ErrInProgress) {
		writer.Header().Set("Retry-After", "1")
	}
	if requestID != "" {
		writer.Header().Set("X-Request-ID", requestID)
	}
	writer.WriteHeader(problem.Status)
	_ = json.NewEncoder(writer).Encode(problem)
}
