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
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/inspection"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/metrictemplate"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/pluginassignment"
	"dbpilot.local/platform/internal/plugincatalog"
	"dbpilot.local/platform/internal/rediscovery"
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
	case errors.Is(err, rediscovery.ErrHostNotOnline):
		status, code, title = http.StatusConflict, "host_not_online", "Host is not online"
	case errors.Is(err, rediscovery.ErrRediscoveryUnavailable):
		status, code, title = http.StatusUnprocessableEntity, "discovery_unavailable", "Database discovery is unavailable"
	case errors.Is(err, metrictemplate.ErrValidationFailed), errors.Is(err, metrictemplate.ErrDialectRejected):
		status, code, title = http.StatusUnprocessableEntity, "template_validation_failed", "Metric template validation failed"
	case errors.Is(err, metrictemplate.ErrTrialFailed):
		status, code, title = http.StatusUnprocessableEntity, "template_trial_failed", "Metric template trial failed"
	case errors.Is(err, metrictemplate.ErrNotApproved):
		status, code, title = http.StatusUnprocessableEntity, "template_not_approved", "Metric template revision is not approved"
	case errors.Is(err, metrictemplate.ErrIncompatible):
		status, code, title = http.StatusUnprocessableEntity, "template_incompatible", "Metric template is incompatible with the selected plugin"
	case errors.Is(err, metrictemplate.ErrSelfApproval):
		status, code, title = http.StatusForbidden, "template_self_approval_forbidden", "Metric template creator cannot approve this revision"
	case errors.Is(err, metrictemplate.ErrPrecondition):
		status, code, title = http.StatusPreconditionFailed, "state_revision_conflict", "Resource revision conflicts with the request"
	case errors.Is(err, metrictemplate.ErrCapacity):
		status, code, title = http.StatusUnprocessableEntity, "template_capacity", "Metric template publication capacity is exceeded"
	case errors.Is(err, databaseinstance.ErrPluginMissing):
		status, code, title = http.StatusUnprocessableEntity, "plugin_not_installed", "Database plugin is not installed"
	case errors.Is(err, plugincatalog.ErrManifestRejected):
		status, code, title = http.StatusUnprocessableEntity, "plugin_manifest_rejected", "Plugin manifest was rejected"
	case errors.Is(err, plugincatalog.ErrSignatureRejected), errors.Is(err, plugincatalog.ErrUnknownPublisher):
		status, code, title = http.StatusUnprocessableEntity, "plugin_signature_rejected", "Plugin signature was rejected"
	case errors.Is(err, plugincatalog.ErrPlatformMismatch):
		status, code, title = http.StatusUnprocessableEntity, "plugin_platform_mismatch", "Plugin platform is unsupported"
	case errors.Is(err, plugincatalog.ErrArtifactUnavailable):
		status, code, title = http.StatusServiceUnavailable, "plugin_artifact_unavailable", "Plugin artifact is unavailable"
	case errors.Is(err, discovery.ErrStaleRevision):
		status, code, title = http.StatusConflict, "candidate_stale", "Discovery report revision is stale"
	case errors.Is(err, plugincatalog.ErrRevisionConflict):
		status, code, title = http.StatusPreconditionFailed, "state_revision_conflict", "Resource revision conflicts with the request"
	case errors.Is(err, pluginassignment.ErrPrecondition):
		status, code, title = http.StatusPreconditionFailed, "state_revision_conflict", "Resource revision conflicts with the request"
	case errors.Is(err, pluginassignment.ErrVersionUnavailable):
		status, code, title = http.StatusUnprocessableEntity, "plugin_version_unavailable", "Plugin version is unavailable"
	case errors.Is(err, pluginassignment.ErrPlatformMismatch):
		status, code, title = http.StatusUnprocessableEntity, "plugin_platform_mismatch", "Plugin platform is unsupported"
	case errors.Is(err, pluginassignment.ErrVersionRevoked):
		status, code, title = http.StatusConflict, "plugin_version_revoked", "Plugin version is revoked"
	case errors.Is(err, pluginassignment.ErrCapacity):
		status, code, title = http.StatusUnprocessableEntity, "plugin_assignment_capacity", "Plugin assignment capacity is exceeded"
	case errors.Is(err, plugincatalog.ErrPackageTooLarge):
		status, code, title = http.StatusUnprocessableEntity, "plugin_manifest_rejected", "Plugin package exceeds verification limits"
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, rediscovery.ErrInvalid), errors.Is(err, metrictemplate.ErrInvalid), errors.Is(err, databaseinstance.ErrInvalid), errors.Is(err, artifact.ErrInvalid), errors.Is(err, audit.ErrInvalidEvent), errors.Is(err, audit.ErrInvalidCursor), errors.Is(err, enrollment.ErrEnrollmentRequestInvalid), errors.Is(err, hostinventory.ErrInvalid), errors.Is(err, discovery.ErrInvalid), errors.Is(err, discovery.ErrSecretEvidence), errors.Is(err, platformscope.ErrInvalid), errors.Is(err, inspection.ErrInvalid), errors.Is(err, inspection.ErrInvalidItem), errors.Is(err, inspection.ErrInvalidSchedule), errors.Is(err, inspection.ErrInvalidReport), errors.Is(err, inspection.ErrUnsafeReport), errors.Is(err, inspection.ErrReportTooLarge), errors.Is(err, inspection.ErrUnknownTarget), errors.Is(err, inspection.ErrNoTargets), errors.Is(err, plugincatalog.ErrInvalid), errors.Is(err, pluginassignment.ErrInvalid):
		status, code, title = http.StatusBadRequest, "invalid_request", "Request validation failed"
	case errors.Is(err, inspection.ErrReportBudgetExceeded), errors.Is(err, inspection.ErrReportBudgetOverflow):
		status, code, title = http.StatusUnprocessableEntity, "inspection_report_budget_exceeded", "Inspection run exceeds report limits"
	case errors.Is(err, ErrUnauthenticated):
		status, code, title = http.StatusUnauthorized, "unauthenticated", "Authentication is required"
	case errors.Is(err, ErrForbidden):
		status, code, title = http.StatusForbidden, "forbidden", "Access is forbidden"
	case errors.Is(err, ErrMethodNotAllowed):
		status, code, title = http.StatusMethodNotAllowed, "method_not_allowed", "Method is not allowed"
	case errors.Is(err, metrictemplate.ErrNotFound), errors.Is(err, databaseinstance.ErrNotFound), errors.Is(err, job.ErrNotFound), errors.Is(err, artifact.ErrNotFound), errors.Is(err, enrollment.ErrEnrollmentNotFound), errors.Is(err, hostinventory.ErrNotFound), errors.Is(err, discovery.ErrNotFound), errors.Is(err, inspection.ErrNotFound), errors.Is(err, plugincatalog.ErrNotFound), errors.Is(err, pluginassignment.ErrNotFound):
		status, code, title = http.StatusNotFound, "not_found", "Resource was not found"
	case errors.Is(err, ErrPreconditionFailed):
		status, code, title = http.StatusPreconditionFailed, "precondition_failed", "Request precondition failed"
	case errors.Is(err, ErrEnrollmentTokenNotReplayable):
		status, code, title = http.StatusConflict, "enrollment_token_not_replayable", "One-time enrollment token delivery cannot be replayed"
	case errors.Is(err, idempotency.ErrKeyConflict), errors.Is(err, inspection.ErrIdempotencyConflict):
		status, code, title = http.StatusConflict, "idempotency_conflict", "Idempotency key conflicts with the request"
	case errors.Is(err, idempotency.ErrInProgress):
		status, code, title = http.StatusConflict, "idempotency_in_progress", "Idempotent request is still processing"
	case errors.Is(err, idempotency.ErrOwnershipConflict):
		status, code, title = http.StatusConflict, "idempotency_ownership_conflict", "Idempotency claim ownership changed"
	case errors.Is(err, metrictemplate.ErrConflict), errors.Is(err, metrictemplate.ErrInvalidTransition), errors.Is(err, databaseinstance.ErrConflict), errors.Is(err, job.ErrConflict), errors.Is(err, job.ErrInvalidTransition), errors.Is(err, artifact.ErrExpired), errors.Is(err, enrollment.ErrEnrollmentConflict), errors.Is(err, enrollment.ErrEnrollmentGenerationConflict), errors.Is(err, hostinventory.ErrConflict), errors.Is(err, discovery.ErrConflict), errors.Is(err, inspection.ErrConflict), errors.Is(err, inspection.ErrDuplicate), errors.Is(err, inspection.ErrRunNotRetryable), errors.Is(err, plugincatalog.ErrConflict), errors.Is(err, pluginassignment.ErrConflict), errors.Is(err, pluginassignment.ErrClaimLost), errors.Is(err, pluginassignment.ErrStaleObservation):
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
