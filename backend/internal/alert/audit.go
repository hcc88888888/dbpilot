package alert

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

const RedactedValue = "[REDACTED]"

var (
	ErrInvalidAuditRecord = errors.New("invalid audit record")
	ErrMissingAuditActor  = errors.New("trusted audit actor is required")
)

type auditActorContextKey struct{}

// ContextWithAuditActor attaches the authenticated subject at the service
// boundary. Repository methods reject configuration writes without it.
func ContextWithAuditActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, auditActorContextKey{}, actor)
}

func auditActorFromContext(ctx context.Context) (string, error) {
	actor, _ := ctx.Value(auditActorContextKey{}).(string)
	if strings.TrimSpace(actor) == "" || actor != strings.TrimSpace(actor) {
		return "", ErrMissingAuditActor
	}
	return actor, nil
}

// AuditWriter is the append-only persistence boundary used by control-plane
// actions. Implementations must not update or delete previously written rows.
type AuditWriter interface {
	AppendAudit(context.Context, AuditRecord) error
}

// MarshalJSON applies the same denylist as persistence so an invalid record
// cannot leak secret-bearing detail fields through logs or API responses.
func (record AuditRecord) MarshalJSON() ([]byte, error) {
	type auditRecordJSON AuditRecord
	sanitized := sanitizeAuditRecord(record)
	return json.Marshal(auditRecordJSON(sanitized))
}

func (record AuditRecord) Validate() error {
	if record.Scope.Validate() != nil || strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.Actor) == "" || !allowedAuditAction(record.Action) || strings.TrimSpace(record.TargetID) == "" || record.OccurredAt.IsZero() {
		return ErrInvalidAuditRecord
	}
	sanitized := sanitizeAuditDetails(record.Action, record.Details)
	if len(sanitized) != len(record.Details) {
		return ErrInvalidAuditRecord
	}
	for key, value := range record.Details {
		if sanitized[key] != value {
			return ErrInvalidAuditRecord
		}
	}
	return nil
}

func allowedAuditAction(action string) bool {
	switch action {
	case "rule.created", "rule.updated", "event.pending", "event.firing", "event.acknowledged", "event.resolved", "evaluation.failed", "policy.created", "policy.updated", "template.created", "template.updated", "silence.created", "silence.updated", "silence.deleted", "delivery.suppressed", "delivery.delivered", "delivery.retrying", "delivery.retry_scheduled", "delivery.abandoned":
		return true
	default:
		return false
	}
}

func sanitizeDetails(details map[string]string) map[string]string {
	if details == nil {
		return map[string]string{}
	}
	sanitized := make(map[string]string, len(details))
	for key, value := range details {
		if sensitiveField(key) {
			sanitized[key] = RedactedValue
		} else {
			sanitized[key] = value
		}
	}
	return sanitized
}

func sanitizeAuditRecord(record AuditRecord) AuditRecord {
	record.Details = sanitizeAuditDetails(record.Action, record.Details)
	return record
}

func sanitizeAuditDetails(action string, details map[string]string) map[string]string {
	sanitized := make(map[string]string, len(details))
	for key, value := range details {
		if allowedAuditDetail(action, key, value) {
			sanitized[key] = value
		}
	}
	return sanitized
}

func allowedAuditDetail(action, key, value string) bool {
	if sensitiveField(key) || containsSecretMaterial(value) {
		return false
	}
	switch action {
	case "rule.created", "rule.updated":
		switch key {
		case "aggregation":
			return allowedAggregation(value)
		case "operator":
			return allowedOperator(value)
		case "severity":
			return allowedSeverity(value)
		case "enabled":
			_, err := strconv.ParseBool(value)
			return err == nil
		case "threshold":
			parsed, err := strconv.ParseFloat(value, 64)
			return err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0)
		}
	case "event.pending", "event.firing", "event.acknowledged", "event.resolved":
		switch key {
		case "state":
			return allowedEventState(EventState(value)) && action == "event."+value
		case "window_start", "window_end", conditionSinceEvidenceKey:
			_, err := time.Parse(time.RFC3339Nano, value)
			return err == nil
		case "samples":
			parsed, err := strconv.Atoi(value)
			return err == nil && parsed >= 0
		case "missing":
			_, err := strconv.ParseBool(value)
			return err == nil
		case "aggregate", "rate":
			parsed, err := strconv.ParseFloat(value, 64)
			return err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0)
		}
	case "evaluation.failed":
		return key == "failure_kind" && value == "rule_evaluation"
	case "silence.created", "silence.updated", "silence.deleted":
		switch key {
		case "starts_at", "ends_at":
			_, err := time.Parse(time.RFC3339Nano, value)
			return err == nil
		case "matcher_count":
			parsed, err := strconv.Atoi(value)
			return err == nil && parsed > 0
		case "reason_present":
			parsed, err := strconv.ParseBool(value)
			return err == nil && parsed
		}
	case "policy.created", "policy.updated":
		switch key {
		case "channel":
			return value == "in_app" || value == "smtp" || value == "webhook"
		case "template_id":
			return validIdentifier(value)
		case "enabled":
			_, err := strconv.ParseBool(value)
			return err == nil
		}
	case "template.created", "template.updated":
		if key == "version" {
			parsed, err := strconv.ParseInt(value, 10, 64)
			return err == nil && parsed > 0
		}
	case "delivery.suppressed", "delivery.delivered", "delivery.retrying", "delivery.retry_scheduled", "delivery.abandoned":
		switch key {
		case "status":
			switch DeliveryStatus(value) {
			case DeliveryAttempting, DeliveryDelivered, DeliverySuppressed, DeliveryRetryScheduled, DeliveryAbandoned:
				return true
			}
		case "channel":
			return validIdentifier(value)
		case "attempt":
			parsed, err := strconv.Atoi(value)
			return err == nil && parsed >= 0
		case "failure_class":
			return sanitizeFailureClass(value) == value
		}
	}
	return false
}

func knownAuditDetailKey(action, key string) bool {
	switch action {
	case "rule.created", "rule.updated":
		return key == "aggregation" || key == "operator" || key == "severity" || key == "enabled" || key == "threshold"
	case "event.pending", "event.firing", "event.acknowledged", "event.resolved":
		return key == "state" || key == "window_start" || key == "window_end" || key == conditionSinceEvidenceKey || key == "samples" || key == "missing" || key == "aggregate" || key == "rate"
	case "evaluation.failed":
		return key == "failure_kind"
	case "silence.created", "silence.updated", "silence.deleted":
		return key == "starts_at" || key == "ends_at" || key == "matcher_count" || key == "reason_present"
	case "policy.created", "policy.updated":
		return key == "channel" || key == "template_id" || key == "enabled"
	case "template.created", "template.updated":
		return key == "version"
	case "delivery.suppressed", "delivery.delivered", "delivery.retrying", "delivery.retry_scheduled", "delivery.abandoned":
		return key == "status" || key == "channel" || key == "attempt" || key == "failure_class"
	default:
		return false
	}
}

func validateAuditDetailTypes(record AuditRecord) error {
	for key, value := range record.Details {
		if knownAuditDetailKey(record.Action, key) && !allowedAuditDetail(record.Action, key, value) {
			return ErrInvalidAuditRecord
		}
	}
	return nil
}

func containsSecretMaterial(value string) bool {
	normalized := strings.ToLower(value)
	for _, marker := range []string{"password=", "passwd=", "secret=", "token=", "bearer ", "authorization:", "postgres://", "postgresql://", "mysql://"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func sensitiveField(field string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(field, "-", "_"), ".", "_"))
	for _, marker := range []string{"password", "passwd", "secret", "token", "credential", "api_key", "authorization"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func newControlPlaneID(prefix string, source io.Reader) (string, error) {
	random := make([]byte, 12)
	if source == nil {
		source = rand.Reader
	}
	if _, err := io.ReadFull(source, random); err != nil {
		return "", fmt.Errorf("generate control-plane ID: %w", err)
	}
	return prefix + "-" + hex.EncodeToString(random), nil
}
