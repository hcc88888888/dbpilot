package alert

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const RedactedValue = "[REDACTED]"

var ErrInvalidAuditRecord = errors.New("invalid audit record")

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
	if record.Scope.Validate() != nil || strings.TrimSpace(record.ID) == "" || strings.TrimSpace(record.Actor) == "" || strings.TrimSpace(record.Action) == "" || strings.TrimSpace(record.TargetID) == "" || record.OccurredAt.IsZero() {
		return ErrInvalidAuditRecord
	}
	for key := range record.Details {
		if sensitiveField(key) {
			return ErrInvalidAuditRecord
		}
	}
	return nil
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
	record.Details = sanitizeAuditDetails(record.Details)
	return record
}

func sanitizeAuditDetails(details map[string]string) map[string]string {
	sanitized := make(map[string]string, len(details))
	for key, value := range details {
		if !sensitiveField(key) {
			sanitized[key] = value
		}
	}
	return sanitized
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

func newControlPlaneID(prefix string, at time.Time) string {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err == nil {
		return prefix + "-" + hex.EncodeToString(random)
	}
	return prefix + "-" + hex.EncodeToString([]byte(at.UTC().Format(time.RFC3339Nano)))
}
