package alert

import "context"

// Repository is the tenant-scoped persistence boundary for the alert control
// plane. Implementations must never infer a scope from an Agent payload.
type Repository interface {
	CreateRule(context.Context, AlertRule) (AlertRule, error)
	UpdateRule(context.Context, AlertRule) (AlertRule, error)
	ListRules(context.Context, Scope) ([]AlertRule, error)
	GetRule(context.Context, Scope, string) (AlertRule, error)
	PutEvent(context.Context, AlertEvent) (AlertEvent, error)
	PutEventAndAudit(context.Context, AlertEvent, AuditRecord) (AlertEvent, error)
	FindEventByFingerprint(context.Context, Scope, string) (AlertEvent, bool, error)
	ListEvents(context.Context, Scope, EventFilter) ([]AlertEvent, error)
	AppendAudit(context.Context, AuditRecord) error
}
