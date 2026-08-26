package alert

import (
	"context"
	"time"
)

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
	ListRuleEvents(context.Context, Scope, string, EventFilter) ([]AlertEvent, error)
	AppendAudit(context.Context, AuditRecord) error
}

// NotificationRepository is the tenant-scoped persistence boundary for
// routing, silence matching, idempotent delivery reservation, and retries. It
// stays separate from Repository so event-only stores need not implement
// notification delivery.
type NotificationRepository interface {
	GetRule(context.Context, Scope, string) (AlertRule, error)
	ListNotificationRoutes(context.Context, Scope, string) ([]NotificationRoute, error)
	ListActiveSilences(context.Context, Scope, time.Time) ([]Silence, error)
	ReserveNotificationDelivery(context.Context, NotificationDelivery, *AuditRecord) (bool, error)
	UpdateNotificationDelivery(context.Context, NotificationDelivery, AuditRecord) error
	ListDueNotificationDeliveries(context.Context, time.Time) ([]NotificationDelivery, error)
}
