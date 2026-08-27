package alert

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

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

// DueAlertRule is a leased rule together with the persisted instant at which
// it became due. The timestamp lets evaluators report schedule delay without
// guessing from a process-local ticker.
type DueAlertRule struct {
	Rule  AlertRule
	DueAt time.Time
}

// RuleScheduleRepository is the optional durable scheduling boundary used by
// production repositories. Claiming uses a renewable, expiring lease so two
// control-plane replicas cannot evaluate the same due rule concurrently and a
// crashed replica does not strand work forever.
type RuleScheduleRepository interface {
	ClaimDueRules(context.Context, Scope, time.Time, string, time.Time, int) ([]DueAlertRule, int, error)
	CompleteRuleEvaluation(context.Context, Scope, string, string, time.Time, time.Time) error
}

// NotificationRepository is the tenant-scoped persistence boundary for
// routing, silence matching, idempotent delivery reservation, and retries. It
// stays separate from Repository so event-only stores need not implement
// notification delivery.
type NotificationRepository interface {
	GetRule(context.Context, Scope, string) (AlertRule, error)
	RecordOrphanedEvent(context.Context, AlertEvent, time.Time) error
	ListNotificationRoutes(context.Context, Scope, string) ([]NotificationRoute, error)
	ListActiveSilences(context.Context, Scope, time.Time) ([]Silence, error)
	ReserveNotificationDelivery(context.Context, NotificationDelivery, *AuditRecord) (bool, error)
	UpdateNotificationDelivery(context.Context, NotificationDelivery, AuditRecord) error
	ClaimDueNotificationDeliveries(context.Context, time.Time, string, time.Time, int) ([]NotificationDelivery, error)
}

type InAppNotificationRepository interface {
	InAppNotificationWriter
	ListInAppNotifications(context.Context, Scope, string, int) ([]InAppNotification, error)
}

type SilenceRepository interface {
	CreateSilence(context.Context, Silence) (Silence, error)
	UpdateSilence(context.Context, Silence) (Silence, error)
	DeleteSilence(context.Context, Scope, string) error
}

type NotificationConfigurationRepository interface {
	CreateNotificationTemplate(context.Context, NotificationTemplate) (NotificationTemplate, error)
	UpdateNotificationTemplate(context.Context, NotificationTemplate) (NotificationTemplate, error)
	CreateNotificationPolicy(context.Context, NotificationPolicy) (NotificationPolicy, error)
	UpdateNotificationPolicy(context.Context, NotificationPolicy) (NotificationPolicy, error)
}

// ControlPlaneRepository is the complete storage-neutral boundary consumed by
// the production HTTP control plane. Every lookup remains explicitly scoped;
// callers cannot retrieve a record by an unqualified identifier.
type ControlPlaneRepository interface {
	Repository
	NewID(string) (string, error)
	DeleteRule(context.Context, Scope, string) error
	GetEvent(context.Context, Scope, string) (AlertEvent, error)
	CountEventsByState(context.Context, Scope) (map[EventState]int, error)
	PutEventAndDisposition(context.Context, AlertEvent, AuditRecord, EventDisposition) (AlertEvent, error)
	AppendEventDisposition(context.Context, EventDisposition, AuditRecord) error
	ListEventDispositions(context.Context, Scope, string, int, int) ([]EventDisposition, error)

	CreateNotificationPolicy(context.Context, NotificationPolicy) (NotificationPolicy, error)
	UpdateNotificationPolicy(context.Context, NotificationPolicy) (NotificationPolicy, error)
	DeleteNotificationPolicy(context.Context, Scope, string) error
	ListNotificationPolicies(context.Context, Scope) ([]NotificationPolicy, error)
	GetNotificationPolicy(context.Context, Scope, string) (NotificationPolicy, error)

	CreateNotificationTemplate(context.Context, NotificationTemplate) (NotificationTemplate, error)
	UpdateNotificationTemplate(context.Context, NotificationTemplate) (NotificationTemplate, error)
	DeleteNotificationTemplate(context.Context, Scope, string) error
	ListNotificationTemplates(context.Context, Scope) ([]NotificationTemplate, error)
	GetNotificationTemplate(context.Context, Scope, string) (NotificationTemplate, error)

	CreateSilence(context.Context, Silence) (Silence, error)
	UpdateSilence(context.Context, Silence) (Silence, error)
	DeleteSilence(context.Context, Scope, string) error
	ListSilences(context.Context, Scope) ([]Silence, error)
	GetSilence(context.Context, Scope, string) (Silence, error)
	ListNotificationDeliveries(context.Context, Scope, string) ([]NotificationDelivery, error)
}

// RunMigrations applies embedded alert-control-plane migrations exactly once.
// A transaction-level advisory lock serializes concurrent server startups.
func RunMigrations(ctx context.Context, database *sql.DB) error {
	if database == nil {
		return errors.New("database is required")
	}
	entries, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list alert migrations: %w", err)
	}
	sort.Strings(entries)
	if _, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())"); err != nil {
		return fmt.Errorf("create migration registry: %w", err)
	}
	for _, name := range entries {
		content, readErr := migrationFiles.ReadFile(name)
		if readErr != nil {
			return fmt.Errorf("read migration %s: %w", name, readErr)
		}
		tx, beginErr := database.BeginTx(ctx, nil)
		if beginErr != nil {
			return fmt.Errorf("begin migration %s: %w", name, beginErr)
		}
		if _, lockErr := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", int64(0x444250494c4f54)); lockErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("lock migrations: %w", lockErr)
		}
		var applied bool
		if queryErr := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM dbpilot_schema_migrations WHERE name = $1)", name).Scan(&applied); queryErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("check migration %s: %w", name, queryErr)
		}
		if applied {
			if commitErr := tx.Commit(); commitErr != nil {
				return fmt.Errorf("commit migration check %s: %w", name, commitErr)
			}
			continue
		}
		body := strings.TrimSpace(string(content))
		body = strings.TrimSpace(strings.TrimPrefix(body, "BEGIN;"))
		body = strings.TrimSpace(strings.TrimSuffix(body, "COMMIT;"))
		if _, execErr := tx.ExecContext(ctx, body); execErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", name, execErr)
		}
		if _, insertErr := tx.ExecContext(ctx, "INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)", name); insertErr != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, insertErr)
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return fmt.Errorf("commit migration %s: %w", name, commitErr)
		}
	}
	return nil
}
