// Package alert defines DBPilot's tenant-scoped alert control-plane contracts.
package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidScope               = errors.New("alert scope requires tenant and project")
	ErrInvalidRule                = errors.New("invalid alert rule")
	ErrInvalidEvent               = errors.New("invalid alert event")
	ErrInvalidEventTransition     = errors.New("invalid alert event transition")
	ErrInvalidEventTransitionTime = errors.New("event transition time is required")
)

// Scope identifies the only tenancy boundary accepted by alert storage.
type Scope struct {
	TenantID  string `json:"tenant_id"`
	ProjectID string `json:"project_id"`
}

func (s Scope) Validate() error {
	if strings.TrimSpace(s.TenantID) == "" || strings.TrimSpace(s.ProjectID) == "" {
		return ErrInvalidScope
	}
	return nil
}

// Key is an unambiguous identity for project assignments. It deliberately
// includes the tenant so a repeated project ID cannot cross an authorization
// boundary.
func (s Scope) Key() string {
	return canonicalParts(s.TenantID, s.ProjectID)
}

// Principal is the authenticated caller's project assignment. Agent payloads
// never populate this value; production inventory resolution owns assignment.
type Principal struct {
	Subject       string
	PlatformAdmin bool
	// Projects contains Scope.Key values resolved by production inventory.
	Projects map[string]struct{}
}

func (p Principal) Allows(scope Scope) bool {
	if scope.Validate() != nil {
		return false
	}
	if p.PlatformAdmin {
		return true
	}
	_, allowed := p.Projects[scope.Key()]
	return allowed
}

type EventState string

const (
	EventPending      EventState = "pending"
	EventFiring       EventState = "firing"
	EventAcknowledged EventState = "acknowledged"
	EventResolved     EventState = "resolved"
)

// AlertRule uses closed option sets rather than an executable expression
// language. This deliberately excludes PromQL and arbitrary aggregation.
type AlertRule struct {
	ID                    string            `json:"id"`
	Scope                 Scope             `json:"scope"`
	Name                  string            `json:"name"`
	Metric                string            `json:"metric"`
	Aggregation           string            `json:"aggregation"`
	Operator              string            `json:"operator"`
	Threshold             float64           `json:"threshold"`
	EvaluationEvery       time.Duration     `json:"evaluation_every"`
	For                   time.Duration     `json:"for"`
	MissingData           string            `json:"missing_data"`
	Severity              string            `json:"severity"`
	NotificationPolicyIDs []string          `json:"notification_policy_ids,omitempty"`
	Labels                map[string]string `json:"labels,omitempty"`
	Enabled               bool              `json:"enabled"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

func (r AlertRule) Validate() error {
	if r.Scope.Validate() != nil || strings.TrimSpace(r.Name) == "" || strings.TrimSpace(r.Metric) == "" {
		return ErrInvalidRule
	}
	if !allowedAggregation(r.Aggregation) || !allowedOperator(r.Operator) || !allowedSeverity(r.Severity) || !allowedMissingData(r.MissingData) {
		return ErrInvalidRule
	}
	if math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) || r.EvaluationEvery <= 0 || r.For <= 0 {
		return ErrInvalidRule
	}
	for _, policyID := range r.NotificationPolicyIDs {
		if !validIdentifier(policyID) {
			return ErrInvalidRule
		}
	}
	return nil
}

func allowedAggregation(value string) bool {
	switch value {
	case "avg", "max", "min", "sum", "count", "rate":
		return true
	default:
		return false
	}
}

func allowedOperator(value string) bool {
	switch value {
	case ">", ">=", "<", "<=", "==", "!=":
		return true
	default:
		return false
	}
}

func allowedSeverity(value string) bool {
	switch value {
	case "info", "warning", "critical":
		return true
	default:
		return false
	}
}

func allowedMissingData(value string) bool {
	switch value {
	case "ignore", "alert", "resolve":
		return true
	default:
		return false
	}
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || character == '_' || character == '-' || character == '.' || (index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

type AlertEvent struct {
	ID             string            `json:"id"`
	Scope          Scope             `json:"scope"`
	RuleID         string            `json:"rule_id"`
	Fingerprint    string            `json:"fingerprint"`
	Labels         map[string]string `json:"labels,omitempty"`
	Evidence       map[string]string `json:"evidence,omitempty"`
	State          EventState        `json:"state"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	FiringAt       time.Time         `json:"firing_at,omitempty"`
	AcknowledgedAt time.Time         `json:"acknowledged_at,omitempty"`
	ResolvedAt     time.Time         `json:"resolved_at,omitempty"`
	LastActor      string            `json:"last_actor,omitempty"`
}

func (e AlertEvent) Validate() error {
	if e.Scope.Validate() != nil || strings.TrimSpace(e.RuleID) == "" || strings.TrimSpace(e.Fingerprint) == "" || !allowedEventState(e.State) {
		return ErrInvalidEvent
	}
	if e.FirstSeen.IsZero() || e.LastSeen.IsZero() || e.LastSeen.Before(e.FirstSeen) {
		return ErrInvalidEvent
	}
	if !validEventTimestamp(e.FiringAt, e.FirstSeen, e.LastSeen) || !validEventTimestamp(e.AcknowledgedAt, e.FirstSeen, e.LastSeen) || !validEventTimestamp(e.ResolvedAt, e.FirstSeen, e.LastSeen) {
		return ErrInvalidEvent
	}
	switch e.State {
	case EventPending:
		if !e.FiringAt.IsZero() || !e.AcknowledgedAt.IsZero() || !e.ResolvedAt.IsZero() {
			return ErrInvalidEvent
		}
	case EventFiring:
		if e.FiringAt.IsZero() || !e.AcknowledgedAt.IsZero() || !e.ResolvedAt.IsZero() {
			return ErrInvalidEvent
		}
	case EventAcknowledged:
		if e.FiringAt.IsZero() || e.AcknowledgedAt.IsZero() || e.AcknowledgedAt.Before(e.FiringAt) || !e.ResolvedAt.IsZero() {
			return ErrInvalidEvent
		}
	case EventResolved:
		if e.ResolvedAt.IsZero() || (!e.FiringAt.IsZero() && e.ResolvedAt.Before(e.FiringAt)) || (!e.AcknowledgedAt.IsZero() && (e.FiringAt.IsZero() || e.ResolvedAt.Before(e.AcknowledgedAt))) {
			return ErrInvalidEvent
		}
	}
	return nil
}

func allowedEventState(state EventState) bool {
	switch state {
	case EventPending, EventFiring, EventAcknowledged, EventResolved:
		return true
	default:
		return false
	}
}

func validEventTimestamp(value, firstSeen, lastSeen time.Time) bool {
	return value.IsZero() || (!value.Before(firstSeen) && !value.After(lastSeen))
}

// Transition returns an event in the requested state without mutating the
// source event. FirstSeen is immutable once recorded.
func (e AlertEvent) Transition(next EventState, at time.Time, actor string) (AlertEvent, error) {
	if at.IsZero() {
		return AlertEvent{}, ErrInvalidEventTransitionTime
	}
	if (!e.FirstSeen.IsZero() && at.Before(e.FirstSeen)) || (!e.LastSeen.IsZero() && at.Before(e.LastSeen)) {
		return AlertEvent{}, ErrInvalidEventTransitionTime
	}
	if !permittedTransition(e.State, next) {
		return AlertEvent{}, ErrInvalidEventTransition
	}
	if e.FirstSeen.IsZero() {
		e.FirstSeen = at
	}
	e.State = next
	e.LastSeen = at
	e.LastActor = actor
	switch next {
	case EventFiring:
		e.FiringAt = at
	case EventAcknowledged:
		e.AcknowledgedAt = at
	case EventResolved:
		e.ResolvedAt = at
	}
	return e, nil
}

func permittedTransition(current, next EventState) bool {
	switch current {
	case EventPending:
		return next == EventFiring || next == EventResolved
	case EventFiring:
		return next == EventAcknowledged || next == EventResolved
	case EventAcknowledged:
		return next == EventResolved
	default:
		return false
	}
}

// EventFingerprint is stable across equivalent label maps and includes the
// tenant/project scope so identical source labels cannot cross tenant bounds.
func EventFingerprint(scope Scope, ruleID string, labels map[string]string) string {
	return fingerprintParts(scope.TenantID, scope.ProjectID, ruleID, canonicalLabels(labels))
}

// SeriesFingerprint identifies a normalized metric label series independently
// of PostgreSQL storage and map iteration order.
func SeriesFingerprint(labels map[string]string) string {
	return fingerprintParts(canonicalLabels(labels))
}

func fingerprintParts(parts ...string) string {
	digest := sha256.Sum256([]byte(canonicalParts(parts...)))
	return hex.EncodeToString(digest[:])
}

func canonicalLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(labels)*2)
	for _, key := range keys {
		parts = append(parts, key, labels[key])
	}
	return canonicalParts(parts...)
}

func canonicalParts(parts ...string) string {
	var canonical strings.Builder
	for _, part := range parts {
		fmt.Fprintf(&canonical, "%d:", len(part))
		canonical.WriteString(part)
	}
	return canonical.String()
}

// NotificationPolicy stores routing configuration but never a secret value.
// SecretRef is intentionally excluded from JSON and audit record structures.
type NotificationPolicy struct {
	ID             string            `json:"id"`
	Scope          Scope             `json:"scope"`
	Name           string            `json:"name"`
	Channel        string            `json:"channel"`
	Target         string            `json:"target"`
	SecretRef      string            `json:"-"`
	TemplateID     string            `json:"template_id"`
	Severities     []string          `json:"severities,omitempty"`
	MatchLabels    map[string]string `json:"match_labels,omitempty"`
	WindowStartUTC string            `json:"window_start_utc,omitempty"`
	WindowEndUTC   string            `json:"window_end_utc,omitempty"`
	Enabled        bool              `json:"enabled"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

type NotificationTemplate struct {
	ID        string    `json:"id"`
	Scope     Scope     `json:"scope"`
	Name      string    `json:"name"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	Revision  int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Silence struct {
	ID        string            `json:"id"`
	Scope     Scope             `json:"scope"`
	Matchers  map[string]string `json:"matchers"`
	StartsAt  time.Time         `json:"starts_at"`
	EndsAt    time.Time         `json:"ends_at"`
	CreatedBy string            `json:"created_by"`
	Reason    string            `json:"reason"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type InAppNotification struct {
	ID         string     `json:"id"`
	Scope      Scope      `json:"scope"`
	DeliveryID string     `json:"delivery_id"`
	EventID    string     `json:"event_id"`
	EventState EventState `json:"event_state"`
	Recipient  string     `json:"recipient"`
	Subject    string     `json:"subject"`
	Body       string     `json:"body"`
	CreatedAt  time.Time  `json:"created_at"`
	ReadAt     time.Time  `json:"read_at,omitempty"`
}

type AuditRecord struct {
	ID         string            `json:"id"`
	Scope      Scope             `json:"scope"`
	Actor      string            `json:"actor"`
	Action     string            `json:"action"`
	TargetID   string            `json:"target_id"`
	OccurredAt time.Time         `json:"occurred_at"`
	Details    map[string]string `json:"details,omitempty"`
}

type EventFilter struct {
	States []EventState
	Limit  int
	Offset int
}
