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

// Principal is the authenticated caller's project assignment. Agent payloads
// never populate this value; production inventory resolution owns assignment.
type Principal struct {
	Subject       string
	PlatformAdmin bool
	Projects      map[string]struct{}
}

func (p Principal) Allows(scope Scope) bool {
	if scope.Validate() != nil {
		return false
	}
	if p.PlatformAdmin {
		return true
	}
	_, allowed := p.Projects[scope.ProjectID]
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

// Transition returns an event in the requested state without mutating the
// source event. FirstSeen is immutable once recorded.
func (e AlertEvent) Transition(next EventState, at time.Time, actor string) (AlertEvent, error) {
	if at.IsZero() {
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
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var canonical strings.Builder
	appendCanonicalPart(&canonical, scope.TenantID)
	appendCanonicalPart(&canonical, scope.ProjectID)
	appendCanonicalPart(&canonical, ruleID)
	for _, key := range keys {
		appendCanonicalPart(&canonical, key)
		appendCanonicalPart(&canonical, labels[key])
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:])
}

func appendCanonicalPart(builder *strings.Builder, value string) {
	fmt.Fprintf(builder, "%d:", len(value))
	builder.WriteString(value)
}

// NotificationPolicy stores routing configuration but never a secret value.
// SecretRef is intentionally excluded from JSON and audit record structures.
type NotificationPolicy struct {
	ID        string    `json:"id"`
	Scope     Scope     `json:"scope"`
	Name      string    `json:"name"`
	Channel   string    `json:"channel"`
	Target    string    `json:"target"`
	SecretRef string    `json:"-"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type NotificationTemplate struct {
	ID        string    `json:"id"`
	Scope     Scope     `json:"scope"`
	Name      string    `json:"name"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
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
	CreatedAt time.Time         `json:"created_at"`
}

type AuditRecord struct {
	ID         string    `json:"id"`
	Scope      Scope     `json:"scope"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	TargetID   string    `json:"target_id"`
	OccurredAt time.Time `json:"occurred_at"`
}

type EventFilter struct {
	States []EventState
	Limit  int
	Offset int
}
