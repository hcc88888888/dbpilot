// Package alert defines DBPilot's tenant-scoped alert control-plane contracts.
package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	ErrInvalidDisposition         = errors.New("invalid alert event disposition")
)

type EventDispositionKind string

const (
	DispositionAcknowledgement EventDispositionKind = "acknowledgement"
	DispositionResolution      EventDispositionKind = "resolution"
	DispositionRootCause       EventDispositionKind = "root_cause"
)

// EventDisposition is an append-only operator record. Root-cause clues use
// the same model as acknowledgement and resolution so actor, reason, category,
// and time are never overwritten by the next event transition.
type EventDisposition struct {
	ID         string               `json:"id"`
	Scope      Scope                `json:"scope"`
	EventID    string               `json:"event_id"`
	Kind       EventDispositionKind `json:"kind"`
	Category   string               `json:"category"`
	Reason     string               `json:"reason"`
	Actor      string               `json:"actor"`
	OccurredAt time.Time            `json:"occurred_at"`
}

func (d EventDisposition) Validate() error {
	if d.Scope.Validate() != nil || !validIdentifier(d.ID) || !validIdentifier(d.EventID) || !validIdentifier(d.Category) || strings.TrimSpace(d.Actor) == "" || d.Actor != strings.TrimSpace(d.Actor) || d.OccurredAt.IsZero() {
		return ErrInvalidDisposition
	}
	switch d.Kind {
	case DispositionAcknowledgement, DispositionResolution, DispositionRootCause:
	default:
		return ErrInvalidDisposition
	}
	reason := strings.TrimSpace(d.Reason)
	if reason == "" || reason != d.Reason || len(reason) > 1024 || containsSecretMaterial(reason) {
		return ErrInvalidDisposition
	}
	return nil
}

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
	LookbackWindow        time.Duration     `json:"lookback_window"`
	For                   time.Duration     `json:"for"`
	MissingData           string            `json:"missing_data"`
	Severity              string            `json:"severity"`
	NotificationPolicyIDs []string          `json:"notification_policy_ids,omitempty"`
	Labels                map[string]string `json:"labels,omitempty"`
	Enabled               bool              `json:"enabled"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// MarshalJSON encodes duration fields as Go duration strings. JSON numbers
// larger than JavaScript's safe-integer range lose precision in browser
// clients, while duration strings remain exact through a read-edit-write cycle.
func (r AlertRule) MarshalJSON() ([]byte, error) {
	type alertRuleJSON struct {
		ID                    string            `json:"id"`
		Scope                 Scope             `json:"scope"`
		Name                  string            `json:"name"`
		Metric                string            `json:"metric"`
		Aggregation           string            `json:"aggregation"`
		Operator              string            `json:"operator"`
		Threshold             float64           `json:"threshold"`
		EvaluationEvery       string            `json:"evaluation_every"`
		LookbackWindow        string            `json:"lookback_window"`
		For                   string            `json:"for"`
		MissingData           string            `json:"missing_data"`
		Severity              string            `json:"severity"`
		NotificationPolicyIDs []string          `json:"notification_policy_ids,omitempty"`
		Labels                map[string]string `json:"labels,omitempty"`
		Enabled               bool              `json:"enabled"`
		CreatedAt             time.Time         `json:"created_at"`
		UpdatedAt             time.Time         `json:"updated_at"`
	}
	return json.Marshal(alertRuleJSON{
		ID: r.ID, Scope: r.Scope, Name: r.Name, Metric: r.Metric, Aggregation: r.Aggregation, Operator: r.Operator,
		Threshold: r.Threshold, EvaluationEvery: r.EvaluationEvery.String(), LookbackWindow: r.LookbackWindow.String(),
		For: r.For.String(), MissingData: r.MissingData, Severity: r.Severity, NotificationPolicyIDs: r.NotificationPolicyIDs,
		Labels: r.Labels, Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	})
}

// UnmarshalJSON accepts both the current exact duration strings and legacy
// numeric nanosecond values so typed Go clients can decode all rule responses.
func (r *AlertRule) UnmarshalJSON(data []byte) error {
	type alertRuleAlias AlertRule
	type alertRuleJSON struct {
		*alertRuleAlias
		EvaluationEvery json.RawMessage `json:"evaluation_every"`
		LookbackWindow  json.RawMessage `json:"lookback_window"`
		For             json.RawMessage `json:"for"`
	}

	decoded := alertRuleAlias(*r)
	wire := alertRuleJSON{alertRuleAlias: &decoded}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}

	evaluationEvery := decoded.EvaluationEvery
	lookbackWindow := decoded.LookbackWindow
	forDuration := decoded.For
	var err error
	if hasJSONDuration(wire.EvaluationEvery) {
		evaluationEvery, err = decodeJSONDuration(wire.EvaluationEvery)
		if err != nil {
			return fmt.Errorf("decode evaluation_every: %w", err)
		}
	}
	if hasJSONDuration(wire.LookbackWindow) {
		lookbackWindow, err = decodeJSONDuration(wire.LookbackWindow)
		if err != nil {
			return fmt.Errorf("decode lookback_window: %w", err)
		}
	}
	if hasJSONDuration(wire.For) {
		forDuration, err = decodeJSONDuration(wire.For)
		if err != nil {
			return fmt.Errorf("decode for: %w", err)
		}
	}

	decoded.EvaluationEvery = evaluationEvery
	decoded.LookbackWindow = lookbackWindow
	decoded.For = forDuration
	*r = AlertRule(decoded)
	return nil
}

func hasJSONDuration(value json.RawMessage) bool {
	return len(value) > 0 && strings.TrimSpace(string(value)) != "null"
}

func decodeJSONDuration(value json.RawMessage) (time.Duration, error) {
	var stringValue string
	if err := json.Unmarshal(value, &stringValue); err == nil {
		duration, err := time.ParseDuration(stringValue)
		if err != nil {
			return 0, err
		}
		return duration, nil
	}

	var nanoseconds int64
	if err := json.Unmarshal(value, &nanoseconds); err != nil {
		return 0, err
	}
	return time.Duration(nanoseconds), nil
}

func (r AlertRule) Validate() error {
	if r.Scope.Validate() != nil || strings.TrimSpace(r.Name) == "" || strings.TrimSpace(r.Metric) == "" {
		return ErrInvalidRule
	}
	if !allowedAggregation(r.Aggregation) || !allowedOperator(r.Operator) || !allowedSeverity(r.Severity) || !allowedMissingData(r.MissingData) {
		return ErrInvalidRule
	}
	if math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) || r.EvaluationEvery <= 0 || r.LookbackWindow < 0 || r.For <= 0 {
		return ErrInvalidRule
	}
	for _, policyID := range r.NotificationPolicyIDs {
		if !validIdentifier(policyID) {
			return ErrInvalidRule
		}
	}
	if !validLabelMatchers(r.Labels) {
		return ErrInvalidRule
	}
	return nil
}

// EffectiveLookbackWindow keeps pre-lookback rules backward compatible while
// making query cadence and aggregation window independent for new rules.
func (r AlertRule) EffectiveLookbackWindow() time.Duration {
	if r.LookbackWindow > 0 {
		return r.LookbackWindow
	}
	return r.EvaluationEvery
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

func validLabelName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || character == '_' || (index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func validLabelMatchers(matchers map[string]string) bool {
	for key, value := range matchers {
		if !validLabelName(key) || strings.TrimSpace(value) == "" || sensitiveField(key) || containsSecretMaterial(value) {
			return false
		}
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
	ID                         string    `json:"id"`
	Scope                      Scope     `json:"scope"`
	Name                       string    `json:"name"`
	Subject                    string    `json:"subject"`
	Body                       string    `json:"body"`
	Revision                   int64     `json:"version"`
	LegacyVersionFromUpdatedAt bool      `json:"-"`
	CreatedAt                  time.Time `json:"created_at"`
	UpdatedAt                  time.Time `json:"updated_at"`
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
	States    []EventState
	Limit     int
	Offset    int
	AfterID   string
	OrderByID bool
}
