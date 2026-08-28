// Package inspection contains storage-neutral host inspection domain values.
package inspection

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

const (
	maxSnapshotItems   = 200
	maxSnapshotTargets = 10000
	maxEvidenceBytes   = 64 * 1024
)

var (
	ErrInvalidItem          = errors.New("invalid inspection item")
	ErrInvalidRunSnapshot   = errors.New("invalid inspection run snapshot")
	ErrInvalidTargetRun     = errors.New("invalid inspection target run")
	ErrInvalidFinding       = errors.New("invalid inspection finding")
	ErrInvalidRunTransition = errors.New("invalid inspection run transition")
)

type FindingLevel string

const (
	LevelHealthy     FindingLevel = "healthy"
	LevelWarning     FindingLevel = "warning"
	LevelCritical    FindingLevel = "critical"
	LevelUnsupported FindingLevel = "unsupported"
	LevelMissingData FindingLevel = "missing_data"
)

type ScopeType string

const ScopeHost ScopeType = "host"

type SourceType string

const (
	SourceMetric     SourceType = "metric"
	SourceMetadata   SourceType = "metadata"
	SourceLogSummary SourceType = "log_summary"
)

type Aggregation string

const (
	AggregationLatest  Aggregation = "latest"
	AggregationAverage Aggregation = "avg"
	AggregationMaximum Aggregation = "max"
	AggregationMinimum Aggregation = "min"
)

type Operator string

const (
	OperatorGT  Operator = "gt"
	OperatorGTE Operator = "gte"
	OperatorLT  Operator = "lt"
	OperatorLTE Operator = "lte"
)

type RunStatus string

const (
	RunQueued           RunStatus = "queued"
	RunCollecting       RunStatus = "collecting"
	RunEvaluating       RunStatus = "evaluating"
	RunGeneratingReport RunStatus = "generating_report"
	RunCompleted        RunStatus = "completed"
	RunPartial          RunStatus = "partial"
	RunFailed           RunStatus = "failed"
	RunCancelled        RunStatus = "cancelled"
)

type TargetStatus string

const (
	TargetPending     TargetStatus = "pending"
	TargetCollecting  TargetStatus = "collecting"
	TargetEvaluating  TargetStatus = "evaluating"
	TargetSucceeded   TargetStatus = "succeeded"
	TargetFailed      TargetStatus = "failed"
	TargetUnsupported TargetStatus = "unsupported"
	TargetCancelled   TargetStatus = "cancelled"
)

// MetricRule is a closed, declarative metric decision. It deliberately has
// no executable expression or arbitrary query field.
type MetricRule struct {
	MetricName        string            `json:"metric_name"`
	Labels            map[string]string `json:"labels,omitempty"`
	Window            time.Duration     `json:"window"`
	Aggregation       Aggregation       `json:"aggregation"`
	Operator          Operator          `json:"operator"`
	WarningThreshold  float64           `json:"warning_threshold"`
	CriticalThreshold float64           `json:"critical_threshold"`
}

func (r MetricRule) Validate() error {
	if !validMetricName(r.MetricName) || r.Window <= 0 || !validAggregation(r.Aggregation) || !validOperator(r.Operator) || !finite(r.WarningThreshold) || !finite(r.CriticalThreshold) || !validLabels(r.Labels) {
		return ErrInvalidItem
	}
	switch r.Operator {
	case OperatorGT, OperatorGTE:
		if r.CriticalThreshold <= r.WarningThreshold {
			return ErrInvalidItem
		}
	case OperatorLT, OperatorLTE:
		if r.CriticalThreshold >= r.WarningThreshold {
			return ErrInvalidItem
		}
	}
	return nil
}

// Item is a versioned and immutable decision definition captured by a run.
// System metadata/log items use their stable ID semantics; first-stage custom
// items are represented only by SourceMetric and a MetricRule.
type Item struct {
	ID                     string      `json:"id"`
	Version                int         `json:"version"`
	Name                   string      `json:"name"`
	Category               string      `json:"category"`
	ScopeType              ScopeType   `json:"scope_type"`
	SourceType             SourceType  `json:"source_type"`
	System                 bool        `json:"system"`
	MetricRule             *MetricRule `json:"metric_rule,omitempty"`
	EvidenceSelector       []string    `json:"evidence_selector,omitempty"`
	RequiredCapabilities   []string    `json:"required_capabilities,omitempty"`
	RecommendationTemplate string      `json:"recommendation_template"`
}

func (i Item) Validate() error {
	if !validID(i.ID) || i.Version < 1 || i.ScopeType != ScopeHost || !validSource(i.SourceType) || !validEvidenceSelector(i.EvidenceSelector) || !validCapabilities(i.RequiredCapabilities) {
		return ErrInvalidItem
	}
	if i.SourceType == SourceMetric {
		if i.MetricRule == nil || i.MetricRule.Validate() != nil {
			return ErrInvalidItem
		}
		if !i.System && len(i.EvidenceSelector) == 0 {
			return ErrInvalidItem
		}
		return nil
	}
	if !i.System {
		return ErrInvalidItem
	}
	if i.MetricRule != nil || len(i.EvidenceSelector) == 0 {
		return ErrInvalidItem
	}
	return nil
}

// Observation is normalized Agent evidence. Values and timestamps are kept
// structured; raw logs and arbitrary metadata are intentionally not retained.
type Observation struct {
	ID         string            `json:"id"`
	TargetID   string            `json:"target_id"`
	Name       string            `json:"name"`
	SourceType SourceType        `json:"source_type"`
	Labels     map[string]string `json:"labels,omitempty"`
	Value      float64           `json:"value"`
	ObservedAt time.Time         `json:"observed_at"`
}

func (o Observation) Validate() error {
	if !validID(o.ID) || !validID(o.TargetID) || !validMetricName(o.Name) || !validSource(o.SourceType) || !finite(o.Value) || !isUTC(o.ObservedAt) || !validLabels(o.Labels) {
		return ErrInvalidFinding
	}
	return nil
}

// TargetRun records immutable target identity plus the Agent-advertised
// source types and normalized non-metric evidence for a particular run.
type TargetRun struct {
	TargetID                string        `json:"target_id"`
	AgentID                 string        `json:"agent_id"`
	Status                  TargetStatus  `json:"status"`
	ObservedAt              time.Time     `json:"observed_at,omitempty"`
	AdvertisedSources       []SourceType  `json:"advertised_sources,omitempty"`
	Capabilities            []string      `json:"capabilities,omitempty"`
	TrustedProcessAllowlist bool          `json:"trusted_process_allowlist"`
	Observations            []Observation `json:"observations,omitempty"`
}

func (t TargetRun) Validate() error {
	if !validID(t.TargetID) || !validID(t.AgentID) || !validTargetStatus(t.Status) || (!t.ObservedAt.IsZero() && !isUTC(t.ObservedAt)) || !validCapabilities(t.Capabilities) {
		return ErrInvalidTargetRun
	}
	seenSources := make(map[SourceType]struct{}, len(t.AdvertisedSources))
	for _, source := range t.AdvertisedSources {
		if !validSource(source) {
			return ErrInvalidTargetRun
		}
		if _, exists := seenSources[source]; exists {
			return ErrInvalidTargetRun
		}
		seenSources[source] = struct{}{}
	}
	seenObservations := make(map[string]struct{}, len(t.Observations))
	for _, observation := range t.Observations {
		if observation.TargetID != t.TargetID || observation.Validate() != nil {
			return ErrInvalidTargetRun
		}
		if _, exists := seenObservations[observation.ID]; exists {
			return ErrInvalidTargetRun
		}
		seenObservations[observation.ID] = struct{}{}
	}
	return nil
}

// RunSnapshot is the immutable scope, item-version, target, and time input
// from which later evaluation and reporting must be reproducible.
type RunSnapshot struct {
	ID        string              `json:"id"`
	Scope     platformscope.Scope `json:"scope"`
	CreatedAt time.Time           `json:"created_at"`
	Items     []Item              `json:"items"`
	Targets   []TargetRun         `json:"targets"`
}

func (r RunSnapshot) Validate() error {
	if !validID(r.ID) || r.Scope.Validate() != nil || !isUTC(r.CreatedAt) || len(r.Items) == 0 || len(r.Items) > maxSnapshotItems || len(r.Targets) == 0 || len(r.Targets) > maxSnapshotTargets {
		return ErrInvalidRunSnapshot
	}
	items := make(map[string]struct{}, len(r.Items))
	for _, item := range r.Items {
		if item.Validate() != nil {
			return ErrInvalidRunSnapshot
		}
		key := item.ID + "\x00" + fmt.Sprintf("%d", item.Version)
		if _, exists := items[key]; exists {
			return ErrInvalidRunSnapshot
		}
		items[key] = struct{}{}
	}
	targets := make(map[string]struct{}, len(r.Targets))
	for _, target := range r.Targets {
		if target.Validate() != nil {
			return ErrInvalidRunSnapshot
		}
		if _, exists := targets[target.TargetID]; exists {
			return ErrInvalidRunSnapshot
		}
		targets[target.TargetID] = struct{}{}
	}
	return nil
}

// Finding is the bounded, secret-safe immutable output of one item version.
type Finding struct {
	Scope             platformscope.Scope `json:"scope"`
	RunID             string              `json:"run_id"`
	TargetID          string              `json:"target_id"`
	ItemID            string              `json:"item_id"`
	ItemVersion       int                 `json:"item_version"`
	Level             FindingLevel        `json:"level"`
	ObservedAt        time.Time           `json:"observed_at"`
	WarningThreshold  *float64            `json:"warning_threshold,omitempty"`
	CriticalThreshold *float64            `json:"critical_threshold,omitempty"`
	Evidence          map[string]string   `json:"evidence"`
}

func (f Finding) Validate() error {
	if f.Scope.Validate() != nil || !validID(f.RunID) || !validID(f.TargetID) || !validID(f.ItemID) || f.ItemVersion < 1 || !validFindingLevel(f.Level) || !isUTC(f.ObservedAt) || evidenceBytes(f.Evidence) > maxEvidenceBytes {
		return ErrInvalidFinding
	}
	for key, value := range f.Evidence {
		if !validEvidenceKey(key) || containsSecretMarker(key) || containsSecretMarker(value) {
			return ErrInvalidFinding
		}
	}
	if (f.WarningThreshold == nil) != (f.CriticalThreshold == nil) {
		return ErrInvalidFinding
	}
	if f.WarningThreshold != nil && (!finite(*f.WarningThreshold) || !finite(*f.CriticalThreshold)) {
		return ErrInvalidFinding
	}
	return nil
}

func ValidateRunTransition(current, next RunStatus) error {
	switch current {
	case RunQueued:
		if next == RunCollecting || next == RunCancelled || next == RunFailed {
			return nil
		}
	case RunCollecting:
		if next == RunEvaluating || next == RunCancelled || next == RunFailed {
			return nil
		}
	case RunEvaluating:
		if next == RunGeneratingReport || next == RunCancelled || next == RunFailed {
			return nil
		}
	case RunGeneratingReport:
		if next == RunCompleted || next == RunPartial || next == RunFailed || next == RunCancelled {
			return nil
		}
	}
	return ErrInvalidRunTransition
}

func AggregateRunStatus(statuses []TargetStatus) RunStatus {
	if len(statuses) == 0 {
		return RunFailed
	}
	succeeded := false
	allCancelled := true
	for _, status := range statuses {
		if status == TargetSucceeded {
			succeeded = true
		}
		if status != TargetCancelled {
			allCancelled = false
		}
	}
	if allCancelled {
		return RunCancelled
	}
	if succeeded {
		for _, status := range statuses {
			if status != TargetSucceeded {
				return RunPartial
			}
		}
		return RunCompleted
	}
	return RunFailed
}

func sortedSources(sources []SourceType) []SourceType {
	result := append([]SourceType(nil), sources...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func validID(value string) bool {
	if value == "" || len(value) > 128 || value != strings.TrimSpace(value) {
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

func validMetricName(value string) bool { return validID(value) && strings.Contains(value, ".") }

func validLabels(labels map[string]string) bool {
	if len(labels) > 16 {
		return false
	}
	for key, value := range labels {
		if !validID(key) || value == "" || len(value) > 128 || value != strings.TrimSpace(value) || containsSecretMarker(key) || containsSecretMarker(value) {
			return false
		}
	}
	return true
}

func validEvidenceSelector(fields []string) bool {
	if len(fields) > 16 {
		return false
	}
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if !validID(field) || containsSecretMarker(field) {
			return false
		}
		if _, exists := seen[field]; exists {
			return false
		}
		seen[field] = struct{}{}
	}
	return true
}

func validCapabilities(values []string) bool {
	if len(values) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validID(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validAggregation(value Aggregation) bool {
	return value == AggregationLatest || value == AggregationAverage || value == AggregationMaximum || value == AggregationMinimum
}

func validOperator(value Operator) bool {
	return value == OperatorGT || value == OperatorGTE || value == OperatorLT || value == OperatorLTE
}

func validSource(value SourceType) bool {
	return value == SourceMetric || value == SourceMetadata || value == SourceLogSummary
}

func validTargetStatus(value TargetStatus) bool {
	switch value {
	case TargetPending, TargetCollecting, TargetEvaluating, TargetSucceeded, TargetFailed, TargetUnsupported, TargetCancelled:
		return true
	default:
		return false
	}
}

func validFindingLevel(value FindingLevel) bool {
	return value == LevelHealthy || value == LevelWarning || value == LevelCritical || value == LevelUnsupported || value == LevelMissingData
}

func validEvidenceKey(value string) bool { return validID(value) }

func evidenceBytes(values map[string]string) int {
	size := 0
	for key, value := range values {
		size += len(key) + len(value)
	}
	return size
}

func isUTC(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func containsSecretMarker(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"password", "secret", "token", "authorization", "credential", "bearer "} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
