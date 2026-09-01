// Package metrictemplate owns immutable custom metric definitions and their
// validation, trial, approval and publication workflow.
package metrictemplate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"dbpilot.local/platform/internal/platformscope"
)

var (
	ErrInvalid           = errors.New("invalid metric template")
	ErrNotFound          = errors.New("metric template not found")
	ErrConflict          = errors.New("metric template conflict")
	ErrPrecondition      = errors.New("metric template precondition failed")
	ErrInvalidTransition = errors.New("invalid metric template transition")
	ErrSelfApproval      = errors.New("metric template creator cannot approve")
	ErrValidationFailed  = errors.New("metric template validation failed")
	ErrDialectRejected   = errors.New("metric template dialect validation failed")
	ErrTrialFailed       = errors.New("metric template trial failed")
	ErrNotApproved       = errors.New("metric template is not approved")
	ErrIncompatible      = errors.New("metric template is incompatible")
	ErrCapacity          = errors.New("metric template publication capacity exceeded")
	ErrLeaseRejected     = errors.New("metric template lease rejected")
)

const (
	DefaultListLimit      = 50
	MaximumListLimit      = 100
	MaximumStatementBytes = 32768
	MaximumVariants       = 16
	MaximumValueMappings  = 32
	MaximumLabelMappings  = 16
	MaximumAssignments    = 128
)

var (
	idPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	templateIDPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	familyPattern      = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	variantPattern     = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	metricNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9_.]{1,127}$`)
	labelPattern       = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	digestPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	fingerprintPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	cursorPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)
)

type Status string

const (
	StatusDraft            Status = "draft"
	StatusValidating       Status = "validating"
	StatusValidated        Status = "validated"
	StatusValidationFailed Status = "validation_failed"
	StatusTrialRunning     Status = "trial_running"
	StatusTrialPassed      Status = "trial_passed"
	StatusTrialFailed      Status = "trial_failed"
	StatusApprovalPending  Status = "approval_pending"
	StatusApproved         Status = "approved"
	StatusRejected         Status = "rejected"
	StatusPublished        Status = "published"
	StatusSuperseded       Status = "superseded"
)

func (value Status) Valid() bool {
	switch value {
	case StatusDraft, StatusValidating, StatusValidated, StatusValidationFailed,
		StatusTrialRunning, StatusTrialPassed, StatusTrialFailed,
		StatusApprovalPending, StatusApproved, StatusRejected, StatusPublished, StatusSuperseded:
		return true
	default:
		return false
	}
}

type QueryKind string

const QuerySQL QueryKind = "sql"

type MetricType string

const (
	MetricGauge            MetricType = "gauge"
	MetricMonotonicGauge   MetricType = "monotonic_gauge"
	MetricCounter          MetricType = "counter"
	MetricMonotonicCounter MetricType = "monotonic_counter"
)

func (value MetricType) Valid() bool {
	return value == MetricGauge || value == MetricMonotonicGauge || value == MetricCounter || value == MetricMonotonicCounter
}

type ValueMapping struct {
	SourceColumn string     `json:"source_column"`
	MetricName   string     `json:"metric_name"`
	MetricType   MetricType `json:"metric_type"`
	Unit         string     `json:"unit"`
}

type LabelMapping struct {
	SourceColumn string `json:"source_column"`
	Label        string `json:"label"`
}

type TemplateDefinition struct {
	DatabaseFamily            string
	Variants                  []string
	Name                      string
	Description               string
	QueryKind                 QueryKind
	ReadOnlyStatement         string
	CollectionIntervalSeconds int
	TimeoutSeconds            int
	MaxRows                   int
	MaxColumns                int
	ValueMappings             []ValueMapping
	LabelMappings             []LabelMapping
	DatabaseVersionRange      string
	PluginVersionRange        string
	CardinalityLimit          int
}

type ValidatedDefinition struct {
	DatabaseFamily            string
	Variants                  []string
	Name                      string
	Description               string
	QueryKind                 QueryKind
	CollectionIntervalSeconds int
	TimeoutSeconds            int
	MaxRows                   int
	MaxColumns                int
	ValueMappings             []ValueMapping
	LabelMappings             []LabelMapping
	DatabaseVersionRange      string
	PluginVersionRange        string
	CardinalityLimit          int
	QueryDigest               string
	// ReadOnlyStatement is deliberately always empty. The authoritative
	// validator receives TemplateDefinition directly and ordinary metadata,
	// Audit, Jobs, errors and public DTOs receive only this redacted value.
	ReadOnlyStatement string
}

type Template struct {
	ID                string
	Scope             platformscope.Scope
	DatabaseFamily    string
	Name              string
	Description       string
	Builtin           bool
	LatestRevision    uint64
	PublishedRevision *uint64
	CreatedAt         time.Time
}

func (value Template) Validate() error {
	if !templateIDPattern.MatchString(value.ID) || value.Scope.Validate() != nil || !familyPattern.MatchString(value.DatabaseFamily) || !bounded(value.Name, 120, true) || !bounded(value.Description, 1000, false) || !validUTC(value.CreatedAt) || value.PublishedRevision != nil && (*value.PublishedRevision == 0 || *value.PublishedRevision > value.LatestRevision) {
		return ErrInvalid
	}
	return nil
}

type TemplateDraft struct {
	ID             string
	DatabaseFamily string
	Name           string
	Description    string
}

func (value TemplateDraft) Validate() error {
	if !templateIDPattern.MatchString(value.ID) || !familyPattern.MatchString(value.DatabaseFamily) || !bounded(value.Name, 120, true) || !bounded(value.Description, 1000, false) {
		return ErrInvalid
	}
	return nil
}

type Draft struct {
	TemplateDefinition
	CreatedBy string
}

type Revision struct {
	ID                        string
	Scope                     platformscope.Scope
	TemplateID                string
	Revision                  uint64
	DatabaseFamily            string
	Variants                  []string
	Name                      string
	Description               string
	QueryKind                 QueryKind
	ReadOnlyStatement         string
	CollectionIntervalSeconds int
	TimeoutSeconds            int
	MaxRows                   int
	MaxColumns                int
	ValueMappings             []ValueMapping
	LabelMappings             []LabelMapping
	DatabaseVersionRange      string
	PluginVersionRange        string
	CardinalityLimit          int
	QueryDigest               string
	Status                    Status
	CreatedBy                 string
	ApprovedBy                string
	ResourceRevision          uint64
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
}

func (value Revision) Definition() TemplateDefinition {
	return TemplateDefinition{DatabaseFamily: value.DatabaseFamily, Variants: append([]string(nil), value.Variants...), Name: value.Name, Description: value.Description, QueryKind: value.QueryKind, ReadOnlyStatement: value.ReadOnlyStatement, CollectionIntervalSeconds: value.CollectionIntervalSeconds, TimeoutSeconds: value.TimeoutSeconds, MaxRows: value.MaxRows, MaxColumns: value.MaxColumns, ValueMappings: append([]ValueMapping(nil), value.ValueMappings...), LabelMappings: append([]LabelMapping(nil), value.LabelMappings...), DatabaseVersionRange: value.DatabaseVersionRange, PluginVersionRange: value.PluginVersionRange, CardinalityLimit: value.CardinalityLimit}
}

func (value Revision) Public() ValidatedDefinition {
	return ValidatedDefinition{DatabaseFamily: value.DatabaseFamily, Variants: append([]string(nil), value.Variants...), Name: value.Name, Description: value.Description, QueryKind: value.QueryKind, CollectionIntervalSeconds: value.CollectionIntervalSeconds, TimeoutSeconds: value.TimeoutSeconds, MaxRows: value.MaxRows, MaxColumns: value.MaxColumns, ValueMappings: append([]ValueMapping(nil), value.ValueMappings...), LabelMappings: append([]LabelMapping(nil), value.LabelMappings...), DatabaseVersionRange: value.DatabaseVersionRange, PluginVersionRange: value.PluginVersionRange, CardinalityLimit: value.CardinalityLimit, QueryDigest: value.QueryDigest}
}

func (value Revision) Validate() error {
	if !idPattern.MatchString(value.ID) || value.Scope.Validate() != nil || !templateIDPattern.MatchString(value.TemplateID) || value.Revision == 0 || !value.Status.Valid() || !idPattern.MatchString(value.CreatedBy) || value.ApprovedBy != "" && (!idPattern.MatchString(value.ApprovedBy) || value.ApprovedBy == value.CreatedBy) || value.ResourceRevision == 0 || !validUTC(value.CreatedAt) || !validUTC(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) || !digestPattern.MatchString(value.QueryDigest) {
		return ErrInvalid
	}
	if !validDefinitionShape(value.Definition()) || DefinitionDigest(value.ReadOnlyStatement) != value.QueryDigest {
		return ErrInvalid
	}
	if (value.Status == StatusApproved || value.Status == StatusPublished || value.Status == StatusSuperseded) != (value.ApprovedBy != "") {
		return ErrInvalid
	}
	return nil
}

func (value Revision) ETag() string {
	if value.ResourceRevision == 0 {
		return ""
	}
	return `"` + strconv.FormatUint(value.ResourceRevision, 10) + `"`
}

func (value Revision) Transition(to Status, actor string, at time.Time) (Revision, error) {
	if !to.Valid() || !idPattern.MatchString(actor) || !validUTC(at) || at.Before(value.UpdatedAt) || !allowedTransition(value.Status, to) {
		return Revision{}, ErrInvalidTransition
	}
	if to == StatusApproved && actor == value.CreatedBy {
		return Revision{}, ErrSelfApproval
	}
	next := value
	next.Status = to
	next.ResourceRevision++
	next.UpdatedAt = at
	if to == StatusApproved {
		next.ApprovedBy = actor
	}
	return next, nil
}

func allowedTransition(from, to Status) bool {
	switch from {
	case StatusDraft:
		return to == StatusValidating || to == StatusValidated || to == StatusValidationFailed
	case StatusValidating:
		return to == StatusValidated || to == StatusValidationFailed
	case StatusValidated:
		return to == StatusTrialRunning
	case StatusTrialRunning:
		return to == StatusTrialPassed || to == StatusTrialFailed
	case StatusTrialPassed:
		return to == StatusApprovalPending || to == StatusApproved
	case StatusApprovalPending:
		return to == StatusApproved || to == StatusRejected
	case StatusApproved:
		return to == StatusPublished
	case StatusPublished:
		return to == StatusSuperseded
	default:
		return false
	}
}

type Actor struct {
	Subject            string
	OperationID        string
	IdempotencyKey     string
	RequestFingerprint string
	RequestID          string
	TraceID            string
}

func (value Actor) Validate() error {
	if !idPattern.MatchString(value.Subject) || !idPattern.MatchString(value.OperationID) || !bounded(value.IdempotencyKey, 128, true) || !fingerprintPattern.MatchString(value.RequestFingerprint) || !bounded(value.RequestID, 256, true) || !bounded(value.TraceID, 256, false) {
		return ErrInvalid
	}
	return nil
}

type TrialRequest struct {
	InstanceID      string
	PluginVersionID string
	Actor           Actor
}

func (value TrialRequest) Validate() error {
	if !idPattern.MatchString(value.InstanceID) || !idPattern.MatchString(value.PluginVersionID) || value.Actor.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

type PublishScope struct {
	InstanceIDs []string
	Actor       Actor
	Rollback    bool
}

func (value PublishScope) Validate() error {
	if len(value.InstanceIDs) > MaximumAssignments || value.Actor.Validate() != nil {
		return ErrInvalid
	}
	seen := map[string]struct{}{}
	for _, id := range value.InstanceIDs {
		if !idPattern.MatchString(id) {
			return ErrInvalid
		}
		if _, exists := seen[id]; exists {
			return ErrInvalid
		}
		seen[id] = struct{}{}
	}
	return nil
}

type Filter struct {
	DatabaseFamily string
	Cursor         string
	Limit          int
}

func (value Filter) Validate() error {
	if value.DatabaseFamily != "" && !familyPattern.MatchString(value.DatabaseFamily) || value.Cursor != "" && !cursorPattern.MatchString(value.Cursor) || value.Limit < 0 || value.Limit > MaximumListLimit {
		return ErrInvalid
	}
	return nil
}

type RevisionFilter struct {
	Cursor string
	Limit  int
}

func (value RevisionFilter) Validate() error {
	if value.Cursor != "" && !cursorPattern.MatchString(value.Cursor) || value.Limit < 0 || value.Limit > MaximumListLimit {
		return ErrInvalid
	}
	return nil
}

type TemplatePage struct {
	Items      []Template
	NextCursor string
}
type RevisionPage struct {
	Items      []Revision
	NextCursor string
}

type CandidateMetric struct {
	Name       string            `json:"name"`
	Value      float64           `json:"value"`
	Unit       string            `json:"unit"`
	MetricType MetricType        `json:"metric_type"`
	Labels     map[string]string `json:"labels"`
}

type TrialResult struct {
	RevisionID     string
	QueryDigest    string
	StatusCode     string
	Metrics        []CandidateMetric
	RowCount       int
	ColumnCount    int
	MetricCount    int
	DurationMillis int64
}

func (value TrialResult) Validate() error {
	if !idPattern.MatchString(value.RevisionID) || !digestPattern.MatchString(value.QueryDigest) || !idPattern.MatchString(value.StatusCode) || len(value.Metrics) > 3200 || value.RowCount < 0 || value.RowCount > 100 || value.ColumnCount < 0 || value.ColumnCount > 32 || value.MetricCount != len(value.Metrics) || value.DurationMillis < 0 || value.DurationMillis > 30000 {
		return ErrInvalid
	}
	for _, metric := range value.Metrics {
		if !metricNamePattern.MatchString(metric.Name) || !metric.MetricType.Valid() || !validUnit(metric.Unit) || math.IsNaN(metric.Value) || math.IsInf(metric.Value, 0) || len(metric.Labels) > MaximumLabelMappings {
			return ErrInvalid
		}
		for label, labelValue := range metric.Labels {
			if !validLabel(label) || len([]byte(labelValue)) > 128 || !utf8.ValidString(labelValue) || strings.ContainsAny(labelValue, "\x00\r\n") {
				return ErrInvalid
			}
		}
	}
	return nil
}

func trialLimitFailure(value TrialResult, cardinalityLimit, maxRows, maxColumns int, mappings []ValueMapping, labelMappings []LabelMapping) string {
	if value.RowCount > maxRows || value.ColumnCount > maxColumns {
		return "bounds_exceeded"
	}
	maximum := maxRows * len(mappings)
	if maximum > cardinalityLimit {
		maximum = cardinalityLimit
	}
	if value.MetricCount > maximum {
		return "high_cardinality"
	}
	allowed := map[string]ValueMapping{}
	for _, mapping := range mappings {
		allowed[mapping.MetricName] = mapping
	}
	allowedLabels := map[string]struct{}{}
	for _, mapping := range labelMappings {
		allowedLabels[mapping.Label] = struct{}{}
	}
	series := make(map[string]struct{}, len(value.Metrics))
	for _, metric := range value.Metrics {
		mapping, ok := allowed[metric.Name]
		if !ok || mapping.MetricType != metric.MetricType || mapping.Unit != metric.Unit {
			return "invalid_result"
		}
		for label := range metric.Labels {
			if _, ok := allowedLabels[label]; !ok {
				return "invalid_result"
			}
		}
		labels, _ := json.Marshal(metric.Labels)
		series[metric.Name+"\x00"+string(labels)] = struct{}{}
	}
	if len(series) > cardinalityLimit {
		return "high_cardinality"
	}
	return ""
}

func DefinitionDigest(statement string) string {
	digest := sha256.Sum256([]byte(statement))
	return hex.EncodeToString(digest[:])
}

func normalizedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func bounded(value string, maximum int, required bool) bool {
	if value == "" {
		return !required
	}
	return value == strings.TrimSpace(value) && utf8.ValidString(value) && utf8.RuneCountInString(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n\t")
}

func validUTC(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }
