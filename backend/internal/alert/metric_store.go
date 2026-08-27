package alert

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

var (
	ErrInvalidMetricSample = errors.New("invalid metric sample")
	ErrInvalidMetricQuery  = errors.New("invalid metric query")
)

// MetricSample is a scoped point-in-time observation accepted from an
// authenticated Agent. Scope and AgentID are assigned by the control plane,
// never trusted from the payload.
type MetricSample struct {
	Scope                                Scope
	AgentID, InstanceID, Component, Role string
	Host, Name                           string
	Labels                               map[string]string
	Value                                float64
	SampledAt                            time.Time
}

// MetricQuery selects metric samples within one project and time window.
// Label matching is exact for every supplied key/value pair.
type MetricQuery struct {
	Scope  Scope
	Name   string
	Labels map[string]string
	From   time.Time
	To     time.Time
}

// MetricStore is storage-neutral so alert evaluation never depends on a
// database driver or query representation.
type MetricStore interface {
	Append(context.Context, []MetricSample) error
	Query(context.Context, MetricQuery) ([]MetricSample, error)
}

// AtomicMetricBatchStore commits a durable batch reservation and all samples
// in one transaction. It returns false when another transaction already
// committed the same authenticated Agent/batch pair.
type AtomicMetricBatchStore interface {
	AppendBatch(context.Context, string, string, []MetricSample) (bool, error)
}

const metricInsertSQL = "INSERT INTO metric_samples (tenant_id, project_id, agent_id, metric, series_fingerprint, labels, value, sampled_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING"
const metricBatchReserveSQL = "INSERT INTO ingest_batch_dedup (agent_id, batch_id, state) VALUES ($1, $2, 'processing') ON CONFLICT DO NOTHING RETURNING state"
const metricBatchCommitSQL = "UPDATE ingest_batch_dedup SET state = 'accepted', accepted_at = NOW() WHERE agent_id = $1 AND batch_id = $2"
const metricQuerySQL = "SELECT tenant_id, project_id, agent_id, metric, labels, value, sampled_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND metric = $3 AND sampled_at >= $4 AND sampled_at <= $5 ORDER BY sampled_at ASC, agent_id ASC"

// Append writes an entire batch transactionally. Replayed samples are safe:
// the table's scoped series/timestamp key makes the insert idempotent.
func (r *PostgresRepository) Append(ctx context.Context, samples []MetricSample) error {
	if len(samples) == 0 {
		return nil
	}
	for _, sample := range samples {
		if err := validateMetricSample(sample); err != nil {
			return err
		}
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := appendMetricSamples(ctx, tx, samples); err != nil {
		return err
	}
	return tx.Commit()
}

// AppendBatch serializes competing instances through PostgreSQL's unique-key
// conflict handling. A failed transaction rolls back both reservation and
// samples, so the caller must not acknowledge and a retry can reserve again.
func (r *PostgresRepository) AppendBatch(ctx context.Context, agentID, batchID string, samples []MetricSample) (bool, error) {
	if strings.TrimSpace(agentID) == "" || strings.TrimSpace(batchID) == "" {
		return false, ErrInvalidMetricSample
	}
	for _, sample := range samples {
		if err := validateMetricSample(sample); err != nil || sample.AgentID != agentID {
			return false, ErrInvalidMetricSample
		}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var state string
	err = tx.QueryRowContext(ctx, metricBatchReserveSQL, agentID, batchID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return false, tx.Commit()
	}
	if err != nil {
		return false, err
	}
	if state != "processing" {
		return false, fmt.Errorf("unexpected metric batch reservation state %q", state)
	}
	if err := appendMetricSamples(ctx, tx, samples); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, metricBatchCommitSQL, agentID, batchID)
	if err != nil {
		return false, err
	}
	updated, err := result.RowsAffected()
	if err != nil || updated != 1 {
		return false, errors.New("metric batch reservation commit did not update exactly one row")
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

type metricSampleExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func appendMetricSamples(ctx context.Context, executor metricSampleExecutor, samples []MetricSample) error {
	for _, sample := range samples {
		labels, err := marshalMap(sample.Labels)
		if err != nil {
			return fmt.Errorf("encode metric labels: %w", err)
		}
		if _, err := executor.ExecContext(ctx, metricInsertSQL, sample.Scope.TenantID, sample.Scope.ProjectID, sample.AgentID, sample.Name, metricSeriesFingerprint(sample.AgentID, sample.Labels), labels, sample.Value, sample.SampledAt); err != nil {
			return err
		}
	}
	return nil
}

// Query keeps the relational scope/name/time boundary in SQL, then applies
// label matching in Go so callers are independent of PostgreSQL JSON syntax.
func (r *PostgresRepository) Query(ctx context.Context, query MetricQuery) ([]MetricSample, error) {
	if err := validateMetricQuery(query); err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, metricQuerySQL, query.Scope.TenantID, query.Scope.ProjectID, query.Name, query.From, query.To)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	samples := make([]MetricSample, 0)
	for rows.Next() {
		var sample MetricSample
		var labels []byte
		if err := rows.Scan(&sample.Scope.TenantID, &sample.Scope.ProjectID, &sample.AgentID, &sample.Name, &labels, &sample.Value, &sample.SampledAt); err != nil {
			return nil, err
		}
		if err := unmarshalMap(labels, &sample.Labels); err != nil {
			return nil, err
		}
		populateMetricIdentity(&sample)
		if labelsMatch(sample.Labels, query.Labels) {
			samples = append(samples, sample)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return samples, nil
}

func validateMetricSample(sample MetricSample) error {
	if sample.Scope.Validate() != nil || strings.TrimSpace(sample.AgentID) == "" || strings.TrimSpace(sample.Name) == "" || sample.SampledAt.IsZero() || math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) {
		return ErrInvalidMetricSample
	}
	return ValidateMetricLabels(sample.Labels)
}

var canonicalResourceDimensions = [...]string{"instance", "component", "role", "host"}

// ValidateMetricLabels enforces the canonical resource identity and rejects
// secret-bearing data before it can reach metric storage or event evidence.
func ValidateMetricLabels(labels map[string]string) error {
	if labels == nil {
		return fmt.Errorf("%w: labels are required", ErrInvalidMetricSample)
	}
	if missing := MissingResourceDimensions(labels); len(missing) > 0 {
		return fmt.Errorf("%w: missing canonical resource dimension %s", ErrInvalidMetricSample, strings.Join(missing, ","))
	}
	for key, value := range labels {
		if strings.TrimSpace(key) == "" || sensitiveField(key) || containsSecretMaterial(value) {
			return fmt.Errorf("%w: unsafe metric label", ErrInvalidMetricSample)
		}
	}
	return nil
}

// MissingResourceDimensions returns canonical names in stable order so the
// evaluator can retain secret-safe evidence for malformed historical input.
func MissingResourceDimensions(labels map[string]string) []string {
	missing := make([]string, 0, len(canonicalResourceDimensions))
	for _, dimension := range canonicalResourceDimensions {
		if strings.TrimSpace(labels[dimension]) == "" {
			missing = append(missing, dimension)
		}
	}
	return missing
}

func validateMetricQuery(query MetricQuery) error {
	if query.Scope.Validate() != nil || strings.TrimSpace(query.Name) == "" || query.From.IsZero() || query.To.IsZero() || query.To.Before(query.From) {
		return ErrInvalidMetricQuery
	}
	return nil
}

func labelsMatch(actual, expected map[string]string) bool {
	for key, value := range expected {
		actualValue, ok := actual[key]
		if !ok || actualValue != value {
			return false
		}
	}
	return true
}

func metricSeriesFingerprint(agentID string, labels map[string]string) string {
	seriesLabels := make(map[string]string, len(labels)+1)
	for key, value := range labels {
		seriesLabels[key] = value
	}
	seriesLabels["agent_id"] = agentID
	return SeriesFingerprint(seriesLabels)
}

func populateMetricIdentity(sample *MetricSample) {
	sample.InstanceID = sample.Labels["instance"]
	sample.Component = sample.Labels["component"]
	sample.Role = sample.Labels["role"]
	sample.Host = sample.Labels["host"]
}

var _ MetricStore = (*PostgresRepository)(nil)
var _ AtomicMetricBatchStore = (*PostgresRepository)(nil)
