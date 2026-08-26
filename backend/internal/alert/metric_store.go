package alert

import (
	"context"
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

const metricInsertSQL = "INSERT INTO metric_samples (tenant_id, project_id, metric, series_fingerprint, labels, value, sampled_at) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING"
const metricQuerySQL = "SELECT tenant_id, project_id, metric, labels, value, sampled_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND metric = $3 AND sampled_at >= $4 AND sampled_at <= $5 ORDER BY sampled_at ASC"

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
	for _, sample := range samples {
		labels, err := marshalMap(sample.Labels)
		if err != nil {
			return fmt.Errorf("encode metric labels: %w", err)
		}
		if _, err := tx.ExecContext(ctx, metricInsertSQL, sample.Scope.TenantID, sample.Scope.ProjectID, sample.Name, SeriesFingerprint(sample.Labels), labels, sample.Value, sample.SampledAt); err != nil {
			return err
		}
	}
	return tx.Commit()
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
		if err := rows.Scan(&sample.Scope.TenantID, &sample.Scope.ProjectID, &sample.Name, &labels, &sample.Value, &sample.SampledAt); err != nil {
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
	if sample.Scope.Validate() != nil || strings.TrimSpace(sample.Name) == "" || sample.SampledAt.IsZero() || math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) {
		return ErrInvalidMetricSample
	}
	return nil
}

func validateMetricQuery(query MetricQuery) error {
	if query.Scope.Validate() != nil || strings.TrimSpace(query.Name) == "" || query.From.IsZero() || query.To.IsZero() || query.To.Before(query.From) {
		return ErrInvalidMetricQuery
	}
	return nil
}

func labelsMatch(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func populateMetricIdentity(sample *MetricSample) {
	sample.InstanceID = sample.Labels["instance"]
	sample.Component = sample.Labels["component"]
	sample.Role = sample.Labels["role"]
	sample.Host = sample.Labels["host"]
}

var _ MetricStore = (*PostgresRepository)(nil)
