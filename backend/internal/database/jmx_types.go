package database

import (
	"context"
	"encoding/json"
	"time"
)

// JSONValue preserves a JMX attribute until its allowlisted metric mapping
// decides how it must be interpreted.
type JSONValue = json.RawMessage

// JMXBean is one bean returned by the read-only JMX JSON endpoint.
type JMXBean struct {
	Name       string               `json:"name"`
	Attributes map[string]JSONValue `json:"-"`
}

// JMXMetricDefinition maps one fixed JMX property to a DBPilot metric.
// Multiplier converts the source value to Unit; zero means one.
type JMXMetricDefinition struct {
	MetricName string
	Unit       string
	Multiplier float64
}

// BeanProperties restricts a bean to its permitted numeric properties.
type BeanProperties map[string]JMXMetricDefinition

// BeanAllowlist is the complete, fixed JMX read boundary for an adapter.
type BeanAllowlist map[string]BeanProperties

// JMXMetricLabels identifies metrics emitted by a component endpoint.
type JMXMetricLabels struct {
	Cluster   string
	Component string
	Role      string
	Host      string
	Instance  string
	Timestamp time.Time
}

// JMXParseStatus tells callers whether a JMX field was ignored or malformed.
type JMXParseStatus string

const (
	JMXParseUnknownBean      JMXParseStatus = "skipped_unknown_bean"
	JMXParseMissingAttribute JMXParseStatus = "missing_attribute"
	JMXParseInvalidAttribute JMXParseStatus = "invalid_attribute"
)

// ParseIssue reports a single skipped bean or property without exposing its
// raw value. Parsing one field never discards other valid metric samples.
type ParseIssue struct {
	Bean     string
	Property string
	Status   JMXParseStatus
}

// JMXClientConfig contains runtime-only connection choices for a JMX client.
// SecretRef is resolved for every request and is never retained in metrics.
type JMXClientConfig struct {
	SecretRef string
	TLS       TLSConfig
	Timeout   time.Duration
}

// JMXClient fetches only fixed, read-only JMX JSON data.
type JMXClient interface {
	Fetch(ctx context.Context, endpoint Endpoint, allowlist BeanAllowlist) ([]JMXBean, error)
}
