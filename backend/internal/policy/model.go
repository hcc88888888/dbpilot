// Package policy defines the signed, declarative telemetry policy accepted by
// the DBPilot agent. It deliberately contains no executable configuration.
package policy

import (
	"errors"
	"time"
)

type SourceKind string

const (
	SourceFileLog         SourceKind = "FILE_LOG"
	SourceJournald        SourceKind = "JOURNALD"
	SourceHostMetrics     SourceKind = "HOST_METRICS"
	SourcePrometheus      SourceKind = "PROMETHEUS"
	SourceHTTPJSONMetrics SourceKind = "HTTP_JSON_METRICS"
	SourceSQLMetrics      SourceKind = "SQL_METRICS"
	SourcePluginMetrics   SourceKind = "PLUGIN_METRICS"
)

var (
	ErrInvalidSignature        = errors.New("invalid policy signature")
	ErrExpiredPolicy           = errors.New("expired policy")
	ErrInvalidAgentID          = errors.New("invalid agent ID")
	ErrPolicyVersionRollback   = errors.New("policy version rollback")
	ErrNoSources               = errors.New("policy has no sources")
	ErrDuplicateSourceID       = errors.New("duplicate source ID")
	ErrSourceKindNotAllowed    = errors.New("source kind is not allowed")
	ErrInvalidLimits           = errors.New("invalid policy limits")
	ErrPathTraversal           = errors.New("path traversal is not allowed")
	ErrPathOutsideAllowRoots   = errors.New("path is outside allowed roots")
	ErrForbiddenPath           = errors.New("path is in a forbidden root")
	ErrInvalidEndpoint         = errors.New("invalid metrics endpoint")
	ErrIntervalTooShort        = errors.New("collection interval is below five seconds")
	ErrTooManyLabels           = errors.New("too many labels")
	ErrPluginNotRegistered     = errors.New("plugin is not registered")
	ErrUnsafePluginParameter   = errors.New("unsafe plugin parameter")
	ErrPathResolution          = errors.New("telemetry path resolution failed")
	ErrVersionStore            = errors.New("policy version store error")
	ErrInvalidMetricTemplateID = errors.New("invalid metric template ID")
)

type Policy struct {
	AgentID   string    `json:"agent_id"`
	Version   uint64    `json:"version"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Sources   []Source  `json:"sources"`
	Limits    Limits    `json:"limits"`
}

type Source struct {
	ID       string            `json:"id"`
	Kind     SourceKind        `json:"kind"`
	Path     string            `json:"path,omitempty"`
	Endpoint string            `json:"endpoint,omitempty"`
	Interval time.Duration     `json:"interval"`
	Labels   map[string]string `json:"labels,omitempty"`
	PluginID string            `json:"plugin_id,omitempty"`
	MetricID string            `json:"metric_id,omitempty"`
	Params   map[string]string `json:"params,omitempty"`
}

type Limits struct {
	MaxSpoolBytes   int64 `json:"max_spool_bytes"`
	MaxBatchBytes   int64 `json:"max_batch_bytes"`
	MaxEventsPerSec int64 `json:"max_events_per_sec"`
}

type SignatureEnvelope struct {
	Policy    Policy `json:"policy"`
	Signature []byte `json:"signature"`
}

type ValidationEnvironment struct {
	AllowedRoots   []string
	ForbiddenRoots []string
	PluginIDs      map[string]struct{}
	ResolvePath    func(string) (string, error)
	// PreviousVersion is the last accepted policy version persisted by the agent.
	// A non-zero value requires the incoming policy to be strictly newer.
	PreviousVersion uint64
	// PluginDefinitions is the runtime registry and parameter schema for
	// declarative plugin metric sources.
	PluginDefinitions map[string]PluginDefinition
	VersionStore      VersionStore
}

type PluginDefinition struct {
	Parameters map[string]ParameterSchema
}

type ParameterSchema struct {
	MaxLength    int
	ValuePattern string
}

// MetricType is the signed-policy representation of a numeric metric's
// aggregation semantics. Collectors reject values outside this closed set.
type MetricType string

const (
	MetricGauge   MetricType = "GAUGE"
	MetricCounter MetricType = "COUNTER"
)

// BasicAuth is deliberately narrow: HTTP metric collectors support only a
// configured basic-auth credential or bearer token, never arbitrary request
// construction.
type BasicAuth struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// HTTPJSONMetricSpec describes one value read from a JSON HTTPS endpoint.
// JSONPath accepts only a dot-separated object path; it is not an expression
// language. MaxResponseBytes and Timeout are upper bounds enforced again by
// the collector even when policy validation has already occurred.
type HTTPJSONMetricSpec struct {
	Endpoint             string            `json:"endpoint"`
	MetricName           string            `json:"metric_name"`
	Type                 MetricType        `json:"type,omitempty"`
	JSONPath             string            `json:"json_path"`
	Labels               map[string]string `json:"labels,omitempty"`
	Headers              map[string]string `json:"headers,omitempty"`
	BasicAuth            BasicAuth         `json:"basic_auth,omitempty"`
	BearerToken          string            `json:"bearer_token,omitempty"`
	Timeout              time.Duration     `json:"timeout,omitempty"`
	MaxResponseBytes     int64             `json:"max_response_bytes,omitempty"`
	AllowedRedirectHosts []string          `json:"allowed_redirect_hosts,omitempty"`
	// AllowInsecureHTTP exists only for an explicitly configured legacy
	// endpoint. The collector defaults to HTTPS and callers should leave it
	// false in production policy.
	AllowInsecureHTTP bool `json:"allow_insecure_http,omitempty"`
}

// SQLMetricSpec selects a runtime-owned SQL metric template. Statement and
// SecretRef remain runtime-only compatibility fields and are never signed or
// serialized into a telemetry policy.
type SQLMetricSpec struct {
	MetricID     string            `json:"metric_id"`
	Statement    string            `json:"-"`
	SecretRef    string            `json:"-"`
	MetricName   string            `json:"metric_name"`
	Type         MetricType        `json:"type,omitempty"`
	ValueColumn  string            `json:"value_column,omitempty"`
	LabelColumns []string          `json:"label_columns,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Timeout      time.Duration     `json:"timeout,omitempty"`
	MaxRows      int               `json:"max_rows,omitempty"`
}

// PluginMetricSpec can name a plugin from the local registry and pass only
// declared parameter values. It intentionally contains no executable path,
// shell, argument list, decoder, or environment surface.
type PluginMetricSpec struct {
	PluginID       string            `json:"plugin_id"`
	Params         map[string]string `json:"params,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Timeout        time.Duration     `json:"timeout,omitempty"`
	MaxOutputBytes int64             `json:"max_output_bytes,omitempty"`
}
