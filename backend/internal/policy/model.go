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
}
