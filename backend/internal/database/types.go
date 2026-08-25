// Package database defines the closed database-adapter boundary used by the
// DBPilot runtime. Credentials remain outside this package's policy-facing
// contracts and are referenced only by a runtime secret URI.
package database

import (
	"context"
	"time"
)

// EngineFamily identifies a database protocol family selected by trusted
// instance configuration. It is never inferred from a driver name.
type EngineFamily string

const (
	MySQLFamily     EngineFamily = "mysql"
	MariaDBFamily   EngineFamily = "mariadb"
	TiDBFamily      EngineFamily = "tidb"
	OceanBaseFamily EngineFamily = "oceanbase"
	PostgresFamily  EngineFamily = "postgres"
	OpenGaussFamily EngineFamily = "opengauss"
	OracleFamily    EngineFamily = "oracle"
	DamengFamily    EngineFamily = "dameng"
	MongoFamily     EngineFamily = "mongo"
	HBaseFamily     EngineFamily = "hbase"
	Neo4JFamily     EngineFamily = "neo4j"
)

// TLSConfig contains non-secret TLS connection settings. Certificate material
// is addressed by runtime secret references so it cannot be included in policy
// documents or connection logs.
type TLSConfig struct {
	Enabled              bool
	ServerName           string
	CASecretRef          string
	CertificateSecretRef string
	KeySecretRef         string
}

// InstanceConfig identifies a database instance and its bounded runtime
// connection settings. SecretRef must identify credentials held by the runtime.
type InstanceConfig struct {
	ID        string
	Family    EngineFamily
	Address   string
	Database  string
	User      string
	SecretRef string

	TLS            TLSConfig
	ConnectTimeout time.Duration
	QueryTimeout   time.Duration
}

// CapabilityMatrix declares the safe operations and registered metric IDs an
// adapter family exposes.
type CapabilityMatrix struct {
	ReadOnlySQL  bool
	Metrics      bool
	Explain      bool
	Transactions bool
	MetricIDs    []string
}

// MetricRow is one numeric result row returned by a registered metric query.
// Keys are declared by the metric template, not supplied by policy SQL.
type MetricRow map[string]float64

// Adapter is the common, deliberately narrow surface implemented by every
// supported database family.
type Adapter interface {
	Family() EngineFamily
	Capabilities() CapabilityMatrix
	Ping(context.Context) error
	QueryMetric(context.Context, string, map[string]any) ([]MetricRow, error)
	Close() error
}

// Factory creates adapters for one registered engine family and declares that
// family's immutable capabilities before an instance is opened.
type Factory interface {
	Capabilities() CapabilityMatrix
	Open(context.Context, InstanceConfig) (Adapter, error)
}

// Registry owns the closed set of adapter factories available to the runtime.
type Registry interface {
	Register(EngineFamily, Factory) error
	Open(context.Context, InstanceConfig) (Adapter, error)
	Capabilities(EngineFamily) (CapabilityMatrix, bool)
}
