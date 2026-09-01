package mysqlplugin

import (
	"context"
	"errors"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
)

const (
	PluginID              = "mysql"
	DatabaseFamily        = "mysql"
	PluginVersion         = "1.0.0"
	ProtocolVersion       = "v1"
	TemplateSchemaVersion = 1
	MaxInstances          = 128
	MaxTemplates          = 128
)

var (
	ErrConfigurationRejected = errors.New("mysql plugin configuration rejected")
	ErrConnectionRejected    = errors.New("mysql plugin connection rejected")
	ErrTemplateRejected      = errors.New("mysql metric template rejected")
	ErrStatementRejected     = errors.New("mysql statement rejected")
	ErrCollectionRejected    = errors.New("mysql collection rejected")
)

type Rows interface {
	Next() bool
	Scan(...any) error
	Columns() ([]string, error)
	Err() error
	Close() error
}

type Pool interface {
	PingContext(context.Context) error
	QueryContext(context.Context, string, ...any) (Rows, error)
	Close() error
}

type Credential struct {
	LeaseID   string
	Revision  uint64
	Username  string
	Secret    []byte
	ExpiresAt time.Time
}

func (credential *Credential) Release() {
	if credential == nil {
		return
	}
	clear(credential.Secret)
}

type TemplateConfig struct {
	ID            string
	Revision      uint64
	Digest        []byte
	Statement     string
	Interval      time.Duration
	Timeout       time.Duration
	MaxRows       uint32
	MaxColumns    uint32
	Cardinality   uint32
	ValueMappings []*pluginv1.MetricValueMapping
	LabelMappings []*pluginv1.MetricLabelMapping
}

func (template *TemplateConfig) Release() {
	if template == nil {
		return
	}
	template.Statement = ""
	clear(template.Digest)
	template.ValueMappings = nil
	template.LabelMappings = nil
}

type InstanceConfig struct {
	ID         string
	Variant    string
	Endpoint   string
	UnixSocket string
	Credential Credential
	Templates  map[string]TemplateConfig
}

func (config *InstanceConfig) Release() {
	if config == nil {
		return
	}
	config.Credential.Release()
	for id, template := range config.Templates {
		template.Release()
		config.Templates[id] = template
	}
}

type Config struct {
	AssignmentID string
	Revision     uint64
	Instances    []InstanceConfig
}

func (config *Config) Release() {
	if config == nil {
		return
	}
	for index := range config.Instances {
		config.Instances[index].Release()
	}
}

type Sample struct {
	Name         string
	Value        float64
	Unit         string
	MetricType   pluginv1.PluginMetricType
	Labels       map[string]string
	SampledAt    time.Time
	CounterReset bool
}

type CollectionStatus int

const (
	CollectionFailed CollectionStatus = iota
	CollectionSucceeded
	CollectionPartial
)

type Batch struct {
	InstanceID       string
	TemplateID       string
	TemplateRevision uint64
	Samples          []Sample
	Status           CollectionStatus
	ErrorCode        string
	CollectedAt      time.Time
	RowCount         uint32
	ColumnCount      uint32
}
