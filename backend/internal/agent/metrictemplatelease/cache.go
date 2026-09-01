// Package metrictemplatelease owns the Agent's memory-only custom template
// lease cache. It deliberately has no filesystem or journal dependency.
package metrictemplatelease

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/plugingateway"
)

var ErrUnavailable = errors.New("metric template lease unavailable")

type Request struct {
	CommandID             string
	AssignmentID          string
	InstanceID            string
	ConfigurationRevision uint64
	OperationRevision     uint64
	TemplateID            string
	RevisionID            string
	QueryDigest           []byte
}

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	metricPattern     = regexp.MustCompile(`^[a-z][a-z0-9_.]{1,127}$`)
	labelPattern      = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

type ValueMapping struct {
	SourceColumn string
	MetricName   string
	MetricType   string
	Unit         string
}

type LabelMapping struct {
	SourceColumn string
	Label        string
}

type Material struct {
	LeaseID, AssignmentID, InstanceID, TemplateID, RevisionID, QueryDigest           string
	Revision                                                                         uint64
	ConfigurationRevision, OperationRevision                                         uint64
	ExpiresAt                                                                        time.Time
	StatementBytes                                                                   []byte
	CollectionIntervalSeconds, TimeoutSeconds, MaxRows, MaxColumns, CardinalityLimit int
	ValueMappings                                                                    []ValueMapping
	LabelMappings                                                                    []LabelMapping
}

func (value Material) clone() Material {
	value.StatementBytes = append([]byte(nil), value.StatementBytes...)
	value.ValueMappings = append([]ValueMapping(nil), value.ValueMappings...)
	value.LabelMappings = append([]LabelMapping(nil), value.LabelMappings...)
	return value
}
func (value *Material) release() {
	if value == nil {
		return
	}
	for index := range value.StatementBytes {
		value.StatementBytes[index] = 0
	}
	value.StatementBytes = nil
	value.ValueMappings = nil
	value.LabelMappings = nil
}

func (value *Material) Release() { value.release() }

type Cache struct {
	now    func() time.Time
	mu     sync.Mutex
	values map[string]Material
	closed bool
}

func NewCache(now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{now: now, values: map[string]Material{}}
}
func (cache *Cache) Store(value Material) error {
	if cache == nil || !validMaterial(value, cache.now().UTC()) {
		return ErrUnavailable
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.closed {
		return ErrUnavailable
	}
	if existing, ok := cache.values[value.RevisionID]; ok {
		existing.release()
	}
	cache.values[value.RevisionID] = value.clone()
	return nil
}

func validMaterial(value Material, now time.Time) bool {
	if !identifierPattern.MatchString(value.LeaseID) || !identifierPattern.MatchString(value.AssignmentID) || !identifierPattern.MatchString(value.InstanceID) || !identifierPattern.MatchString(value.TemplateID) || !identifierPattern.MatchString(value.RevisionID) || value.Revision == 0 || value.ConfigurationRevision == 0 || value.OperationRevision == 0 || len(value.StatementBytes) == 0 || len(value.StatementBytes) > 32768 || statementDigest(value.StatementBytes) != value.QueryDigest || !value.ExpiresAt.After(now) || value.CollectionIntervalSeconds < 10 || value.CollectionIntervalSeconds > 86400 || value.TimeoutSeconds < 1 || value.TimeoutSeconds > 30 || value.MaxRows < 1 || value.MaxRows > 100 || value.MaxColumns < 1 || value.MaxColumns > 32 || value.CardinalityLimit < 1 || value.CardinalityLimit > 10000 || len(value.ValueMappings) == 0 || len(value.ValueMappings) > 32 || len(value.LabelMappings) > 16 {
		return false
	}
	for _, mapping := range value.ValueMappings {
		if !identifierPattern.MatchString(mapping.SourceColumn) || !metricPattern.MatchString(mapping.MetricName) || !validMetricType(mapping.MetricType) || !validUnit(mapping.Unit) {
			return false
		}
	}
	for _, mapping := range value.LabelMappings {
		if !identifierPattern.MatchString(mapping.SourceColumn) || !labelPattern.MatchString(mapping.Label) || strings.HasPrefix(mapping.Label, "dbpilot.") || strings.HasPrefix(mapping.Label, "dbpilot_") {
			return false
		}
	}
	return true
}

func validMetricType(value string) bool {
	return value == "gauge" || value == "monotonic_gauge" || value == "counter" || value == "monotonic_counter"
}

func validUnit(value string) bool {
	return value == "1" || value == "By" || value == "s" || value == "ms" || value == "us" || value == "ns" || value == "%"
}
func (cache *Cache) PluginConfiguration(assignmentID string, configurationRevision uint64, instanceID, variant, endpoint, unixSocket, revisionID string) (plugingateway.PluginConfiguration, error) {
	if cache == nil || assignmentID == "" || configurationRevision == 0 || instanceID == "" || revisionID == "" || (endpoint == "") == (unixSocket == "") {
		return plugingateway.PluginConfiguration{}, ErrUnavailable
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.closed {
		return plugingateway.PluginConfiguration{}, ErrUnavailable
	}
	value, ok := cache.values[revisionID]
	if !ok || value.AssignmentID != assignmentID || value.InstanceID != instanceID || value.ConfigurationRevision != configurationRevision || !value.ExpiresAt.After(cache.now().UTC()) {
		if ok {
			value.release()
			delete(cache.values, revisionID)
		}
		return plugingateway.PluginConfiguration{}, ErrUnavailable
	}
	template := &pluginv1.MetricTemplateConfiguration{TemplateId: value.TemplateID, Revision: value.Revision, QueryDigest: decodeDigest(value.QueryDigest), QueryKind: "sql", ReadOnlyStatement: string(value.StatementBytes), CollectionIntervalSeconds: uint32(value.CollectionIntervalSeconds), TimeoutSeconds: uint32(value.TimeoutSeconds), MaxRows: uint32(value.MaxRows), MaxColumns: uint32(value.MaxColumns), CardinalityLimit: uint32(value.CardinalityLimit)}
	for _, mapping := range value.ValueMappings {
		template.ValueMappings = append(template.ValueMappings, &pluginv1.MetricValueMapping{SourceColumn: mapping.SourceColumn, MetricName: mapping.MetricName, MetricType: string(mapping.MetricType), Unit: mapping.Unit})
	}
	for _, mapping := range value.LabelMappings {
		template.LabelMappings = append(template.LabelMappings, &pluginv1.MetricLabelMapping{SourceColumn: mapping.SourceColumn, Label: mapping.Label})
	}
	instance := &pluginv1.PluginInstanceConfiguration{InstanceId: instanceID, DatabaseVariant: variant, Endpoint: endpoint, UnixSocket: unixSocket, Templates: []*pluginv1.MetricTemplateConfiguration{template}}
	return plugingateway.PluginConfiguration{AssignmentID: assignmentID, ConfigurationRevision: configurationRevision, Instances: []*pluginv1.PluginInstanceConfiguration{instance}}, nil
}
func (cache *Cache) Close() {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	if !cache.closed {
		cache.closed = true
		for key, value := range cache.values {
			value.release()
			delete(cache.values, key)
		}
	}
	cache.mu.Unlock()
}

func ReleasePluginConfiguration(value *plugingateway.PluginConfiguration) {
	if value == nil {
		return
	}
	for _, instance := range value.Instances {
		if instance == nil {
			continue
		}
		for _, template := range instance.Templates {
			if template != nil {
				template.ReadOnlyStatement = ""
				template.ValueMappings = nil
				template.LabelMappings = nil
			}
		}
	}
}
func decodeDigest(value string) []byte {
	if len(value) != 64 {
		return nil
	}
	result := make([]byte, 32)
	for index := 0; index < 32; index++ {
		high, ok1 := hexNibble(value[index*2])
		low, ok2 := hexNibble(value[index*2+1])
		if !ok1 || !ok2 {
			return nil
		}
		result[index] = high<<4 | low
	}
	return result
}
func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}

func statementDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
