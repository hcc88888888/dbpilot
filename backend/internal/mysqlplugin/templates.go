package mysqlplugin

import (
	"crypto/sha256"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/plugincontract"
	"vitess.io/vitess/go/vt/sqlparser"
)

type BuiltinDefinition struct {
	TemplateID string
	SourceName string
	MetricType pluginv1.PluginMetricType
	Unit       string
}

var builtinCatalog = map[string]BuiltinDefinition{
	"mysql.up":                  {TemplateID: "mysql.up", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, Unit: "1"},
	"mysql.connections.current": {TemplateID: "mysql.connections.current", SourceName: "Threads_connected", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, Unit: "1"},
	"mysql.queries.total":       {TemplateID: "mysql.queries.total", SourceName: "Queries", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_COUNTER, Unit: "{query}"},
	"mysql.threads.running":     {TemplateID: "mysql.threads.running", SourceName: "Threads_running", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, Unit: "1"},
	"mysql.uptime.seconds":      {TemplateID: "mysql.uptime.seconds", SourceName: "Uptime", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_GAUGE, Unit: "s"},
}

var (
	templateIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	metricNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_.]{1,127}$`)
	labelPattern      = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

var safeGenericFunctions = map[string]struct{}{
	"abs": {}, "ascii": {}, "bit_length": {}, "ceil": {}, "ceiling": {}, "char_length": {}, "character_length": {},
	"coalesce": {}, "concat": {}, "concat_ws": {}, "database": {}, "date_format": {}, "floor": {}, "greatest": {},
	"hex": {}, "if": {}, "ifnull": {}, "instr": {}, "json_extract": {}, "json_unquote": {}, "lcase": {}, "least": {},
	"left": {}, "length": {}, "locate": {}, "lower": {}, "ltrim": {}, "mod": {}, "nullif": {}, "octet_length": {},
	"power": {}, "rand": {}, "replace": {}, "reverse": {}, "right": {}, "round": {}, "rtrim": {}, "schema": {},
	"strcmp": {}, "substr": {}, "substring": {}, "trim": {}, "ucase": {}, "unhex": {}, "upper": {}, "version": {},
}

func BuiltinCatalog() map[string]BuiltinDefinition {
	result := make(map[string]BuiltinDefinition, len(builtinCatalog))
	for key, value := range builtinCatalog {
		result[key] = value
	}
	return result
}

func BuiltinDescriptors() []*pluginv1.BuiltinMetricTemplateDescriptor {
	catalog := BuiltinCatalog()
	ids := SortedBuiltinTemplateIDs(catalog)
	result := make([]*pluginv1.BuiltinMetricTemplateDescriptor, 0, len(ids))
	for _, id := range ids {
		definition := catalog[id]
		descriptor := &pluginv1.BuiltinMetricTemplateDescriptor{TemplateId: id, Revision: 1, CollectionIntervalSeconds: 10, Metrics: []*pluginv1.BuiltinMetricDescriptor{{MetricName: id, MetricType: definition.MetricType, Unit: definition.Unit}}}
		descriptor.DefinitionDigest = plugincontract.BuiltinDescriptorDigest(descriptor)
		result = append(result, descriptor)
	}
	return result
}

func SortedBuiltinTemplateIDs(catalog map[string]BuiltinDefinition) []string {
	result := make([]string, 0, len(catalog))
	for id := range catalog {
		result = append(result, id)
	}
	slicesSort(result)
	return result
}

type StatementParser interface{ Validate(string) error }

type MySQLStatementParser struct{ parser *sqlparser.Parser }

func NewMySQLStatementParser() MySQLStatementParser {
	return MySQLStatementParser{parser: sqlparser.NewTestParser()}
}

func (parser MySQLStatementParser) Validate(statement string) error {
	trimmed := strings.TrimSpace(statement)
	if trimmed == "" || strings.Contains(trimmed, ";") {
		return ErrStatementRejected
	}
	parsed, err := parser.parser.Parse(trimmed)
	if err != nil {
		return ErrStatementRejected
	}
	if _, ok := parsed.(sqlparser.SelectStatement); !ok {
		return ErrStatementRejected
	}
	if err := sqlparser.Walk(func(node sqlparser.SQLNode) (bool, error) {
		function, ok := node.(*sqlparser.FuncExpr)
		if !ok {
			return true, nil
		}
		if function.Qualifier.String() != "" {
			return false, ErrStatementRejected
		}
		if _, allowed := safeGenericFunctions[strings.ToLower(function.Name.String())]; !allowed {
			return false, ErrStatementRejected
		}
		return true, nil
	}, parsed); err != nil {
		return ErrStatementRejected
	}
	lower := strings.ToLower(sqlparser.String(parsed))
	for _, prohibited := range []string{" into outfile ", " into dumpfile ", " for update", " lock in share mode", "sleep(", "benchmark(", "get_lock(", "release_lock(", "load_file("} {
		if strings.Contains(" "+lower+" ", prohibited) {
			return ErrStatementRejected
		}
	}
	return nil
}

func ValidateTemplate(template *pluginv1.MetricTemplateConfiguration, parser StatementParser) error {
	if template == nil || parser == nil || !templateIDPattern.MatchString(template.GetTemplateId()) || template.GetRevision() == 0 || template.GetQueryKind() != "sql" || template.GetCollectionIntervalSeconds() < 10 || template.GetCollectionIntervalSeconds() > 86400 || template.GetTimeoutSeconds() == 0 || template.GetTimeoutSeconds() > 30 || template.GetMaxRows() == 0 || template.GetMaxRows() > 100 || template.GetMaxColumns() == 0 || template.GetMaxColumns() > 32 || template.GetCardinalityLimit() == 0 || template.GetCardinalityLimit() > 10000 || len(template.GetValueMappings()) == 0 || len(template.GetValueMappings()) > 32 || len(template.GetLabelMappings()) > 16 || len(template.GetReadOnlyStatement()) == 0 || len(template.GetReadOnlyStatement()) > 32768 || template.GetReadOnlyStatement() != strings.TrimSpace(template.GetReadOnlyStatement()) || !utf8.ValidString(template.GetReadOnlyStatement()) || strings.ContainsRune(template.GetReadOnlyStatement(), 0) {
		return ErrTemplateRejected
	}
	digest := sha256.Sum256([]byte(template.GetReadOnlyStatement()))
	if len(template.GetQueryDigest()) != sha256.Size || !equalBytes(digest[:], template.GetQueryDigest()) || parser.Validate(template.GetReadOnlyStatement()) != nil {
		return ErrTemplateRejected
	}
	columns := map[string]struct{}{}
	metrics := map[string]struct{}{}
	for _, mapping := range template.GetValueMappings() {
		if mapping == nil || !boundedIdentifier(mapping.GetSourceColumn()) || !metricNamePattern.MatchString(mapping.GetMetricName()) || !validMetricType(mapping.GetMetricType()) || !validUnit(mapping.GetUnit()) {
			return ErrTemplateRejected
		}
		if _, duplicate := metrics[mapping.GetMetricName()]; duplicate {
			return ErrTemplateRejected
		}
		if _, duplicate := columns[mapping.GetSourceColumn()]; duplicate {
			return ErrTemplateRejected
		}
		metrics[mapping.GetMetricName()] = struct{}{}
		columns[mapping.GetSourceColumn()] = struct{}{}
	}
	labels := map[string]struct{}{}
	for _, mapping := range template.GetLabelMappings() {
		if mapping == nil || !boundedIdentifier(mapping.GetSourceColumn()) || !validLabel(mapping.GetLabel()) {
			return ErrTemplateRejected
		}
		if _, duplicate := labels[mapping.GetLabel()]; duplicate {
			return ErrTemplateRejected
		}
		labels[mapping.GetLabel()] = struct{}{}
		columns[mapping.GetSourceColumn()] = struct{}{}
	}
	if len(columns) > int(template.GetMaxColumns()) {
		return ErrTemplateRejected
	}
	return nil
}

func validMetricType(value string) bool {
	switch value {
	case "gauge", "monotonic_gauge", "counter", "monotonic_counter":
		return true
	}
	return false
}
func validUnit(value string) bool {
	switch value {
	case "1", "By", "s", "ms", "us", "ns", "%":
		return true
	}
	return false
}
func boundedIdentifier(value string) bool {
	return value != "" && len([]byte(value)) <= 128 && utf8.ValidString(value) && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}
func validLabel(value string) bool {
	if !labelPattern.MatchString(value) || strings.HasPrefix(value, "dbpilot.") || strings.HasPrefix(value, "dbpilot_") {
		return false
	}
	switch value {
	case "tenant_id", "project_id", "host_id", "agent_id", "instance_id", "plugin_id", "assignment_id", "template_id", "template_revision", "revision_id", "query", "statement":
		return false
	}
	return true
}
func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var value byte
	for i := range left {
		value |= left[i] ^ right[i]
	}
	return value == 0
}

func slicesSort(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
