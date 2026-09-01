package mysqlplugin

import (
	"testing"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"github.com/stretchr/testify/require"
)

func TestBuiltinCatalogIsCanonicalAndImmutableByCopy(t *testing.T) {
	catalog := BuiltinCatalog()
	require.Equal(t, []string{"mysql.connections.current", "mysql.queries.total", "mysql.threads.running", "mysql.up", "mysql.uptime.seconds"}, SortedBuiltinTemplateIDs(catalog))
	require.Equal(t, pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, catalog["mysql.connections.current"].MetricType)
	require.Equal(t, pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_COUNTER, catalog["mysql.queries.total"].MetricType)
	require.Equal(t, "{query}", catalog["mysql.queries.total"].Unit)
	require.Equal(t, "s", catalog["mysql.uptime.seconds"].Unit)
	delete(catalog, "mysql.up")
	require.Contains(t, BuiltinCatalog(), "mysql.up")
}

func TestMySQLStatementParserAcceptsSingleReadOnlyQueryAndRejectsDangerousForms(t *testing.T) {
	parser := NewMySQLStatementParser()
	require.NoError(t, parser.Validate("SELECT value FROM performance_schema.global_status"))
	require.NoError(t, parser.Validate("WITH values_cte AS (SELECT 1 AS value) SELECT value FROM values_cte"))
	require.NoError(t, parser.Validate("SELECT COUNT(*) AS value FROM orders"))
	for _, statement := range []string{
		"SELECT 1; SELECT 2",
		"DELETE FROM orders",
		"SELECT * FROM orders FOR UPDATE",
		"SELECT * INTO OUTFILE '/tmp/leak' FROM orders",
		"SELECT SLEEP(1)",
		"SELECT evil_side_effect_udf()",
		"CALL mutate_orders()",
	} {
		require.ErrorIs(t, parser.Validate(statement), ErrStatementRejected, statement)
	}
}

func TestValidateTemplateRepeatsServerHardLimits(t *testing.T) {
	valid := fixtureTemplate("custom-a", 2, "SELECT 1 AS value")
	require.NoError(t, ValidateTemplate(valid, NewMySQLStatementParser()))
	mutations := []func(*pluginv1.MetricTemplateConfiguration){
		func(value *pluginv1.MetricTemplateConfiguration) { value.TemplateId = "Invalid Template" },
		func(value *pluginv1.MetricTemplateConfiguration) { value.CollectionIntervalSeconds = 9 },
		func(value *pluginv1.MetricTemplateConfiguration) { value.CollectionIntervalSeconds = 86401 },
		func(value *pluginv1.MetricTemplateConfiguration) { value.TimeoutSeconds = 31 },
		func(value *pluginv1.MetricTemplateConfiguration) { value.MaxRows = 101 },
		func(value *pluginv1.MetricTemplateConfiguration) { value.MaxColumns = 33 },
		func(value *pluginv1.MetricTemplateConfiguration) {
			value.LabelMappings = make([]*pluginv1.MetricLabelMapping, 17)
		},
		func(value *pluginv1.MetricTemplateConfiguration) { value.ValueMappings = nil },
		func(value *pluginv1.MetricTemplateConfiguration) { value.ValueMappings[0].SourceColumn = "bad\ncolumn" },
		func(value *pluginv1.MetricTemplateConfiguration) { value.ValueMappings[0].MetricName = "MYSQL.Bad" },
		func(value *pluginv1.MetricTemplateConfiguration) { value.ValueMappings[0].Unit = "rows" },
		func(value *pluginv1.MetricTemplateConfiguration) {
			value.LabelMappings = []*pluginv1.MetricLabelMapping{{SourceColumn: "role", Label: "instance_id"}}
		},
		func(value *pluginv1.MetricTemplateConfiguration) {
			value.LabelMappings = []*pluginv1.MetricLabelMapping{{SourceColumn: "role", Label: "dbpilot.role"}}
		},
		func(value *pluginv1.MetricTemplateConfiguration) {
			value.ValueMappings = append(value.ValueMappings, &pluginv1.MetricValueMapping{SourceColumn: "value", MetricName: "mysql.custom.other", MetricType: "gauge", Unit: "1"})
		},
		func(value *pluginv1.MetricTemplateConfiguration) {
			value.ReadOnlyStatement = "SELECT '" + string(make([]byte, 32769)) + "'"
		},
	}
	for _, mutate := range mutations {
		candidate := fixtureTemplate("custom-a", 2, "SELECT 1 AS value")
		mutate(candidate)
		require.ErrorIs(t, ValidateTemplate(candidate, NewMySQLStatementParser()), ErrTemplateRejected)
	}
}
