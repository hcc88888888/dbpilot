package controlplane

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/metrictemplate"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestMetricTemplateRevisionDTOContainsDigestButNeverQueryText(t *testing.T) {
	now := time.Date(2026, 9, 1, 4, 0, 0, 0, time.UTC)
	value := metrictemplate.Revision{ID: "revision-a", Scope: platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, TemplateID: "mysql.custom", Revision: 1, DatabaseFamily: "mysql", Variants: []string{"mysql"}, Name: "Custom", QueryKind: metrictemplate.QuerySQL, ReadOnlyStatement: "SELECT confidential_value FROM customer_table", CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, ValueMappings: []metrictemplate.ValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: metrictemplate.MetricGauge, Unit: "1"}}, LabelMappings: []metrictemplate.LabelMapping{}, CardinalityLimit: 1, QueryDigest: metrictemplate.DefinitionDigest("SELECT confidential_value FROM customer_table"), Status: metrictemplate.StatusDraft, CreatedBy: "creator", ResourceRevision: 1, CreatedAt: now, UpdatedAt: now}

	dto, err := openAPIMetricTemplateRevision(value)
	require.NoError(t, err)
	encoded, err := json.Marshal(dto)
	require.NoError(t, err)
	require.Contains(t, string(encoded), value.QueryDigest)
	require.NotContains(t, string(encoded), value.ReadOnlyStatement)
	require.NotContains(t, string(encoded), "read_only_statement")
	require.False(t, strings.Contains(strings.ToLower(string(encoded)), "customer_table"))
}
