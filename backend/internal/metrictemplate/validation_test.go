package metrictemplate

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateDefinitionAcceptsOneBoundedReadOnlyQueryAndAppliesDefaults(t *testing.T) {
	definition := validDefinition()
	definition.TimeoutSeconds = 0
	definition.MaxRows = 0

	validated, err := ValidateDefinition(definition)
	require.NoError(t, err)
	require.Equal(t, 5, validated.TimeoutSeconds)
	require.Equal(t, 1, validated.MaxRows)
	require.Len(t, validated.QueryDigest, 64)
	require.Empty(t, validated.ReadOnlyStatement, "ordinary validated metadata must not retain SQL")
}

func TestValidateDefinitionRejectsUnsafeStructureAndBounds(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*TemplateDefinition)
	}{
		{"multiple statements", func(value *TemplateDefinition) { value.ReadOnlyStatement = "SELECT 1; SELECT 2" }},
		{"line comment", func(value *TemplateDefinition) { value.ReadOnlyStatement = "SELECT 1 -- hidden" }},
		{"block comment", func(value *TemplateDefinition) { value.ReadOnlyStatement = "SELECT /* hidden */ 1" }},
		{"dml cte", func(value *TemplateDefinition) {
			value.ReadOnlyStatement = "WITH changed AS (DELETE FROM t RETURNING id) SELECT id FROM changed"
		}},
		{"select into", func(value *TemplateDefinition) { value.ReadOnlyStatement = "SELECT value INTO archive FROM metrics" }},
		{"locking read", func(value *TemplateDefinition) { value.ReadOnlyStatement = "SELECT value FROM metrics FOR UPDATE" }},
		{"dangerous function", func(value *TemplateDefinition) { value.ReadOnlyStatement = "SELECT pg_sleep(1)" }},
		{"oversized query", func(value *TemplateDefinition) {
			value.ReadOnlyStatement = "SELECT '" + strings.Repeat("x", MaximumStatementBytes) + "'"
		}},
		{"timeout", func(value *TemplateDefinition) { value.TimeoutSeconds = 31 }},
		{"rows", func(value *TemplateDefinition) { value.MaxRows = 101 }},
		{"columns", func(value *TemplateDefinition) { value.MaxColumns = 33 }},
		{"interval", func(value *TemplateDefinition) { value.CollectionIntervalSeconds = 9 }},
		{"cardinality", func(value *TemplateDefinition) { value.CardinalityLimit = 10001 }},
		{"reserved label", func(value *TemplateDefinition) {
			value.LabelMappings = []LabelMapping{{SourceColumn: "tenant", Label: "tenant_id"}}
		}},
		{"noncanonical metric", func(value *TemplateDefinition) { value.ValueMappings[0].MetricName = "MySQL Connections" }},
		{"unknown type", func(value *TemplateDefinition) { value.ValueMappings[0].MetricType = "histogram" }},
		{"unknown unit", func(value *TemplateDefinition) { value.ValueMappings[0].Unit = "megabytes" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validDefinition()
			test.mutate(&value)
			_, err := ValidateDefinition(value)
			require.ErrorIs(t, err, ErrValidationFailed)
		})
	}
}

func TestDialectValidatorIsExplicitAuthoritativeBoundary(t *testing.T) {
	serverValidated, err := ValidateDefinition(validDefinition())
	require.NoError(t, err)
	validator := DeterministicDialectValidator{Validate: func(_ context.Context, value TemplateDefinition) error {
		require.Equal(t, "SELECT value FROM metrics", value.ReadOnlyStatement)
		return ErrDialectRejected
	}}
	_, err = validator.ValidateReadOnly(context.Background(), validDefinition())
	require.ErrorIs(t, err, ErrDialectRejected)
	require.NotEmpty(t, serverValidated.QueryDigest)
}

func validDefinition() TemplateDefinition {
	return TemplateDefinition{
		DatabaseFamily: "mysql", Variants: []string{"mysql"}, Name: "Custom connections", QueryKind: QuerySQL,
		ReadOnlyStatement: "SELECT value FROM metrics", CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2,
		ValueMappings: []ValueMapping{{SourceColumn: "value", MetricName: "mysql.connections.current", MetricType: MetricGauge, Unit: "1"}},
		LabelMappings: []LabelMapping{}, CardinalityLimit: 10,
	}
}
