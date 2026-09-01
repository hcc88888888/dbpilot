package metrictemplate

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestPublishedLeaseSurvivesRestartWithoutLiveExecutionFence(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer database.Close()
	now := time.Date(2026, 9, 1, 7, 0, 0, 0, time.UTC)
	statement := "SELECT value FROM metrics"
	rows := leaseAuthorizationRows().AddRow("tenant-a", "project-a", "host-a", "agent-a", "assignment-a", "instance-a", 7, 9, "revision-a", DefinitionDigest(statement), "template-a", 1, []byte(statement), 60, 5, 1, 2, 10, []byte(`[{"source_column":"value","metric_name":"mysql.custom.value","metric_type":"gauge","unit":"1"}]`), []byte(`[]`), false)
	mock.ExpectQuery("FROM plugin_assignment_instances").WillReturnRows(rows)
	authorizer := PostgresLeaseAuthorizer{Database: database, Fences: fixedExecutionFence(false), Now: func() time.Time { return now }}
	authorization, err := authorizer.AuthorizeMetricTemplateLease(context.Background(), AuthenticatedAgent{AgentID: "agent-a", SessionID: "session-restarted"}, LeaseRequest{Nonce: make([]byte, 32), CommandID: "command-reconcile-a", AssignmentID: "assignment-a", InstanceID: "instance-a", ConfigurationRevision: 7, OperationRevision: 9, TemplateID: "template-a", RevisionID: "revision-a", QueryDigest: DefinitionDigest(statement)})
	require.NoError(t, err)
	require.False(t, authorization.Trial)
	require.Equal(t, []byte(statement), authorization.Definition.StatementBytes)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestUnpublishedTrialLeaseRequiresLiveExecutionFence(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer database.Close()
	mock.ExpectQuery("FROM plugin_assignment_instances").WillReturnError(sql.ErrNoRows)
	authorizer := PostgresLeaseAuthorizer{Database: database, Fences: fixedExecutionFence(false)}
	_, err = authorizer.AuthorizeMetricTemplateLease(context.Background(), AuthenticatedAgent{AgentID: "agent-a", SessionID: "session-a"}, LeaseRequest{Nonce: make([]byte, 32), CommandID: "command-trial-a", AssignmentID: "assignment-a", InstanceID: "instance-a", ConfigurationRevision: 7, OperationRevision: 9, TemplateID: "template-a", RevisionID: "revision-a", QueryDigest: strings64("a")})
	require.ErrorIs(t, err, ErrLeaseRejected)
	require.NoError(t, mock.ExpectationsWereMet(), "restart path must not query unpublished trial rows without a live Start fence")
}

func TestUnpublishedTrialLeaseUsesLiveExecutionFence(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer database.Close()
	now := time.Date(2026, 9, 1, 7, 0, 0, 0, time.UTC)
	statement := "SELECT value FROM metrics"
	rows := leaseAuthorizationRows().AddRow("tenant-a", "project-a", "host-a", "agent-a", "assignment-a", "instance-a", 7, 9, "revision-a", DefinitionDigest(statement), "template-a", 1, []byte(statement), 60, 5, 1, 2, 10, []byte(`[{"source_column":"value","metric_name":"mysql.custom.value","metric_type":"gauge","unit":"1"}]`), []byte(`[]`), true)
	mock.ExpectQuery("FROM metric_template_trials").WillReturnRows(rows)
	authorizer := PostgresLeaseAuthorizer{Database: database, Fences: fixedExecutionFence(true), Now: func() time.Time { return now }}
	authorization, err := authorizer.AuthorizeMetricTemplateLease(context.Background(), AuthenticatedAgent{AgentID: "agent-a", SessionID: "session-live"}, LeaseRequest{Nonce: make([]byte, 32), CommandID: "command-trial-a", AssignmentID: "assignment-a", InstanceID: "instance-a", ConfigurationRevision: 7, OperationRevision: 9, TemplateID: "template-a", RevisionID: "revision-a", QueryDigest: DefinitionDigest(statement)})
	require.NoError(t, err)
	require.True(t, authorization.Trial)
	require.NoError(t, mock.ExpectationsWereMet())
}

func leaseAuthorizationRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"tenant_id", "project_id", "host_id", "agent_id", "assignment_id", "instance_id", "configuration_revision", "operation_revision", "revision_id", "query_digest", "template_id", "revision", "read_only_statement", "collection_interval_seconds", "timeout_seconds", "max_rows", "max_columns", "cardinality_limit", "value_mappings", "label_mappings", "trial"})
}

type fixedExecutionFence bool

func (value fixedExecutionFence) ExecutionLeaseActive(string, string, time.Time) bool {
	return bool(value)
}
