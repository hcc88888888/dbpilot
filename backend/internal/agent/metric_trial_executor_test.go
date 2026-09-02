package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/metrictemplatelease"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
	"github.com/stretchr/testify/require"
)

func TestMetricTemplateTrialExecutorLeasesCallsDedicatedRPCAndReturnsTypedResult(t *testing.T) {
	query := []byte("SELECT value FROM metrics")
	leaser := &recordingMetricTemplateLeaser{material: metrictemplatelease.Material{LeaseID: "lease-a", AssignmentID: "assignment-a", InstanceID: "instance-a", TemplateID: "template-a", RevisionID: "revision-a", Revision: 3, ConfigurationRevision: 5, OperationRevision: 7, QueryDigest: stringDigest(query), ExpiresAt: time.Now().Add(time.Minute), StatementBytes: query, CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2, CardinalityLimit: 10, ValueMappings: []metrictemplatelease.ValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: "gauge", Unit: "1"}}}}
	gateway := &recordingMetricTrialGateway{result: plugingateway.TrialResult{Succeeded: true, Metrics: []plugingateway.TrialMetric{{Name: "mysql.custom.value", Value: 4, Unit: "1", MetricType: "gauge", Labels: map[string]string{"role": "primary"}}}, RowCount: 1, ColumnCount: 2, MetricCount: 1, DurationMillis: 3}}
	executor, err := NewMetricTemplateTrialExecutor(leaser, gateway)
	require.NoError(t, err)
	reference := &agentv1.MetricTemplateCommandReference{TemplateId: "template-a", RevisionId: "revision-a", QueryDigest: decodeMetricDigest(t, leaser.material.QueryDigest), TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2, CardinalityLimit: 10}
	envelope := &agentv1.CommandEnvelope{CommandId: "command-a", Command: &agentv1.CommandEnvelope_CollectDatabaseMetrics{CollectDatabaseMetrics: &agentv1.CollectDatabaseMetrics{AssignmentId: "assignment-a", ConfigurationRevision: 5, OperationRevision: 7, InstanceIds: []string{"instance-a"}, TemplateIds: []string{"template-a"}, TemplateRevisions: []*agentv1.MetricTemplateCommandReference{reference}, Trial: true}}}
	reporter := fencedProgressReporter{fence: pluginsupervisor.ExecutionFence{CommandID: "command-a", ExecutionToken: bytesOfAgent(1, 32), LeaseRevision: 1, StartedAt: time.Now().UTC()}}
	result, err := executor.Execute(context.Background(), envelope, &reporter)
	require.NoError(t, err)
	require.Equal(t, agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, result.GetState())
	require.Equal(t, "succeeded", result.GetMetricTemplateTrialResult().GetStatusCode())
	require.Equal(t, "template-a", gateway.definition.GetTemplateId())
	require.Equal(t, uint32(1), result.GetMetricTemplateTrialResult().GetMetricCount())
	require.Equal(t, make([]byte, len(query)), query, "leased query bytes are zeroed on return")
}

func TestMetricTemplateTrialExecutorDropsFailedHighCardinalityRows(t *testing.T) {
	query := []byte("SELECT value FROM metrics")
	leaser := &recordingMetricTemplateLeaser{material: metrictemplatelease.Material{LeaseID: "lease-a", AssignmentID: "assignment-a", InstanceID: "instance-a", TemplateID: "template-a", RevisionID: "revision-a", Revision: 3, ConfigurationRevision: 5, OperationRevision: 7, QueryDigest: stringDigest(query), ExpiresAt: time.Now().Add(time.Minute), StatementBytes: query, CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 20, MaxColumns: 2, CardinalityLimit: 5, ValueMappings: []metrictemplatelease.ValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: "gauge", Unit: "1"}}}}
	gateway := &recordingMetricTrialGateway{result: plugingateway.TrialResult{Succeeded: false, Metrics: []plugingateway.TrialMetric{{Name: "mysql.custom.value", Value: 4, Unit: "1", MetricType: "gauge", Labels: map[string]string{"dimension": "raw-row"}}}, RowCount: 6, ColumnCount: 2, MetricCount: 5, ErrorCode: "high_cardinality"}}
	executor, err := NewMetricTemplateTrialExecutor(leaser, gateway)
	require.NoError(t, err)
	reference := &agentv1.MetricTemplateCommandReference{TemplateId: "template-a", RevisionId: "revision-a", QueryDigest: decodeMetricDigest(t, leaser.material.QueryDigest), TimeoutSeconds: 5, MaxRows: 20, MaxColumns: 2, CardinalityLimit: 5}
	envelope := &agentv1.CommandEnvelope{CommandId: "command-a", Command: &agentv1.CommandEnvelope_CollectDatabaseMetrics{CollectDatabaseMetrics: &agentv1.CollectDatabaseMetrics{AssignmentId: "assignment-a", ConfigurationRevision: 5, OperationRevision: 7, InstanceIds: []string{"instance-a"}, TemplateIds: []string{"template-a"}, TemplateRevisions: []*agentv1.MetricTemplateCommandReference{reference}, Trial: true}}}
	reporter := fencedProgressReporter{fence: pluginsupervisor.ExecutionFence{CommandID: "command-a", ExecutionToken: bytesOfAgent(1, 32), LeaseRevision: 1, StartedAt: time.Now().UTC()}}
	result, err := executor.Execute(context.Background(), envelope, &reporter)
	require.NoError(t, err)
	require.Equal(t, agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, result.GetState())
	require.Equal(t, "METRIC_TEMPLATE_TRIAL_FAILED", result.GetErrorCode())
	require.Equal(t, "high_cardinality", result.GetMetricTemplateTrialResult().GetStatusCode())
	require.Zero(t, result.GetMetricTemplateTrialResult().GetMetricCount())
	require.Empty(t, result.GetMetricTemplateTrialResult().GetCandidateMetrics())
}

type recordingMetricTemplateLeaser struct {
	request  metrictemplatelease.Request
	material metrictemplatelease.Material
}

func (leaser *recordingMetricTemplateLeaser) LeaseMetricTemplate(_ context.Context, request metrictemplatelease.Request) (metrictemplatelease.Material, error) {
	leaser.request = request
	return leaser.material, nil
}

type recordingMetricTrialGateway struct {
	definition *pluginv1.TrialMetricTemplateDefinition
	result     plugingateway.TrialResult
}

func (gateway *recordingMetricTrialGateway) TrialMetricTemplate(_ context.Context, _ string, _, _ uint64, _ string, definition *pluginv1.TrialMetricTemplateDefinition) (plugingateway.TrialResult, error) {
	gateway.definition = definition
	return gateway.result, nil
}

func stringDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
func decodeMetricDigest(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	require.NoError(t, err)
	return decoded
}
