package agent

import (
	"context"
	"errors"
	"testing"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/commandvalidation"
	"github.com/stretchr/testify/require"
)

func TestCollectNowExecutorValidatesAndCollectsExactlyOnce(t *testing.T) {
	collector := &recordingCollectNowCollector{}
	executor, err := NewCollectNowExecutor(collector)
	require.NoError(t, err)
	envelope := &agentv1.CommandEnvelope{
		AgentId: "agent-a",
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"health"}}},
	}

	result, err := executor.Execute(context.Background(), envelope, nil)

	require.NoError(t, err)
	require.Equal(t, int32(1), collector.calls)
	require.Equal(t, agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, result.GetState())
	require.Equal(t, "dependency telemetry collection completed", result.GetSummary())
	require.Empty(t, result.GetArtifacts(), "CollectNow stores telemetry in the spool and must not invent an Artifact ID")
}

func TestCollectNowExecutorRejectsTargetsBeforeCollection(t *testing.T) {
	collector := &recordingCollectNowCollector{}
	executor, err := NewCollectNowExecutor(collector)
	require.NoError(t, err)
	envelope := &agentv1.CommandEnvelope{
		AgentId: "agent-a",
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{
			CollectionKinds: []string{"health"}, InstanceIds: []string{"instance-a"},
		}},
	}

	result, err := executor.Execute(context.Background(), envelope, nil)

	require.Nil(t, result)
	require.ErrorIs(t, err, commandvalidation.ErrTargetUnauthorized)
	require.Zero(t, collector.calls)
}

func TestCollectNowExecutorRejectsAnotherValidCommandKind(t *testing.T) {
	collector := &recordingCollectNowCollector{}
	executor, err := NewCollectNowExecutor(collector)
	require.NoError(t, err)
	envelope := &agentv1.CommandEnvelope{
		AgentId: "agent-a",
		Command: &agentv1.CommandEnvelope_ExecuteRegisteredProcess{ExecuteRegisteredProcess: &agentv1.ExecuteRegisteredProcess{ProcessId: "safe-process"}},
	}

	result, err := executor.Execute(context.Background(), envelope, nil)

	require.Nil(t, result)
	require.ErrorIs(t, err, commandvalidation.ErrInvalidCommand)
	require.Zero(t, collector.calls)
}

func TestCollectNowExecutorReturnsFixedFailureWithoutCollectorErrorLeakage(t *testing.T) {
	collector := &recordingCollectNowCollector{err: errors.New("postgres://admin:secret@db.internal/production")}
	executor, err := NewCollectNowExecutor(collector)
	require.NoError(t, err)
	envelope := &agentv1.CommandEnvelope{
		AgentId: "agent-a",
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"health"}}},
	}

	result, err := executor.Execute(context.Background(), envelope, nil)

	require.NoError(t, err)
	require.Equal(t, int32(1), collector.calls)
	require.Equal(t, agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, result.GetState())
	require.Equal(t, "COLLECT_NOW_FAILED", result.GetErrorCode())
	require.Equal(t, "dependency telemetry collection failed", result.GetSummary())
	require.NotContains(t, result.String(), "secret")
	require.NotContains(t, result.String(), "db.internal")
	require.Empty(t, result.GetArtifacts())
}

type recordingCollectNowCollector struct {
	calls int32
	err   error
}

func (collector *recordingCollectNowCollector) CollectOnce(context.Context) error {
	collector.calls++
	return collector.err
}
