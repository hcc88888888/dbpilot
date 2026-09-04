package main

import (
	"context"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestDatabaseInstanceResultRecorderClassifiesOnlyFixedTerminalOutcomes(t *testing.T) {
	store := &recordingValidationResultStore{}
	recorder := databaseInstanceResultRecorder{Store: store}
	command := &agentv1.ValidateDatabaseInstance{AssignmentId: "assignment-a", InstanceId: "instance-a", ConfigurationRevision: 7}
	at := time.Date(2026, 9, 4, 6, 0, 0, 0, time.UTC)
	require.NoError(t, recorder.RecordDatabaseInstanceValidationProgress(context.Background(), platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, "job-a", "command-a", command, at))
	require.Equal(t, 1, store.progressCalls)

	for _, test := range []struct {
		state agentv1.CommandResultState
		code  string
		want  databaseinstance.ValidationResult
	}{
		{agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, "", databaseinstance.ValidationResult{Status: databaseinstance.ConnectionSucceeded}},
		{agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, "instance_tls_failed", databaseinstance.ValidationResult{Status: databaseinstance.ConnectionTLSFailed, ErrorCode: databaseinstance.ConnectionErrorTLS}},
		{agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT, "", databaseinstance.ValidationResult{Status: databaseinstance.ConnectionPluginFailed, ErrorCode: databaseinstance.ConnectionErrorPlugin}},
	} {
		require.NoError(t, recorder.RecordDatabaseInstanceValidationResult(context.Background(), platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, "job-a", "command-a", command, &agentv1.CommandResult{State: test.state, ErrorCode: test.code}, at))
		require.Equal(t, test.want, store.result)
	}
}

func TestDatabaseInstanceResultRecorderReturnsEffectiveFencedOutcome(t *testing.T) {
	store := &recordingValidationResultStore{effective: databaseinstance.ValidationResult{Status: databaseinstance.ConnectionPluginFailed, ErrorCode: databaseinstance.ConnectionErrorPlugin}}
	recorder := databaseInstanceResultRecorder{Store: store}
	effectiveRecorder, ok := any(recorder).(interface {
		FinalizeDatabaseInstanceValidationResult(context.Context, platformscope.Scope, string, string, *agentv1.ValidateDatabaseInstance, *agentv1.CommandResult, time.Time) (*agentv1.CommandResult, error)
	})
	require.True(t, ok, "validation recorder must return the database-effective fenced outcome")
	if !ok {
		return
	}
	command := &agentv1.ValidateDatabaseInstance{AssignmentId: "assignment-a", InstanceId: "instance-a", ConfigurationRevision: 7}
	incoming := &agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "database instance connection validation succeeded"}

	effective, err := effectiveRecorder.FinalizeDatabaseInstanceValidationResult(context.Background(), platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, "job-a", "command-a", command, incoming, time.Date(2026, 9, 4, 6, 0, 0, 0, time.UTC))

	require.NoError(t, err)
	require.Equal(t, agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, effective.GetState())
	require.Equal(t, "plugin_failed", effective.GetErrorCode())
	require.Equal(t, "database instance connection validation failed", effective.GetSummary())
}

type recordingValidationResultStore struct {
	progressCalls int
	result        databaseinstance.ValidationResult
	effective     databaseinstance.ValidationResult
}

func (store *recordingValidationResultStore) RecordValidationProgress(context.Context, platformscope.Scope, string, string, *agentv1.ValidateDatabaseInstance, time.Time) error {
	store.progressCalls++
	return nil
}
func (store *recordingValidationResultStore) RecordValidationResult(_ context.Context, _ platformscope.Scope, _, _ string, _ *agentv1.ValidateDatabaseInstance, result databaseinstance.ValidationResult, _ time.Time) error {
	store.result = result
	return nil
}
func (store *recordingValidationResultStore) FinalizeValidationResult(_ context.Context, _ platformscope.Scope, _, _ string, _ *agentv1.ValidateDatabaseInstance, result databaseinstance.ValidationResult, _ time.Time) (databaseinstance.ValidationResult, error) {
	store.result = result
	if store.effective.Status != "" {
		return store.effective, nil
	}
	return result, nil
}
func (store *recordingValidationResultStore) ReconcileValidationTerminals(context.Context, time.Time, int) (int, error) {
	return 0, nil
}
