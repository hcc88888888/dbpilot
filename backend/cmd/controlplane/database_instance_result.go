package main

import (
	"context"
	"errors"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/platformscope"
)

type databaseInstanceResultRecorder struct {
	Store databaseinstance.ValidationResultRecorder
}

func (recorder databaseInstanceResultRecorder) RecordDatabaseInstanceValidationProgress(ctx context.Context, scope platformscope.Scope, jobID, commandID string, command *agentv1.ValidateDatabaseInstance, at time.Time) error {
	if recorder.Store == nil {
		return errors.New("database instance validation result store is unavailable")
	}
	return recorder.Store.RecordValidationProgress(ctx, scope, jobID, commandID, command, at)
}

func (recorder databaseInstanceResultRecorder) RecordDatabaseInstanceValidationResult(ctx context.Context, scope platformscope.Scope, jobID, commandID string, command *agentv1.ValidateDatabaseInstance, result *agentv1.CommandResult, at time.Time) error {
	_, err := recorder.FinalizeDatabaseInstanceValidationResult(ctx, scope, jobID, commandID, command, result, at)
	return err
}

func (recorder databaseInstanceResultRecorder) FinalizeDatabaseInstanceValidationResult(ctx context.Context, scope platformscope.Scope, jobID, commandID string, command *agentv1.ValidateDatabaseInstance, result *agentv1.CommandResult, at time.Time) (*agentv1.CommandResult, error) {
	if recorder.Store == nil || result == nil {
		return nil, errors.New("database instance validation result store is unavailable")
	}
	outcome := databaseinstance.ValidationResult{Status: databaseinstance.ConnectionPluginFailed, ErrorCode: databaseinstance.ConnectionErrorPlugin}
	if result.GetState() == agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED && result.GetErrorCode() == "" {
		outcome = databaseinstance.ValidationResult{Status: databaseinstance.ConnectionSucceeded}
	} else if result.GetState() == agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED {
		switch result.GetErrorCode() {
		case "instance_authentication_failed":
			outcome = databaseinstance.ValidationResult{Status: databaseinstance.ConnectionAuthenticationFailed, ErrorCode: databaseinstance.ConnectionErrorAuthentication}
		case "instance_tls_failed":
			outcome = databaseinstance.ValidationResult{Status: databaseinstance.ConnectionTLSFailed, ErrorCode: databaseinstance.ConnectionErrorTLS}
		case "instance_unreachable":
			outcome = databaseinstance.ValidationResult{Status: databaseinstance.ConnectionUnreachable, ErrorCode: databaseinstance.ConnectionErrorUnreachable}
		case "database_version_unsupported":
			outcome = databaseinstance.ValidationResult{Status: databaseinstance.ConnectionUnsupportedVersion, ErrorCode: databaseinstance.ConnectionErrorUnsupportedVersion}
		}
	}
	effective, err := recorder.Store.FinalizeValidationResult(ctx, scope, jobID, commandID, command, outcome, at)
	if err != nil {
		return nil, err
	}
	return effectiveValidationCommandResult(commandID, result.GetState(), effective), nil
}

func effectiveValidationCommandResult(commandID string, incoming agentv1.CommandResultState, effective databaseinstance.ValidationResult) *agentv1.CommandResult {
	switch incoming {
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED:
		return &agentv1.CommandResult{CommandId: commandID, State: incoming, Summary: "database instance connection validation cancelled"}
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT, agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED:
		return &agentv1.CommandResult{CommandId: commandID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT, Summary: "database instance connection validation timed out"}
	}
	result := &agentv1.CommandResult{CommandId: commandID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, Summary: "database instance connection validation failed", ErrorCode: string(effective.ErrorCode)}
	if effective.Status == databaseinstance.ConnectionSucceeded {
		result.State = agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED
		result.Summary = "database instance connection validation succeeded"
		result.ErrorCode = ""
	}
	return result
}

func (recorder databaseInstanceResultRecorder) ReconcileDatabaseInstanceValidationTerminals(ctx context.Context, at time.Time, limit int) (int, error) {
	if recorder.Store == nil {
		return 0, errors.New("database instance validation result store is unavailable")
	}
	return recorder.Store.ReconcileValidationTerminals(ctx, at, limit)
}
