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
	if recorder.Store == nil || result == nil {
		return errors.New("database instance validation result store is unavailable")
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
	return recorder.Store.RecordValidationResult(ctx, scope, jobID, commandID, command, outcome, at)
}

func (recorder databaseInstanceResultRecorder) ReconcileDatabaseInstanceValidationTerminals(ctx context.Context, at time.Time, limit int) (int, error) {
	if recorder.Store == nil {
		return 0, errors.New("database instance validation result store is unavailable")
	}
	return recorder.Store.ReconcileValidationTerminals(ctx, at, limit)
}
