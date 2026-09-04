package databaseinstance

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
)

func (repository *PostgresRepository) StartValidation(ctx context.Context, scope platformscope.Scope, instanceID string, request ValidationRequest) (job.Job, error) {
	if repository == nil || repository.database == nil || repository.jobs == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(instanceID) || request.Validate() != nil {
		return job.Job{}, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return job.Job{}, err
	}
	rollback := func() { _ = tx.Rollback() }
	if jobID, found, lookupErr := lookupValidationMutation(ctx, tx, scope, instanceID, request); lookupErr != nil {
		rollback()
		return job.Job{}, lookupErr
	} else if found {
		rollback()
		return repository.jobs.Get(ctx, scope, jobID)
	}
	instance, err := getInstanceTxForUpdate(ctx, tx, scope, instanceID)
	if err != nil {
		rollback()
		return job.Job{}, err
	}
	if instance.ManagementStatus == StatusRetired {
		rollback()
		return job.Job{}, ErrConflict
	}
	if instance.PluginID == "" || instance.PluginAssignmentRevision == 0 || instance.CapabilityState == CapabilityPluginNotInstalled {
		rollback()
		return job.Job{}, ErrPluginMissing
	}
	if instance.ConnectionTestStatus == ConnectionQueued || instance.ConnectionTestStatus == ConnectionRunning {
		rollback()
		return job.Job{}, ErrConflict
	}
	target, err := loadValidationTarget(ctx, tx, instance)
	if err != nil {
		rollback()
		return job.Job{}, err
	}
	instance.CapabilityState = CapabilityPluginAvailable
	created, message, err := BuildValidationJob(instance, target, request, databaseTime(ctx, tx))
	if err != nil {
		rollback()
		return job.Job{}, err
	}
	if err := repository.jobs.CreateInTx(ctx, tx, created, []job.OutboxMessage{message}); err != nil {
		rollback()
		return job.Job{}, err
	}
	previousStatus := instance.ManagementStatus
	result, err := tx.ExecContext(ctx, `UPDATE managed_database_instances SET capability_state='plugin_available',connection_test_status='queued',connection_test_error_code='',connection_test_at=$1,management_status='connection_testing',connection_validation_job_id=$6,connection_validation_command_id=$7,revision=revision+1,updated_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND instance_id=$4 AND revision=$5 AND management_status<>'retired' AND connection_validation_job_id='' AND connection_validation_command_id=''`, created.CreatedAt, scope.TenantID, scope.ProjectID, instanceID, instance.Revision, created.ID, message.ID)
	if err != nil {
		rollback()
		return job.Job{}, mapPostgresError(err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		rollback()
		return job.Job{}, ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO database_instance_validations (tenant_id,project_id,job_id,command_id,instance_id,assignment_id,configuration_revision,operation_revision,actor_id,operation_id,idempotency_key,request_fingerprint,request_id,trace_id,previous_management_status,status,error_code,requested_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'queued','',$16)`, scope.TenantID, scope.ProjectID, created.ID, message.ID, instanceID, target.AssignmentID, target.ConfigurationRevision, target.OperationRevision, request.Audit.Actor, request.Audit.OperationID, request.Audit.IdempotencyKey, request.Audit.RequestFingerprint, request.Audit.RequestID, request.Audit.TraceID, previousStatus, created.CreatedAt)
	if err != nil {
		rollback()
		return job.Job{}, mapPostgresError(err)
	}
	if err := insertValidationAudit(ctx, tx, instance, request.Audit, created.ID, message.ID, target, "database_instance.connection_test_started", "success", "", created.CreatedAt); err != nil {
		rollback()
		return job.Job{}, err
	}
	if err := repository.commit(tx); err != nil {
		stored, getErr := repository.jobs.Get(ctx, scope, created.ID)
		if getErr == nil && stored.ID == created.ID && stored.InstanceID == instanceID && stored.SourceResource == created.SourceResource {
			return stored, nil
		}
		return job.Job{}, err
	}
	return repository.jobs.Get(ctx, scope, created.ID)
}

func loadValidationTarget(ctx context.Context, tx *sql.Tx, instance Instance) (ValidationTarget, error) {
	var target ValidationTarget
	var pluginID, desiredState, desiredVersion, installedVersion, processState, health string
	var activeConfiguration, observedOperation, boundCount int64
	err := tx.QueryRowContext(ctx, `SELECT assignment.assignment_id,assignment.plugin_id,assignment.configuration_revision,assignment.operation_revision,assignment.desired_state,assignment.desired_version,observation.installed_version,observation.process_state,observation.health,observation.active_configuration_revision,observation.observed_operation_revision,observation.bound_instance_count FROM plugin_assignment_instances binding JOIN plugin_assignments assignment ON assignment.tenant_id=binding.tenant_id AND assignment.project_id=binding.project_id AND assignment.assignment_id=binding.assignment_id JOIN plugin_observations observation ON observation.tenant_id=assignment.tenant_id AND observation.project_id=assignment.project_id AND observation.assignment_id=assignment.assignment_id WHERE binding.tenant_id=$1 AND binding.project_id=$2 AND binding.instance_id=$3`, instance.Scope.TenantID, instance.Scope.ProjectID, instance.ID).Scan(&target.AssignmentID, &pluginID, &target.ConfigurationRevision, &target.OperationRevision, &desiredState, &desiredVersion, &installedVersion, &processState, &health, &activeConfiguration, &observedOperation, &boundCount)
	if errors.Is(err, sql.ErrNoRows) {
		return ValidationTarget{}, ErrPluginUnavailable
	}
	if err != nil {
		return ValidationTarget{}, mapPostgresError(err)
	}
	if target.Validate() != nil || pluginID != instance.PluginID || target.ConfigurationRevision != instance.PluginAssignmentRevision || desiredState != "running" || desiredVersion != installedVersion || processState != "running" || health != "healthy" || activeConfiguration != int64(target.ConfigurationRevision) || observedOperation != int64(target.OperationRevision) || boundCount < 1 {
		return ValidationTarget{}, ErrPluginUnavailable
	}
	return target, nil
}

func lookupValidationMutation(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, instanceID string, request ValidationRequest) (string, bool, error) {
	var jobID, storedInstance, fingerprint string
	err := tx.QueryRowContext(ctx, `SELECT job_id,instance_id,request_fingerprint FROM database_instance_validations WHERE tenant_id=$1 AND project_id=$2 AND actor_id=$3 AND operation_id=$4 AND idempotency_key=$5`, scope.TenantID, scope.ProjectID, request.Audit.Actor, request.Audit.OperationID, request.Audit.IdempotencyKey).Scan(&jobID, &storedInstance, &fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, mapPostgresError(err)
	}
	if storedInstance != instanceID || fingerprint != request.Audit.RequestFingerprint {
		return "", false, ErrConflict
	}
	return jobID, true, nil
}

func (repository *PostgresRepository) RecordValidationProgress(ctx context.Context, scope platformscope.Scope, jobID, commandID string, command *agentv1.ValidateDatabaseInstance, at time.Time) error {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(jobID) || !identifierPattern.MatchString(commandID) || command == nil || !validUTC(at) {
		return ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	state, err := loadValidationState(ctx, tx, scope, jobID, commandID)
	if err != nil {
		return err
	}
	if !state.matches(command) {
		return ErrConflict
	}
	if state.Status == ConnectionRunning || terminalConnectionStatus(state.Status) {
		return tx.Commit()
	}
	if state.Status != ConnectionQueued {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE database_instance_validations SET status='running',started_at=COALESCE(started_at,$1) WHERE tenant_id=$2 AND project_id=$3 AND job_id=$4 AND command_id=$5 AND status='queued'`, at, scope.TenantID, scope.ProjectID, jobID, commandID); err != nil {
		return mapPostgresError(err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE managed_database_instances SET connection_test_status='running',connection_test_error_code='',connection_test_at=$1,management_status='connection_testing',revision=revision+1,updated_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND instance_id=$4 AND connection_test_status='queued' AND management_status<>'retired' AND connection_validation_job_id=$5 AND connection_validation_command_id=$6`, at, scope.TenantID, scope.ProjectID, state.InstanceID, jobID, commandID)
	if err != nil {
		return mapPostgresError(err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (repository *PostgresRepository) RecordValidationResult(ctx context.Context, scope platformscope.Scope, jobID, commandID string, command *agentv1.ValidateDatabaseInstance, outcome ValidationResult, at time.Time) error {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(jobID) || !identifierPattern.MatchString(commandID) || command == nil || outcome.Validate() != nil || !validUTC(at) {
		return ErrInvalid
	}
	var last error
	for attempt := 0; attempt < 16; attempt++ {
		err := repository.recordValidationResultOnce(ctx, scope, jobID, commandID, command, outcome, at)
		if !isSerializationFailure(err) {
			return err
		}
		last = err
	}
	return last
}

func (repository *PostgresRepository) FinalizeValidationResult(ctx context.Context, scope platformscope.Scope, jobID, commandID string, command *agentv1.ValidateDatabaseInstance, outcome ValidationResult, at time.Time) (ValidationResult, error) {
	if err := repository.RecordValidationResult(ctx, scope, jobID, commandID, command, outcome, at); err != nil {
		return ValidationResult{}, err
	}
	var effective ValidationResult
	err := repository.database.QueryRowContext(ctx, `SELECT status,error_code FROM database_instance_validations WHERE tenant_id=$1 AND project_id=$2 AND job_id=$3 AND command_id=$4`, scope.TenantID, scope.ProjectID, jobID, commandID).Scan(&effective.Status, &effective.ErrorCode)
	if err != nil {
		return ValidationResult{}, mapPostgresError(err)
	}
	if effective.Validate() != nil {
		return ValidationResult{}, ErrInvalid
	}
	return effective, nil
}

func (repository *PostgresRepository) recordValidationResultOnce(ctx context.Context, scope platformscope.Scope, jobID, commandID string, command *agentv1.ValidateDatabaseInstance, outcome ValidationResult, at time.Time) error {
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	state, err := loadValidationState(ctx, tx, scope, jobID, commandID)
	if err != nil {
		return err
	}
	if !state.matches(command) {
		return ErrConflict
	}
	if terminalConnectionStatus(state.Status) {
		return tx.Commit()
	}
	if state.Status != ConnectionQueued && state.Status != ConnectionRunning {
		return ErrConflict
	}
	if !validationFenceCurrent(ctx, tx, scope, state) {
		outcome = ValidationResult{Status: ConnectionPluginFailed, ErrorCode: ConnectionErrorPlugin}
	}
	management := managementForValidation(outcome.Status, state.PreviousManagementStatus)
	capability := CapabilityPluginAvailable
	if outcome.Status == ConnectionPluginFailed {
		capability = CapabilityPluginFailed
	}
	result, err := tx.ExecContext(ctx, `UPDATE managed_database_instances SET capability_state=$1,connection_test_status=$2,connection_test_error_code=$3,connection_test_at=$4,management_status=$5,connection_validation_job_id='',connection_validation_command_id='',revision=revision+1,updated_at=$4 WHERE tenant_id=$6 AND project_id=$7 AND instance_id=$8 AND connection_test_status IN ('queued','running') AND management_status<>'retired' AND connection_validation_job_id=$9 AND connection_validation_command_id=$10`, capability, outcome.Status, outcome.ErrorCode, at, management, scope.TenantID, scope.ProjectID, state.InstanceID, jobID, commandID)
	if err != nil {
		return mapPostgresError(err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows > 1 {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE database_instance_validations SET status=$1,error_code=$2,started_at=COALESCE(started_at,$3),completed_at=$3 WHERE tenant_id=$4 AND project_id=$5 AND job_id=$6 AND command_id=$7 AND status IN ('queued','running')`, outcome.Status, outcome.ErrorCode, at, scope.TenantID, scope.ProjectID, jobID, commandID); err != nil {
		return mapPostgresError(err)
	}
	instance, err := getInstanceTx(ctx, tx, scope, state.InstanceID)
	if err != nil {
		return err
	}
	action, auditResult := "database_instance.connection_test_failed", "failure"
	if outcome.Status == ConnectionSucceeded {
		action, auditResult = "database_instance.connection_test_succeeded", "success"
	}
	target := ValidationTarget{AssignmentID: state.AssignmentID, ConfigurationRevision: state.ConfigurationRevision, OperationRevision: state.OperationRevision}
	if err := insertValidationAudit(ctx, tx, instance, state.Audit, jobID, commandID, target, action, auditResult, outcome.ErrorCode, at); err != nil {
		return err
	}
	return tx.Commit()
}

func (repository *PostgresRepository) ReconcileValidationTerminals(ctx context.Context, at time.Time, limit int) (int, error) {
	if repository == nil || repository.database == nil || ctx == nil || !validUTC(at) || limit < 1 || limit > 1024 {
		return 0, ErrInvalid
	}
	rows, err := repository.database.QueryContext(ctx, `SELECT validation.tenant_id,validation.project_id,validation.job_id,validation.command_id,validation.assignment_id,validation.instance_id,validation.configuration_revision,value.status,outbox.command_status FROM database_instance_validations validation JOIN jobs value ON value.tenant_id=validation.tenant_id AND value.project_id=validation.project_id AND value.id=validation.job_id JOIN command_outbox outbox ON outbox.tenant_id=validation.tenant_id AND outbox.project_id=validation.project_id AND outbox.id=validation.command_id WHERE validation.status IN ('queued','running') AND (value.status IN ('succeeded','failed','cancelled','timed_out') OR outbox.command_status IN ('succeeded','failed','cancelled','timed_out','rejected')) ORDER BY validation.requested_at,validation.tenant_id,validation.project_id,validation.job_id LIMIT $1`, limit)
	if err != nil {
		return 0, mapPostgresError(err)
	}
	type terminalValidation struct {
		scope                                      platformscope.Scope
		jobID, commandID, assignmentID, instanceID string
		configurationRevision                      uint64
		jobStatus, commandStatus                   string
	}
	values := make([]terminalValidation, 0, limit)
	for rows.Next() {
		var value terminalValidation
		var configuration int64
		if err := rows.Scan(&value.scope.TenantID, &value.scope.ProjectID, &value.jobID, &value.commandID, &value.assignmentID, &value.instanceID, &configuration, &value.jobStatus, &value.commandStatus); err != nil {
			_ = rows.Close()
			return 0, mapPostgresError(err)
		}
		if configuration < 1 {
			_ = rows.Close()
			return 0, ErrInvalid
		}
		value.configurationRevision = uint64(configuration)
		values = append(values, value)
	}
	if err := rows.Close(); err != nil {
		return 0, mapPostgresError(err)
	}
	var reconcileErrors []error
	reconciled := 0
	for _, value := range values {
		outcome := ValidationResult{Status: ConnectionPluginFailed, ErrorCode: ConnectionErrorPlugin}
		if value.jobStatus == string(job.StatusSucceeded) && value.commandStatus == string(job.CommandSucceeded) {
			outcome = ValidationResult{Status: ConnectionSucceeded}
		}
		command := &agentv1.ValidateDatabaseInstance{AssignmentId: value.assignmentID, InstanceId: value.instanceID, ConfigurationRevision: value.configurationRevision}
		if err := repository.RecordValidationResult(ctx, value.scope, value.jobID, value.commandID, command, outcome, at); err != nil {
			if !errors.Is(err, ErrConflict) {
				reconcileErrors = append(reconcileErrors, fmt.Errorf("reconcile database instance validation %q: %w", value.jobID, err))
			}
			continue
		}
		reconciled++
	}
	return reconciled, errors.Join(reconcileErrors...)
}

func (repository *PostgresRepository) ListValidationJobRepairs(ctx context.Context, at time.Time, limit int) ([]ValidationJobRepair, error) {
	if repository == nil || repository.database == nil || ctx == nil || !validUTC(at) || limit < 1 || limit > 1024 {
		return nil, ErrInvalid
	}
	rows, err := repository.database.QueryContext(ctx, `SELECT validation.tenant_id,validation.project_id,validation.job_id,validation.command_id,outbox.target_id,validation.status,validation.error_code,validation.completed_at,value.status,outbox.command_status FROM database_instance_validations validation JOIN jobs value ON value.tenant_id=validation.tenant_id AND value.project_id=validation.project_id AND value.id=validation.job_id JOIN command_outbox outbox ON outbox.tenant_id=validation.tenant_id AND outbox.project_id=validation.project_id AND outbox.id=validation.command_id AND outbox.job_id=validation.job_id WHERE validation.status IN ('succeeded','authentication_failed','tls_failed','unreachable','unsupported_version','plugin_failed') AND (value.status NOT IN ('succeeded','failed','cancelled','timed_out') OR outbox.command_status NOT IN ('succeeded','failed','cancelled','timed_out','rejected')) ORDER BY validation.completed_at,validation.tenant_id,validation.project_id,validation.job_id LIMIT $1`, limit)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()
	repairs := make([]ValidationJobRepair, 0, limit)
	for rows.Next() {
		var repair ValidationJobRepair
		var jobStatus job.Status
		var commandStatus job.CommandStatus
		if err := rows.Scan(&repair.Scope.TenantID, &repair.Scope.ProjectID, &repair.JobID, &repair.CommandID, &repair.AgentID, &repair.Result.Status, &repair.Result.ErrorCode, &repair.At, &jobStatus, &commandStatus); err != nil {
			return nil, mapPostgresError(err)
		}
		repair.Cause = validationRepairCause(jobStatus, commandStatus)
		repair.At = repair.At.UTC()
		if repair.Scope.Validate() != nil || !identifierPattern.MatchString(repair.JobID) || !identifierPattern.MatchString(repair.CommandID) || !identifierPattern.MatchString(repair.AgentID) || repair.Result.Validate() != nil || !validUTC(repair.At) || repair.Cause == "" {
			return nil, ErrInvalid
		}
		repairs = append(repairs, repair)
	}
	if err := rows.Err(); err != nil {
		return nil, mapPostgresError(err)
	}
	return repairs, nil
}

func validationRepairCause(jobStatus job.Status, commandStatus job.CommandStatus) job.CommandStatus {
	switch commandStatus {
	case job.CommandSucceeded, job.CommandFailed, job.CommandCancelled, job.CommandTimedOut, job.CommandRejected:
		return commandStatus
	}
	switch jobStatus {
	case job.StatusSucceeded:
		return job.CommandSucceeded
	case job.StatusCancelled:
		return job.CommandCancelled
	case job.StatusTimedOut:
		return job.CommandTimedOut
	case job.StatusFailed:
		return job.CommandFailed
	default:
		return job.CommandFailed
	}
}

type validationState struct {
	JobID                    string
	CommandID                string
	InstanceID               string
	AssignmentID             string
	ConfigurationRevision    uint64
	OperationRevision        uint64
	PreviousManagementStatus ManagementStatus
	Status                   ConnectionTestStatus
	ErrorCode                ConnectionTestErrorCode
	Audit                    MutationAudit
}

func (state validationState) matches(command *agentv1.ValidateDatabaseInstance) bool {
	return command != nil && command.GetAssignmentId() == state.AssignmentID && command.GetInstanceId() == state.InstanceID && command.GetConfigurationRevision() == state.ConfigurationRevision
}

func loadValidationState(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, jobID, commandID string) (validationState, error) {
	state := validationState{JobID: jobID, CommandID: commandID}
	var configuration, operation int64
	err := tx.QueryRowContext(ctx, `SELECT instance_id,assignment_id,configuration_revision,operation_revision,previous_management_status,status,error_code,actor_id,operation_id,idempotency_key,request_fingerprint,request_id,trace_id FROM database_instance_validations WHERE tenant_id=$1 AND project_id=$2 AND job_id=$3 AND command_id=$4 FOR UPDATE`, scope.TenantID, scope.ProjectID, jobID, commandID).Scan(&state.InstanceID, &state.AssignmentID, &configuration, &operation, &state.PreviousManagementStatus, &state.Status, &state.ErrorCode, &state.Audit.Actor, &state.Audit.OperationID, &state.Audit.IdempotencyKey, &state.Audit.RequestFingerprint, &state.Audit.RequestID, &state.Audit.TraceID)
	if errors.Is(err, sql.ErrNoRows) {
		return validationState{}, ErrNotFound
	}
	if err != nil {
		return validationState{}, mapPostgresError(err)
	}
	if configuration < 1 || operation < 1 {
		return validationState{}, ErrInvalid
	}
	state.ConfigurationRevision, state.OperationRevision = uint64(configuration), uint64(operation)
	return state, nil
}

func validationFenceCurrent(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, state validationState) bool {
	var configuration, operation int64
	var desiredState, processState, health string
	err := tx.QueryRowContext(ctx, `SELECT assignment.configuration_revision,assignment.operation_revision,assignment.desired_state,observation.process_state,observation.health FROM plugin_assignment_instances binding JOIN plugin_assignments assignment ON assignment.tenant_id=binding.tenant_id AND assignment.project_id=binding.project_id AND assignment.assignment_id=binding.assignment_id JOIN plugin_observations observation ON observation.tenant_id=assignment.tenant_id AND observation.project_id=assignment.project_id AND observation.assignment_id=assignment.assignment_id JOIN managed_database_instances instance ON instance.tenant_id=binding.tenant_id AND instance.project_id=binding.project_id AND instance.instance_id=binding.instance_id WHERE binding.tenant_id=$1 AND binding.project_id=$2 AND binding.assignment_id=$3 AND binding.instance_id=$4 AND instance.connection_validation_job_id=$5 AND instance.connection_validation_command_id=$6`, scope.TenantID, scope.ProjectID, state.AssignmentID, state.InstanceID, state.JobID, state.CommandID).Scan(&configuration, &operation, &desiredState, &processState, &health)
	return err == nil && configuration == int64(state.ConfigurationRevision) && operation == int64(state.OperationRevision) && desiredState == "running" && processState == "running" && health == "healthy"
}

func managementForValidation(status ConnectionTestStatus, previous ManagementStatus) ManagementStatus {
	switch status {
	case ConnectionSucceeded:
		if previous == StatusMonitoring {
			return StatusMonitoring
		}
		return StatusManaged
	case ConnectionAuthenticationFailed:
		return StatusAuthenticationFailed
	case ConnectionTLSFailed:
		return StatusTLSFailed
	case ConnectionUnreachable:
		return StatusUnreachable
	case ConnectionUnsupportedVersion:
		return StatusUnsupportedVersion
	default:
		return StatusPluginFailed
	}
}

func terminalConnectionStatus(status ConnectionTestStatus) bool {
	switch status {
	case ConnectionSucceeded, ConnectionAuthenticationFailed, ConnectionTLSFailed, ConnectionUnreachable, ConnectionUnsupportedVersion, ConnectionPluginFailed:
		return true
	default:
		return false
	}
}

func databaseTime(ctx context.Context, tx *sql.Tx) time.Time {
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now) != nil {
		return time.Time{}
	}
	return now.UTC()
}

func insertValidationAudit(ctx context.Context, tx *sql.Tx, instance Instance, audit MutationAudit, jobID, commandID string, target ValidationTarget, action, result string, code ConnectionTestErrorCode, at time.Time) error {
	identity := instance.Scope.Key() + "\x00" + action + "\x00" + jobID + "\x00" + commandID
	digest := sha256.Sum256([]byte(identity))
	detail, err := json.Marshal(map[string]any{"job_id": jobID, "command_id": commandID, "assignment_id": target.AssignmentID, "configuration_revision": target.ConfigurationRevision, "operation_revision": target.OperationRevision, "error_code": code})
	if err != nil {
		return ErrInvalid
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events (id,tenant_id,project_id,occurred_at,action,actor_type,actor_id,resource_type,resource_id,result,request_id,trace_id,job_id,command_id,dedupe_key,detail,created_at) VALUES ($1,$2,$3,$4,$5,'user',$6,'database_instance',$7,$8,$9,$10,$11,$12,$13,$14,$4) ON CONFLICT (tenant_id,project_id,dedupe_key) WHERE dedupe_key<>'' DO NOTHING`, "audit-dbi-validation-"+hex.EncodeToString(digest[:]), instance.Scope.TenantID, instance.Scope.ProjectID, at, action, audit.Actor, instance.ID, result, audit.RequestID, audit.TraceID, jobID, commandID, "database-instance-validation:"+hex.EncodeToString(digest[:]), detail)
	if err != nil {
		return fmt.Errorf("record database instance validation Audit: %w", err)
	}
	return nil
}

var _ ValidationResultRecorder = (*PostgresRepository)(nil)
var _ ValidationJobRepairSource = (*PostgresRepository)(nil)
