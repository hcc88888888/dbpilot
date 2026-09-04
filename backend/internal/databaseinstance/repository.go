package databaseinstance

import (
	"context"
	"database/sql"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
)

// AssignmentBinding is the secret-free projection written to an instance
// after the plugin assignment is ensured in the same acceptance transaction.
type AssignmentBinding struct {
	AssignmentID          string
	PluginID              string
	DesiredVersion        string
	ConfigurationRevision uint64
}

type AcceptanceProvisioner interface {
	EnsureForInstanceTx(context.Context, *sql.Tx, Instance, MutationAudit) (AssignmentBinding, error)
}
type RetirementProvisioner interface {
	DetachInstanceTx(context.Context, *sql.Tx, Instance, MutationAudit) error
}
type AcceptanceProvisionerFunc func(context.Context, *sql.Tx, Instance, MutationAudit) (AssignmentBinding, error)

func (function AcceptanceProvisionerFunc) EnsureForInstanceTx(ctx context.Context, tx *sql.Tx, instance Instance, audit MutationAudit) (AssignmentBinding, error) {
	return function(ctx, tx, instance, audit)
}

type Repository interface {
	AcceptCandidate(context.Context, platformscope.Scope, string, AcceptCandidateRequest) (Instance, error)
	List(context.Context, platformscope.Scope, Filter) (Page, error)
	Get(context.Context, platformscope.Scope, string) (Instance, error)
	Update(context.Context, platformscope.Scope, string, uint64, Update) (Instance, error)
	Retire(context.Context, platformscope.Scope, string, uint64, MutationAudit) (Instance, error)
	StartValidation(context.Context, platformscope.Scope, string, ValidationRequest) (job.Job, error)
}

type Service interface {
	AcceptCandidate(context.Context, platformscope.Scope, string, AcceptCandidateRequest) (Instance, error)
	List(context.Context, platformscope.Scope, Filter) (Page, error)
	Get(context.Context, platformscope.Scope, string) (Instance, error)
	Update(context.Context, platformscope.Scope, string, uint64, Update) (Instance, error)
	Retire(context.Context, platformscope.Scope, string, uint64, MutationAudit) (Instance, error)
	StartValidation(context.Context, platformscope.Scope, string, ValidationRequest) (job.Job, error)
}

type ValidationJobStore interface {
	CreateInTx(context.Context, *sql.Tx, job.Job, []job.OutboxMessage) error
	Get(context.Context, platformscope.Scope, string) (job.Job, error)
}

type ValidationResult struct {
	Status    ConnectionTestStatus
	ErrorCode ConnectionTestErrorCode
}

func (result ValidationResult) Validate() error {
	now := time.Now().UTC()
	if !validConnectionTestState(result.Status, result.ErrorCode, &now) || result.Status == ConnectionQueued || result.Status == ConnectionRunning || result.Status == ConnectionNotTested {
		return ErrInvalid
	}
	return nil
}

type ValidationResultRecorder interface {
	RecordValidationProgress(context.Context, platformscope.Scope, string, string, *agentv1.ValidateDatabaseInstance, time.Time) error
	RecordValidationResult(context.Context, platformscope.Scope, string, string, *agentv1.ValidateDatabaseInstance, ValidationResult, time.Time) error
	FinalizeValidationResult(context.Context, platformscope.Scope, string, string, *agentv1.ValidateDatabaseInstance, ValidationResult, time.Time) (ValidationResult, error)
	ReconcileValidationTerminals(context.Context, time.Time, int) (int, error)
}
