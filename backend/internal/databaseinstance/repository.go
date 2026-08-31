package databaseinstance

import (
	"context"
	"database/sql"

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
}

type Service interface {
	AcceptCandidate(context.Context, platformscope.Scope, string, AcceptCandidateRequest) (Instance, error)
	List(context.Context, platformscope.Scope, Filter) (Page, error)
	Get(context.Context, platformscope.Scope, string) (Instance, error)
	Update(context.Context, platformscope.Scope, string, uint64, Update) (Instance, error)
	Retire(context.Context, platformscope.Scope, string, uint64, MutationAudit) (Instance, error)
}
