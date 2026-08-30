package databaseinstance

import (
	"context"

	"dbpilot.local/platform/internal/platformscope"
)

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
