package discovery

import (
	"context"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

type AgentBinding struct {
	Scope   platformscope.Scope
	HostID  string
	AgentID string
}

func (binding AgentBinding) Validate() error {
	if binding.Scope.Validate() != nil || !identifierPattern.MatchString(binding.HostID) || !identifierPattern.MatchString(binding.AgentID) {
		return ErrInvalid
	}
	return nil
}

type Repository interface {
	ResolveAgentBinding(context.Context, string) (AgentBinding, error)
	RecordReport(context.Context, Report, time.Time, time.Duration) ([]Candidate, error)
	List(context.Context, platformscope.Scope, Filter) (Page, error)
	Get(context.Context, platformscope.Scope, string) (Candidate, error)
	Ignore(context.Context, platformscope.Scope, string, string, time.Time) (Candidate, error)
}

type Service interface {
	RecordReport(context.Context, Report) ([]Candidate, error)
	List(context.Context, platformscope.Scope, Filter) (Page, error)
	Get(context.Context, platformscope.Scope, string) (Candidate, error)
	Ignore(context.Context, platformscope.Scope, string, string) (Candidate, error)
}
