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
	CommittedReport(context.Context, Report) (bool, error)
	RecordReport(context.Context, Report, time.Time, time.Duration) ([]Candidate, error)
	List(context.Context, platformscope.Scope, Filter) (Page, error)
	Get(context.Context, platformscope.Scope, string) (Candidate, error)
	Ignore(context.Context, platformscope.Scope, string, string, time.Time) (Candidate, error)
}

type RulePolicyRegistry interface {
	Allows(context.Context, RuleAttestation) error
}

type StaticRulePolicyRegistry struct{ Allowed []RuleAttestation }

func (registry StaticRulePolicyRegistry) Allows(ctx context.Context, candidate RuleAttestation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, allowed := range registry.Allowed {
		if sameRulePolicy(allowed, candidate) {
			return nil
		}
	}
	return ErrConflict
}
func sameRulePolicy(left, right RuleAttestation) bool {
	return left.Version == right.Version && left.Algorithm == right.Algorithm && left.KeyID == right.KeyID && left.Revision == right.Revision && left.Digest == right.Digest && left.IssuedAt.Equal(right.IssuedAt) && left.ExpiresAt.Equal(right.ExpiresAt) && left.DisappearanceGrace == right.DisappearanceGrace
}

type Service interface {
	RecordReport(context.Context, Report) ([]Candidate, error)
	List(context.Context, platformscope.Scope, Filter) (Page, error)
	Get(context.Context, platformscope.Scope, string) (Candidate, error)
	Ignore(context.Context, platformscope.Scope, string, string) (Candidate, error)
}
