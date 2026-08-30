package agent

import (
	"context"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
)

type DiscoveryCommandRunner interface {
	Execute(context.Context, *agentv1.CommandEnvelope, interface {
		Report(*agentv1.CommandProgress) error
	}) (*agentv1.CommandResult, error)
}

type DiscoveryCommandExecutor struct{ Runner DiscoveryCommandRunner }

func (executor DiscoveryCommandExecutor) Execute(ctx context.Context, envelope *agentv1.CommandEnvelope, reporter ProgressReporter) (*agentv1.CommandResult, error) {
	return executor.Runner.Execute(ctx, envelope, reporter)
}
