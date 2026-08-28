package agent

import (
	"context"
	"errors"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/commandvalidation"
)

// CollectNowCollector is the configured, trusted collection boundary exposed
// to the typed command executor. DependencyCollector implements it.
type CollectNowCollector interface {
	CollectOnce(context.Context) error
}

// CollectNowExecutor maps one validated CollectNow command to exactly one
// dependency collection. Collection payloads remain in the telemetry spool;
// command results expose only fixed status text and never collector errors.
type CollectNowExecutor struct{ collector CollectNowCollector }

func NewCollectNowExecutor(collector CollectNowCollector) (*CollectNowExecutor, error) {
	if isNilDependencyBoundary(collector) {
		return nil, errors.New("CollectNow collector is required")
	}
	return &CollectNowExecutor{collector: collector}, nil
}

func (executor *CollectNowExecutor) Execute(ctx context.Context, envelope *agentv1.CommandEnvelope, _ ProgressReporter) (*agentv1.CommandResult, error) {
	if executor == nil || isNilDependencyBoundary(executor.collector) {
		return nil, errors.New("CollectNow executor is unavailable")
	}
	if err := commandvalidation.Validate(ctx, envelope, nil); err != nil {
		return nil, err
	}
	if envelope.GetCollectNow() == nil {
		return nil, commandvalidation.ErrInvalidCommand
	}
	if err := executor.collector.CollectOnce(ctx); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return &agentv1.CommandResult{
			State:   agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED,
			Summary: "dependency telemetry collection failed", ErrorCode: "COLLECT_NOW_FAILED",
		}, nil
	}
	return &agentv1.CommandResult{
		State:   agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED,
		Summary: "dependency telemetry collection completed",
	}, nil
}

var _ CommandExecutor = (*CollectNowExecutor)(nil)
