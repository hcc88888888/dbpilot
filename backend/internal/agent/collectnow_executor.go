package agent

import (
	"context"
	"errors"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/commandvalidation"
)

// CollectNowExecutor maps one validated CollectNow command to exactly one
// selected collection. Collection payloads remain in the telemetry spool;
// command results expose only fixed status text and never collector errors.
type CollectNowExecutor struct{ collector Collector }

func NewCollectNowExecutor(collector Collector) (*CollectNowExecutor, error) {
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
	request, err := normalizeCollectionRequest(CollectionRequest{
		Kinds:       envelope.GetCollectNow().GetCollectionKinds(),
		InstanceIDs: envelope.GetCollectNow().GetInstanceIds(),
	})
	if err == nil {
		err = executor.collector.Collect(ctx, request)
	}
	if err != nil {
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
