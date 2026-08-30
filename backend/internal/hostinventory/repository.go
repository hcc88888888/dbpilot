package hostinventory

import (
	"context"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

type Repository interface {
	RecordObservation(context.Context, platformscope.Scope, Observation, time.Time) (Host, error)
	RecordHello(context.Context, platformscope.Scope, string, time.Time) (Host, error)
	RecordHeartbeat(context.Context, platformscope.Scope, string, time.Time) (Host, error)
	List(context.Context, platformscope.Scope, Filter) (Page, error)
	Get(context.Context, platformscope.Scope, string) (Host, error)
	Decommission(context.Context, platformscope.Scope, string, uint64, time.Time, DecommissionTransition) (Host, error)
}

type AgentScopeResolver interface {
	ScopeForAgent(context.Context, string) (platformscope.Scope, error)
}
