package telemetry

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
)

type lifecycleComponent struct{}

func (lifecycleComponent) Start(context.Context, component.Host) error { return nil }
func (lifecycleComponent) Shutdown(context.Context) error              { return nil }

// If a receiver reports a fatal status after startup, Healthy must surface it
// rather than allowing the Engine to continue reporting ACTIVE.
func TestEmbeddedCandidateHealthyFailsAfterFatalComponentStatus(t *testing.T) {
	candidate := &embeddedCandidate{
		started:    true,
		host:       embeddedHost{extensions: make(map[component.ID]component.Component)},
		processors: []component.Component{lifecycleComponent{}},
		receivers:  []component.Component{lifecycleComponent{}},
	}
	candidate.host.Report(componentstatus.NewFatalErrorEvent(errors.New("receiver stopped")))
	require.Error(t, candidate.Healthy(context.Background()))
}
