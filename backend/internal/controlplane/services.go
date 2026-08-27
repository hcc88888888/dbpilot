package controlplane

import (
	"context"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/monitoring"
)

// Services contains the dependencies made available to HTTP handlers.
// Monitoring deliberately uses its storage-neutral QueryStore boundary.
type Services struct {
	Repository alert.ControlPlaneRepository
	Evaluator  EvaluatorHealthReader
	Monitoring monitoring.QueryStore
	Now        func() time.Time
	Ready      func(context.Context) error
}
