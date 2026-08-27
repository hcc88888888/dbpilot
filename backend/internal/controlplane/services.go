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
	// MonitoringResponseBytes caps complete monitoring HTTP envelopes for every
	// QueryStore implementation. Zero uses monitoring's conservative default.
	MonitoringResponseBytes int
	Now                     func() time.Time
	Ready                   func(context.Context) error
}
