//go:build !linux

package pluginsupervisor

import (
	"context"
	"time"
)

type GRPCHealthCheckerConfig struct{ Timeout time.Duration }
type GRPCHealthChecker struct{}

func NewGRPCHealthChecker(GRPCHealthCheckerConfig) *GRPCHealthChecker { return &GRPCHealthChecker{} }
func (*GRPCHealthChecker) Handshake(context.Context, Process, HealthRequest) error {
	return ErrProcessUnsupported
}

var _ HealthChecker = (*GRPCHealthChecker)(nil)
