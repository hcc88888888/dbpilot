//go:build !linux

package pluginsupervisor

import (
	"context"
	"time"
)

type OSProcessRunnerConfig struct {
	OutputLimit     int
	Now             func() time.Time
	FailureObserver func(string, error)
}

type OSProcessRunner struct{}

func NewOSProcessRunner(OSProcessRunnerConfig) *OSProcessRunner { return &OSProcessRunner{} }

func (*OSProcessRunner) Start(context.Context, Executable, LaunchConfiguration) (Process, error) {
	return nil, ErrProcessUnsupported
}

var _ ProcessRunner = (*OSProcessRunner)(nil)

func CurrentProcessIdentity() (uint32, uint32, bool) { return 0, 0, false }
