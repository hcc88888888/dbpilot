//go:build linux

package pluginsupervisor

import (
	"errors"
	"os"
	"syscall"
	"time"

	"dbpilot.local/platform/internal/agent/pluginstate"
)

func reconcilePersistedProcess(state pluginstate.FamilyState) (pluginstate.FamilyState, bool) {
	if state.ProcessID <= 0 && state.ProcessStartTicks == 0 {
		return state, false
	}
	if state.ProcessID > 0 && state.ProcessID != os.Getpid() {
		if startTicks, err := readProcessStartTicks(state.ProcessID); err == nil && startTicks == state.ProcessStartTicks {
			_ = syscall.Kill(-state.ProcessID, syscall.SIGTERM)
			deadline := time.Now().Add(500 * time.Millisecond)
			for time.Now().Before(deadline) {
				if err := syscall.Kill(state.ProcessID, 0); errors.Is(err, syscall.ESRCH) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			_ = syscall.Kill(-state.ProcessID, syscall.SIGKILL)
		}
	}
	state.ProcessID, state.ProcessStartTicks, state.StartedAt = 0, 0, time.Time{}
	state.ProcessState, state.HealthState = pluginstate.ProcessStopped, pluginstate.HealthUnknown
	state.LastErrorCode = "agent_restart_reconciled"
	return state, true
}
