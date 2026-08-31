//go:build !linux

package pluginsupervisor

import (
	"time"

	"dbpilot.local/platform/internal/agent/pluginstate"
)

func reconcilePersistedProcess(state pluginstate.FamilyState) (pluginstate.FamilyState, bool) {
	if state.ProcessID <= 0 && state.ProcessStartTicks == 0 {
		return state, false
	}
	state.ProcessID, state.ProcessStartTicks, state.StartedAt = 0, 0, time.Time{}
	state.ProcessState, state.HealthState = pluginstate.ProcessStopped, pluginstate.HealthUnknown
	state.LastErrorCode = "agent_restart_reconciled"
	return state, true
}
