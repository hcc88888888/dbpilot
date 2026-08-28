//go:build linux

package agent

import (
	"context"

	"golang.org/x/sys/unix"
)

func readTimeSync(ctx context.Context) TimeSyncObservation {
	if ctx == nil || ctx.Err() != nil {
		return TimeSyncObservation{}
	}
	var state unix.Timex
	clockState, err := unix.Adjtimex(&state)
	if err != nil {
		return TimeSyncObservation{}
	}
	return TimeSyncObservation{Available: true, Synchronized: clockState != unix.TIME_ERROR && state.Status&unix.STA_UNSYNC == 0}
}
