//go:build !linux

package agent

import "context"

// Non-Linux builds provide explicit unavailable evidence instead of guessing
// synchronization state from wall-clock behavior.
func readTimeSync(context.Context) TimeSyncObservation { return TimeSyncObservation{} }
