//go:build !linux

package agent

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnsupportedTimeSyncReportsExplicitUnavailableObservation(t *testing.T) {
	require.Equal(t, TimeSyncObservation{}, readTimeSync(context.Background()))
}
