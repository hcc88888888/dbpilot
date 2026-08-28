package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCollectionCoordinatorSelectsOnlyRequestedCollector(t *testing.T) {
	tests := []struct {
		name string
		kind string
		want []string
	}{
		{name: "host", kind: "host", want: []string{"host"}},
		{name: "dependencies", kind: "dependencies", want: []string{"dependencies"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := []string{}
			coordinator := &CollectionCoordinator{
				Host:         recordingRequestCollector{name: "host", calls: &calls},
				Dependencies: recordingRequestCollector{name: "dependencies", calls: &calls},
			}

			err := coordinator.Collect(context.Background(), CollectionRequest{Kinds: []string{test.kind}})

			require.NoError(t, err)
			require.Equal(t, test.want, calls)
		})
	}
}

func TestCollectionCoordinatorSortsAndDeduplicatesKinds(t *testing.T) {
	calls := []string{}
	coordinator := &CollectionCoordinator{
		Host:         recordingRequestCollector{name: "host", calls: &calls},
		Dependencies: recordingRequestCollector{name: "dependencies", calls: &calls},
	}

	err := coordinator.Collect(context.Background(), CollectionRequest{Kinds: []string{"HOST", "dependencies", "host", " dependencies "}})

	require.NoError(t, err)
	require.Equal(t, []string{"dependencies", "host"}, calls)
}

func TestCollectionCoordinatorRejectsUnknownKindsBeforeCollection(t *testing.T) {
	calls := []string{}
	coordinator := &CollectionCoordinator{
		Host:         recordingRequestCollector{name: "host", calls: &calls},
		Dependencies: recordingRequestCollector{name: "dependencies", calls: &calls},
	}

	err := coordinator.Collect(context.Background(), CollectionRequest{Kinds: []string{"host", "secrets"}})

	require.Error(t, err)
	require.Empty(t, calls)
}

func TestCollectionCoordinatorCancellationStopsRemainingCollectors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := []string{}
	coordinator := &CollectionCoordinator{
		Dependencies: recordingRequestCollector{name: "dependencies", calls: &calls, after: cancel},
		Host:         recordingRequestCollector{name: "host", calls: &calls},
	}

	err := coordinator.Collect(ctx, CollectionRequest{Kinds: []string{"host", "dependencies"}})

	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, []string{"dependencies"}, calls)
}

func TestCollectionCoordinatorRejectsUnavailableTypedNilCollector(t *testing.T) {
	var typedNil *recordingRequestCollector
	err := (&CollectionCoordinator{Host: typedNil}).Collect(context.Background(), CollectionRequest{Kinds: []string{"host"}})
	require.Error(t, err)
}

func TestCollectionCoordinatorPreflightsEveryCollectorBeforeSideEffects(t *testing.T) {
	tests := []struct {
		name        string
		coordinator *CollectionCoordinator
	}{
		{
			name:        "later host unavailable",
			coordinator: &CollectionCoordinator{Dependencies: recordingRequestCollector{name: "dependencies"}},
		},
		{
			name:        "dependencies unavailable",
			coordinator: &CollectionCoordinator{Host: recordingRequestCollector{name: "host"}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := []string{}
			if collector, ok := test.coordinator.Dependencies.(recordingRequestCollector); ok {
				collector.calls = &calls
				test.coordinator.Dependencies = collector
			}
			if collector, ok := test.coordinator.Host.(recordingRequestCollector); ok {
				collector.calls = &calls
				test.coordinator.Host = collector
			}

			err := test.coordinator.Collect(context.Background(), CollectionRequest{Kinds: []string{"host", "dependencies"}})

			require.Error(t, err)
			require.Empty(t, calls)
		})
	}
}

func TestDependencyCollectionAdapterRejectsNonDependencyRequest(t *testing.T) {
	adapter := NewDependencyCollectionAdapter(&DependencyCollector{})
	err := adapter.Collect(context.Background(), CollectionRequest{Kinds: []string{"host"}})
	require.ErrorContains(t, err, "does not include dependencies")
}

type recordingRequestCollector struct {
	name  string
	calls *[]string
	after func()
	err   error
}

func (collector recordingRequestCollector) Collect(_ context.Context, request CollectionRequest) error {
	*collector.calls = append(*collector.calls, collector.name)
	requireNormalizedRequest := request.Kinds
	if len(requireNormalizedRequest) == 0 {
		return errors.New("request kinds were not propagated")
	}
	if collector.after != nil {
		collector.after()
	}
	return collector.err
}
