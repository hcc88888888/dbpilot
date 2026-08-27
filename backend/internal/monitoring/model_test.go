package monitoring

import (
	"context"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"github.com/stretchr/testify/require"
)

func TestRangeQueryValidateDefaultsAndRejectsMoreThanSevenDays(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	query := RangeQuery{To: now}
	require.NoError(t, query.Validate(now))
	require.Equal(t, now.Add(-time.Hour), query.From)
	require.Equal(t, time.Minute, query.Step)
	require.ErrorIs(t, (&RangeQuery{From: now.Add(-8 * 24 * time.Hour), To: now}).Validate(now), ErrRangeTooLarge)
}

func TestRangeQueryValidateRejectsTooManyBuckets(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	query := RangeQuery{From: now.Add(-time.Hour), To: now, Step: time.Second}

	require.ErrorIs(t, query.Validate(now), ErrTooManyBuckets)
}

func TestClassifySampleMarksTwoIntervalsWithoutUpdateAsStale(t *testing.T) {
	status := ClassifySample(
		time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 27, 9, 29, 0, 0, time.UTC),
		15*time.Minute,
	)
	require.Equal(t, StatusStale, status)
}

func TestClassifyInstanceReturnsOfflineWhenHeartbeatIsStale(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	require.Equal(t, StatusOffline, ClassifyInstance(now, now.Add(-time.Minute), now.Add(-31*time.Minute), 15*time.Minute))
}

func TestBuildSeriesPreservesMissingBucketsAsNull(t *testing.T) {
	series := BuildSeries("host.cpu", time.Unix(0, 0).UTC(), time.Unix(120, 0).UTC(), time.Minute, []SamplePoint{{At: time.Unix(0, 0).UTC(), Value: 12}})
	require.Len(t, series.Buckets, 3)
	require.Nil(t, series.Buckets[1].Value)
}

func TestInstanceDTONeverCarriesRawPayloadOrSecret(t *testing.T) {
	got := RedactInstance(Instance{Labels: map[string]string{"password": "hidden", "engine": "mysql"}, RawPayload: "secret"})
	require.NotContains(t, got.Labels, "password")
	require.Empty(t, got.RawPayload)
	require.Equal(t, "mysql", got.Labels["engine"])
}

func TestInstanceDTORedactsCommonCredentialLabelsAndInlineSecrets(t *testing.T) {
	got := RedactInstance(Instance{
		Labels:       map[string]string{"api_key": "key-1", "access_key": "key-2", "client_secret": "key-3", "engine": "mysql"},
		ErrorSummary: "collector rejected request: password=hunter2",
	})

	require.Equal(t, map[string]string{"engine": "mysql"}, got.Labels)
	require.Empty(t, got.ErrorSummary)
}

func TestMemoryStoreRejectsCrossScopeInstanceAndReturnsCopies(t *testing.T) {
	scope := alert.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	store := NewMemoryStore(
		[]Instance{{ID: "db-1", Scope: scope, Labels: map[string]string{"engine": "mysql"}}},
		nil,
		nil,
	)

	page, err := store.ListInstances(context.Background(), scope, InstanceQuery{Limit: 10})
	require.NoError(t, err)
	page.Items[0].Labels["engine"] = "mutated"

	again, err := store.ListInstances(context.Background(), scope, InstanceQuery{Limit: 10})
	require.NoError(t, err)
	require.Equal(t, "mysql", again.Items[0].Labels["engine"])

	_, err = store.GetInstance(context.Background(), alert.Scope{TenantID: "tenant-b", ProjectID: "project-a"}, "db-1", validRange())
	require.ErrorIs(t, err, ErrInstanceNotFound)
}

func TestMemoryStoreDetailBuildsNullBucketsWithoutMutatingStoredDTO(t *testing.T) {
	scope := alert.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	store := NewMemoryStore(
		[]Instance{{
			ID: "db-1", Scope: scope, Labels: map[string]string{"engine": "mysql", "password": "hidden"}, RawPayload: "raw",
			LastSampleAt: time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC), LastHeartbeatAt: time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC), CollectEvery: time.Hour,
		}},
		[]alert.MetricSample{{Scope: scope, InstanceID: "db-1", Name: "host.cpu", Value: 12, SampledAt: time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)}},
		nil,
	)
	store.SetNow(func() time.Time { return time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC) })

	detail, err := store.GetInstance(context.Background(), scope, "db-1", RangeQuery{From: time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC), Step: time.Hour})
	require.NoError(t, err)
	require.Len(t, detail.Metrics, 1)
	require.Nil(t, detail.Metrics[0].Buckets[1].Value)
	require.NotContains(t, detail.Instance.Labels, "password")
	require.Empty(t, detail.Instance.RawPayload)
}

func TestMemoryStoreDetailUsesNewestNonNilBucketForLatest(t *testing.T) {
	scope := alert.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	store := NewMemoryStore(
		[]Instance{{ID: "db-1", Scope: scope, LastSampleAt: time.Date(2026, 8, 27, 9, 30, 0, 0, time.UTC), LastHeartbeatAt: time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC), CollectEvery: time.Hour}},
		[]alert.MetricSample{{Scope: scope, InstanceID: "db-1", Name: "host.cpu", Value: 12, SampledAt: time.Date(2026, 8, 27, 9, 30, 0, 0, time.UTC)}},
		nil,
	)
	store.SetNow(func() time.Time { return time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC) })

	detail, err := store.GetInstance(context.Background(), scope, "db-1", RangeQuery{From: time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC), Step: time.Hour})
	require.NoError(t, err)
	require.Nil(t, detail.Metrics[0].Buckets[1].Value)
	require.NotNil(t, detail.Instance.Latest["host.cpu"])
	require.Equal(t, 12.0, *detail.Instance.Latest["host.cpu"])
}

func TestMemoryStoreOverviewReturnsClassifiedRedactedInstances(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	scope := alert.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	store := NewMemoryStore([]Instance{{
		ID: "db-1", Scope: scope, Labels: map[string]string{"password": "hidden"},
		LastSampleAt: now.Add(-31 * time.Minute), LastHeartbeatAt: now, CollectEvery: 15 * time.Minute,
	}}, nil, nil)
	store.SetNow(func() time.Time { return now })

	overview, err := store.Overview(context.Background(), scope, RangeQuery{To: now})
	require.NoError(t, err)
	require.Equal(t, 1, overview.Stale)
	require.Equal(t, StatusStale, overview.Instances[0].Status)
	require.NotContains(t, overview.Instances[0].Labels, "password")
}

func TestMemoryStorePagesInStableIDOrderAndCopiesCapabilities(t *testing.T) {
	scope := alert.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	store := NewMemoryStore(
		[]Instance{{ID: "db-2", Scope: scope}, {ID: "db-1", Scope: scope}, {ID: "db-3", Scope: scope}},
		nil,
		[]Capability{{Engine: "mysql", MetricIDs: []string{"host.cpu"}}},
	)

	first, err := store.ListInstances(context.Background(), scope, InstanceQuery{Limit: 2})
	require.NoError(t, err)
	require.Equal(t, []string{"db-1", "db-2"}, []string{first.Items[0].ID, first.Items[1].ID})
	require.Equal(t, 2, first.NextOffset)
	second, err := store.ListInstances(context.Background(), scope, InstanceQuery{Limit: 2, Offset: first.NextOffset})
	require.NoError(t, err)
	require.Equal(t, []string{"db-3"}, []string{second.Items[0].ID})
	require.Zero(t, second.NextOffset)

	capabilities, err := store.Capabilities(context.Background(), scope)
	require.NoError(t, err)
	capabilities[0].MetricIDs[0] = "mutated"
	again, err := store.Capabilities(context.Background(), scope)
	require.NoError(t, err)
	require.Equal(t, "host.cpu", again[0].MetricIDs[0])
}

func validRange() RangeQuery {
	return RangeQuery{From: time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC), Step: time.Minute}
}
