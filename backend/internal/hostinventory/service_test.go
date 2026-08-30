package hostinventory

import (
	"context"
	"math"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

var _ Service = (*ApplicationService)(nil)

func TestServiceRecordObservationResolvesTrustedScopeAndDoesNotInventHeartbeat(t *testing.T) {
	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	repository := &recordingRepository{recordObservationResult: validHostFixture()}
	repository.recordObservationResult.LastHeartbeatAt = time.Time{}
	resolver := &fixedAgentScopes{scope: scope}
	service := ApplicationService{Repository: repository, AgentScopes: resolver, Now: func() time.Time { return now }, StaleAfter: time.Minute, OfflineAfter: 5 * time.Minute}

	host, err := service.RecordObservation(context.Background(), validObservationFixture())

	require.NoError(t, err)
	require.Equal(t, scope, repository.recordObservationScope)
	require.Equal(t, now, repository.recordObservationReceivedAt)
	require.Equal(t, HostOffline, host.Status)
	require.Equal(t, 1, resolver.calls)
}

func TestServiceRecordHeartbeatUsesAuthenticatedAgentScope(t *testing.T) {
	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	host := validHostFixture()
	host.LastHeartbeatAt = now
	repository := &recordingRepository{recordHeartbeatResult: host}
	service := ApplicationService{Repository: repository, AgentScopes: &fixedAgentScopes{scope: scope}, Now: func() time.Time { return now }, StaleAfter: time.Minute, OfflineAfter: 5 * time.Minute}

	got, err := service.RecordHeartbeat(context.Background(), "agent-1", now)

	require.NoError(t, err)
	require.Equal(t, scope, repository.recordHeartbeatScope)
	require.Equal(t, "agent-1", repository.recordHeartbeatAgentID)
	require.Equal(t, now, repository.recordHeartbeatAt)
	require.Equal(t, HostOnline, got.Status)
}

func TestServiceRecordHeartbeatClassifiesAgainstCurrentTime(t *testing.T) {
	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	heartbeatAt := now.Add(-2 * time.Minute)
	host := validHostFixture()
	host.LastHeartbeatAt = heartbeatAt
	repository := &recordingRepository{recordHeartbeatResult: host}
	service := ApplicationService{
		Repository: repository, AgentScopes: &fixedAgentScopes{scope: host.Scope}, Now: func() time.Time { return now },
		StaleAfter: time.Minute, OfflineAfter: 5 * time.Minute,
	}

	got, err := service.RecordHeartbeat(context.Background(), host.AgentID, heartbeatAt)

	require.NoError(t, err)
	require.Equal(t, HostStale, got.Status)
}

func TestServiceRecordHeartbeatPreservesDecommissionedHostDuringRace(t *testing.T) {
	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	host := validHostFixture()
	host.Status = HostDecommissioned
	transition := validDecommissionTransition()
	host.DecommissionTransition = &transition
	host.LastHeartbeatAt = now.Add(-time.Hour)
	repository := &recordingRepository{recordHeartbeatResult: host}
	service := ApplicationService{
		Repository: repository, AgentScopes: &fixedAgentScopes{scope: host.Scope}, Now: func() time.Time { return now },
		StaleAfter: time.Minute, OfflineAfter: 5 * time.Minute,
	}

	got, err := service.RecordHeartbeat(context.Background(), host.AgentID, now)

	require.NoError(t, err)
	require.Equal(t, HostDecommissioned, got.Status)
}

func TestServiceListClassifiesUsingHeartbeatAndRejectsOutOfScopeRows(t *testing.T) {
	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	online := validHostFixture()
	online.LastHeartbeatAt = now.Add(-30 * time.Second)
	stale := validHostFixture()
	stale.ID, stale.AgentID, stale.LastHeartbeatAt = "host-2", "agent-2", now.Add(-2*time.Minute)
	repository := &recordingRepository{listResult: Page{Items: []Host{online, stale}, NextCursor: "host-2"}}
	service := ApplicationService{Repository: repository, Now: func() time.Time { return now }, StaleAfter: time.Minute, OfflineAfter: 5 * time.Minute}

	page, err := service.List(context.Background(), scope, Filter{Limit: 10})

	require.NoError(t, err)
	require.Equal(t, HostOnline, page.Items[0].Status)
	require.Equal(t, HostStale, page.Items[1].Status)
	require.Equal(t, "host-2", page.NextCursor)
	require.Equal(t, now, repository.listFilter.now)
	require.Equal(t, time.Minute, repository.listFilter.staleAfter)
	require.Equal(t, 5*time.Minute, repository.listFilter.offlineAfter)

	repository.listResult.Items[1].Scope.ProjectID = "project-2"
	_, err = service.List(context.Background(), scope, Filter{Limit: 10})
	require.ErrorIs(t, err, ErrInvalid)
}

func TestServiceGetAndDecommissionEnforceScopeIdentityAndCAS(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	host := validHostFixture()
	host.Status, host.Version = HostDecommissioned, 3
	transition := validDecommissionTransition()
	host.DecommissionTransition = &transition
	repository := &recordingRepository{getResult: validHostFixture(), decommissionResult: host}
	service := ApplicationService{Repository: repository, Now: func() time.Time { return now }, StaleAfter: time.Minute, OfflineAfter: 5 * time.Minute}

	got, err := service.Get(context.Background(), scope, "host-1")
	require.NoError(t, err)
	require.Equal(t, scope, got.Scope)

	decommissionContext := WithDecommissionTransition(context.Background(), transition)
	got, err = service.Decommission(decommissionContext, scope, "host-1", 2)
	require.NoError(t, err)
	require.Equal(t, HostDecommissioned, got.Status)
	require.Equal(t, uint64(3), got.Version)
	require.Equal(t, uint64(2), repository.decommissionExpectedVersion)
	require.Equal(t, now, repository.decommissionAt)
	require.Equal(t, transition, repository.decommissionTransition)

	repository.decommissionResult.Scope.ProjectID = "project-2"
	_, err = service.Decommission(decommissionContext, scope, "host-1", 2)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestServiceRejectsInvalidWindowsAndInputsBeforeRepository(t *testing.T) {
	repository := &recordingRepository{}
	service := ApplicationService{Repository: repository, Now: time.Now, StaleAfter: 5 * time.Minute, OfflineAfter: time.Minute}

	_, err := service.List(context.Background(), platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, Filter{})
	require.ErrorIs(t, err, ErrInvalid)
	_, err = service.Decommission(context.Background(), platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, "host-1", 0)
	require.ErrorIs(t, err, ErrInvalid)
	service.StaleAfter, service.OfflineAfter = time.Minute, 5*time.Minute
	service.Now = func() time.Time { return time.Now().UTC() }
	_, err = service.Decommission(context.Background(), platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, "host-1", math.MaxUint64)
	require.ErrorIs(t, err, ErrInvalid)
	_, err = service.Decommission(context.Background(), platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, "host-1", 2)
	require.ErrorIs(t, err, ErrInvalid, "decommission requires durable idempotency correlation")
	require.Zero(t, repository.calls)
}

type fixedAgentScopes struct {
	scope platformscope.Scope
	err   error
	calls int
}

func (resolver *fixedAgentScopes) ScopeForAgent(context.Context, string) (platformscope.Scope, error) {
	resolver.calls++
	return resolver.scope, resolver.err
}

type recordingRepository struct {
	calls                       int
	recordObservationScope      platformscope.Scope
	recordObservationReceivedAt time.Time
	recordObservationResult     Host
	recordObservationErr        error
	recordHeartbeatScope        platformscope.Scope
	recordHeartbeatAgentID      string
	recordHeartbeatAt           time.Time
	recordHeartbeatResult       Host
	recordHeartbeatErr          error
	listScope                   platformscope.Scope
	listFilter                  Filter
	listResult                  Page
	listErr                     error
	getResult                   Host
	getErr                      error
	decommissionExpectedVersion uint64
	decommissionAt              time.Time
	decommissionTransition      DecommissionTransition
	decommissionResult          Host
	decommissionErr             error
}

func (repository *recordingRepository) RecordObservation(_ context.Context, scope platformscope.Scope, _ Observation, receivedAt time.Time) (Host, error) {
	repository.calls++
	repository.recordObservationScope = scope
	repository.recordObservationReceivedAt = receivedAt
	return repository.recordObservationResult, repository.recordObservationErr
}

func (repository *recordingRepository) RecordHeartbeat(_ context.Context, scope platformscope.Scope, agentID string, at time.Time) (Host, error) {
	repository.calls++
	repository.recordHeartbeatScope = scope
	repository.recordHeartbeatAgentID = agentID
	repository.recordHeartbeatAt = at
	return repository.recordHeartbeatResult, repository.recordHeartbeatErr
}

func (repository *recordingRepository) List(_ context.Context, scope platformscope.Scope, filter Filter) (Page, error) {
	repository.calls++
	repository.listScope, repository.listFilter = scope, filter
	return repository.listResult, repository.listErr
}

func (repository *recordingRepository) Get(context.Context, platformscope.Scope, string) (Host, error) {
	repository.calls++
	return repository.getResult, repository.getErr
}

func (repository *recordingRepository) Decommission(_ context.Context, _ platformscope.Scope, _ string, expectedVersion uint64, at time.Time, transition DecommissionTransition) (Host, error) {
	repository.calls++
	repository.decommissionExpectedVersion, repository.decommissionAt = expectedVersion, at
	repository.decommissionTransition = transition
	return repository.decommissionResult, repository.decommissionErr
}

var _ Repository = (*recordingRepository)(nil)
