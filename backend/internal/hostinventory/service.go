package hostinventory

import (
	"context"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

const (
	DefaultStaleAfter   = 2 * time.Minute
	DefaultOfflineAfter = 5 * time.Minute
)

type Service interface {
	RecordObservation(context.Context, Observation) (Host, error)
	List(context.Context, platformscope.Scope, Filter) (Page, error)
	Get(context.Context, platformscope.Scope, string) (Host, error)
	Decommission(context.Context, platformscope.Scope, string, uint64) (Host, error)
}

type ApplicationService struct {
	Repository   Repository
	AgentScopes  AgentScopeResolver
	Now          func() time.Time
	StaleAfter   time.Duration
	OfflineAfter time.Duration
}

func NewService(repository Repository, agentScopes AgentScopeResolver) *ApplicationService {
	return &ApplicationService{Repository: repository, AgentScopes: agentScopes}
}

func (service ApplicationService) RecordObservation(ctx context.Context, observation Observation) (Host, error) {
	if ctx == nil || service.Repository == nil || service.AgentScopes == nil || observation.Validate() != nil {
		return Host{}, ErrInvalid
	}
	scope, err := service.AgentScopes.ScopeForAgent(ctx, observation.AgentID)
	if err != nil {
		return Host{}, err
	}
	if scope.Validate() != nil {
		return Host{}, ErrInvalid
	}
	now, staleAfter, offlineAfter, err := service.classification()
	if err != nil {
		return Host{}, err
	}
	host, err := service.Repository.RecordObservation(ctx, scope, observation, now)
	if err != nil {
		return Host{}, err
	}
	if host.Validate() != nil || host.Scope != scope || host.ID != observation.HostID || host.AgentID != observation.AgentID || host.ObservationRevision < observation.Revision {
		return Host{}, ErrInvalid
	}
	host.Status = ClassifyHost(now, host, staleAfter, offlineAfter)
	return host, nil
}

// RecordHeartbeat is intentionally separate from inventory observations: only
// a verified AgentControl Heartbeat is allowed to establish host liveness.
func (service ApplicationService) RecordHeartbeat(ctx context.Context, agentID string, at time.Time) (Host, error) {
	if ctx == nil || service.Repository == nil || service.AgentScopes == nil || !identifierPattern.MatchString(agentID) || !validUTC(at) {
		return Host{}, ErrInvalid
	}
	scope, err := service.AgentScopes.ScopeForAgent(ctx, agentID)
	if err != nil {
		return Host{}, err
	}
	if scope.Validate() != nil {
		return Host{}, ErrInvalid
	}
	now, staleAfter, offlineAfter, err := service.classification()
	if err != nil {
		return Host{}, err
	}
	host, err := service.Repository.RecordHeartbeat(ctx, scope, agentID, at)
	if err != nil {
		return Host{}, err
	}
	if host.Validate() != nil || host.Scope != scope || host.AgentID != agentID || (host.Status != HostDecommissioned && host.LastHeartbeatAt.Before(at)) {
		return Host{}, ErrInvalid
	}
	host.Status = ClassifyHost(now, host, staleAfter, offlineAfter)
	return host, nil
}

func (service ApplicationService) List(ctx context.Context, scope platformscope.Scope, filter Filter) (Page, error) {
	if ctx == nil || service.Repository == nil || scope.Validate() != nil || filter.Validate() != nil {
		return Page{}, ErrInvalid
	}
	now, staleAfter, offlineAfter, err := service.classification()
	if err != nil {
		return Page{}, err
	}
	filter.now, filter.staleAfter, filter.offlineAfter = now, staleAfter, offlineAfter
	page, err := service.Repository.List(ctx, scope, filter)
	if err != nil {
		return Page{}, err
	}
	for index := range page.Items {
		if page.Items[index].Validate() != nil || page.Items[index].Scope != scope {
			return Page{}, ErrInvalid
		}
		page.Items[index].Status = ClassifyHost(now, page.Items[index], staleAfter, offlineAfter)
		if filter.Status != "" && page.Items[index].Status != filter.Status {
			return Page{}, ErrInvalid
		}
	}
	if page.Items == nil {
		page.Items = []Host{}
	}
	return page, nil
}

func (service ApplicationService) Get(ctx context.Context, scope platformscope.Scope, hostID string) (Host, error) {
	if ctx == nil || service.Repository == nil || scope.Validate() != nil || !identifierPattern.MatchString(hostID) {
		return Host{}, ErrInvalid
	}
	now, staleAfter, offlineAfter, err := service.classification()
	if err != nil {
		return Host{}, err
	}
	host, err := service.Repository.Get(ctx, scope, hostID)
	if err != nil {
		return Host{}, err
	}
	if host.Validate() != nil || host.Scope != scope || host.ID != hostID {
		return Host{}, ErrInvalid
	}
	host.Status = ClassifyHost(now, host, staleAfter, offlineAfter)
	return host, nil
}

func (service ApplicationService) Decommission(ctx context.Context, scope platformscope.Scope, hostID string, expectedVersion uint64) (Host, error) {
	transition, transitionOK := DecommissionTransitionFromContext(ctx)
	if ctx == nil || service.Repository == nil || scope.Validate() != nil || !identifierPattern.MatchString(hostID) || !validPostgresRevision(expectedVersion, false) || !transitionOK {
		return Host{}, ErrInvalid
	}
	now, _, _, err := service.classification()
	if err != nil {
		return Host{}, err
	}
	host, err := service.Repository.Decommission(ctx, scope, hostID, expectedVersion, now, transition)
	if err != nil {
		return Host{}, err
	}
	if host.Validate() != nil || host.Scope != scope || host.ID != hostID || host.Status != HostDecommissioned || host.Version != expectedVersion+1 || host.DecommissionTransition == nil || !host.DecommissionTransition.Matches(transition) {
		return Host{}, ErrInvalid
	}
	return host, nil
}

func (service ApplicationService) classification() (time.Time, time.Duration, time.Duration, error) {
	staleAfter, offlineAfter := service.StaleAfter, service.OfflineAfter
	if staleAfter == 0 {
		staleAfter = DefaultStaleAfter
	}
	if offlineAfter == 0 {
		offlineAfter = DefaultOfflineAfter
	}
	if staleAfter <= 0 || offlineAfter <= staleAfter {
		return time.Time{}, 0, 0, ErrInvalid
	}
	now := time.Now().UTC()
	if service.Now != nil {
		now = service.Now()
	}
	if !validUTC(now) {
		return time.Time{}, 0, 0, ErrInvalid
	}
	return now, staleAfter, offlineAfter, nil
}
