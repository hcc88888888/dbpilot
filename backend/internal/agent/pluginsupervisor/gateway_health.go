package pluginsupervisor

import (
	"context"
	"errors"
	"sync"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/credentialcache"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"dbpilot.local/platform/internal/agent/pluginstate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GatewayHealthChecker makes the Supervisor's activation gate use the same
// private UDS client as all later plugin RPCs. It preserves Task9's exact
// process, executable and inherited-nonce proof before accepting a process.
type GatewayHealthChecker struct {
	client      *plugingateway.Client
	credentials CredentialLeaser
	mu          sync.Mutex
	sessions    map[int]*plugingateway.Session
	streams     map[int]context.CancelFunc
	expiries    map[int]context.CancelFunc
	activation  map[int]gatewayActivation
	cache       *credentialcache.Cache
}

type gatewayActivation struct {
	health pluginstate.HealthState
	code   string
}

func NewGatewayHealthChecker(client *plugingateway.Client) *GatewayHealthChecker {
	return &GatewayHealthChecker{client: client, sessions: make(map[int]*plugingateway.Session), streams: make(map[int]context.CancelFunc), expiries: make(map[int]context.CancelFunc), activation: make(map[int]gatewayActivation), cache: credentialcache.New(time.Now)}
}

func NewGatewayHealthCheckerWithCredentials(client *plugingateway.Client, credentials CredentialLeaser) *GatewayHealthChecker {
	checker := NewGatewayHealthChecker(client)
	checker.credentials = credentials
	return checker
}

func (checker *GatewayHealthChecker) Handshake(ctx context.Context, process Process, request HealthRequest) error {
	if checker == nil || checker.client == nil || process == nil {
		return ErrHealthHandshake
	}
	expected := plugingateway.ExpectedPlugin{
		PID: process.PID(), ExpectedUserID: request.ExpectedUserID, ExpectedGroupID: request.ExpectedGroupID,
		RuntimeDirectory: request.RuntimeDirectory, AssignmentID: request.AssignmentID, PluginID: request.PluginID,
		DatabaseFamily: request.DatabaseFamily, Version: request.Version, ProtocolVersion: request.ProtocolVersion,
		ExecutablePath: request.ExecutablePath, ExecutableSHA256: append([]byte(nil), request.ExecutableSHA256...),
		LaunchNonce: append([]byte(nil), request.LaunchNonce...), ConfigurationRevision: request.ConfigurationRevision,
		OperationRevision: request.OperationRevision, InstanceIDs: append([]string(nil), request.InstanceIDs...), TemplateIDs: append([]string(nil), request.TemplateIDs...),
		SupportedVariants: append([]string(nil), request.SupportedVariants...), SignedCapabilities: append([]string(nil), request.SignedCapabilities...), MetricTemplateSchemaVersion: request.MetricTemplateSchemaVersion,
		TemplateConfigurations: cloneTemplateConfigurations(request.TemplateConfigurations),
	}
	session, err := checker.client.Open(expected)
	if err != nil {
		return ErrHealthHandshake
	}
	if _, err = session.Handshake(ctx, expected); err != nil {
		return ErrHealthHandshake
	}
	if len(request.SupportedVariants) == 0 || len(request.SignedCapabilities) == 0 || request.MetricTemplateSchemaVersion == 0 || len(request.InstanceDescriptors) == 0 {
		checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "plugin_reconcile_unavailable")
		return nil
	}
	if len(request.TemplateConfigurations) == 0 || !sameTemplateProjection(request.TemplateIDs, request.TemplateConfigurations) {
		checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "waiting_templates")
		return nil
	}
	{
		var instances []*pluginv1.PluginInstanceConfiguration
		var releases []func()
		if checker.credentials == nil {
			if !request.CredentialsComplete {
				checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "waiting_credentials")
				return nil
			}
			instances = instancesWithoutCredentials(request)
		} else {
			var leaseErr error
			instances, releases, leaseErr = leaseInstancesWithCache(ctx, checker.credentials, checker.cache, request, time.Now().UTC())
			if leaseErr != nil {
				checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "waiting_credentials")
				return nil
			}
		}
		for _, release := range releases {
			defer release()
		}
		configuration := plugingateway.PluginConfiguration{AssignmentID: request.AssignmentID, ConfigurationRevision: request.ConfigurationRevision, Instances: instances}
		defer configuration.Release()
		if err := session.ApplyConfiguration(ctx, configuration); err != nil {
			return ErrHealthHandshake
		}
		checker.scheduleCredentialExpiry(process, session, request.AssignmentID, earliestCredentialExpiry(instances))
		for _, instanceID := range request.InstanceIDs {
			result, validateErr := session.ValidateInstance(ctx, instanceID)
			if validateErr != nil || !result.Valid {
				return ErrHealthHandshake
			}
		}
		if err := session.CheckHealth(ctx); err != nil {
			return ErrHealthHandshake
		}
		if sink := checker.client.MetricSink(); sink != nil {
			if err := session.CollectNow(ctx, request.InstanceIDs, request.TemplateIDs); err != nil {
				return ErrHealthHandshake
			}
			streamContext, cancel := context.WithCancel(context.Background())
			ready := make(chan error, 1)
			streamResult := make(chan error, 1)
			go func() {
				streamErr := session.RunMetricStreamReady(streamContext, sink, ready)
				streamResult <- streamErr
				if streamErr != nil && streamContext.Err() == nil {
					// A plugin whose metric stream ends has lost a core correctness
					// boundary. Terminate it so Task9's monitored process lifecycle
					// records the failure and applies its restart/circuit policy.
					_ = process.Kill()
				}
			}()
			if readyErr := <-ready; readyErr != nil {
				cancel()
				return ErrHealthHandshake
			}
			select {
			case streamErr := <-streamResult:
				cancel()
				if streamErr != nil {
					return ErrHealthHandshake
				}
			default:
			}
			checker.mu.Lock()
			checker.streams[process.PID()] = cancel
			checker.mu.Unlock()
		}
	}
	checker.storeActivation(process.PID(), session, pluginstate.HealthHealthy, "")
	return nil
}

func instancesWithoutCredentials(request HealthRequest) []*pluginv1.PluginInstanceConfiguration {
	instances := make([]*pluginv1.PluginInstanceConfiguration, 0, len(request.InstanceDescriptors))
	for _, descriptor := range request.InstanceDescriptors {
		templates := make([]*pluginv1.MetricTemplateConfiguration, len(request.TemplateConfigurations))
		for index, template := range request.TemplateConfigurations {
			templates[index] = proto.Clone(template).(*pluginv1.MetricTemplateConfiguration)
		}
		instances = append(instances, &pluginv1.PluginInstanceConfiguration{InstanceId: descriptor.InstanceID, DatabaseVariant: descriptor.DatabaseVariant, Endpoint: descriptor.Endpoint, UnixSocket: descriptor.UnixSocket, Templates: templates})
	}
	return instances
}

var errCredentialLease = errors.New("credential lease unavailable")

func leaseInstances(ctx context.Context, leaser CredentialLeaser, request HealthRequest, now time.Time) ([]*pluginv1.PluginInstanceConfiguration, []func(), error) {
	return leaseInstancesWithCache(ctx, leaser, nil, request, now)
}

func leaseInstancesWithCache(ctx context.Context, leaser CredentialLeaser, cache *credentialcache.Cache, request HealthRequest, now time.Time) ([]*pluginv1.PluginInstanceConfiguration, []func(), error) {
	if ctx == nil || ctx.Err() != nil || leaser == nil || request.AssignmentID == "" || request.DatabaseFamily == "" || request.ConfigurationRevision == 0 || request.OperationRevision == 0 || len(request.InstanceDescriptors) == 0 {
		return nil, nil, errCredentialLease
	}
	instances := make([]*pluginv1.PluginInstanceConfiguration, 0, len(request.InstanceDescriptors))
	releases := make([]func(), 0, len(request.InstanceDescriptors))
	fail := func() ([]*pluginv1.PluginInstanceConfiguration, []func(), error) {
		for _, release := range releases {
			release()
		}
		return nil, nil, errCredentialLease
	}
	for _, descriptor := range request.InstanceDescriptors {
		lease, err := leaser.LeaseCredential(ctx, CredentialLeaseRequest{AssignmentID: request.AssignmentID, InstanceID: descriptor.InstanceID, DatabaseFamily: request.DatabaseFamily, ConfigurationRevision: request.ConfigurationRevision, OperationRevision: request.OperationRevision})
		if err != nil || lease.LeaseID == "" || lease.AssignmentID != request.AssignmentID || lease.InstanceID != descriptor.InstanceID || lease.DatabaseFamily != request.DatabaseFamily || lease.CredentialRevision == 0 || lease.ConfigurationRevision != request.ConfigurationRevision || lease.OperationRevision != request.OperationRevision || !lease.ExpiresAt.After(now) || len(lease.SecretBytes) == 0 {
			lease.Release()
			return fail()
		}
		username := lease.Username
		secretBytes := lease.SecretBytes
		if cache != nil {
			key := credentialcache.Key{AssignmentID: lease.AssignmentID, InstanceID: lease.InstanceID, CredentialRevision: lease.CredentialRevision, ConfigurationRevision: lease.ConfigurationRevision, OperationRevision: lease.OperationRevision}
			handle, cacheErr := cache.Get(ctx, key, func(context.Context) (credentialcache.Lease, error) {
				return credentialcache.Lease{ID: lease.LeaseID, Key: key, ExpiresAt: lease.ExpiresAt, Username: lease.Username, SecretBytes: append([]byte(nil), lease.SecretBytes...)}, nil
			})
			lease.Release()
			if cacheErr != nil {
				return fail()
			}
			username, secretBytes = handle.Username, handle.SecretBytes
			releases = append(releases, handle.Release)
		} else {
			leasePointer := &lease
			releases = append(releases, leasePointer.Release)
		}
		templates := make([]*pluginv1.MetricTemplateConfiguration, len(request.TemplateConfigurations))
		for index, template := range request.TemplateConfigurations {
			templates[index] = proto.Clone(template).(*pluginv1.MetricTemplateConfiguration)
		}
		instances = append(instances, &pluginv1.PluginInstanceConfiguration{InstanceId: descriptor.InstanceID, DatabaseVariant: descriptor.DatabaseVariant, Endpoint: descriptor.Endpoint, UnixSocket: descriptor.UnixSocket, CredentialLease: &pluginv1.CredentialLease{LeaseId: lease.LeaseID, CredentialRevision: lease.CredentialRevision, Username: username, SecretBytes: append([]byte(nil), secretBytes...), ExpiresAt: timestamppb.New(lease.ExpiresAt)}, Templates: templates})
	}
	return instances, releases, nil
}

func earliestCredentialExpiry(instances []*pluginv1.PluginInstanceConfiguration) time.Time {
	var earliest time.Time
	for _, instance := range instances {
		lease := instance.GetCredentialLease()
		if lease == nil || lease.GetExpiresAt() == nil || !lease.GetExpiresAt().IsValid() {
			continue
		}
		expires := lease.GetExpiresAt().AsTime().UTC()
		if earliest.IsZero() || expires.Before(earliest) {
			earliest = expires
		}
	}
	return earliest
}

func (checker *GatewayHealthChecker) scheduleCredentialExpiry(process Process, session *plugingateway.Session, assignmentID string, expiresAt time.Time) {
	if checker == nil || process == nil || session == nil || expiresAt.IsZero() {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	checker.mu.Lock()
	if previous := checker.expiries[process.PID()]; previous != nil {
		previous()
	}
	checker.expiries[process.PID()] = cancel
	checker.mu.Unlock()
	go func() {
		timer := time.NewTimer(time.Until(expiresAt))
		defer timer.Stop()
		select {
		case <-timer.C:
			clearContext, clearCancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = session.RemoveCredentials(clearContext)
			clearCancel()
			checker.cache.InvalidateAssignment(assignmentID)
			checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "waiting_credentials")
			_ = process.Kill()
		case <-ctx.Done():
		}
	}()
}

func (checker *GatewayHealthChecker) storeActivation(pid int, session *plugingateway.Session, health pluginstate.HealthState, code string) {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	checker.sessions[pid] = session
	checker.activation[pid] = gatewayActivation{health: health, code: code}
}

func (checker *GatewayHealthChecker) ActivationState(process Process) (pluginstate.HealthState, string) {
	if checker == nil || process == nil {
		return pluginstate.HealthUnhealthy, "plugin_reconcile_unavailable"
	}
	checker.mu.Lock()
	defer checker.mu.Unlock()
	value, ok := checker.activation[process.PID()]
	if !ok {
		return pluginstate.HealthUnhealthy, "plugin_reconcile_unavailable"
	}
	return value.health, value.code
}

// Shutdown drains through the verified gateway before the Supervisor signals
// the process. This keeps RPC lifecycle ownership with the Supervisor.
func (checker *GatewayHealthChecker) Shutdown(ctx context.Context, process Process, timeout time.Duration) error {
	if checker == nil || process == nil || timeout <= 0 {
		return ErrHealthHandshake
	}
	checker.mu.Lock()
	session := checker.sessions[process.PID()]
	if cancel := checker.streams[process.PID()]; cancel != nil {
		cancel()
		delete(checker.streams, process.PID())
	}
	if cancel := checker.expiries[process.PID()]; cancel != nil {
		cancel()
		delete(checker.expiries, process.PID())
	}
	delete(checker.sessions, process.PID())
	delete(checker.activation, process.PID())
	checker.mu.Unlock()
	if session == nil {
		return ErrHealthHandshake
	}
	_ = session.RemoveCredentials(ctx)
	checker.cache.InvalidateAssignment(session.AssignmentID())
	if session.Shutdown(ctx, timeout) != nil {
		return ErrHealthHandshake
	}
	return nil
}

func sameTemplateProjection(ids []string, templates []*pluginv1.MetricTemplateConfiguration) bool {
	if len(ids) == 0 || len(ids) != len(templates) {
		return false
	}
	seen := map[string]struct{}{}
	for _, template := range templates {
		if template == nil || !containsString(ids, template.GetTemplateId()) {
			return false
		}
		if _, duplicate := seen[template.GetTemplateId()]; duplicate {
			return false
		}
		seen[template.GetTemplateId()] = struct{}{}
	}
	return true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

var _ HealthChecker = (*GatewayHealthChecker)(nil)
