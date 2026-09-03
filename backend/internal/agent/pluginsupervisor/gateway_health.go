package pluginsupervisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/credentialcache"
	"dbpilot.local/platform/internal/agent/metrictemplatelease"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"dbpilot.local/platform/internal/agent/pluginstate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GatewayHealthChecker makes the Supervisor's activation gate use the same
// private UDS client as all later plugin RPCs. It preserves Task9's exact
// process, executable and inherited-nonce proof before accepting a process.
type GatewayHealthChecker struct {
	client            *plugingateway.Client
	credentials       CredentialLeaser
	templates         MetricTemplateLeaser
	mu                sync.Mutex
	sessions          map[int]*plugingateway.Session
	streams           map[int]*metricStreamHandle
	mutations         map[int]*sync.Mutex
	expiries          map[int]context.CancelFunc
	activation        map[int]gatewayActivation
	cache             *credentialcache.Cache
	leaseFlights      map[string]*credentialFlight
	activeCredentials map[int]activeCredentialConfiguration
	leaseEpochs       map[string]uint64
}

type activeCredentialConfiguration struct {
	configuration plugingateway.PluginConfiguration
	deadline      time.Time
}

type metricStreamHandle struct {
	cancel        context.CancelFunc
	done          chan struct{}
	mu            sync.Mutex
	err           error
	killOnFailure bool
	completed     bool
}

func (handle *metricStreamHandle) complete(err error, unexpectedFailure bool, process Process) {
	handle.mu.Lock()
	handle.err = err
	handle.completed = true
	kill := unexpectedFailure && handle.killOnFailure
	close(handle.done)
	handle.mu.Unlock()
	if kill {
		_ = process.Kill()
	}
}

func (handle *metricStreamHandle) result() error {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.err
}

func (handle *metricStreamHandle) armOrKill(process Process) error {
	handle.mu.Lock()
	if handle.completed {
		handle.mu.Unlock()
		_ = process.Kill()
		return ErrHealthHandshake
	}
	handle.killOnFailure = true
	handle.mu.Unlock()
	return nil
}

type credentialFlight struct {
	ready        chan struct{}
	lease        CredentialLease
	err          error
	waiters      int
	completed    bool
	timer        *time.Timer
	assignmentID string
	epoch        uint64
	cancel       context.CancelFunc
}

type credentialLeaserFunc func(context.Context, CredentialLeaseRequest) (CredentialLease, error)

func (function credentialLeaserFunc) LeaseCredential(ctx context.Context, request CredentialLeaseRequest) (CredentialLease, error) {
	return function(ctx, request)
}

type gatewayActivation struct {
	health pluginstate.HealthState
	code   string
}

func NewGatewayHealthChecker(client *plugingateway.Client) *GatewayHealthChecker {
	return &GatewayHealthChecker{client: client, sessions: make(map[int]*plugingateway.Session), streams: make(map[int]*metricStreamHandle), mutations: make(map[int]*sync.Mutex), expiries: make(map[int]context.CancelFunc), activation: make(map[int]gatewayActivation), cache: credentialcache.New(time.Now), leaseFlights: make(map[string]*credentialFlight), activeCredentials: make(map[int]activeCredentialConfiguration), leaseEpochs: make(map[string]uint64)}
}

func NewGatewayHealthCheckerWithCredentials(client *plugingateway.Client, credentials CredentialLeaser) *GatewayHealthChecker {
	checker := NewGatewayHealthChecker(client)
	checker.credentials = credentials
	if templates, ok := credentials.(MetricTemplateLeaser); ok {
		checker.templates = templates
	}
	return checker
}

func (checker *GatewayHealthChecker) mutationFor(pid int) *sync.Mutex {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	mutation := checker.mutations[pid]
	if mutation == nil {
		mutation = &sync.Mutex{}
		checker.mutations[pid] = mutation
	}
	return mutation
}

func (checker *GatewayHealthChecker) startMetricStream(ctx context.Context, process Process, session *plugingateway.Session, requireCommit, killOnFailure bool) (*metricStreamHandle, error) {
	if checker == nil || checker.client == nil || ctx == nil || ctx.Err() != nil || process == nil || session == nil || checker.client.MetricSink() == nil {
		return nil, ErrHealthHandshake
	}
	streamContext, cancel := context.WithCancel(context.Background())
	handle := &metricStreamHandle{cancel: cancel, done: make(chan struct{}), killOnFailure: killOnFailure}
	ready := make(chan error, 1)
	go func() {
		var streamErr error
		if requireCommit {
			streamErr = session.RunMetricStreamCommitted(streamContext, checker.client.MetricSink(), ready)
		} else {
			streamErr = session.RunMetricStreamReady(streamContext, checker.client.MetricSink(), ready)
		}
		handle.complete(streamErr, streamErr != nil && streamContext.Err() == nil, process)
	}()
	select {
	case readyErr := <-ready:
		if readyErr != nil {
			stopContext, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = stopMetricStream(stopContext, handle)
			stopCancel()
			return nil, ErrHealthHandshake
		}
	case <-ctx.Done():
		stopContext, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = stopMetricStream(stopContext, handle)
		stopCancel()
		return nil, ErrHealthHandshake
	}
	select {
	case <-handle.done:
		if handle.result() != nil {
			return nil, ErrHealthHandshake
		}
	default:
	}
	return handle, nil
}

func stopMetricStream(ctx context.Context, handle *metricStreamHandle) error {
	if handle == nil {
		return nil
	}
	handle.cancel()
	select {
	case <-handle.done:
		return nil
	case <-ctx.Done():
		return ErrHealthHandshake
	}
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
		return healthHandshakeFailure("open")
	}
	capabilities, handshakeErr := session.Handshake(ctx, expected)
	if handshakeErr != nil {
		return healthHandshakeFailure("protocol")
	}
	if len(request.SupportedVariants) == 0 || len(request.SignedCapabilities) == 0 || request.MetricTemplateSchemaVersion == 0 || len(request.InstanceDescriptors) == 0 {
		checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "plugin_reconcile_unavailable")
		return nil
	}
	if len(request.TemplateConfigurations) == 0 && len(request.TemplateReferences) == 0 && len(capabilities.BuiltinTemplateIDs) == 0 || len(request.TemplateConfigurations) > 0 && !sameTemplateProjection(request.TemplateIDs, request.TemplateConfigurations) || len(request.TemplateReferences) > 0 && !validTemplateReferences(request.TemplateIDs, request.InstanceIDs, request.TemplateLeaseCommandID, request.TemplateReferences, request.InstanceTemplateRefs) {
		checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "waiting_templates")
		return nil
	}
	{
		var instances []*pluginv1.PluginInstanceConfiguration
		var releases []func()
		var configurationValidFor time.Duration
		if checker.credentials == nil {
			if !request.CredentialsComplete {
				checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "waiting_credentials")
				return nil
			}
			instances = instancesWithoutCredentials(request)
		} else {
			var leaseErr error
			instances, releases, configurationValidFor, leaseErr = leaseInstancesWithCache(ctx, credentialLeaserFunc(checker.leaseCredential), checker.cache, request, time.Now().UTC())
			if leaseErr != nil {
				checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "waiting_credentials")
				return nil
			}
		}
		for _, release := range releases {
			defer release()
		}
		if len(request.TemplateReferences) > 0 {
			if checker.templates == nil {
				checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "waiting_templates")
				return nil
			}
			perInstance, templateReleases, _, leaseErr := leaseMetricTemplates(ctx, checker.templates, request, time.Now().UTC())
			if leaseErr != nil {
				checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "waiting_templates")
				return nil
			}
			for _, release := range templateReleases {
				defer release()
			}
			for _, instance := range instances {
				instance.Templates = cloneTemplateConfigurations(perInstance[instance.GetInstanceId()])
			}
			if session.SetExpectedInstanceTemplateConfigurations(perInstance) != nil {
				return healthHandshakeFailure("template_projection")
			}
		}
		configuration := plugingateway.PluginConfiguration{AssignmentID: request.AssignmentID, ConfigurationRevision: request.ConfigurationRevision, Instances: instances}
		defer configuration.Release()
		if err := session.ApplyConfiguration(ctx, configuration); err != nil {
			return healthHandshakeFailure("apply_configuration")
		}
		for _, instanceID := range request.InstanceIDs {
			result, validateErr := session.ValidateInstance(ctx, instanceID)
			if validateErr != nil || !result.Valid {
				return healthHandshakeFailure("validate_instance")
			}
		}
		checker.storeActiveCredentialConfiguration(process.PID(), configuration, configurationValidFor)
		checker.scheduleCredentialRenewal(process, session, request, configurationValidFor)
		if err := session.CheckHealth(ctx); err != nil {
			return healthHandshakeFailure("health")
		}
		if sink := checker.client.MetricSink(); sink != nil {
			hasResumeCursors, resumeErr := session.HasResumeCursors(ctx, sink)
			if resumeErr != nil {
				return healthHandshakeFailure("metric_resume")
			}
			if !hasResumeCursors {
				for _, instance := range instances {
					templateIDs, configuredErr := session.ConfiguredTemplateIDs(instance.GetInstanceId())
					if configuredErr != nil {
						return healthHandshakeFailure("configured_templates")
					}
					for _, templateID := range templateIDs {
						if err := session.CollectNow(ctx, []string{instance.GetInstanceId()}, []string{templateID}); err != nil {
							return healthHandshakeFailure("initial_collection")
						}
					}
				}
			}
			stream, streamErr := checker.startMetricStream(ctx, process, session, false, true)
			if streamErr != nil {
				return healthHandshakeFailure("metric_stream")
			}
			checker.mu.Lock()
			checker.streams[process.PID()] = stream
			checker.mu.Unlock()
		}
	}
	checker.storeActivation(process.PID(), session, pluginstate.HealthHealthy, "")
	return nil
}

func (checker *GatewayHealthChecker) ApplyConfiguration(ctx context.Context, process Process, request HealthRequest) error {
	if checker == nil || checker.client == nil || process == nil || ctx == nil || ctx.Err() != nil {
		return ErrHealthHandshake
	}
	mutation := checker.mutationFor(process.PID())
	mutation.Lock()
	defer mutation.Unlock()
	checker.mu.Lock()
	session := checker.sessions[process.PID()]
	previousStream := checker.streams[process.PID()]
	active, hasActive := checker.activeCredentials[process.PID()]
	previous := clonePluginConfiguration(active.configuration)
	checker.mu.Unlock()
	defer previous.Release()
	if session == nil || session.AssignmentID() != request.AssignmentID || len(request.SupportedVariants) == 0 || len(request.SignedCapabilities) == 0 || request.MetricTemplateSchemaVersion == 0 || len(request.InstanceDescriptors) == 0 {
		return ErrHealthHandshake
	}
	if !hasActive || previous.AssignmentID != request.AssignmentID || previous.ConfigurationRevision != session.ConfigurationRevision() || checker.credentials != nil && !time.Now().Before(active.deadline) {
		return ErrHealthHandshake
	}
	if len(request.TemplateConfigurations) == 0 && len(request.TemplateReferences) == 0 && len(request.InstanceTemplateConfigurations) == 0 && len(request.TemplateIDs) > 0 || len(request.TemplateConfigurations) > 0 && !sameTemplateProjection(request.TemplateIDs, request.TemplateConfigurations) || len(request.TemplateReferences) > 0 && !validTemplateReferences(request.TemplateIDs, request.InstanceIDs, request.TemplateLeaseCommandID, request.TemplateReferences, request.InstanceTemplateRefs) {
		return ErrHealthHandshake
	}
	var instances []*pluginv1.PluginInstanceConfiguration
	var releases []func()
	var configurationValidFor time.Duration
	if checker.credentials == nil {
		if !request.CredentialsComplete {
			return ErrHealthHandshake
		}
		instances = instancesWithoutCredentials(request)
	} else {
		var leaseErr error
		instances, releases, configurationValidFor, leaseErr = leaseInstancesWithCache(ctx, credentialLeaserFunc(checker.leaseCredential), checker.cache, request, time.Now().UTC())
		if leaseErr != nil {
			return ErrHealthHandshake
		}
	}
	for _, release := range releases {
		defer release()
	}
	if len(request.InstanceTemplateConfigurations) > 0 {
		for _, instance := range instances {
			templates, exists := request.InstanceTemplateConfigurations[instance.GetInstanceId()]
			if !exists {
				return ErrHealthHandshake
			}
			instance.Templates = cloneTemplateConfigurations(templates)
		}
	}
	expected := plugingateway.ExpectedPlugin{
		PID: process.PID(), ExpectedUserID: request.ExpectedUserID, ExpectedGroupID: request.ExpectedGroupID,
		RuntimeDirectory: request.RuntimeDirectory, AssignmentID: request.AssignmentID, PluginID: request.PluginID,
		DatabaseFamily: request.DatabaseFamily, Version: request.Version, ProtocolVersion: request.ProtocolVersion,
		ExecutablePath: request.ExecutablePath, ExecutableSHA256: append([]byte(nil), request.ExecutableSHA256...),
		LaunchNonce: append([]byte(nil), request.LaunchNonce...), ConfigurationRevision: request.ConfigurationRevision,
		OperationRevision: request.OperationRevision, InstanceIDs: append([]string(nil), request.InstanceIDs...), TemplateIDs: append([]string(nil), request.TemplateIDs...),
		SupportedVariants: append([]string(nil), request.SupportedVariants...), SignedCapabilities: append([]string(nil), request.SignedCapabilities...), MetricTemplateSchemaVersion: request.MetricTemplateSchemaVersion,
		TemplateConfigurations: cloneTemplateConfigurations(request.TemplateConfigurations), InstanceTemplateConfigurations: cloneTemplateConfigurationMap(request.InstanceTemplateConfigurations),
	}
	if len(request.TemplateReferences) > 0 {
		if checker.templates == nil {
			return ErrHealthHandshake
		}
		perInstance, templateReleases, _, leaseErr := leaseMetricTemplates(ctx, checker.templates, request, time.Now().UTC())
		if leaseErr != nil {
			return ErrHealthHandshake
		}
		for _, release := range templateReleases {
			defer release()
		}
		for _, instance := range instances {
			instance.Templates = cloneTemplateConfigurations(perInstance[instance.GetInstanceId()])
		}
		expected.InstanceTemplateConfigurations = perInstance
	}
	configuration := plugingateway.PluginConfiguration{AssignmentID: request.AssignmentID, ConfigurationRevision: request.ConfigurationRevision, Instances: instances}
	defer configuration.Release()
	if previousStream != nil {
		if stopMetricStream(ctx, previousStream) != nil {
			_ = process.Kill()
			return healthHandshakeFailure("metric_stream_quiesce")
		}
		checker.mu.Lock()
		if checker.streams[process.PID()] == previousStream {
			delete(checker.streams, process.PID())
		}
		checker.mu.Unlock()
	}
	reopenPrevious := func(reopenContext context.Context) error {
		if previousStream == nil {
			return nil
		}
		stream, streamErr := checker.startMetricStream(reopenContext, process, session, false, true)
		if streamErr != nil {
			_ = process.Kill()
			return ErrHealthHandshake
		}
		checker.mu.Lock()
		checker.streams[process.PID()] = stream
		checker.mu.Unlock()
		return nil
	}
	if err := session.ApplyConfigurationUpdate(ctx, expected, configuration, previous); err != nil {
		recoveryContext, recoveryCancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = reopenPrevious(recoveryContext)
		recoveryCancel()
		return healthHandshakeFailure("apply_configuration_update")
	}
	var candidateStream *metricStreamHandle
	if previousStream != nil {
		var streamErr error
		candidateStream, streamErr = checker.startMetricStream(ctx, process, session, true, false)
		if streamErr != nil {
			recoveryContext, recoveryCancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer recoveryCancel()
			if rollbackErr := session.RollbackConfigurationUpdate(recoveryContext, previous); rollbackErr != nil {
				_ = process.Kill()
				return healthHandshakeFailure("configuration_rollback")
			}
			_ = reopenPrevious(recoveryContext)
			return healthHandshakeFailure("metric_stream_reopen")
		}
	}
	if candidateStream != nil && candidateStream.armOrKill(process) != nil {
		return healthHandshakeFailure("metric_stream_arm")
	}
	if err := session.FinalizeConfigurationUpdate(); err != nil {
		if candidateStream != nil {
			stopContext, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = stopMetricStream(stopContext, candidateStream)
			stopCancel()
		}
		_ = process.Kill()
		return healthHandshakeFailure("configuration_commit")
	}
	if candidateStream != nil {
		checker.mu.Lock()
		checker.streams[process.PID()] = candidateStream
		checker.mu.Unlock()
	}
	checker.storeActiveCredentialConfiguration(process.PID(), configuration, configurationValidFor)
	checker.scheduleCredentialRenewal(process, session, request, configurationValidFor)
	checker.storeActivation(process.PID(), session, pluginstate.HealthHealthy, "")
	return nil
}

func (checker *GatewayHealthChecker) ApplyTypedConfiguration(ctx context.Context, process Process, request HealthRequest, command *agentv1.ApplyPluginConfiguration) error {
	if checker == nil || process == nil || command == nil || command.GetAssignmentId() != request.AssignmentID || command.GetConfigurationRevision() != request.ConfigurationRevision {
		return ErrHealthHandshake
	}
	checker.mu.Lock()
	active, ok := checker.activeCredentials[process.PID()]
	previous := clonePluginConfiguration(active.configuration)
	checker.mu.Unlock()
	defer previous.Release()
	if !ok || previous.AssignmentID != request.AssignmentID || len(previous.Instances) != len(command.GetInstances()) {
		return ErrHealthHandshake
	}
	byID := make(map[string]*pluginv1.PluginInstanceConfiguration, len(previous.Instances))
	for _, instance := range previous.Instances {
		byID[instance.GetInstanceId()] = instance
	}
	request.ExpectedCredentialRevisions = make(map[string]uint64, len(command.GetInstances()))
	request.InstanceTemplateConfigurations = make(map[string][]*pluginv1.MetricTemplateConfiguration, len(command.GetInstances()))
	for _, instance := range command.GetInstances() {
		stored := byID[instance.GetInstanceId()]
		if stored == nil || instance.GetCredentialRevision() == 0 || stored.GetDatabaseVariant() != instance.GetDatabaseVariant() || stored.GetEndpoint() != instance.GetEndpoint() || stored.GetUnixSocket() != instance.GetUnixSocket() || !samePublicTemplateProjection(stored.GetTemplates(), instance.GetTemplates()) {
			return ErrHealthHandshake
		}
		request.ExpectedCredentialRevisions[instance.GetInstanceId()] = instance.GetCredentialRevision()
		request.InstanceTemplateConfigurations[instance.GetInstanceId()] = cloneTemplateConfigurations(stored.GetTemplates())
		delete(byID, instance.GetInstanceId())
	}
	if len(byID) != 0 {
		return ErrHealthHandshake
	}
	request.TemplateConfigurations = nil
	request.TemplateLeaseCommandID = ""
	request.TemplateReferences = nil
	request.InstanceTemplateRefs = nil
	return checker.ApplyConfiguration(ctx, process, request)
}

func (checker *GatewayHealthChecker) ValidateTypedInstance(ctx context.Context, process Process, request HealthRequest, instanceID string) (plugingateway.ValidationResult, error) {
	if checker == nil || process == nil || instanceID == "" || request.AssignmentID == "" {
		return plugingateway.ValidationResult{}, ErrHealthHandshake
	}
	mutation := checker.mutationFor(process.PID())
	mutation.Lock()
	defer mutation.Unlock()
	checker.mu.Lock()
	session := checker.sessions[process.PID()]
	active, ok := checker.activeCredentials[process.PID()]
	checker.mu.Unlock()
	if session == nil || !ok || session.AssignmentID() != request.AssignmentID || session.ConfigurationRevision() != request.ConfigurationRevision || session.OperationRevision() != request.OperationRevision || !time.Now().Before(active.deadline) {
		return plugingateway.ValidationResult{}, ErrHealthHandshake
	}
	result, err := session.ValidateInstance(ctx, instanceID)
	if err != nil {
		return plugingateway.ValidationResult{}, ErrHealthHandshake
	}
	return result, nil
}

func samePublicTemplateProjection(stored []*pluginv1.MetricTemplateConfiguration, command []*agentv1.PluginTemplateRevision) bool {
	if len(stored) != len(command) {
		return false
	}
	byID := make(map[string]*pluginv1.MetricTemplateConfiguration, len(stored))
	for _, template := range stored {
		byID[template.GetTemplateId()] = template
	}
	for _, template := range command {
		current := byID[template.GetTemplateId()]
		if current == nil || current.GetRevision() != template.GetRevision() || !bytes.Equal(current.GetQueryDigest(), template.GetQueryDigest()) {
			return false
		}
		delete(byID, template.GetTemplateId())
	}
	return len(byID) == 0
}

func cloneTemplateConfigurationMap(values map[string][]*pluginv1.MetricTemplateConfiguration) map[string][]*pluginv1.MetricTemplateConfiguration {
	if values == nil {
		return nil
	}
	result := make(map[string][]*pluginv1.MetricTemplateConfiguration, len(values))
	for instanceID, templates := range values {
		result[instanceID] = cloneTemplateConfigurations(templates)
	}
	return result
}

func healthHandshakeFailure(stage string) error {
	log.Printf("database plugin health handshake failed: stage=%s", stage)
	return ErrHealthHandshake
}

func clonePluginConfiguration(value plugingateway.PluginConfiguration) plugingateway.PluginConfiguration {
	cloned := plugingateway.PluginConfiguration{AssignmentID: value.AssignmentID, ConfigurationRevision: value.ConfigurationRevision, Instances: make([]*pluginv1.PluginInstanceConfiguration, len(value.Instances))}
	for index, instance := range value.Instances {
		cloned.Instances[index] = proto.Clone(instance).(*pluginv1.PluginInstanceConfiguration)
	}
	return cloned
}

func (checker *GatewayHealthChecker) storeActiveCredentialConfiguration(pid int, configuration plugingateway.PluginConfiguration, validFor time.Duration) {
	checker.mu.Lock()
	old := checker.activeCredentials[pid]
	checker.activeCredentials[pid] = activeCredentialConfiguration{configuration: clonePluginConfiguration(configuration), deadline: time.Now().Add(validFor)}
	checker.mu.Unlock()
	old.configuration.Release()
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

func leaseInstances(ctx context.Context, leaser CredentialLeaser, request HealthRequest, now time.Time) ([]*pluginv1.PluginInstanceConfiguration, []func(), time.Duration, error) {
	return leaseInstancesWithCache(ctx, leaser, nil, request, now)
}

func leaseMetricTemplates(ctx context.Context, leaser MetricTemplateLeaser, request HealthRequest, now time.Time) (map[string][]*pluginv1.MetricTemplateConfiguration, []func(), time.Duration, error) {
	if ctx == nil || leaser == nil || request.TemplateLeaseCommandID == "" || !validTemplateReferences(request.TemplateIDs, request.InstanceIDs, request.TemplateLeaseCommandID, request.TemplateReferences, request.InstanceTemplateRefs) {
		return nil, nil, 0, ErrHealthHandshake
	}
	result := make(map[string][]*pluginv1.MetricTemplateConfiguration, len(request.InstanceIDs))
	for _, instanceID := range request.InstanceIDs {
		result[instanceID] = []*pluginv1.MetricTemplateConfiguration{}
	}
	releases := make([]func(), 0)
	validFor := time.Duration(0)
	failed := true
	defer func() {
		if failed {
			for _, release := range releases {
				release()
			}
			clearTemplateConfigurationMap(result)
		}
	}()
	for _, instance := range request.InstanceTemplateRefs {
		for _, reference := range instance.Templates {
			material, err := leaser.LeaseMetricTemplate(ctx, metrictemplatelease.Request{CommandID: request.TemplateLeaseCommandID, AssignmentID: request.AssignmentID, InstanceID: instance.InstanceID, ConfigurationRevision: request.ConfigurationRevision, OperationRevision: request.OperationRevision, TemplateID: reference.TemplateID, RevisionID: reference.RevisionID, QueryDigest: append([]byte(nil), reference.QueryDigest...)})
			if err != nil || !materialMatchesReference(material, request, instance.InstanceID, reference, now) {
				material.Release()
				return nil, nil, 0, ErrHealthHandshake
			}
			retained := &material
			releases = append(releases, retained.Release)
			configuration := &pluginv1.MetricTemplateConfiguration{TemplateId: material.TemplateID, Revision: material.Revision, QueryDigest: append([]byte(nil), reference.QueryDigest...), QueryKind: "sql", ReadOnlyStatement: string(material.StatementBytes), CollectionIntervalSeconds: uint32(material.CollectionIntervalSeconds), TimeoutSeconds: uint32(material.TimeoutSeconds), MaxRows: uint32(material.MaxRows), MaxColumns: uint32(material.MaxColumns), CardinalityLimit: uint32(material.CardinalityLimit)}
			for _, mapping := range material.ValueMappings {
				configuration.ValueMappings = append(configuration.ValueMappings, &pluginv1.MetricValueMapping{SourceColumn: mapping.SourceColumn, MetricName: mapping.MetricName, MetricType: mapping.MetricType, Unit: mapping.Unit})
			}
			for _, mapping := range material.LabelMappings {
				configuration.LabelMappings = append(configuration.LabelMappings, &pluginv1.MetricLabelMapping{SourceColumn: mapping.SourceColumn, Label: mapping.Label})
			}
			result[instance.InstanceID] = append(result[instance.InstanceID], configuration)
			remaining := material.ExpiresAt.Sub(now)
			if validFor == 0 || remaining < validFor {
				validFor = remaining
			}
		}
	}
	failed = false
	return result, releases, validFor, nil
}

func clearTemplateConfigurationMap(values map[string][]*pluginv1.MetricTemplateConfiguration) {
	for _, templates := range values {
		for _, template := range templates {
			if template != nil {
				template.ReadOnlyStatement = ""
				template.ValueMappings = nil
				template.LabelMappings = nil
			}
		}
	}
}

func materialMatchesReference(material metrictemplatelease.Material, request HealthRequest, instanceID string, reference TemplateReference, now time.Time) bool {
	if material.AssignmentID != request.AssignmentID || material.InstanceID != instanceID || material.ConfigurationRevision != request.ConfigurationRevision || material.OperationRevision != request.OperationRevision || material.TemplateID != reference.TemplateID || material.RevisionID != reference.RevisionID || material.QueryDigest != hex.EncodeToString(reference.QueryDigest) || material.TimeoutSeconds != int(reference.TimeoutSeconds) || material.MaxRows != int(reference.MaxRows) || material.MaxColumns != int(reference.MaxColumns) || material.CardinalityLimit != int(reference.CardinalityLimit) || !material.ExpiresAt.After(now) || len(material.StatementBytes) == 0 {
		return false
	}
	digest := sha256.Sum256(material.StatementBytes)
	return hex.EncodeToString(digest[:]) == material.QueryDigest
}

func leaseInstancesWithCache(ctx context.Context, leaser CredentialLeaser, cache *credentialcache.Cache, request HealthRequest, now time.Time) ([]*pluginv1.PluginInstanceConfiguration, []func(), time.Duration, error) {
	if ctx == nil || ctx.Err() != nil || leaser == nil || request.AssignmentID == "" || request.DatabaseFamily == "" || request.ConfigurationRevision == 0 || request.OperationRevision == 0 || len(request.InstanceDescriptors) == 0 {
		return nil, nil, 0, errCredentialLease
	}
	instances := make([]*pluginv1.PluginInstanceConfiguration, 0, len(request.InstanceDescriptors))
	releases := make([]func(), 0, len(request.InstanceDescriptors))
	fail := func() ([]*pluginv1.PluginInstanceConfiguration, []func(), time.Duration, error) {
		for _, release := range releases {
			release()
		}
		return nil, nil, 0, errCredentialLease
	}
	var minimumValidFor time.Duration
	for _, descriptor := range request.InstanceDescriptors {
		lease, err := leaser.LeaseCredential(ctx, CredentialLeaseRequest{AssignmentID: request.AssignmentID, InstanceID: descriptor.InstanceID, DatabaseFamily: request.DatabaseFamily, ConfigurationRevision: request.ConfigurationRevision, OperationRevision: request.OperationRevision})
		expectedCredentialRevision := request.ExpectedCredentialRevisions[descriptor.InstanceID]
		if err != nil || lease.LeaseID == "" || lease.AssignmentID != request.AssignmentID || lease.InstanceID != descriptor.InstanceID || lease.DatabaseFamily != request.DatabaseFamily || lease.CredentialRevision == 0 || expectedCredentialRevision != 0 && lease.CredentialRevision != expectedCredentialRevision || lease.ConfigurationRevision != request.ConfigurationRevision || lease.OperationRevision != request.OperationRevision || lease.ValidFor <= 0 || len(lease.SecretBytes) == 0 {
			lease.Release()
			return fail()
		}
		if minimumValidFor == 0 || lease.ValidFor < minimumValidFor {
			minimumValidFor = lease.ValidFor
		}
		username := lease.Username
		secretBytes := lease.SecretBytes
		if cache != nil {
			key := credentialcache.Key{AssignmentID: lease.AssignmentID, InstanceID: lease.InstanceID, CredentialRevision: lease.CredentialRevision, ConfigurationRevision: lease.ConfigurationRevision, OperationRevision: lease.OperationRevision}
			handle, cacheErr := cache.Get(ctx, key, func(context.Context) (credentialcache.Lease, error) {
				return credentialcache.Lease{ID: lease.LeaseID, Key: key, ExpiresAt: lease.ExpiresAt, ValidFor: lease.ValidFor, Username: lease.Username, SecretBytes: append([]byte(nil), lease.SecretBytes...)}, nil
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
	return instances, releases, minimumValidFor, nil
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

func (checker *GatewayHealthChecker) scheduleCredentialRenewal(process Process, session *plugingateway.Session, request HealthRequest, validFor time.Duration) {
	if checker == nil || process == nil || session == nil || validFor <= 0 {
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
		mutation := checker.mutationFor(process.PID())
		deadline := time.Now().Add(validFor)
		backoff := time.Second
		removed := false
		for {
			remaining := time.Until(deadline)
			lead := remaining / 5
			if lead < time.Second {
				lead = time.Second
			}
			if lead > 30*time.Second {
				lead = 30 * time.Second
			}
			wait := remaining - lead
			jitter := time.Duration(process.PID()%251) * time.Millisecond
			if wait > jitter {
				wait -= jitter
			}
			if removed || wait < 0 {
				wait = backoff
			}
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			mutation.Lock()
			if ctx.Err() != nil {
				mutation.Unlock()
				return
			}
			callContext, callCancel := context.WithTimeout(ctx, 15*time.Second)
			checker.invalidateCredentialFlights(request.AssignmentID)
			instances, releases, renewedFor, err := leaseInstancesWithCache(callContext, credentialLeaserFunc(checker.leaseCredential), checker.cache, request, time.Now().UTC())
			if err == nil {
				if !checker.copyActiveTemplates(process.PID(), instances) {
					err = errCredentialLease
				}
				configuration := plugingateway.PluginConfiguration{AssignmentID: request.AssignmentID, ConfigurationRevision: request.ConfigurationRevision, Instances: instances}
				if err == nil {
					err = session.ApplyConfiguration(callContext, configuration)
				}
				applied := err == nil
				if err == nil {
					for _, instanceID := range request.InstanceIDs {
						result, validateErr := session.ValidateInstance(callContext, instanceID)
						if validateErr != nil || !result.Valid {
							err = errCredentialLease
							break
						}
					}
				}
				if err == nil {
					checker.storeActiveCredentialConfiguration(process.PID(), configuration, renewedFor)
					deadline = time.Now().Add(renewedFor)
					removed = false
					backoff = time.Second
					checker.storeActivation(process.PID(), session, pluginstate.HealthHealthy, "")
					configuration.Release()
					for _, release := range releases {
						release()
					}
					callCancel()
					mutation.Unlock()
					continue
				}
				configuration.Release()
				for _, release := range releases {
					release()
				}
				if applied && !checker.rollbackCredentialConfiguration(callContext, process.PID(), session, request.InstanceIDs) {
					callCancel()
					checker.forceCredentialStop(process, session, request.AssignmentID)
					mutation.Unlock()
					return
				}
			}
			callCancel()
			if !removed && !time.Now().Before(deadline) {
				clearContext, clearCancel := context.WithTimeout(context.Background(), 10*time.Second)
				removeErr := session.RemoveCredentials(clearContext)
				clearCancel()
				if removeErr != nil {
					checker.forceCredentialStop(process, session, request.AssignmentID)
					mutation.Unlock()
					return
				}
				checker.cache.InvalidateAssignment(request.AssignmentID)
				checker.mu.Lock()
				expired := checker.activeCredentials[process.PID()]
				delete(checker.activeCredentials, process.PID())
				checker.mu.Unlock()
				expired.configuration.Release()
				checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "waiting_credentials")
				removed = true
			}
			if backoff < 10*time.Second {
				backoff *= 2
			}
			mutation.Unlock()
		}
	}()
}

func (checker *GatewayHealthChecker) copyActiveTemplates(pid int, instances []*pluginv1.PluginInstanceConfiguration) bool {
	checker.mu.Lock()
	active := clonePluginConfiguration(checker.activeCredentials[pid].configuration)
	checker.mu.Unlock()
	defer active.Release()
	if len(active.Instances) != len(instances) {
		return false
	}
	byID := map[string]*pluginv1.PluginInstanceConfiguration{}
	for _, instance := range active.Instances {
		byID[instance.GetInstanceId()] = instance
	}
	for _, instance := range instances {
		stored := byID[instance.GetInstanceId()]
		if stored == nil {
			return false
		}
		instance.Templates = cloneTemplateConfigurations(stored.GetTemplates())
	}
	return true
}

func (checker *GatewayHealthChecker) rollbackCredentialConfiguration(ctx context.Context, pid int, session *plugingateway.Session, instanceIDs []string) bool {
	checker.mu.Lock()
	active, ok := checker.activeCredentials[pid]
	configuration := clonePluginConfiguration(active.configuration)
	valid := ok && time.Now().Before(active.deadline)
	checker.mu.Unlock()
	defer configuration.Release()
	if !valid || session.ApplyConfiguration(ctx, configuration) != nil {
		return false
	}
	for _, instanceID := range instanceIDs {
		result, err := session.ValidateInstance(ctx, instanceID)
		if err != nil || !result.Valid {
			return false
		}
	}
	return true
}

func (checker *GatewayHealthChecker) forceCredentialStop(process Process, session *plugingateway.Session, assignmentID string) {
	checker.mu.Lock()
	if stream := checker.streams[process.PID()]; stream != nil {
		stream.cancel()
		delete(checker.streams, process.PID())
	}
	active := checker.activeCredentials[process.PID()]
	delete(checker.activeCredentials, process.PID())
	checker.mu.Unlock()
	active.configuration.Release()
	checker.cache.InvalidateAssignment(assignmentID)
	checker.invalidateCredentialFlights(assignmentID)
	checker.storeActivation(process.PID(), session, pluginstate.HealthDegraded, "waiting_credentials")
	_ = process.Kill()
}

func (checker *GatewayHealthChecker) leaseCredential(ctx context.Context, request CredentialLeaseRequest) (CredentialLease, error) {
	if checker == nil || checker.credentials == nil || ctx == nil || ctx.Err() != nil {
		return CredentialLease{}, errCredentialLease
	}
	key := request.AssignmentID + "\x00" + request.InstanceID + "\x00" + fmt.Sprint(request.ConfigurationRevision) + "\x00" + fmt.Sprint(request.OperationRevision)
	checker.mu.Lock()
	flight := checker.leaseFlights[key]
	if flight != nil {
		flight.waiters++
		checker.mu.Unlock()
		return checker.awaitCredentialFlight(ctx, key, flight)
	}
	flightCtx, flightCancel := context.WithCancel(ctx)
	flight = &credentialFlight{ready: make(chan struct{}), waiters: 1, assignmentID: request.AssignmentID, epoch: checker.leaseEpochs[request.AssignmentID], cancel: flightCancel}
	checker.leaseFlights[key] = flight
	checker.mu.Unlock()
	lease, err := checker.credentials.LeaseCredential(flightCtx, request)
	checker.mu.Lock()
	if flight.completed || checker.leaseEpochs[request.AssignmentID] != flight.epoch || checker.leaseFlights[key] != flight {
		lease.Release()
		checker.mu.Unlock()
		return CredentialLease{}, errCredentialLease
	}
	flight.completed = true
	if err != nil {
		flight.err = errCredentialLease
		lease.Release()
	} else {
		flight.lease = lease.Clone()
		lease.Release()
	}
	close(flight.ready)
	if flight.err == nil {
		remaining := flight.lease.ValidFor
		if remaining > 0 {
			flight.timer = time.AfterFunc(remaining, func() {
				checker.mu.Lock()
				if checker.leaseFlights[key] == flight {
					flight.lease.Release()
					delete(checker.leaseFlights, key)
				}
				checker.mu.Unlock()
			})
		}
	}
	if flight.waiters == 0 && flight.err != nil {
		flight.lease.Release()
		delete(checker.leaseFlights, key)
	}
	checker.mu.Unlock()
	return checker.awaitCredentialFlight(ctx, key, flight)
}

func (checker *GatewayHealthChecker) awaitCredentialFlight(ctx context.Context, key string, flight *credentialFlight) (CredentialLease, error) {
	select {
	case <-ctx.Done():
		checker.mu.Lock()
		flight.waiters--
		if flight.waiters == 0 && flight.completed && flight.err != nil {
			flight.lease.Release()
			delete(checker.leaseFlights, key)
		}
		checker.mu.Unlock()
		return CredentialLease{}, errCredentialLease
	case <-flight.ready:
		checker.mu.Lock()
		flight.waiters--
		lease, err := flight.lease.Clone(), flight.err
		if flight.waiters == 0 && flight.err != nil {
			flight.lease.Release()
			delete(checker.leaseFlights, key)
		}
		checker.mu.Unlock()
		if err != nil {
			lease.Release()
			return CredentialLease{}, errCredentialLease
		}
		return lease, nil
	}
}

func (checker *GatewayHealthChecker) invalidateCredentialFlights(assignmentID string) {
	checker.mu.Lock()
	checker.leaseEpochs[assignmentID]++
	for key, flight := range checker.leaseFlights {
		if strings.HasPrefix(key, assignmentID+"\x00") {
			if flight.cancel != nil {
				flight.cancel()
			}
			if flight.timer != nil {
				flight.timer.Stop()
			}
			flight.lease.Release()
			if !flight.completed {
				flight.completed = true
				flight.err = errCredentialLease
				close(flight.ready)
			}
			delete(checker.leaseFlights, key)
		}
	}
	checker.mu.Unlock()
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

func (checker *GatewayHealthChecker) TrialMetricTemplate(ctx context.Context, assignmentID string, configurationRevision, operationRevision uint64, instanceID string, definition *pluginv1.TrialMetricTemplateDefinition) (plugingateway.TrialResult, error) {
	if checker == nil || ctx == nil || ctx.Err() != nil || assignmentID == "" || configurationRevision == 0 || operationRevision == 0 || instanceID == "" || definition == nil {
		return plugingateway.TrialResult{}, ErrHealthHandshake
	}
	checker.mu.Lock()
	var session *plugingateway.Session
	for _, candidate := range checker.sessions {
		if candidate != nil && candidate.AssignmentID() == assignmentID && candidate.ConfigurationRevision() == configurationRevision && candidate.OperationRevision() == operationRevision {
			if session != nil {
				checker.mu.Unlock()
				return plugingateway.TrialResult{}, ErrHealthHandshake
			}
			session = candidate
		}
	}
	checker.mu.Unlock()
	if session == nil {
		return plugingateway.TrialResult{}, ErrHealthHandshake
	}
	return session.TrialMetricTemplate(ctx, configurationRevision, operationRevision, instanceID, definition)
}

// Shutdown drains through the verified gateway before the Supervisor signals
// the process. This keeps RPC lifecycle ownership with the Supervisor.
func (checker *GatewayHealthChecker) Shutdown(ctx context.Context, process Process, timeout time.Duration) error {
	if checker == nil || process == nil || timeout <= 0 {
		return ErrHealthHandshake
	}
	mutation := checker.mutationFor(process.PID())
	mutation.Lock()
	defer mutation.Unlock()
	checker.mu.Lock()
	session := checker.sessions[process.PID()]
	stream := checker.streams[process.PID()]
	if stream != nil {
		delete(checker.streams, process.PID())
	}
	if cancel := checker.expiries[process.PID()]; cancel != nil {
		cancel()
		delete(checker.expiries, process.PID())
	}
	delete(checker.sessions, process.PID())
	delete(checker.activation, process.PID())
	active := checker.activeCredentials[process.PID()]
	delete(checker.activeCredentials, process.PID())
	checker.mu.Unlock()
	if stopMetricStream(ctx, stream) != nil {
		active.configuration.Release()
		return ErrHealthHandshake
	}
	active.configuration.Release()
	if session == nil {
		return ErrHealthHandshake
	}
	_ = session.RemoveCredentials(ctx)
	checker.cache.InvalidateAssignment(session.AssignmentID())
	checker.invalidateCredentialFlights(session.AssignmentID())
	if session.Shutdown(ctx, timeout) != nil {
		return ErrHealthHandshake
	}
	return nil
}

func (checker *GatewayHealthChecker) CleanupUnexpectedExit(process Process) {
	if checker == nil || process == nil {
		return
	}
	pid := process.PID()
	mutation := checker.mutationFor(pid)
	mutation.Lock()
	defer mutation.Unlock()
	checker.mu.Lock()
	session := checker.sessions[pid]
	if stream := checker.streams[pid]; stream != nil {
		stream.cancel()
	}
	if cancel := checker.expiries[pid]; cancel != nil {
		cancel()
	}
	active := checker.activeCredentials[pid]
	delete(checker.streams, pid)
	delete(checker.expiries, pid)
	delete(checker.sessions, pid)
	delete(checker.activation, pid)
	delete(checker.activeCredentials, pid)
	checker.mu.Unlock()
	active.configuration.Release()
	assignmentID := active.configuration.AssignmentID
	if session != nil {
		assignmentID = session.AssignmentID()
	}
	if assignmentID != "" {
		checker.cache.InvalidateAssignment(assignmentID)
		checker.invalidateCredentialFlights(assignmentID)
	}
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
var _ UnexpectedExitCleaner = (*GatewayHealthChecker)(nil)
