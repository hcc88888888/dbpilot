package pluginsupervisor

import (
	"context"
	"sync"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/plugingateway"
)

// GatewayHealthChecker makes the Supervisor's activation gate use the same
// private UDS client as all later plugin RPCs. It preserves Task9's exact
// process, executable and inherited-nonce proof before accepting a process.
type GatewayHealthChecker struct {
	client   *plugingateway.Client
	mu       sync.Mutex
	sessions map[int]*plugingateway.Session
	streams  map[int]context.CancelFunc
}

func NewGatewayHealthChecker(client *plugingateway.Client) *GatewayHealthChecker {
	return &GatewayHealthChecker{client: client, sessions: make(map[int]*plugingateway.Session), streams: make(map[int]context.CancelFunc)}
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
	}
	session, err := checker.client.Open(expected)
	if err != nil {
		return ErrHealthHandshake
	}
	if _, err = session.Handshake(ctx, expected); err != nil {
		return ErrHealthHandshake
	}
	if len(request.InstanceDescriptors) == 0 {
		if err := session.CheckHealth(ctx); err != nil {
			return ErrHealthHandshake
		}
	} else {
		instances := make([]*pluginv1.PluginInstanceConfiguration, 0, len(request.InstanceDescriptors))
		for _, descriptor := range request.InstanceDescriptors {
			instances = append(instances, &pluginv1.PluginInstanceConfiguration{InstanceId: descriptor.InstanceID, DatabaseVariant: descriptor.DatabaseVariant, Endpoint: descriptor.Endpoint, UnixSocket: descriptor.UnixSocket})
		}
		if err := session.ApplyConfiguration(ctx, plugingateway.PluginConfiguration{AssignmentID: request.AssignmentID, ConfigurationRevision: request.ConfigurationRevision, Instances: instances}); err != nil {
			return ErrHealthHandshake
		}
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
			streamContext, cancel := context.WithCancel(context.Background())
			checker.mu.Lock()
			checker.streams[process.PID()] = cancel
			checker.mu.Unlock()
			go func() {
				if streamErr := session.RunMetricStream(streamContext, sink); streamErr != nil && streamContext.Err() == nil {
					// A plugin whose metric stream ends has lost a core correctness
					// boundary. Terminate it so Task9's monitored process lifecycle
					// records the failure and applies its restart/circuit policy.
					_ = process.Kill()
				}
			}()
		}
	}
	checker.mu.Lock()
	checker.sessions[process.PID()] = session
	checker.mu.Unlock()
	return nil
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
	delete(checker.sessions, process.PID())
	checker.mu.Unlock()
	if session == nil || session.Shutdown(ctx, timeout) != nil {
		return ErrHealthHandshake
	}
	return nil
}

var _ HealthChecker = (*GatewayHealthChecker)(nil)
