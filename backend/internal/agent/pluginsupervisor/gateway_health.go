package pluginsupervisor

import (
	"context"
	"sync"
	"time"

	"dbpilot.local/platform/internal/agent/plugingateway"
)

// GatewayHealthChecker makes the Supervisor's activation gate use the same
// private UDS client as all later plugin RPCs. It preserves Task9's exact
// process, executable and inherited-nonce proof before accepting a process.
type GatewayHealthChecker struct {
	client   *plugingateway.Client
	mu       sync.Mutex
	sessions map[int]*plugingateway.Session
}

func NewGatewayHealthChecker(client *plugingateway.Client) *GatewayHealthChecker {
	return &GatewayHealthChecker{client: client, sessions: make(map[int]*plugingateway.Session)}
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
		OperationRevision: request.OperationRevision, InstanceIDs: append([]string(nil), request.InstanceIDs...),
	}
	session, err := checker.client.Open(expected)
	if err != nil {
		return ErrHealthHandshake
	}
	if _, err = session.Handshake(ctx, expected); err != nil {
		return ErrHealthHandshake
	}
	if err := session.CheckHealth(ctx); err != nil {
		return ErrHealthHandshake
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
	delete(checker.sessions, process.PID())
	checker.mu.Unlock()
	if session == nil || session.Shutdown(ctx, timeout) != nil {
		return ErrHealthHandshake
	}
	return nil
}

var _ HealthChecker = (*GatewayHealthChecker)(nil)
