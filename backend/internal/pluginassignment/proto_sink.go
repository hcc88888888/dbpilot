package pluginassignment

import (
	"context"
	"crypto/subtle"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/platformscope"
)

type AgentScopeResolver interface {
	ScopeForAgent(context.Context, string) (platformscope.Scope, error)
}

type ProtoSink struct {
	Service     Service
	AgentScopes AgentScopeResolver
}

func (sink ProtoSink) SubmitPlugin(agentID string, report *agentv1.PluginObservation) error {
	return sink.RecordPluginObservation(context.Background(), agentID, report)
}

func (sink ProtoSink) RecordPluginObservation(ctx context.Context, agentID string, report *agentv1.PluginObservation) error {
	if sink.Service == nil || sink.AgentScopes == nil || ctx == nil || report == nil || subtle.ConstantTimeCompare([]byte(agentID), []byte(report.GetAgentId())) != 1 {
		return ErrInvalid
	}
	scope, err := sink.AgentScopes.ScopeForAgent(ctx, agentID)
	if err != nil {
		return err
	}
	observedAt, ok := protoTime(report.GetObservedAt())
	if !ok {
		return ErrInvalid
	}
	converted := ObservationReport{Scope: scope, HostID: report.GetHostId(), AgentID: agentID, ObservationRevision: report.GetObservationRevision(), Assignments: make([]ObservedState, 0, len(report.GetAssignments())), ObservedAt: observedAt}
	for _, wire := range report.GetAssignments() {
		value, err := observedFromProto(report.GetObservationRevision(), wire)
		if err != nil {
			return err
		}
		converted.Assignments = append(converted.Assignments, value)
	}
	return sink.Service.RecordObservation(ctx, converted)
}

func observedFromProto(reportRevision uint64, wire *agentv1.PluginAssignmentObservation) (ObservedState, error) {
	if wire == nil {
		return ObservedState{}, ErrInvalid
	}
	observedAt, ok := protoTime(wire.GetObservedAt())
	if !ok {
		return ObservedState{}, ErrInvalid
	}
	value := ObservedState{AssignmentID: wire.GetAssignmentId(), PluginID: wire.GetPluginId(), DatabaseFamily: wire.GetDatabaseFamily(), InstalledVersion: wire.GetInstalledVersion(), PID: wire.GetProcessId(), RestartCount: wire.GetRestartCount(), BoundInstanceCount: wire.GetBoundInstanceCount(), ActiveConfigurationRevision: wire.GetActiveConfigurationRevision(), ObservedOperationRevision: wire.GetObservedOperationRevision(), LastErrorCode: wire.GetLastErrorCode(), ObservationRevision: reportRevision, ObservedAt: observedAt}
	slots := map[agentv1.PluginActiveSlot]ActiveSlot{agentv1.PluginActiveSlot_PLUGIN_ACTIVE_SLOT_NONE: SlotNone, agentv1.PluginActiveSlot_PLUGIN_ACTIVE_SLOT_A: SlotA, agentv1.PluginActiveSlot_PLUGIN_ACTIVE_SLOT_B: SlotB}
	processes := map[agentv1.PluginProcessState]ProcessState{agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_ABSENT: "absent", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_DOWNLOADING: "downloading", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_VERIFYING: "verifying", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_INSTALLED: "installed", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_STARTING: "starting", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_HANDSHAKING: "handshaking", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_RUNNING: "running", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_DEGRADED: "degraded", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_RESTARTING: "restarting", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_CIRCUIT_OPEN: "circuit_open", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_DRAINING: "draining", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_STOPPED: "stopped", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_UNINSTALLING: "uninstalling", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_DOWNLOAD_FAILED: "download_failed", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_SIGNATURE_REJECTED: "signature_rejected", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_MANIFEST_REJECTED: "manifest_rejected", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_PLATFORM_MISMATCH: "platform_mismatch", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_START_FAILED: "start_failed", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_HANDSHAKE_FAILED: "handshake_failed", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_UPGRADING: "upgrading", agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_ROLLBACK: "rollback"}
	health := map[agentv1.PluginHealthState]HealthState{agentv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY: HealthHealthy, agentv1.PluginHealthState_PLUGIN_HEALTH_STATE_DEGRADED: HealthDegraded, agentv1.PluginHealthState_PLUGIN_HEALTH_STATE_UNHEALTHY: HealthUnhealthy}
	circuits := map[agentv1.PluginCircuitState]CircuitState{agentv1.PluginCircuitState_PLUGIN_CIRCUIT_STATE_CLOSED: CircuitClosed, agentv1.PluginCircuitState_PLUGIN_CIRCUIT_STATE_OPEN: CircuitOpen, agentv1.PluginCircuitState_PLUGIN_CIRCUIT_STATE_HALF_OPEN: CircuitHalfOpen}
	var exists bool
	if value.ActiveSlot, exists = slots[wire.GetActiveSlot()]; !exists {
		return ObservedState{}, ErrInvalid
	}
	if value.ProcessState, exists = processes[wire.GetProcessState()]; !exists {
		return ObservedState{}, ErrInvalid
	}
	if value.Health, exists = health[wire.GetHealth()]; !exists {
		return ObservedState{}, ErrInvalid
	}
	if value.CircuitState, exists = circuits[wire.GetCircuitState()]; !exists {
		return ObservedState{}, ErrInvalid
	}
	if wire.GetStartedAt() != nil {
		started, ok := protoTime(wire.GetStartedAt())
		if !ok {
			return ObservedState{}, ErrInvalid
		}
		value.StartedAt = &started
	}
	if value.Validate() != nil {
		return ObservedState{}, ErrInvalid
	}
	return value, nil
}

func protoTime(value interface {
	IsValid() bool
	AsTime() time.Time
}) (time.Time, bool) {
	if value == nil || !value.IsValid() {
		return time.Time{}, false
	}
	result := value.AsTime().UTC()
	return result, !result.IsZero()
}

var _ interface {
	SubmitPlugin(string, *agentv1.PluginObservation) error
} = ProtoSink{}
