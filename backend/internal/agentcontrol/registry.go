package agentcontrol

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/commandvalidation"
	"google.golang.org/protobuf/proto"
)

var (
	ErrAgentUnavailable        = errors.New("Agent session is unavailable")
	ErrSessionQueueFull        = errors.New("Agent session send queue is full")
	ErrCapabilityNotAdvertised = errors.New("command capability was not advertised")
	ErrCommandExpired          = errors.New("command has expired")
	ErrAgentMismatch           = errors.New("command Agent ID does not match target Agent")
	ErrInvalidCommand          = errors.New("command envelope is invalid")
	ErrDuplicateSession        = errors.New("Agent already has an active session")
)

type dispatchError struct {
	err       error
	retryable bool
}

func (e *dispatchError) Error() string   { return e.err.Error() }
func (e *dispatchError) Unwrap() error   { return e.err }
func (e *dispatchError) Retryable() bool { return e.retryable }

func IsRetryableDispatchError(err error) bool {
	var retryable interface{ Retryable() bool }
	return errors.As(err, &retryable) && retryable.Retryable()
}

type session struct {
	sessionID        string
	agentID          string
	credentialLeaf   [sha256.Size]byte
	credentialSerial string
	capabilities     map[string]struct{}
	capabilityList   []string
	active           []*agentv1.CommandRecoveryState
	send             chan *agentv1.ServerMessage
	cancel           context.CancelFunc
	lastHeartbeat    time.Time
	leaseDurations   map[string]time.Duration
	leases           map[string]time.Time
	executionTokens  map[string][]byte
	leaseRevisions   map[string]uint64
}

// SessionInfo is a defensive snapshot of an authenticated live Agent session.
type SessionInfo struct {
	SessionID      string
	AgentID        string
	Capabilities   []string
	ActiveCommands []*agentv1.CommandRecoveryState
	LastHeartbeat  time.Time
	Leases         map[string]time.Time
	LeaseRevisions map[string]uint64
}

// Registry owns the single live session for each Agent and is the command Dispatcher.
type Registry struct {
	mu              sync.RWMutex
	queueCapacity   int
	sessions        map[string]*session
	now             func() time.Time
	sessionSequence uint64
}

func NewRegistry(queueCapacity int) *Registry {
	if queueCapacity <= 0 {
		queueCapacity = 1
	}
	return &Registry{queueCapacity: queueCapacity, sessions: make(map[string]*session), now: time.Now}
}

func (r *Registry) register(agentID string, capabilities []string, active []*agentv1.CommandRecoveryState, cancel context.CancelFunc) error {
	return r.registerCredential(agentID, capabilities, active, [sha256.Size]byte{}, "", cancel)
}

func (r *Registry) registerCredential(agentID string, capabilities []string, active []*agentv1.CommandRecoveryState, fingerprint [sha256.Size]byte, serial string, cancel context.CancelFunc) error {
	capabilitySet := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		capability = strings.TrimSpace(capability)
		if capability != "" {
			capabilitySet[capability] = struct{}{}
		}
	}
	capabilityList := make([]string, 0, len(capabilitySet))
	for capability := range capabilitySet {
		capabilityList = append(capabilityList, capability)
	}
	sort.Strings(capabilityList)

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.sessions[agentID]; exists {
		return ErrDuplicateSession
	}
	r.sessionSequence++
	r.sessions[agentID] = &session{
		sessionID: fmt.Sprintf("session-%d", r.sessionSequence), agentID: agentID,
		credentialLeaf: fingerprint, credentialSerial: serial, capabilities: capabilitySet, capabilityList: capabilityList,
		active: cloneRecoveryStates(active), send: make(chan *agentv1.ServerMessage, r.queueCapacity), cancel: cancel,
		leaseDurations: make(map[string]time.Duration), leases: make(map[string]time.Time),
		executionTokens: make(map[string][]byte), leaseRevisions: make(map[string]uint64),
	}
	return nil
}

func (r *Registry) unregister(agentID string, expected *session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.sessions[agentID]
	if !exists || current != expected {
		return
	}
	delete(r.sessions, agentID)
	for {
		select {
		case message := <-current.send:
			clearCredentialLeaseResponse(message.GetCredentialLeaseResponse())
			clearMetricTemplateLeaseResponse(message.GetMetricTemplateLeaseResponse())
		default:
			return
		}
	}
}

// Terminate removes and cancels the exact live Agent session. It is used only
// after a credential-generation or host-status transaction has committed.
func (r *Registry) Terminate(agentID string) bool {
	if r == nil || strings.TrimSpace(agentID) == "" {
		return false
	}
	r.mu.Lock()
	current := r.sessions[agentID]
	if current != nil {
		delete(r.sessions, agentID)
		for {
			select {
			case message := <-current.send:
				clearCredentialLeaseResponse(message.GetCredentialLeaseResponse())
				clearMetricTemplateLeaseResponse(message.GetMetricTemplateLeaseResponse())
			default:
				r.mu.Unlock()
				current.cancel()
				return true
			}
		}
	}
	r.mu.Unlock()
	return false
}

// TerminateSuperseded cancels only a session authenticated with a credential
// other than the newly committed leaf. This preserves a new-certificate
// reconnect that races the post-commit replacement cleanup.
func (r *Registry) TerminateSuperseded(agentID string, activeFingerprint [sha256.Size]byte) bool {
	if r == nil || strings.TrimSpace(agentID) == "" || activeFingerprint == ([sha256.Size]byte{}) {
		return false
	}
	r.mu.Lock()
	current := r.sessions[agentID]
	if current == nil || current.credentialLeaf == activeFingerprint {
		r.mu.Unlock()
		return false
	}
	delete(r.sessions, agentID)
	for {
		select {
		case message := <-current.send:
			clearCredentialLeaseResponse(message.GetCredentialLeaseResponse())
			clearMetricTemplateLeaseResponse(message.GetMetricTemplateLeaseResponse())
		default:
			r.mu.Unlock()
			current.cancel()
			return true
		}
	}
}

func (r *Registry) liveSession(agentID string) (*session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, exists := r.sessions[agentID]
	return session, exists
}

func (r *Registry) Session(agentID string) (SessionInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	current, exists := r.sessions[agentID]
	if !exists {
		return SessionInfo{}, false
	}
	leases := make(map[string]time.Time, len(current.leases))
	for commandID, deadline := range current.leases {
		leases[commandID] = deadline
	}
	revisions := make(map[string]uint64, len(current.leaseRevisions))
	for commandID, revision := range current.leaseRevisions {
		revisions[commandID] = revision
	}
	return SessionInfo{
		SessionID: current.sessionID,
		AgentID:   current.agentID, Capabilities: append([]string(nil), current.capabilityList...),
		ActiveCommands: cloneRecoveryStates(current.active), LastHeartbeat: current.lastHeartbeat, Leases: leases, LeaseRevisions: revisions,
	}, true
}

// ExecutionLeaseActive proves that CommandStart established a live execution
// fence for the exact authenticated Agent and command. It exposes no token.
func (r *Registry) ExecutionLeaseActive(agentID, commandID string, at time.Time) bool {
	if r == nil || agentID == "" || commandID == "" || at.IsZero() {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	current := r.sessions[agentID]
	if current == nil || !current.leases[commandID].After(at.UTC()) || current.leaseRevisions[commandID] == 0 || len(current.executionTokens[commandID]) != sha256.Size {
		return false
	}
	return true
}

func (r *Registry) snapshot(agentID string, expected *session) (SessionInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	current, exists := r.sessions[agentID]
	if !exists || current != expected {
		return SessionInfo{}, false
	}
	leasing := make(map[string]time.Time, len(current.leases))
	for commandID, deadline := range current.leases {
		leasing[commandID] = deadline
	}
	revisions := make(map[string]uint64, len(current.leaseRevisions))
	for commandID, revision := range current.leaseRevisions {
		revisions[commandID] = revision
	}
	return SessionInfo{SessionID: current.sessionID, AgentID: current.agentID, Capabilities: append([]string(nil), current.capabilityList...), ActiveCommands: cloneRecoveryStates(current.active), LastHeartbeat: current.lastHeartbeat, Leases: leasing, LeaseRevisions: revisions}, true
}

func (r *Registry) enqueue(agentID string, message *agentv1.ServerMessage) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	current, exists := r.sessions[agentID]
	if !exists {
		return &dispatchError{err: ErrAgentUnavailable, retryable: true}
	}
	select {
	case current.send <- message:
		return nil
	default:
		return &dispatchError{err: ErrSessionQueueFull, retryable: true}
	}
}

func (r *Registry) AcknowledgeDiscovery(agentID string, acknowledgement *agentv1.DiscoveryReportAcknowledgement) error {
	if acknowledgement == nil {
		return ErrAgentUnavailable
	}
	return r.enqueue(agentID, &agentv1.ServerMessage{MessageId: "discovery-ack-" + acknowledgement.GetHostId(), Message: &agentv1.ServerMessage_DiscoveryReportAcknowledgement{DiscoveryReportAcknowledgement: acknowledgement}})
}

func (r *Registry) Supports(agentID string, required ...string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	current := r.sessions[agentID]
	if current == nil {
		return false
	}
	for _, capability := range required {
		if _, ok := current.capabilities[capability]; !ok {
			return false
		}
	}
	return true
}

func (r *Registry) Dispatch(ctx context.Context, agentID string, envelope *agentv1.CommandEnvelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if envelope == nil || strings.TrimSpace(envelope.GetCommandId()) == "" || envelope.GetCommand() == nil {
		return &dispatchError{err: ErrInvalidCommand}
	}
	if envelope.GetAgentId() != agentID {
		return &dispatchError{err: ErrAgentMismatch}
	}
	if envelope.GetExpiresAt() == nil || !envelope.GetExpiresAt().IsValid() || !envelope.GetExpiresAt().AsTime().After(r.now()) {
		return &dispatchError{err: ErrCommandExpired}
	}
	capabilities := commandCapabilities(envelope)
	if len(capabilities) == 0 {
		return &dispatchError{err: ErrInvalidCommand}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.sessions[agentID]
	if !exists {
		return &dispatchError{err: ErrAgentUnavailable, retryable: true}
	}
	for _, capability := range capabilities {
		if _, advertised := current.capabilities[capability]; !advertised {
			return &dispatchError{err: fmt.Errorf("%w: %s", ErrCapabilityNotAdvertised, capability)}
		}
	}
	cloned := proto.Clone(envelope).(*agentv1.CommandEnvelope)
	message := &agentv1.ServerMessage{MessageId: cloned.GetCommandId(), Message: &agentv1.ServerMessage_Command{Command: cloned}}
	select {
	case current.send <- message:
		return nil
	default:
		return &dispatchError{err: ErrSessionQueueFull, retryable: true}
	}
}

// Start dispatches the persisted execution fence after the observer has
// authorized it. Prepare delivery never creates an execution lease.
func (r *Registry) Start(ctx context.Context, agentID string, start *agentv1.CommandStart) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := commandvalidation.ValidateStart(start, r.now()); err != nil {
		return &dispatchError{err: ErrInvalidCommand}
	}
	return r.enqueueStart(agentID, start)
}

// ReplayStart re-enqueues an already persisted fence. Shape validation is
// intentional: the Agent journal classifies an exact late replay by its
// durable state and never starts expired prepared work.
func (r *Registry) ReplayStart(ctx context.Context, agentID string, start *agentv1.CommandStart) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := commandvalidation.ValidateStartShape(start); err != nil {
		return &dispatchError{err: ErrInvalidCommand}
	}
	return r.enqueueStart(agentID, start)
}

func (r *Registry) enqueueStart(agentID string, start *agentv1.CommandStart) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.sessions[agentID]
	if !exists {
		return &dispatchError{err: ErrAgentUnavailable, retryable: true}
	}
	cloned := proto.Clone(start).(*agentv1.CommandStart)
	message := &agentv1.ServerMessage{MessageId: "start-" + cloned.GetCommandId(), Message: &agentv1.ServerMessage_CommandStart{CommandStart: cloned}}
	select {
	case current.send <- message:
		current.executionTokens[cloned.GetCommandId()] = append([]byte(nil), cloned.GetExecutionToken()...)
		current.leaseRevisions[cloned.GetCommandId()] = cloned.GetLeaseRevision()
		lease := time.Duration(cloned.GetLeaseSeconds()) * time.Second
		current.leaseDurations[cloned.GetCommandId()] = lease
		current.leases[cloned.GetCommandId()] = r.now().Add(lease)
		return nil
	default:
		return &dispatchError{err: ErrSessionQueueFull, retryable: true}
	}
}

func (r *Registry) Cancel(ctx context.Context, agentID, commandID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(commandID) == "" {
		return &dispatchError{err: ErrInvalidCommand}
	}
	r.mu.RLock()
	current, exists := r.sessions[agentID]
	if !exists {
		r.mu.RUnlock()
		return &dispatchError{err: ErrAgentUnavailable, retryable: true}
	}
	cancellation := &agentv1.CommandCancellation{CommandId: commandID}
	if token := current.executionTokens[commandID]; len(token) == sha256.Size && current.leaseRevisions[commandID] > 0 {
		cancellation.ExecutionToken = append([]byte(nil), token...)
		cancellation.LeaseRevision = current.leaseRevisions[commandID]
	}
	err := enqueueCancellation(current, commandID, cancellation)
	r.mu.RUnlock()
	return err
}

func (r *Registry) CancelPrepared(ctx context.Context, agentID, commandID, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(commandID) == "" {
		return &dispatchError{err: ErrInvalidCommand}
	}
	r.mu.RLock()
	current, exists := r.sessions[agentID]
	if !exists {
		r.mu.RUnlock()
		return &dispatchError{err: ErrAgentUnavailable, retryable: true}
	}
	err := enqueueCancellation(current, commandID, &agentv1.CommandCancellation{CommandId: commandID, Reason: reason})
	r.mu.RUnlock()
	return err
}

// CancelExecution sends the durable control-plane fence even after a Registry
// restart, when the in-memory Start maps are intentionally empty.
func (r *Registry) CancelExecution(ctx context.Context, agentID, commandID string, executionToken []byte, executionRevision uint64, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(commandID) == "" || len(executionToken) != sha256.Size || executionRevision == 0 {
		return &dispatchError{err: ErrInvalidCommand}
	}
	r.mu.RLock()
	current, exists := r.sessions[agentID]
	if !exists {
		r.mu.RUnlock()
		return &dispatchError{err: ErrAgentUnavailable, retryable: true}
	}
	cancellation := &agentv1.CommandCancellation{
		CommandId: commandID, Reason: reason, ExecutionToken: append([]byte(nil), executionToken...), LeaseRevision: executionRevision,
	}
	err := enqueueCancellation(current, commandID, cancellation)
	r.mu.RUnlock()
	return err
}

func enqueueCancellation(current *session, commandID string, cancellation *agentv1.CommandCancellation) error {
	message := &agentv1.ServerMessage{MessageId: commandID, Message: &agentv1.ServerMessage_CommandCancellation{CommandCancellation: cancellation}}
	select {
	case current.send <- message:
		return nil
	default:
		return &dispatchError{err: ErrSessionQueueFull, retryable: true}
	}
}

func (r *Registry) renew(agentID string, heartbeat *agentv1.Heartbeat, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.sessions[agentID]
	if !exists {
		return
	}
	current.lastHeartbeat = at
	for _, active := range heartbeat.GetActiveCommands() {
		if active == nil || !matchingExecutionToken(current.executionTokens[active.GetCommandId()], active.GetExecutionToken()) || current.leaseRevisions[active.GetCommandId()] != active.GetLeaseRevision() {
			continue
		}
		if lease := current.leaseDurations[active.GetCommandId()]; lease > 0 {
			current.leases[active.GetCommandId()] = at.Add(lease)
		}
	}
}

func matchingExecutionToken(left, right []byte) bool {
	return len(left) == sha256.Size && len(right) == sha256.Size && subtle.ConstantTimeCompare(left, right) == 1
}

func commandCapability(envelope *agentv1.CommandEnvelope) (string, bool) {
	capabilities := commandCapabilities(envelope)
	if len(capabilities) == 0 {
		return "", false
	}
	return capabilities[0], true
}

func commandCapabilities(envelope *agentv1.CommandEnvelope) []string {
	switch envelope.GetCommand().(type) {
	case *agentv1.CommandEnvelope_CollectNow:
		return []string{"collect_now"}
	case *agentv1.CommandEnvelope_InspectInstance:
		return []string{"inspect_instance"}
	case *agentv1.CommandEnvelope_ExecuteSql:
		return []string{"execute_sql"}
	case *agentv1.CommandEnvelope_ExecuteRegisteredProcess:
		return []string{"execute_registered_process"}
	case *agentv1.CommandEnvelope_CollectDiagnostic:
		return []string{"collect_diagnostic"}
	case *agentv1.CommandEnvelope_DiscoverDatabases:
		return []string{"discover_databases"}
	case *agentv1.CommandEnvelope_ReconcilePlugin:
		command := envelope.GetReconcilePlugin()
		capabilities := []string{"plugin.reconcile.v1"}
		if len(command.GetInstanceDescriptors()) > 0 || command.GetDesiredState() == agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_RUNNING || command.GetDesiredState() == agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_INSTALLED {
			capabilities = append(capabilities, "plugin_reconcile.instance_descriptors.v1")
		}
		if command.GetDesiredState() == agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_RUNNING && (len(command.GetTemplateRevisions()) > 0 || len(command.GetInstanceTemplateRevisions()) > 0) {
			capabilities = append(capabilities, "metric_template_lease.v1")
		}
		return capabilities
	case *agentv1.CommandEnvelope_ApplyPluginConfiguration:
		return []string{"plugin.configuration.apply.v1"}
	case *agentv1.CommandEnvelope_ValidateDatabaseInstance:
		return []string{"plugin.instance.validate.v1"}
	case *agentv1.CommandEnvelope_DrainPlugin:
		return []string{"plugin.drain.v1"}
	case *agentv1.CommandEnvelope_CollectDatabaseMetrics:
		capabilities := []string{"plugin.metrics.collect.v1"}
		if len(envelope.GetCollectDatabaseMetrics().GetTemplateRevisions()) > 0 {
			capabilities = append(capabilities, "metric_template_lease.v1")
		}
		return capabilities
	default:
		return nil
	}
}

func cloneRecoveryStates(states []*agentv1.CommandRecoveryState) []*agentv1.CommandRecoveryState {
	cloned := make([]*agentv1.CommandRecoveryState, 0, len(states))
	for _, state := range states {
		if state != nil {
			cloned = append(cloned, proto.Clone(state).(*agentv1.CommandRecoveryState))
		}
	}
	return cloned
}

var _ Dispatcher = (*Registry)(nil)

type Dispatcher interface {
	Dispatch(context.Context, string, *agentv1.CommandEnvelope) error
	Start(context.Context, string, *agentv1.CommandStart) error
	ReplayStart(context.Context, string, *agentv1.CommandStart) error
	Cancel(context.Context, string, string) error
	CancelPrepared(context.Context, string, string, string) error
	CancelExecution(context.Context, string, string, []byte, uint64, string) error
}
