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
	agentID         string
	capabilities    map[string]struct{}
	capabilityList  []string
	active          []*agentv1.CommandRecoveryState
	send            chan *agentv1.ServerMessage
	cancel          context.CancelFunc
	lastHeartbeat   time.Time
	leaseDurations  map[string]time.Duration
	leases          map[string]time.Time
	executionTokens map[string][]byte
	leaseRevisions  map[string]uint64
}

// SessionInfo is a defensive snapshot of an authenticated live Agent session.
type SessionInfo struct {
	AgentID        string
	Capabilities   []string
	ActiveCommands []*agentv1.CommandRecoveryState
	LastHeartbeat  time.Time
	Leases         map[string]time.Time
	LeaseRevisions map[string]uint64
}

// Registry owns the single live session for each Agent and is the command Dispatcher.
type Registry struct {
	mu            sync.RWMutex
	queueCapacity int
	sessions      map[string]*session
	now           func() time.Time
}

func NewRegistry(queueCapacity int) *Registry {
	if queueCapacity <= 0 {
		queueCapacity = 1
	}
	return &Registry{queueCapacity: queueCapacity, sessions: make(map[string]*session), now: time.Now}
}

func (r *Registry) register(agentID string, capabilities []string, active []*agentv1.CommandRecoveryState, cancel context.CancelFunc) error {
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
	r.sessions[agentID] = &session{
		agentID: agentID, capabilities: capabilitySet, capabilityList: capabilityList,
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
		AgentID: current.agentID, Capabilities: append([]string(nil), current.capabilityList...),
		ActiveCommands: cloneRecoveryStates(current.active), LastHeartbeat: current.lastHeartbeat, Leases: leases, LeaseRevisions: revisions,
	}, true
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
	return SessionInfo{AgentID: current.agentID, Capabilities: append([]string(nil), current.capabilityList...), ActiveCommands: cloneRecoveryStates(current.active), LastHeartbeat: current.lastHeartbeat, Leases: leasing, LeaseRevisions: revisions}, true
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
	capability, ok := commandCapability(envelope)
	if !ok {
		return &dispatchError{err: ErrInvalidCommand}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.sessions[agentID]
	if !exists {
		return &dispatchError{err: ErrAgentUnavailable, retryable: true}
	}
	if _, advertised := current.capabilities[capability]; !advertised {
		return &dispatchError{err: fmt.Errorf("%w: %s", ErrCapabilityNotAdvertised, capability)}
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
	message := &agentv1.ServerMessage{MessageId: commandID, Message: &agentv1.ServerMessage_CommandCancellation{CommandCancellation: &agentv1.CommandCancellation{CommandId: commandID}}}
	select {
	case current.send <- message:
		r.mu.RUnlock()
		return nil
	default:
		r.mu.RUnlock()
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
	switch envelope.GetCommand().(type) {
	case *agentv1.CommandEnvelope_CollectNow:
		return "collect_now", true
	case *agentv1.CommandEnvelope_InspectInstance:
		return "inspect_instance", true
	case *agentv1.CommandEnvelope_ExecuteSql:
		return "execute_sql", true
	case *agentv1.CommandEnvelope_ExecuteRegisteredProcess:
		return "execute_registered_process", true
	case *agentv1.CommandEnvelope_CollectDiagnostic:
		return "collect_diagnostic", true
	default:
		return "", false
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
	Cancel(context.Context, string, string) error
}
