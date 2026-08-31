package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/commandjournal"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
	"dbpilot.local/platform/internal/commandvalidation"
	discoverydomain "dbpilot.local/platform/internal/discovery"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const ControlProtocolVersion = "1"
const CapabilityDiscoveryReportACKV1 = "discovery_report_ack_v1"
const CapabilityDiscoverySourceResultsV1 = "discovery_source_results_v1"
const CapabilityDiscoverySourceResultsPendingLegacyV1 = "discovery_source_results_pending_legacy_v1"
const CapabilityDiscoveryPolicyAttestationV1 = "discovery_policy_attestation_v1"

var ErrControlStreamDisconnected = errors.New("Agent control stream is disconnected")

type discoveryControlIncompatibleError struct{}

func (discoveryControlIncompatibleError) Error() string {
	return "discovery unavailable: control plane lacks ACK or policy attestation capability"
}

var ErrDiscoveryControlIncompatible error = discoveryControlIncompatibleError{}
var ErrDiscoveryCompatibilityUnknown = errors.New("discovery compatibility unknown until HelloAck")

type DiscoveryCompatibility uint32

const (
	DiscoveryCompatibilityUnknown DiscoveryCompatibility = iota
	DiscoveryCompatibilityCompatible
	DiscoveryCompatibilityIncompatible
)

type nonRetryableDiscoveryError struct{}

func (nonRetryableDiscoveryError) Error() string               { return "discovery report rejected non-retryably" }
func (nonRetryableDiscoveryError) NonRetryableDiscovery() bool { return true }

const controlSendQueueCapacity = 64

type ProgressReporter interface {
	Report(*agentv1.CommandProgress) error
}

type CommandExecutor interface {
	Execute(context.Context, *agentv1.CommandEnvelope, ProgressReporter) (*agentv1.CommandResult, error)
}

type ExecutorRegistry struct {
	mu               sync.RWMutex
	executors        map[CommandKind]CommandExecutor
	processExecutors map[string]CommandExecutor
}

func NewExecutorRegistry() *ExecutorRegistry {
	return &ExecutorRegistry{executors: make(map[CommandKind]CommandExecutor), processExecutors: make(map[string]CommandExecutor)}
}

func (r *ExecutorRegistry) Register(kind CommandKind, executor CommandExecutor) error {
	if !knownCommandKind(kind) {
		return fmt.Errorf("unknown command kind %q", kind)
	}
	if kind == CommandKindExecuteRegisteredProcess {
		return errors.New("registered process executors must be bound to an exact process ID")
	}
	if executor == nil {
		return errors.New("command executor is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.executors[kind]; exists {
		return fmt.Errorf("command executor already registered for %q", kind)
	}
	r.executors[kind] = executor
	return nil
}

func (r *ExecutorRegistry) RegisterProcess(processID string, executor CommandExecutor) error {
	if executor == nil {
		return errors.New("command executor is required")
	}
	probe := &agentv1.CommandEnvelope{AgentId: "registry", Command: &agentv1.CommandEnvelope_ExecuteRegisteredProcess{ExecuteRegisteredProcess: &agentv1.ExecuteRegisteredProcess{ProcessId: processID}}}
	if err := commandvalidation.Validate(context.Background(), probe, nil); err != nil {
		return fmt.Errorf("invalid registered process ID: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.processExecutors[processID]; exists {
		return fmt.Errorf("command executor already registered for process %q", processID)
	}
	r.processExecutors[processID] = executor
	return nil
}

func (r *ExecutorRegistry) Capabilities() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	set := make(map[string]struct{}, len(r.executors)+2)
	for kind, executor := range r.executors {
		set[string(kind)] = struct{}{}
		if provider, ok := executor.(interface{ AdditionalCapabilities() []string }); ok {
			for _, capability := range provider.AdditionalCapabilities() {
				if strings.TrimSpace(capability) != "" {
					set[capability] = struct{}{}
				}
			}
		}
	}
	if len(r.processExecutors) > 0 {
		set[string(CommandKindExecuteRegisteredProcess)] = struct{}{}
	}
	capabilities := make([]string, 0, len(set))
	for capability := range set {
		capabilities = append(capabilities, capability)
	}
	sort.Strings(capabilities)
	return capabilities
}

func (r *ExecutorRegistry) executor(envelope *agentv1.CommandEnvelope) (CommandExecutor, bool) {
	kind, ok := envelopeCommandKind(envelope)
	if !ok {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if kind == CommandKindExecuteRegisteredProcess {
		executor, exists := r.processExecutors[envelope.GetExecuteRegisteredProcess().GetProcessId()]
		return executor, exists
	}
	executor, exists := r.executors[kind]
	return executor, exists
}

type ControlStream interface {
	Send(*agentv1.AgentMessage) error
	Recv() (*agentv1.ServerMessage, error)
	CloseSend() error
}

type StreamOpener func(context.Context) (ControlStream, error)

type CommandJournal interface {
	Prepare(context.Context, *agentv1.CommandEnvelope, time.Time) (bool, error)
	AuthorizeStart(context.Context, string, []byte, uint64, time.Time) error
	CancelPrepared(context.Context, string, time.Time) error
	MarkInterrupted(context.Context, string, time.Time) error
	Complete(context.Context, string, *agentv1.CommandResult, time.Time) error
	Active(context.Context) ([]commandjournal.Entry, error)
	PendingResults(context.Context) ([]commandjournal.Entry, error)
	MarkReported(context.Context, string, [sha256.Size]byte, time.Time) error
	MarkResultConflicted(context.Context, string, [sha256.Size]byte, string, time.Time) error
	Get(context.Context, string) (commandjournal.Entry, error)
}

type ControlClientConfig struct {
	AgentID            string
	AgentVersion       string
	OperatingSystem    string
	Architecture       string
	DatabaseAdapters   []string
	StreamOpener       StreamOpener
	Journal            CommandJournal
	Verifier           *CommandVerifier
	Executors          *ExecutorRegistry
	HeartbeatInterval  time.Duration
	ReconnectBackoff   time.Duration
	ResultRetryBackoff time.Duration
	Now                func() time.Time
	PluginObservations interface {
		Observation() *agentv1.PluginObservation
	}
}

type ControlClient struct {
	agentID            string
	agentVersion       string
	operatingSystem    string
	architecture       string
	databaseAdapters   []string
	openStream         StreamOpener
	journal            CommandJournal
	verifier           *CommandVerifier
	executors          *ExecutorRegistry
	heartbeatInterval  time.Duration
	reconnectBackoff   time.Duration
	resultRetryBackoff time.Duration
	now                func() time.Time
	pluginObservations interface {
		Observation() *agentv1.PluginObservation
	}

	sessionMu                  sync.RWMutex
	session                    *controlSession
	sendMu                     sync.Mutex
	runningMu                  sync.Mutex
	running                    map[string]runningCommand
	executorWait               sync.WaitGroup
	messageSequence            atomic.Uint64
	executionErrors            chan error
	discoveryMu                sync.Mutex
	discoveryWaiters           map[uint64]*discoveryAckWaiter
	discoveryCompatibility     atomic.Uint32
	discoverySourceResults     atomic.Bool
	discoverySourceResultsPeer atomic.Bool
	artifactLeaseMu            sync.Mutex
	artifactLeaseWaiters       map[string]*artifactLeaseWaiter
}

type artifactLeaseWaiter struct {
	request pluginsupervisor.ArtifactLeaseRequest
	result  chan artifactLeaseResult
}

type artifactLeaseResult struct {
	lease pluginsupervisor.ArtifactLease
	err   error
}

type discoveryAckWaiter struct {
	digest [sha256.Size]byte
	hostID string
	result chan error
}

type controlSendRequest struct {
	message *agentv1.AgentMessage
	result  chan error
}

type runningCommand struct {
	cancel         context.CancelFunc
	executionToken []byte
	leaseRevision  uint64
}

type controlSession struct {
	ctx                    context.Context
	cancel                 context.CancelFunc
	stream                 ControlStream
	outgoing               chan controlSendRequest
	sendErrors             chan error
	wait                   sync.WaitGroup
	resultRetryMu          sync.Mutex
	resultRetries          map[string]*scheduledResultRetry
	sourceUpgradeEligible  bool
	sourceUpgradeRequested atomic.Bool
	reconnect              chan struct{}
}

type scheduledResultRetry struct{ cancel context.CancelFunc }

func NewControlClient(config ControlClientConfig) (*ControlClient, error) {
	if strings.TrimSpace(config.AgentID) == "" {
		return nil, errors.New("Agent control client Agent ID is required")
	}
	if config.StreamOpener == nil || config.Journal == nil || config.Verifier == nil || config.Executors == nil {
		return nil, errors.New("Agent control client stream, journal, verifier, and executor registry are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if strings.TrimSpace(config.OperatingSystem) == "" {
		config.OperatingSystem = runtime.GOOS
	}
	if strings.TrimSpace(config.Architecture) == "" {
		config.Architecture = runtime.GOARCH
	}
	return &ControlClient{
		agentID: config.AgentID, agentVersion: config.AgentVersion, operatingSystem: config.OperatingSystem, architecture: config.Architecture,
		databaseAdapters: append([]string(nil), config.DatabaseAdapters...), openStream: config.StreamOpener, journal: config.Journal,
		verifier: config.Verifier, executors: config.Executors,
		pluginObservations: config.PluginObservations,
		heartbeatInterval:  boundedDuration(config.HeartbeatInterval, 30*time.Second, 10*time.Millisecond, 5*time.Minute),
		reconnectBackoff:   boundedDuration(config.ReconnectBackoff, time.Second, 10*time.Millisecond, time.Minute),
		resultRetryBackoff: boundedDuration(config.ResultRetryBackoff, 100*time.Millisecond, 10*time.Millisecond, 5*time.Second),
		now:                config.Now, running: make(map[string]runningCommand),
		executionErrors:      make(chan error, 1),
		discoveryWaiters:     make(map[uint64]*discoveryAckWaiter),
		artifactLeaseWaiters: make(map[string]*artifactLeaseWaiter),
	}, nil
}

func (c *ControlClient) Run(ctx context.Context) (runErr error) {
	defer func() {
		c.cancelAll()
		c.executorWait.Wait()
		if runErr == nil {
			select {
			case runErr = <-c.executionErrors:
			default:
			}
		}
	}()
	for {
		select {
		case executionErr := <-c.executionErrors:
			return executionErr
		default:
		}
		if err := ctx.Err(); err != nil {
			return nil
		}
		sessionContext, cancelSession := context.WithCancel(ctx)
		stream, err := c.openStream(sessionContext)
		if err == nil {
			err = c.runSession(sessionContext, cancelSession, stream, ctx)
			cancelSession()
			_ = stream.CloseSend()
		} else {
			cancelSession()
		}
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errDiscoveryProtocolReconnect) {
			continue
		}
		var fatal *fatalControlError
		if errors.As(err, &fatal) {
			return fatal.err
		}
		if permanentControlStreamError(err) {
			return err
		}
		if err := c.waitForReconnect(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

func permanentControlStreamError(err error) bool {
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied, codes.FailedPrecondition:
		return true
	default:
		return false
	}
}

func (c *ControlClient) runSession(ctx context.Context, cancel context.CancelFunc, stream ControlStream, executionParent context.Context) error {
	active, err := c.journal.Active(ctx)
	if err != nil {
		return fmt.Errorf("load command recovery state: %w", err)
	}
	recovery := make([]*agentv1.CommandRecoveryState, 0, len(active))
	for _, entry := range active {
		state := agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_PREPARED
		switch entry.State {
		case commandjournal.StateStartAuthorized:
			state = agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_START_AUTHORIZED
		case commandjournal.StateRunning:
			state = agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_RUNNING
		}
		recovery = append(recovery, &agentv1.CommandRecoveryState{CommandId: entry.CommandID, State: state, ExecutionToken: append([]byte(nil), entry.ExecutionToken...), LeaseRevision: entry.LeaseRevision})
	}
	capabilities := append(c.executors.Capabilities(), CapabilityDiscoveryPolicyAttestationV1, CapabilityDiscoveryReportACKV1)
	sort.Strings(capabilities)
	advertisesSourceResults := hasCapabilities(capabilities, CapabilityDiscoverySourceResultsV1)
	hello := &agentv1.AgentMessage{Message: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		ProtocolVersion: ControlProtocolVersion, AgentId: c.agentID, AgentVersion: c.agentVersion,
		OperatingSystem: c.operatingSystem, Architecture: c.architecture, Capabilities: capabilities,
		DatabaseAdapters: append([]string(nil), c.databaseAdapters...), ActiveCommands: recovery,
	}}}
	if err := c.sendOnStream(stream, hello); err != nil {
		cancel()
		_ = stream.CloseSend()
		return err
	}

	type receiveResult struct {
		message *agentv1.ServerMessage
		err     error
	}
	received := make(chan receiveResult, 1)
	session := &controlSession{ctx: ctx, cancel: cancel, stream: stream, outgoing: make(chan controlSendRequest, controlSendQueueCapacity), sendErrors: make(chan error, 1), resultRetries: make(map[string]*scheduledResultRetry), reconnect: make(chan struct{}, 1)}
	session.wait.Add(1)
	go func() {
		defer session.wait.Done()
		for {
			message, receiveErr := stream.Recv()
			select {
			case received <- receiveResult{message: message, err: receiveErr}:
			case <-ctx.Done():
				return
			}
			if receiveErr != nil {
				return
			}
		}
	}()
	defer func() {
		session.cancel()
		_ = stream.CloseSend()
		c.clearSession(session)
		session.wait.Wait()
	}()

	var first receiveResult
	select {
	case first = <-received:
	case <-ctx.Done():
		return ctx.Err()
	}
	if first.err != nil {
		return first.err
	}
	if first.message.GetHelloAck() == nil || first.message.GetHelloAck().GetProtocolVersion() != ControlProtocolVersion {
		return errors.New("control plane did not accept the Agent protocol version")
	}
	peerSourceResults := hasCapabilities(first.message.GetHelloAck().GetCapabilities(), CapabilityDiscoverySourceResultsV1)
	c.discoverySourceResultsPeer.Store(peerSourceResults)
	c.discoverySourceResults.Store(advertisesSourceResults && peerSourceResults)
	session.sourceUpgradeEligible = !advertisesSourceResults && hasCapabilities(capabilities, CapabilityDiscoverySourceResultsPendingLegacyV1) && peerSourceResults
	if hasCapabilities(first.message.GetHelloAck().GetCapabilities(), CapabilityDiscoveryReportACKV1, CapabilityDiscoveryPolicyAttestationV1) {
		c.discoveryCompatibility.Store(uint32(DiscoveryCompatibilityCompatible))
	} else {
		c.discoveryCompatibility.Store(uint32(DiscoveryCompatibilityIncompatible))
	}
	defer c.discoveryCompatibility.Store(uint32(DiscoveryCompatibilityUnknown))
	defer c.discoverySourceResults.Store(false)
	defer c.discoverySourceResultsPeer.Store(false)
	session.wait.Add(1)
	go c.runSendLoop(session)
	c.setSession(session)
	if err := c.sendHeartbeat(session); err != nil {
		return err
	}
	if err := c.replayPendingResults(ctx, session); err != nil {
		return err
	}

	heartbeats := time.NewTicker(c.heartbeatInterval)
	defer heartbeats.Stop()
	for {
		select {
		case item := <-received:
			if item.err != nil {
				return item.err
			}
			if err := c.handleServerMessage(ctx, executionParent, item.message); err != nil {
				return err
			}
		case sendErr := <-session.sendErrors:
			return sendErr
		case executionErr := <-c.executionErrors:
			return &fatalControlError{err: executionErr}
		case <-heartbeats.C:
			if err := c.sendHeartbeat(session); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-session.reconnect:
			return errDiscoveryProtocolReconnect
		}
	}
}

type fatalControlError struct{ err error }

var errDiscoveryProtocolReconnect = errors.New("graceful discovery protocol reconnect")

func (e *fatalControlError) Error() string { return e.err.Error() }
func (e *fatalControlError) Unwrap() error { return e.err }

func (c *ControlClient) runSendLoop(session *controlSession) {
	defer session.wait.Done()
	for {
		select {
		case request := <-session.outgoing:
			if session.ctx.Err() != nil {
				request.result <- ErrControlStreamDisconnected
				return
			}
			err := c.sendOnStream(session.stream, request.message)
			request.result <- err
			if err != nil {
				select {
				case session.sendErrors <- err:
				default:
				}
				return
			}
		case <-session.ctx.Done():
			return
		}
	}
}

func (c *ControlClient) handleServerMessage(ctx, executionParent context.Context, message *agentv1.ServerMessage) error {
	if message == nil {
		return errors.New("empty control-plane message")
	}
	switch typed := message.GetMessage().(type) {
	case *agentv1.ServerMessage_Command:
		return c.handleCommand(ctx, executionParent, typed.Command)
	case *agentv1.ServerMessage_CommandStart:
		return c.handleCommandStart(ctx, executionParent, typed.CommandStart)
	case *agentv1.ServerMessage_CommandCancellation:
		if err := commandvalidation.ValidateCancellation(typed.CommandCancellation); err != nil {
			return errors.New("command cancellation is invalid")
		}
		if err := c.cancelCommand(ctx, typed.CommandCancellation); err != nil {
			return err
		}
	case *agentv1.ServerMessage_CommandResultAcknowledgement:
		acknowledgement := typed.CommandResultAcknowledgement
		if err := commandvalidation.ValidateResultAcknowledgement(acknowledgement); err != nil {
			return errors.New("command result acknowledgement is invalid")
		}
		if !acknowledgement.GetPersisted() && acknowledgement.GetRetryable() {
			return c.scheduleResultRetry(ctx, acknowledgement)
		}
		if acknowledgement.GetPersisted() && !acknowledgement.GetRetryable() {
			c.cancelResultRetry(acknowledgement.GetCommandId())
			var digest [sha256.Size]byte
			copy(digest[:], acknowledgement.GetResultDigest())
			if err := c.journal.MarkReported(ctx, acknowledgement.GetCommandId(), digest, c.now()); err != nil {
				if errors.Is(err, commandjournal.ErrResultDigestMismatch) {
					return nil
				}
				return &fatalControlError{err: fmt.Errorf("mark durably acknowledged command result reported: %w", err)}
			}
		} else if !acknowledgement.GetRetryable() {
			c.cancelResultRetry(acknowledgement.GetCommandId())
			var digest [sha256.Size]byte
			copy(digest[:], acknowledgement.GetResultDigest())
			if err := c.journal.MarkResultConflicted(ctx, acknowledgement.GetCommandId(), digest, acknowledgement.GetReasonCode(), c.now()); err != nil {
				if errors.Is(err, commandjournal.ErrResultDigestMismatch) {
					return nil
				}
				return &fatalControlError{err: fmt.Errorf("persist non-retryable command result conflict: %w", err)}
			}
		}
	case *agentv1.ServerMessage_PolicyUpdate, *agentv1.ServerMessage_FlowControlInstruction:
		// Policy and flow-control consumers are independent runtime boundaries.
	case *agentv1.ServerMessage_HelloAck:
		return errors.New("duplicate Hello acknowledgement")
	case *agentv1.ServerMessage_DiscoveryReportAcknowledgement:
		return c.handleDiscoveryAcknowledgement(typed.DiscoveryReportAcknowledgement)
	case *agentv1.ServerMessage_PluginArtifactLeaseResponse:
		return c.handlePluginArtifactLeaseResponse(typed.PluginArtifactLeaseResponse)
	default:
		return errors.New("unsupported control-plane message")
	}
	return nil
}

func (c *ControlClient) scheduleResultRetry(ctx context.Context, acknowledgement *agentv1.CommandResultAcknowledgement) error {
	entry, err := c.journal.Get(ctx, acknowledgement.GetCommandId())
	if err != nil {
		return &fatalControlError{err: fmt.Errorf("load retryable command result: %w", err)}
	}
	if entry.Result == nil || (entry.State != commandjournal.StateCompleted && entry.State != commandjournal.StateInterrupted) || !entry.ReportedAt.IsZero() || subtle.ConstantTimeCompare(entry.ResultDigest[:], acknowledgement.GetResultDigest()) != 1 {
		return nil
	}
	c.sessionMu.RLock()
	session := c.session
	c.sessionMu.RUnlock()
	if session == nil || session.ctx.Err() != nil {
		return ErrControlStreamDisconnected
	}
	session.resultRetryMu.Lock()
	if _, exists := session.resultRetries[acknowledgement.GetCommandId()]; exists {
		session.resultRetryMu.Unlock()
		return nil
	}
	retryContext, cancel := context.WithCancel(session.ctx)
	retry := &scheduledResultRetry{cancel: cancel}
	session.resultRetries[acknowledgement.GetCommandId()] = retry
	session.wait.Add(1)
	session.resultRetryMu.Unlock()
	resultDigest := entry.ResultDigest
	commandID := entry.CommandID
	go func() {
		defer session.wait.Done()
		defer c.finishResultRetry(session, commandID, retry)
		timer := time.NewTimer(c.resultRetryBackoff)
		defer timer.Stop()
		select {
		case <-retryContext.Done():
			return
		case <-timer.C:
		}
		pending, loadErr := c.journal.Get(retryContext, commandID)
		if loadErr != nil || pending.Result == nil || (pending.State != commandjournal.StateCompleted && pending.State != commandjournal.StateInterrupted) || !pending.ReportedAt.IsZero() || subtle.ConstantTimeCompare(pending.ResultDigest[:], resultDigest[:]) != 1 {
			return
		}
		select {
		case <-retryContext.Done():
			return
		default:
		}
		_ = c.sendThroughSession(session, &agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandResult{CommandResult: pending.Result}})
	}()
	return nil
}

func (c *ControlClient) finishResultRetry(session *controlSession, commandID string, expected *scheduledResultRetry) {
	session.resultRetryMu.Lock()
	if session.resultRetries[commandID] == expected {
		delete(session.resultRetries, commandID)
	}
	session.resultRetryMu.Unlock()
}

func (c *ControlClient) cancelResultRetry(commandID string) {
	c.sessionMu.RLock()
	session := c.session
	c.sessionMu.RUnlock()
	if session == nil {
		return
	}
	session.resultRetryMu.Lock()
	retry := session.resultRetries[commandID]
	if retry != nil {
		delete(session.resultRetries, commandID)
	}
	session.resultRetryMu.Unlock()
	if retry != nil {
		retry.cancel()
	}
}

func (c *ControlClient) handleCommand(ctx, executionParent context.Context, envelope *agentv1.CommandEnvelope) error {
	if err := c.verifier.Verify(ctx, envelope); err != nil {
		return c.sendAcknowledgement(envelopeID(envelope), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED, commandRejectionReason(err))
	}
	_, exists := c.executors.executor(envelope)
	if !exists {
		return c.sendAcknowledgement(envelope.GetCommandId(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED, "CAPABILITY_UNAVAILABLE")
	}
	prepared, err := c.journal.Prepare(ctx, envelope, c.now())
	if err != nil {
		if errors.Is(err, commandjournal.ErrCommandIDConflict) {
			return c.sendAcknowledgement(envelope.GetCommandId(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED, "COMMAND_ID_CONFLICT")
		}
		if errors.Is(err, commandjournal.ErrNonceReplay) {
			return c.sendAcknowledgement(envelope.GetCommandId(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED, "NONCE_REPLAY")
		}
		return fmt.Errorf("durably prepare command: %w", err)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal prepared command envelope: %w", err)
	}
	digest := sha256.Sum256(encoded)
	if !prepared {
		entry, getErr := c.journal.Get(ctx, envelope.GetCommandId())
		if getErr != nil {
			return fmt.Errorf("load duplicate prepared command: %w", getErr)
		}
		digest = entry.EnvelopeDigest
	}
	return c.sendAgentMessage(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandPrepared{CommandPrepared: &agentv1.CommandPrepared{CommandId: envelope.GetCommandId(), EnvelopeDigest: digest[:]}}})
}

func (c *ControlClient) handleCommandStart(ctx, executionParent context.Context, start *agentv1.CommandStart) error {
	if err := commandvalidation.ValidateStartShape(start); err != nil {
		return errors.New("command start is invalid")
	}
	entry, err := c.journal.Get(ctx, start.GetCommandId())
	if err != nil {
		return fmt.Errorf("load prepared command: %w", err)
	}
	if entry.Envelope == nil {
		return errors.New("prepared command envelope is unavailable")
	}
	executor, exists := c.executors.executor(entry.Envelope)
	if !exists {
		return errors.New("prepared command executor is unavailable")
	}
	startDeadline := start.GetStartDeadline().AsTime().UTC()
	if err := c.journal.AuthorizeStart(ctx, start.GetCommandId(), start.GetExecutionToken(), start.GetLeaseRevision(), startDeadline); err != nil {
		if errors.Is(err, commandjournal.ErrStartDeadlineExceeded) {
			return c.expireAuthorizedStart(ctx, start.GetCommandId())
		}
		if errors.Is(err, commandjournal.ErrAlreadyRunning) || errors.Is(err, commandjournal.ErrStartConflict) {
			return nil
		}
		if errors.Is(err, commandjournal.ErrInvalidTransition) {
			return nil
		}
		return fmt.Errorf("authorize prepared command start: %w", err)
	}
	if !c.now().UTC().Before(startDeadline) {
		return c.interruptUnlaunchedStart(ctx, start.GetCommandId())
	}
	executionContext, cancel := context.WithCancel(executionParent)
	c.runningMu.Lock()
	c.running[start.GetCommandId()] = runningCommand{cancel: cancel, executionToken: append([]byte(nil), start.GetExecutionToken()...), leaseRevision: start.GetLeaseRevision()}
	c.runningMu.Unlock()
	c.executorWait.Add(1)
	go func() {
		defer c.executorWait.Done()
		defer cancel()
		c.execute(executionContext, entry.Envelope, start.GetExecutionToken(), start.GetLeaseRevision(), executor)
	}()
	return nil
}

func (c *ControlClient) expireAuthorizedStart(ctx context.Context, commandID string) error {
	entry, err := c.journal.Get(ctx, commandID)
	if err != nil {
		return fmt.Errorf("load expired command start: %w", err)
	}
	switch entry.State {
	case commandjournal.StateRunning, commandjournal.StateInterrupted, commandjournal.StateCompleted, commandjournal.StateCancelled:
		return nil
	case commandjournal.StatePrepared:
		if err := c.journal.CancelPrepared(ctx, commandID, c.now()); err != nil && !errors.Is(err, commandjournal.ErrInvalidTransition) {
			return fmt.Errorf("persist expired prepared command: %w", err)
		}
		return nil
	case commandjournal.StateStartAuthorized:
		return c.persistInterruptedStart(ctx, commandID)
	default:
		return fmt.Errorf("expire command start from unsupported state %q", entry.State)
	}
}

func (c *ControlClient) interruptUnlaunchedStart(ctx context.Context, commandID string) error {
	c.runningMu.Lock()
	_, launched := c.running[commandID]
	c.runningMu.Unlock()
	if launched {
		return nil
	}
	return c.persistInterruptedStart(ctx, commandID)
}

func (c *ControlClient) persistInterruptedStart(ctx context.Context, commandID string) error {
	if err := c.journal.MarkInterrupted(ctx, commandID, c.now()); err != nil {
		return fmt.Errorf("persist interrupted command start: %w", err)
	}
	entry, err := c.journal.Get(ctx, commandID)
	if err != nil {
		return fmt.Errorf("load interrupted command result: %w", err)
	}
	if entry.Result == nil {
		return errors.New("interrupted command result is unavailable")
	}
	if err := c.sendAgentMessage(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandResult{CommandResult: entry.Result}}); err != nil && !errors.Is(err, ErrControlStreamDisconnected) {
		return err
	}
	return nil
}

func (c *ControlClient) execute(ctx context.Context, envelope *agentv1.CommandEnvelope, executionToken []byte, leaseRevision uint64, executor CommandExecutor) {
	reporter := commandProgressReporter{client: c, commandID: envelope.GetCommandId(), executionToken: append([]byte(nil), executionToken...), leaseRevision: leaseRevision, startedAt: c.now().UTC()}
	result, executionErr := executor.Execute(ctx, envelope, reporter)
	if result == nil {
		result = &agentv1.CommandResult{CommandId: envelope.GetCommandId()}
	}
	result.CommandId = envelope.GetCommandId()
	result.ExecutionToken = append([]byte(nil), executionToken...)
	result.LeaseRevision = leaseRevision
	if executionErr != nil || result.GetState() == agentv1.CommandResultState_COMMAND_RESULT_STATE_UNSPECIFIED {
		if errors.Is(ctx.Err(), context.Canceled) {
			result.State = agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED
			result.ErrorCode = "COMMAND_CANCELLED"
		} else {
			result.State = agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED
			result.ErrorCode = "EXECUTOR_FAILED"
			result.Summary = "command execution failed"
		}
	}
	if err := c.journal.Complete(context.Background(), envelope.GetCommandId(), result, c.now()); err != nil {
		c.reportExecutionError(fmt.Errorf("persist terminal command result: %w", err))
	} else {
		_ = c.sendAgentMessage(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandResult{CommandResult: result}})
	}
	c.runningMu.Lock()
	delete(c.running, envelope.GetCommandId())
	c.runningMu.Unlock()
}

func (c *ControlClient) replayPendingResults(ctx context.Context, session *controlSession) error {
	pending, err := c.journal.PendingResults(ctx)
	if err != nil {
		return &fatalControlError{err: fmt.Errorf("load pending command results: %w", err)}
	}
	for _, entry := range pending {
		if entry.Result == nil {
			continue
		}
		if err := c.sendThroughSession(session, &agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandResult{CommandResult: entry.Result}}); err != nil {
			return err
		}
	}
	return nil
}

func (c *ControlClient) reportExecutionError(err error) {
	select {
	case c.executionErrors <- err:
	default:
	}
}

func (c *ControlClient) sendHeartbeat(session *controlSession) error {
	c.runningMu.Lock()
	activeIDs := make([]string, 0, len(c.running))
	activeByID := make(map[string]runningCommand, len(c.running))
	for commandID, running := range c.running {
		activeIDs = append(activeIDs, commandID)
		activeByID[commandID] = runningCommand{executionToken: append([]byte(nil), running.executionToken...), leaseRevision: running.leaseRevision}
	}
	c.runningMu.Unlock()
	sort.Strings(activeIDs)
	active := make([]*agentv1.ActiveCommand, 0, len(activeIDs))
	for _, commandID := range activeIDs {
		running := activeByID[commandID]
		active = append(active, &agentv1.ActiveCommand{CommandId: commandID, ExecutionToken: running.executionToken, LeaseRevision: running.leaseRevision})
	}
	message := &agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{AgentId: c.agentID, RunningCommands: uint32(len(active)), ActiveCommandIds: activeIDs, ActiveCommands: active}}}
	if err := c.sendThroughSession(session, message); err != nil {
		return err
	}
	if c.pluginObservations != nil {
		observation := c.pluginObservations.Observation()
		if observation != nil && observation.GetAgentId() == c.agentID && observation.GetHostId() != "" && observation.GetObservationRevision() != 0 && observation.GetObservedAt() != nil && observation.GetObservedAt().IsValid() && len(observation.GetAssignments()) <= 128 {
			return c.sendThroughSession(session, &agentv1.AgentMessage{Message: &agentv1.AgentMessage_PluginObservation{PluginObservation: observation}})
		}
	}
	return nil
}

func (c *ControlClient) sendAcknowledgement(commandID string, state agentv1.CommandAcknowledgementState, reason string) error {
	return c.sendAgentMessage(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandAcknowledgement{CommandAcknowledgement: &agentv1.CommandAcknowledgement{CommandId: commandID, State: state, ReasonCode: reason}}})
}

type commandProgressReporter struct {
	client         *ControlClient
	commandID      string
	executionToken []byte
	leaseRevision  uint64
	startedAt      time.Time
}

func (r commandProgressReporter) ExecutionFence() pluginsupervisor.ExecutionFence {
	return pluginsupervisor.ExecutionFence{CommandID: r.commandID, ExecutionToken: append([]byte(nil), r.executionToken...), LeaseRevision: r.leaseRevision, StartedAt: r.startedAt}
}

func (r commandProgressReporter) Report(progress *agentv1.CommandProgress) error {
	if progress == nil {
		return errors.New("command progress is required")
	}
	if progress.GetCommandId() == "" {
		progress.CommandId = r.commandID
	}
	if progress.GetCommandId() != r.commandID {
		return errors.New("command progress ID does not match execution")
	}
	if len(progress.GetExecutionToken()) == 0 {
		progress.ExecutionToken = append([]byte(nil), r.executionToken...)
	}
	if !executionTokensEqual(progress.GetExecutionToken(), r.executionToken) {
		return errors.New("command progress token does not match execution")
	}
	if progress.GetLeaseRevision() == 0 {
		progress.LeaseRevision = r.leaseRevision
	}
	if progress.GetLeaseRevision() != r.leaseRevision {
		return errors.New("command progress revision does not match execution")
	}
	return r.client.sendAgentMessage(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandProgress{CommandProgress: progress}})
}

func (c *ControlClient) cancelCommand(ctx context.Context, cancellation *agentv1.CommandCancellation) error {
	if len(cancellation.GetExecutionToken()) == 0 && cancellation.GetLeaseRevision() == 0 {
		if err := c.journal.CancelPrepared(ctx, cancellation.GetCommandId(), c.now()); err != nil && !errors.Is(err, commandjournal.ErrInvalidTransition) && !errors.Is(err, commandjournal.ErrCommandNotFound) {
			return fmt.Errorf("durably cancel prepared command: %w", err)
		}
		return nil
	}
	c.runningMu.Lock()
	running, exists := c.running[cancellation.GetCommandId()]
	c.runningMu.Unlock()
	if !exists || !executionTokensEqual(running.executionToken, cancellation.GetExecutionToken()) || running.leaseRevision != cancellation.GetLeaseRevision() {
		return nil
	}
	running.cancel()
	return nil
}

func executionTokensEqual(left, right []byte) bool {
	return len(left) == sha256.Size && len(right) == sha256.Size && subtle.ConstantTimeCompare(left, right) == 1
}

func (c *ControlClient) cancelAll() {
	c.runningMu.Lock()
	cancellations := make([]context.CancelFunc, 0, len(c.running))
	for _, running := range c.running {
		cancellations = append(cancellations, running.cancel)
	}
	c.runningMu.Unlock()
	for _, cancel := range cancellations {
		cancel()
	}
}

func (c *ControlClient) setSession(session *controlSession) {
	c.sessionMu.Lock()
	c.session = session
	c.sessionMu.Unlock()
}

func (c *ControlClient) clearSession(expected *controlSession) {
	c.sessionMu.Lock()
	if c.session == expected {
		c.session = nil
	}
	c.sessionMu.Unlock()
	c.failPluginArtifactLeaseWaiters()
}

// LeasePluginArtifact requests an operation-bound, ephemeral artifact lease on
// the already authenticated AgentControl stream. The returned URL and headers
// live only in the caller and are never written to the command journal.
func (c *ControlClient) LeasePluginArtifact(ctx context.Context, request pluginsupervisor.ArtifactLeaseRequest) (pluginsupervisor.ArtifactLease, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || !validArtifactLeaseResource(request.AssignmentID) || !validArtifactLeaseResource(request.ArtifactID) || request.OperationRevision == 0 {
		return pluginsupervisor.ArtifactLease{}, pluginsupervisor.ErrArtifactLease
	}
	var nonce [sha256.Size]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return pluginsupervisor.ArtifactLease{}, pluginsupervisor.ErrArtifactLease
	}
	waiter := &artifactLeaseWaiter{request: request, result: make(chan artifactLeaseResult, 1)}
	key := string(nonce[:])
	c.artifactLeaseMu.Lock()
	if _, duplicate := c.artifactLeaseWaiters[key]; duplicate {
		c.artifactLeaseMu.Unlock()
		return pluginsupervisor.ArtifactLease{}, pluginsupervisor.ErrArtifactLease
	}
	c.artifactLeaseWaiters[key] = waiter
	c.artifactLeaseMu.Unlock()
	defer func() {
		c.artifactLeaseMu.Lock()
		if c.artifactLeaseWaiters[key] == waiter {
			delete(c.artifactLeaseWaiters, key)
		}
		c.artifactLeaseMu.Unlock()
	}()
	message := &agentv1.AgentMessage{Message: &agentv1.AgentMessage_PluginArtifactLeaseRequest{PluginArtifactLeaseRequest: &agentv1.PluginArtifactLeaseRequest{RequestNonce: nonce[:], AssignmentId: request.AssignmentID, ArtifactId: request.ArtifactID, OperationRevision: request.OperationRevision}}}
	if err := c.sendAgentMessage(message); err != nil {
		return pluginsupervisor.ArtifactLease{}, pluginsupervisor.ErrArtifactLease
	}
	select {
	case <-ctx.Done():
		return pluginsupervisor.ArtifactLease{}, pluginsupervisor.ErrArtifactLease
	case result := <-waiter.result:
		return result.lease, result.err
	}
}

func (c *ControlClient) handlePluginArtifactLeaseResponse(response *agentv1.PluginArtifactLeaseResponse) error {
	if response == nil || len(response.GetRequestNonce()) != sha256.Size {
		return nil
	}
	key := string(response.GetRequestNonce())
	c.artifactLeaseMu.Lock()
	waiter := c.artifactLeaseWaiters[key]
	if waiter != nil {
		delete(c.artifactLeaseWaiters, key)
	}
	c.artifactLeaseMu.Unlock()
	if waiter == nil {
		return nil
	}
	valid := validArtifactLeaseResource(response.GetLeaseId()) && response.GetAssignmentId() == waiter.request.AssignmentID && response.GetArtifactId() == waiter.request.ArtifactID && response.GetOperationRevision() == waiter.request.OperationRevision && response.GetExpiresAt() != nil && response.GetExpiresAt().IsValid() && response.GetExpiresAt().AsTime().After(c.now()) && response.GetDownloadUrl() != "" && len(response.GetDownloadUrl()) <= 2048 && len(response.GetRequestHeaders()) <= 8
	if !valid {
		waiter.result <- artifactLeaseResult{err: pluginsupervisor.ErrArtifactLease}
		return nil
	}
	headers := make(map[string]string, len(response.GetRequestHeaders()))
	for name, value := range response.GetRequestHeaders() {
		if name == "" || len(name) > 128 || value == "" || len(value) > 4096 || strings.ContainsAny(name+value, "\x00\r\n") {
			waiter.result <- artifactLeaseResult{err: pluginsupervisor.ErrArtifactLease}
			return nil
		}
		headers[name] = value
	}
	waiter.result <- artifactLeaseResult{lease: pluginsupervisor.ArtifactLease{LeaseID: response.GetLeaseId(), AssignmentID: response.GetAssignmentId(), ArtifactID: response.GetArtifactId(), OperationRevision: response.GetOperationRevision(), ExpiresAt: response.GetExpiresAt().AsTime().UTC(), DownloadURL: response.GetDownloadUrl(), RequestHeaders: headers}}
	return nil
}

func (c *ControlClient) failPluginArtifactLeaseWaiters() {
	c.artifactLeaseMu.Lock()
	waiters := make([]*artifactLeaseWaiter, 0, len(c.artifactLeaseWaiters))
	for key, waiter := range c.artifactLeaseWaiters {
		delete(c.artifactLeaseWaiters, key)
		waiters = append(waiters, waiter)
	}
	c.artifactLeaseMu.Unlock()
	for _, waiter := range waiters {
		select {
		case waiter.result <- artifactLeaseResult{err: pluginsupervisor.ErrArtifactLease}:
		default:
		}
	}
}

func validArtifactLeaseResource(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if index == 0 && !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9') || index > 0 && !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '.' || character == ':' || character == '-') {
			return false
		}
	}
	return true
}

func (c *ControlClient) sendAgentMessage(message *agentv1.AgentMessage) error {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	if c.session == nil {
		return ErrControlStreamDisconnected
	}
	return c.sendThroughSession(c.session, message)
}

// ReportDiscovery sends a bounded discovery report on the authenticated
// AgentControl stream. Server-side scope is resolved from the mTLS Agent ID.
func (c *ControlClient) ReportDiscovery(ctx context.Context, report *agentv1.DiscoveryReport) error {
	switch c.DiscoveryCompatibility() {
	case DiscoveryCompatibilityUnknown:
		return ErrDiscoveryCompatibilityUnknown
	case DiscoveryCompatibilityIncompatible:
		return ErrDiscoveryControlIncompatible
	}
	if report == nil || report.GetAgentId() != c.agentID || report.GetObservationRevision() == 0 || report.GetRuleRevision() == 0 || len(report.GetCandidates()) > 1024 {
		return errors.New("discovery report is invalid")
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil || len(encoded) > discoverydomain.MaximumDiscoveryReportBytes {
		return errors.New("discovery report exceeds transport limit")
	}
	digest := sha256.Sum256(encoded)
	waiter := &discoveryAckWaiter{digest: digest, hostID: report.GetHostId(), result: make(chan error, 1)}
	c.discoveryMu.Lock()
	if _, exists := c.discoveryWaiters[report.GetObservationRevision()]; exists {
		c.discoveryMu.Unlock()
		return errors.New("discovery report revision is already pending")
	}
	c.discoveryWaiters[report.GetObservationRevision()] = waiter
	c.discoveryMu.Unlock()
	defer func() {
		c.discoveryMu.Lock()
		if c.discoveryWaiters[report.GetObservationRevision()] == waiter {
			delete(c.discoveryWaiters, report.GetObservationRevision())
		}
		c.discoveryMu.Unlock()
	}()
	c.sessionMu.RLock()
	session := c.session
	c.sessionMu.RUnlock()
	if session == nil {
		return ErrControlStreamDisconnected
	}
	if err := c.sendThroughSession(session, &agentv1.AgentMessage{Message: &agentv1.AgentMessage_DiscoveryReport{DiscoveryReport: report}}); err != nil {
		return err
	}
	select {
	case err := <-waiter.result:
		return err
	case <-session.ctx.Done():
		return ErrControlStreamDisconnected
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *ControlClient) DiscoveryCompatibility() DiscoveryCompatibility {
	return DiscoveryCompatibility(c.discoveryCompatibility.Load())
}

func (c *ControlClient) DiscoverySourceResultsSupported() bool {
	return c.discoverySourceResults.Load()
}

func (c *ControlClient) DiscoverySourceResultsPeerSupported() bool {
	return c.discoverySourceResultsPeer.Load()
}

func (c *ControlClient) RequestDiscoverySourceResultsReconnect() bool {
	c.sessionMu.RLock()
	session := c.session
	c.sessionMu.RUnlock()
	if session == nil || !session.sourceUpgradeEligible || !c.discoverySourceResultsPeer.Load() || !session.sourceUpgradeRequested.CompareAndSwap(false, true) {
		return false
	}
	select {
	case session.reconnect <- struct{}{}:
	default:
	}
	return true
}

func hasCapabilities(values []string, required ...string) bool {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	for _, value := range required {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}

func (c *ControlClient) handleDiscoveryAcknowledgement(ack *agentv1.DiscoveryReportAcknowledgement) error {
	if ack == nil || ack.GetAgentId() != c.agentID || ack.GetObservationRevision() == 0 || len(ack.GetReportDigest()) != sha256.Size {
		return errors.New("discovery acknowledgement is invalid")
	}
	c.discoveryMu.Lock()
	waiter := c.discoveryWaiters[ack.GetObservationRevision()]
	c.discoveryMu.Unlock()
	if waiter == nil {
		return nil
	}
	var outcome error
	if ack.GetHostId() != waiter.hostID || subtle.ConstantTimeCompare(waiter.digest[:], ack.GetReportDigest()) != 1 {
		outcome = errors.New("discovery acknowledgement correlation mismatch")
	} else if ack.GetPersisted() && !ack.GetRetryable() {
		outcome = nil
	} else if ack.GetRetryable() {
		outcome = errors.New("discovery report persistence retry requested")
	} else {
		outcome = nonRetryableDiscoveryError{}
	}
	select {
	case waiter.result <- outcome:
	default:
	}
	return nil
}

func (c *ControlClient) sendThroughSession(session *controlSession, message *agentv1.AgentMessage) error {
	if session.ctx.Err() != nil {
		return ErrControlStreamDisconnected
	}
	request := controlSendRequest{message: message, result: make(chan error, 1)}
	select {
	case session.outgoing <- request:
	case <-session.ctx.Done():
		return ErrControlStreamDisconnected
	}
	select {
	case err := <-request.result:
		return err
	case <-session.ctx.Done():
		return ErrControlStreamDisconnected
	}
}

func (c *ControlClient) sendOnStream(stream ControlStream, message *agentv1.AgentMessage) error {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	message.MessageId = fmt.Sprintf("agent-%d", c.messageSequence.Add(1))
	message.SentAt = timestamppb.New(c.now())
	return stream.Send(message)
}

func commandRejectionReason(err error) string {
	switch {
	case errors.Is(err, ErrInvalidCommandSignature):
		return "INVALID_SIGNATURE"
	case errors.Is(err, ErrCommandExpired):
		return "COMMAND_EXPIRED"
	case errors.Is(err, ErrCommandAgentMismatch):
		return "AGENT_MISMATCH"
	case errors.Is(err, ErrCommandCapabilityUnavailable):
		return "CAPABILITY_UNAVAILABLE"
	case errors.Is(err, ErrCommandNonceReplay):
		return "NONCE_REPLAY"
	case errors.Is(err, ErrCommandTargetUnauthorized):
		return "TARGET_UNAUTHORIZED"
	default:
		return "INVALID_COMMAND"
	}
}

func envelopeID(envelope *agentv1.CommandEnvelope) string {
	if envelope == nil {
		return ""
	}
	return envelope.GetCommandId()
}

func boundedDuration(value, fallback, minimum, maximum time.Duration) time.Duration {
	if value <= 0 {
		value = fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func (c *ControlClient) waitForReconnect(ctx context.Context) error {
	timer := time.NewTimer(c.reconnectBackoff)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case executionErr := <-c.executionErrors:
		return executionErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
