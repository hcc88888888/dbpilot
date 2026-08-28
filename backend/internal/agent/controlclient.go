package agent

import (
	"context"
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
	"dbpilot.local/platform/internal/commandvalidation"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const ControlProtocolVersion = "1"

var ErrControlStreamDisconnected = errors.New("Agent control stream is disconnected")

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
	capabilities := make([]string, 0, len(r.executors))
	for kind := range r.executors {
		capabilities = append(capabilities, string(kind))
	}
	if len(r.processExecutors) > 0 {
		capabilities = append(capabilities, string(CommandKindExecuteRegisteredProcess))
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
	Accept(context.Context, *agentv1.CommandEnvelope) (bool, error)
	Start(context.Context, string, time.Time) error
	Complete(context.Context, string, *agentv1.CommandResult, time.Time) error
	Active(context.Context) ([]commandjournal.Entry, error)
	PendingResults(context.Context) ([]commandjournal.Entry, error)
	MarkReported(context.Context, string, time.Time) error
}

type ControlClientConfig struct {
	AgentID           string
	AgentVersion      string
	OperatingSystem   string
	Architecture      string
	DatabaseAdapters  []string
	StreamOpener      StreamOpener
	Journal           CommandJournal
	Verifier          *CommandVerifier
	Executors         *ExecutorRegistry
	HeartbeatInterval time.Duration
	ReconnectBackoff  time.Duration
	Now               func() time.Time
}

type ControlClient struct {
	agentID           string
	agentVersion      string
	operatingSystem   string
	architecture      string
	databaseAdapters  []string
	openStream        StreamOpener
	journal           CommandJournal
	verifier          *CommandVerifier
	executors         *ExecutorRegistry
	heartbeatInterval time.Duration
	reconnectBackoff  time.Duration
	now               func() time.Time

	sessionMu       sync.RWMutex
	session         *controlSession
	sendMu          sync.Mutex
	runningMu       sync.Mutex
	running         map[string]context.CancelFunc
	executorWait    sync.WaitGroup
	messageSequence atomic.Uint64
	executionErrors chan error
}

type controlSendRequest struct {
	message *agentv1.AgentMessage
	result  chan error
}

type controlSession struct {
	ctx        context.Context
	cancel     context.CancelFunc
	stream     ControlStream
	outgoing   chan controlSendRequest
	sendErrors chan error
	wait       sync.WaitGroup
}

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
		heartbeatInterval: boundedDuration(config.HeartbeatInterval, 30*time.Second, 10*time.Millisecond, 5*time.Minute),
		reconnectBackoff:  boundedDuration(config.ReconnectBackoff, time.Second, 10*time.Millisecond, time.Minute),
		now:               config.Now, running: make(map[string]context.CancelFunc),
		executionErrors: make(chan error, 1),
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
		var fatal *fatalControlError
		if errors.As(err, &fatal) {
			return fatal.err
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

func (c *ControlClient) runSession(ctx context.Context, cancel context.CancelFunc, stream ControlStream, executionParent context.Context) error {
	active, err := c.journal.Active(ctx)
	if err != nil {
		return fmt.Errorf("load command recovery state: %w", err)
	}
	recovery := make([]*agentv1.CommandRecoveryState, 0, len(active))
	for _, entry := range active {
		state := agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_ACCEPTED
		if entry.State == commandjournal.StateRunning {
			state = agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_RUNNING
		}
		recovery = append(recovery, &agentv1.CommandRecoveryState{CommandId: entry.CommandID, State: state})
	}
	hello := &agentv1.AgentMessage{Message: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		ProtocolVersion: ControlProtocolVersion, AgentId: c.agentID, AgentVersion: c.agentVersion,
		OperatingSystem: c.operatingSystem, Architecture: c.architecture, Capabilities: c.executors.Capabilities(),
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
	session := &controlSession{ctx: ctx, cancel: cancel, stream: stream, outgoing: make(chan controlSendRequest, controlSendQueueCapacity), sendErrors: make(chan error, 1)}
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
	session.wait.Add(1)
	go c.runSendLoop(session)
	c.setSession(session)
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
		}
	}
}

type fatalControlError struct{ err error }

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
	case *agentv1.ServerMessage_CommandCancellation:
		if typed.CommandCancellation != nil {
			c.cancelCommand(typed.CommandCancellation.GetCommandId())
		}
	case *agentv1.ServerMessage_CommandResultAcknowledgement:
		acknowledgement := typed.CommandResultAcknowledgement
		if acknowledgement == nil || strings.TrimSpace(acknowledgement.GetCommandId()) == "" {
			return errors.New("command result acknowledgement is invalid")
		}
		if acknowledgement.GetPersisted() {
			if err := c.journal.MarkReported(ctx, acknowledgement.GetCommandId(), c.now()); err != nil {
				return &fatalControlError{err: fmt.Errorf("mark durably acknowledged command result reported: %w", err)}
			}
		}
	case *agentv1.ServerMessage_PolicyUpdate, *agentv1.ServerMessage_FlowControlInstruction:
		// Policy and flow-control consumers are independent runtime boundaries.
	case *agentv1.ServerMessage_HelloAck:
		return errors.New("duplicate Hello acknowledgement")
	default:
		return errors.New("unsupported control-plane message")
	}
	return nil
}

func (c *ControlClient) handleCommand(ctx, executionParent context.Context, envelope *agentv1.CommandEnvelope) error {
	if err := c.verifier.Verify(ctx, envelope); err != nil {
		return c.sendAcknowledgement(envelopeID(envelope), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED, commandRejectionReason(err))
	}
	executor, exists := c.executors.executor(envelope)
	if !exists {
		return c.sendAcknowledgement(envelope.GetCommandId(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED, "CAPABILITY_UNAVAILABLE")
	}
	accepted, err := c.journal.Accept(ctx, envelope)
	if err != nil {
		if errors.Is(err, commandjournal.ErrCommandIDConflict) {
			return c.sendAcknowledgement(envelope.GetCommandId(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED, "COMMAND_ID_CONFLICT")
		}
		if errors.Is(err, commandjournal.ErrNonceReplay) {
			return c.sendAcknowledgement(envelope.GetCommandId(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED, "NONCE_REPLAY")
		}
		return fmt.Errorf("durably accept command: %w", err)
	}
	if !accepted {
		return c.sendAcknowledgement(envelope.GetCommandId(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_DUPLICATE, "")
	}
	if err := c.journal.Start(ctx, envelope.GetCommandId(), c.now()); err != nil {
		return fmt.Errorf("start accepted command: %w", err)
	}
	executionContext, cancel := context.WithCancel(executionParent)
	c.runningMu.Lock()
	c.running[envelope.GetCommandId()] = cancel
	c.runningMu.Unlock()
	ackErr := c.sendAcknowledgement(envelope.GetCommandId(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED, "")
	c.executorWait.Add(1)
	go func() {
		defer c.executorWait.Done()
		defer cancel()
		c.execute(executionContext, envelope, executor)
	}()
	return ackErr
}

func (c *ControlClient) execute(ctx context.Context, envelope *agentv1.CommandEnvelope, executor CommandExecutor) {
	reporter := commandProgressReporter{client: c, commandID: envelope.GetCommandId()}
	result, executionErr := executor.Execute(ctx, envelope, reporter)
	if result == nil {
		result = &agentv1.CommandResult{CommandId: envelope.GetCommandId()}
	}
	result.CommandId = envelope.GetCommandId()
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
	active := make([]string, 0, len(c.running))
	for commandID := range c.running {
		active = append(active, commandID)
	}
	c.runningMu.Unlock()
	sort.Strings(active)
	message := &agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{AgentId: c.agentID, RunningCommands: uint32(len(active)), ActiveCommandIds: active}}}
	return c.sendThroughSession(session, message)
}

func (c *ControlClient) sendAcknowledgement(commandID string, state agentv1.CommandAcknowledgementState, reason string) error {
	return c.sendAgentMessage(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandAcknowledgement{CommandAcknowledgement: &agentv1.CommandAcknowledgement{CommandId: commandID, State: state, ReasonCode: reason}}})
}

type commandProgressReporter struct {
	client    *ControlClient
	commandID string
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
	return r.client.sendAgentMessage(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandProgress{CommandProgress: progress}})
}

func (c *ControlClient) cancelCommand(commandID string) {
	c.runningMu.Lock()
	cancel := c.running[commandID]
	c.runningMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *ControlClient) cancelAll() {
	c.runningMu.Lock()
	cancellations := make([]context.CancelFunc, 0, len(c.running))
	for _, cancel := range c.running {
		cancellations = append(cancellations, cancel)
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
}

func (c *ControlClient) sendAgentMessage(message *agentv1.AgentMessage) error {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	if c.session == nil {
		return ErrControlStreamDisconnected
	}
	return c.sendThroughSession(c.session, message)
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
