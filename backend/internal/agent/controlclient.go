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
	"google.golang.org/protobuf/types/known/timestamppb"
)

const ControlProtocolVersion = "1"

var ErrControlStreamDisconnected = errors.New("Agent control stream is disconnected")

type ProgressReporter interface {
	Report(*agentv1.CommandProgress) error
}

type CommandExecutor interface {
	Execute(context.Context, *agentv1.CommandEnvelope, ProgressReporter) (*agentv1.CommandResult, error)
}

type ExecutorRegistry struct {
	mu        sync.RWMutex
	executors map[CommandKind]CommandExecutor
}

func NewExecutorRegistry() *ExecutorRegistry {
	return &ExecutorRegistry{executors: make(map[CommandKind]CommandExecutor)}
}

func (r *ExecutorRegistry) Register(kind CommandKind, executor CommandExecutor) error {
	if !knownCommandKind(kind) {
		return fmt.Errorf("unknown command kind %q", kind)
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

func (r *ExecutorRegistry) Capabilities() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	capabilities := make([]string, 0, len(r.executors))
	for kind := range r.executors {
		capabilities = append(capabilities, string(kind))
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

	streamMu        sync.RWMutex
	stream          ControlStream
	sendMu          sync.Mutex
	runningMu       sync.Mutex
	running         map[string]context.CancelFunc
	messageSequence atomic.Uint64
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
	}, nil
}

func (c *ControlClient) Run(ctx context.Context) error {
	defer c.cancelAll()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		stream, err := c.openStream(ctx)
		if err == nil {
			c.setStream(stream)
			err = c.runSession(ctx, stream)
			c.clearStream(stream)
			_ = stream.CloseSend()
		}
		if ctx.Err() != nil {
			return nil
		}
		if !waitContext(ctx, c.reconnectBackoff) {
			return nil
		}
	}
}

func (c *ControlClient) runSession(ctx context.Context, stream ControlStream) error {
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
		return err
	}

	type receiveResult struct {
		message *agentv1.ServerMessage
		err     error
	}
	received := make(chan receiveResult, 1)
	go func() {
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

	heartbeats := time.NewTicker(c.heartbeatInterval)
	defer heartbeats.Stop()
	for {
		select {
		case item := <-received:
			if item.err != nil {
				return item.err
			}
			if err := c.handleServerMessage(ctx, item.message); err != nil {
				return err
			}
		case <-heartbeats.C:
			if err := c.sendHeartbeat(stream); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *ControlClient) handleServerMessage(ctx context.Context, message *agentv1.ServerMessage) error {
	if message == nil {
		return errors.New("empty control-plane message")
	}
	switch typed := message.GetMessage().(type) {
	case *agentv1.ServerMessage_Command:
		return c.handleCommand(ctx, typed.Command)
	case *agentv1.ServerMessage_CommandCancellation:
		if typed.CommandCancellation != nil {
			c.cancelCommand(typed.CommandCancellation.GetCommandId())
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

func (c *ControlClient) handleCommand(ctx context.Context, envelope *agentv1.CommandEnvelope) error {
	if err := c.verifier.Verify(ctx, envelope); err != nil {
		return c.sendAcknowledgement(envelopeID(envelope), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED, commandRejectionReason(err))
	}
	executor, exists := c.executors.executor(envelope)
	if !exists {
		return c.sendAcknowledgement(envelope.GetCommandId(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED, "CAPABILITY_UNAVAILABLE")
	}
	accepted, err := c.journal.Accept(ctx, envelope)
	if err != nil {
		return fmt.Errorf("durably accept command: %w", err)
	}
	if !accepted {
		return c.sendAcknowledgement(envelope.GetCommandId(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_DUPLICATE, "")
	}
	if err := c.journal.Start(ctx, envelope.GetCommandId(), c.now()); err != nil {
		return fmt.Errorf("start accepted command: %w", err)
	}
	executionContext, cancel := context.WithCancel(ctx)
	c.runningMu.Lock()
	c.running[envelope.GetCommandId()] = cancel
	c.runningMu.Unlock()
	ackErr := c.sendAcknowledgement(envelope.GetCommandId(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED, "")
	go func() {
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
	if err := c.journal.Complete(context.Background(), envelope.GetCommandId(), result, c.now()); err == nil {
		_ = c.sendAgentMessage(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandResult{CommandResult: result}})
	}
	c.runningMu.Lock()
	delete(c.running, envelope.GetCommandId())
	c.runningMu.Unlock()
}

func (c *ControlClient) sendHeartbeat(stream ControlStream) error {
	c.runningMu.Lock()
	active := make([]string, 0, len(c.running))
	for commandID := range c.running {
		active = append(active, commandID)
	}
	c.runningMu.Unlock()
	sort.Strings(active)
	message := &agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{AgentId: c.agentID, RunningCommands: uint32(len(active)), ActiveCommandIds: active}}}
	return c.sendOnStream(stream, message)
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

func (c *ControlClient) setStream(stream ControlStream) {
	c.streamMu.Lock()
	c.stream = stream
	c.streamMu.Unlock()
}

func (c *ControlClient) clearStream(expected ControlStream) {
	c.streamMu.Lock()
	if c.stream == expected {
		c.stream = nil
	}
	c.streamMu.Unlock()
}

func (c *ControlClient) sendAgentMessage(message *agentv1.AgentMessage) error {
	c.streamMu.RLock()
	stream := c.stream
	c.streamMu.RUnlock()
	if stream == nil {
		return ErrControlStreamDisconnected
	}
	return c.sendOnStream(stream, message)
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

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
