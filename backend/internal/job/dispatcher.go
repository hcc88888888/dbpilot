package job

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agentcontrol"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/commandvalidation"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	commandOutboxType          = "agent.command"
	commandNonceBytes          = 32
	defaultCommandClaimLimit   = 64
	commandTransitionAttempts  = 8
	maximumInlineResultSummary = 4096
)

const DefaultCommandDeliveryTTL = 24 * time.Hour

var (
	ErrInvalidCommandPayload = errors.New("invalid command outbox payload")
	ErrCommandAgentMismatch  = errors.New("command Agent does not match the authenticated Agent")
)

type CommandSigner interface {
	Sign(context.Context, *agentv1.CommandEnvelope) error
}

type Ed25519CommandSigner struct{ privateKey ed25519.PrivateKey }

func NewEd25519CommandSigner(privateKey ed25519.PrivateKey) (*Ed25519CommandSigner, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("command signer requires an Ed25519 private key")
	}
	return &Ed25519CommandSigner{privateKey: append(ed25519.PrivateKey(nil), privateKey...)}, nil
}

func NewEd25519CommandSignerPEM(contents []byte) (*Ed25519CommandSigner, error) {
	block, remaining := pem.Decode(contents)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(remaining)) != 0 {
		return nil, errors.New("command signing private key must be one PKCS#8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse command signing PKCS#8 private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("command signing private key must be Ed25519")
	}
	return NewEd25519CommandSigner(privateKey)
}

func (signer *Ed25519CommandSigner) Sign(ctx context.Context, envelope *agentv1.CommandEnvelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if signer == nil || len(signer.privateKey) != ed25519.PrivateKeySize || envelope == nil {
		return ErrInvalidCommandPayload
	}
	unsigned := proto.Clone(envelope).(*agentv1.CommandEnvelope)
	unsigned.Signature = nil
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(unsigned)
	if err != nil {
		return fmt.Errorf("marshal command signing payload: %w", err)
	}
	envelope.Signature = ed25519.Sign(signer.privateKey, payload)
	return nil
}

type CommandAuditRecorder interface {
	Record(context.Context, audit.Event) (audit.Event, error)
	RecordOnce(context.Context, audit.Event) (audit.Event, error)
}

type CommandLifecycleConfig struct {
	DispatchRepository DispatchRepository
	Jobs               Repository
	Agents             agentcontrol.Dispatcher
	Signer             CommandSigner
	Audit              CommandAuditRecorder
	ClaimLimit         int
	Now                func() time.Time
	NonceReader        io.Reader
	OnError            func(error)
	TargetAuthorizer   commandvalidation.TargetAuthorizer
}

// CommandLifecycle is both the periodic transactional-outbox worker and the
// AgentControl observer. Every callback resolves command correlation from the
// durable outbox row; no process-local command map is authoritative.
type CommandLifecycle struct {
	dispatchRepository DispatchRepository
	jobs               Repository
	agents             agentcontrol.Dispatcher
	signer             CommandSigner
	audit              CommandAuditRecorder
	claimLimit         int
	now                func() time.Time
	nonceReader        io.Reader
	onError            func(error)
	targetAuthorizer   commandvalidation.TargetAuthorizer
}

func NewCommandLifecycle(config CommandLifecycleConfig) (*CommandLifecycle, error) {
	if config.DispatchRepository == nil || config.Jobs == nil || config.Agents == nil || config.Signer == nil || config.Audit == nil {
		return nil, errors.New("command lifecycle dependencies are required")
	}
	if config.ClaimLimit < 0 {
		return nil, errors.New("command claim limit must not be negative")
	}
	if config.ClaimLimit == 0 {
		config.ClaimLimit = defaultCommandClaimLimit
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.NonceReader == nil {
		config.NonceReader = rand.Reader
	}
	if config.OnError == nil {
		config.OnError = func(error) {}
	}
	return &CommandLifecycle{
		dispatchRepository: config.DispatchRepository, jobs: config.Jobs, agents: config.Agents,
		signer: config.Signer, audit: config.Audit, claimLimit: config.ClaimLimit,
		now: config.Now, nonceReader: config.NonceReader, onError: config.OnError,
		targetAuthorizer: config.TargetAuthorizer,
	}, nil
}

func (lifecycle *CommandLifecycle) DispatchPending(ctx context.Context, at time.Time) (int, error) {
	if lifecycle == nil || at.IsZero() {
		return 0, errors.New("command lifecycle and dispatch time are required")
	}
	at = at.UTC()
	var maintenanceErrors []error
	if err := lifecycle.dispatchCancellations(ctx, at); err != nil {
		maintenanceErrors = append(maintenanceErrors, err)
	}
	if err := lifecycle.expireExecutions(ctx, at); err != nil {
		maintenanceErrors = append(maintenanceErrors, err)
	}
	messages, err := lifecycle.dispatchRepository.ClaimOutbox(ctx, lifecycle.claimLimit, at)
	if err != nil {
		return 0, errors.Join(append(maintenanceErrors, err)...)
	}
	dispatched := 0
	var dispatchErrors []error
	for _, message := range messages {
		wasDispatched, err := lifecycle.dispatchOne(ctx, message, at.UTC())
		if err != nil {
			dispatchErrors = append(dispatchErrors, fmt.Errorf("dispatch command %q: %w", message.ID, err))
			continue
		}
		if wasDispatched {
			dispatched++
		}
	}
	return dispatched, errors.Join(append(maintenanceErrors, dispatchErrors...)...)
}

func (lifecycle *CommandLifecycle) dispatchOne(ctx context.Context, message OutboxMessage, at time.Time) (bool, error) {
	current, err := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
	if err != nil {
		return false, err
	}
	if current.Status == StatusCancelling || current.Status == StatusCancelled || message.CancellationRequestedAt != nil {
		return false, lifecycle.cancelUndelivered(ctx, message, at)
	}
	if isTerminal(current.Status) {
		if len(message.PreparedEnvelope) > 0 {
			unsigned, decodeErr := decodeUnsignedCommand(ctx, message, lifecycle.targetAuthorizer)
			if decodeErr != nil {
				return false, decodeErr
			}
			prepared, decodeErr := decodePreparedCommand(message, unsigned, message.PreparedEnvelope)
			if decodeErr != nil {
				return false, decodeErr
			}
			if !prepared.GetExpiresAt().AsTime().After(at) {
				return false, lifecycle.expireDelivery(ctx, message, at)
			}
		}
		event := lifecycle.auditEvent(current, message, "command.skipped_terminal_job", "success", map[string]any{"job_status": string(current.Status)}, at, "command.skipped_terminal_job:"+message.ID)
		if _, err := lifecycle.audit.RecordOnce(ctx, event); err != nil {
			return false, err
		}
		return false, lifecycle.dispatchRepository.MarkCommandTerminal(ctx, message.Scope, message.ID, commandStatusForJob(current.Status), at)
	}
	unsigned, err := decodeUnsignedCommand(ctx, message, lifecycle.targetAuthorizer)
	if err != nil {
		return false, err
	}
	proposed := append([]byte(nil), message.PreparedEnvelope...)
	if len(proposed) == 0 {
		envelope := proto.Clone(unsigned).(*agentv1.CommandEnvelope)
		envelope.CommandId = message.ID
		envelope.JobId = message.JobID
		envelope.IssuedAt = timestamppb.New(at)
		envelope.ExpiresAt = timestamppb.New(at.Add(DefaultCommandDeliveryTTL))
		envelope.Nonce = make([]byte, commandNonceBytes)
		if _, err := io.ReadFull(lifecycle.nonceReader, envelope.Nonce); err != nil {
			return false, fmt.Errorf("generate command nonce: %w", err)
		}
		if err := lifecycle.signer.Sign(ctx, envelope); err != nil {
			return false, err
		}
		proposed, err = proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
		if err != nil {
			return false, fmt.Errorf("marshal prepared command envelope: %w", err)
		}
	}
	stored, err := lifecycle.dispatchRepository.PrepareCommandEnvelope(ctx, message.Scope, message.ID, proposed)
	if err != nil {
		return false, err
	}
	envelope, err := decodePreparedCommand(message, unsigned, stored)
	if err != nil {
		return false, err
	}
	if !envelope.GetExpiresAt().AsTime().After(at) {
		return false, lifecycle.expireDelivery(ctx, message, at)
	}
	if err := lifecycle.agents.Dispatch(ctx, envelope.GetAgentId(), envelope); err != nil {
		return false, err
	}
	value, err := lifecycle.ensureDispatched(ctx, message, at)
	if err != nil {
		return false, err
	}
	return true, lifecycle.recordAudit(ctx, value, message, "command.dispatched", "success", map[string]any{"state": "dispatched"})
}

func (lifecycle *CommandLifecycle) dispatchCancellations(ctx context.Context, at time.Time) error {
	messages, err := lifecycle.dispatchRepository.ClaimPendingCancellations(ctx, lifecycle.claimLimit, at)
	if err != nil {
		return err
	}
	var result []error
	for _, message := range messages {
		if message.PublishedAt == nil && (message.CommandStatus == "" || message.CommandStatus == CommandPending) {
			if err := lifecycle.cancelUndelivered(ctx, message, at); err != nil {
				result = append(result, fmt.Errorf("cancel undelivered command %q: %w", message.ID, err))
			}
			continue
		}
		if err := lifecycle.agents.Cancel(ctx, message.TargetID, message.ID); err != nil {
			result = append(result, fmt.Errorf("dispatch command cancellation %q: %w", message.ID, err))
		}
		if err := lifecycle.dispatchRepository.DeferCancellation(ctx, message.Scope, message.ID, at.Add(DefaultCancellationRetry)); err != nil && !errors.Is(err, ErrNotFound) {
			result = append(result, fmt.Errorf("defer command cancellation %q: %w", message.ID, err))
		}
	}
	return errors.Join(result...)
}

func (lifecycle *CommandLifecycle) cancelUndelivered(ctx context.Context, message OutboxMessage, at time.Time) error {
	target := TargetResult{TargetID: message.TargetID, Status: TargetCancelled, ResultSummary: "cancelled before Agent execution", FinishedAt: timePointer(at)}
	value, _, err := lifecycle.applyTarget(ctx, message, target, at)
	if err != nil {
		return err
	}
	event := lifecycle.auditEvent(value, message, "command.cancelled_before_dispatch", "success", map[string]any{"reason": "job_cancellation"}, at, "command.cancelled_before_dispatch:"+message.ID)
	if _, err := lifecycle.audit.RecordOnce(ctx, event); err != nil {
		return err
	}
	return lifecycle.dispatchRepository.MarkCommandTerminal(ctx, message.Scope, message.ID, CommandCancelled, at)
}

func (lifecycle *CommandLifecycle) expireExecutions(ctx context.Context, at time.Time) error {
	messages, err := lifecycle.dispatchRepository.ClaimExpiredCommands(ctx, lifecycle.claimLimit, at)
	if err != nil {
		return err
	}
	var result []error
	for _, message := range messages {
		target := TargetResult{TargetID: message.TargetID, Status: TargetTimedOut, ErrorSummary: "execution lease expired", FinishedAt: timePointer(at)}
		value, _, applyErr := lifecycle.applyTarget(ctx, message, target, at)
		if applyErr != nil {
			result = append(result, fmt.Errorf("expire command %q: %w", message.ID, applyErr))
			continue
		}
		event := lifecycle.auditEvent(value, message, "command.execution_timed_out", "failure", map[string]any{"reason": "execution_deadline"}, at, "command.execution_timed_out:"+message.ID)
		if _, recordErr := lifecycle.audit.RecordOnce(ctx, event); recordErr != nil {
			result = append(result, fmt.Errorf("audit expired command %q: %w", message.ID, recordErr))
			continue
		}
		if markErr := lifecycle.dispatchRepository.MarkCommandTerminal(ctx, message.Scope, message.ID, CommandTimedOut, at); markErr != nil {
			result = append(result, fmt.Errorf("terminalize expired command %q: %w", message.ID, markErr))
		}
	}
	return errors.Join(result...)
}

func (lifecycle *CommandLifecycle) expireDelivery(ctx context.Context, message OutboxMessage, at time.Time) error {
	target := TargetResult{TargetID: message.TargetID, Status: TargetTimedOut, ErrorSummary: "delivery deadline exceeded", FinishedAt: timePointer(at)}
	value, _, err := lifecycle.applyTarget(ctx, message, target, at)
	if err != nil {
		return err
	}
	if _, err := lifecycle.audit.RecordOnce(ctx, lifecycle.auditEvent(value, message, "command.delivery_timed_out", "failure", map[string]any{"reason": "delivery_deadline"}, at, "command.delivery_timed_out:"+message.ID)); err != nil {
		return err
	}
	return lifecycle.dispatchRepository.MarkCommandTerminal(ctx, message.Scope, message.ID, CommandTimedOut, at)
}

func decodePreparedCommand(message OutboxMessage, unsigned *agentv1.CommandEnvelope, stored []byte) (*agentv1.CommandEnvelope, error) {
	if unsigned == nil || len(stored) == 0 {
		return nil, ErrInvalidCommandPayload
	}
	envelope := new(agentv1.CommandEnvelope)
	if err := proto.Unmarshal(stored, envelope); err != nil || len(envelope.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrInvalidCommandPayload
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, stored) {
		return nil, ErrInvalidCommandPayload
	}
	if envelope.GetCommandId() != message.ID || envelope.GetJobId() != message.JobID || envelope.GetAgentId() != message.TargetID || envelope.GetIssuedAt() == nil || !envelope.GetIssuedAt().IsValid() || envelope.GetExpiresAt() == nil || !envelope.GetExpiresAt().IsValid() || !envelope.GetExpiresAt().AsTime().After(envelope.GetIssuedAt().AsTime()) || len(envelope.GetNonce()) != commandNonceBytes || len(envelope.GetSignature()) != ed25519.SignatureSize {
		return nil, ErrInvalidCommandPayload
	}
	preparedPayload := proto.Clone(envelope).(*agentv1.CommandEnvelope)
	preparedPayload.CommandId = ""
	preparedPayload.JobId = ""
	preparedPayload.IssuedAt = nil
	preparedPayload.ExpiresAt = nil
	preparedPayload.Nonce = nil
	preparedPayload.Signature = nil
	if !proto.Equal(preparedPayload, unsigned) {
		return nil, ErrInvalidCommandPayload
	}
	return envelope, nil
}

func decodeUnsignedCommand(ctx context.Context, message OutboxMessage, authorizer commandvalidation.TargetAuthorizer) (*agentv1.CommandEnvelope, error) {
	if message.Scope.Validate() != nil || strings.TrimSpace(message.ID) == "" || strings.TrimSpace(message.JobID) == "" || message.Type != commandOutboxType || strings.TrimSpace(message.TargetID) == "" || len(message.Payload) == 0 {
		return nil, ErrInvalidCommandPayload
	}
	envelope := new(agentv1.CommandEnvelope)
	if err := proto.Unmarshal(message.Payload, envelope); err != nil || len(envelope.ProtoReflect().GetUnknown()) != 0 {
		return nil, ErrInvalidCommandPayload
	}
	if envelope.GetCommandId() != "" || envelope.GetJobId() != "" || envelope.GetIssuedAt() != nil || envelope.GetExpiresAt() != nil || len(envelope.GetNonce()) != 0 || len(envelope.GetSignature()) != 0 {
		return nil, ErrInvalidCommandPayload
	}
	if envelope.GetCommand() == nil || envelope.GetLeaseSeconds() == 0 || envelope.GetLeaseSeconds() > commandvalidation.MaximumTimeoutSeconds || strings.TrimSpace(envelope.GetAgentId()) == "" || envelope.GetAgentId() != message.TargetID {
		return nil, ErrInvalidCommandPayload
	}
	if err := commandvalidation.Validate(ctx, envelope, authorizer); err != nil {
		return nil, ErrInvalidCommandPayload
	}
	return envelope, nil
}

func (lifecycle *CommandLifecycle) ensureDispatched(ctx context.Context, message OutboxMessage, at time.Time) (Job, error) {
	for attempt := 0; attempt < commandTransitionAttempts; attempt++ {
		value, err := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
		if err != nil {
			return Job{}, err
		}
		switch value.Status {
		case StatusQueued:
			value, err = lifecycle.jobs.Transition(ctx, Transition{Scope: message.Scope, JobID: message.JobID, CurrentVersion: value.Version, To: StatusDispatched, At: at})
			if errors.Is(err, ErrConflict) {
				continue
			}
			return value, err
		case StatusDispatched, StatusRunning, StatusSucceeded, StatusFailed, StatusCancelling, StatusCancelled, StatusTimedOut:
			return value, nil
		default:
			return Job{}, ErrInvalidTransition
		}
	}
	return Job{}, ErrConflict
}

func (lifecycle *CommandLifecycle) Connected(ctx context.Context, session agentcontrol.SessionInfo) {
	active := make([]string, 0, len(session.ActiveCommands))
	for _, state := range session.ActiveCommands {
		if state != nil && strings.TrimSpace(state.GetCommandId()) != "" && (state.GetState() == agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_ACCEPTED || state.GetState() == agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_RUNNING) {
			active = append(active, state.GetCommandId())
		}
	}
	lifecycle.renewExecutionLeases(ctx, session.AgentID, active, lifecycle.currentTime())
	messages, err := lifecycle.dispatchRepository.PendingCancellationsForAgent(ctx, session.AgentID, lifecycle.claimLimit)
	if err != nil {
		lifecycle.onError(err)
		return
	}
	for _, message := range messages {
		if err := lifecycle.agents.Cancel(ctx, session.AgentID, message.ID); err != nil {
			lifecycle.onError(err)
		}
	}
}

func (lifecycle *CommandLifecycle) Heartbeat(ctx context.Context, agentID string, heartbeat *agentv1.Heartbeat) {
	if heartbeat == nil || heartbeat.GetAgentId() != agentID {
		lifecycle.onError(ErrCommandAgentMismatch)
		return
	}
	lifecycle.renewExecutionLeases(ctx, agentID, heartbeat.GetActiveCommandIds(), lifecycle.currentTime())
}

func (lifecycle *CommandLifecycle) renewExecutionLeases(ctx context.Context, agentID string, commandIDs []string, at time.Time) {
	seen := make(map[string]struct{}, len(commandIDs))
	for _, commandID := range commandIDs {
		if strings.TrimSpace(commandID) == "" {
			continue
		}
		if _, duplicate := seen[commandID]; duplicate {
			continue
		}
		seen[commandID] = struct{}{}
		message, err := lifecycle.dispatchRepository.LookupCommand(ctx, commandID)
		if err != nil {
			lifecycle.onError(err)
			continue
		}
		if message.TargetID != agentID {
			lifecycle.onError(ErrCommandAgentMismatch)
			continue
		}
		envelope, err := decodeUnsignedCommand(ctx, message, lifecycle.targetAuthorizer)
		if err != nil {
			lifecycle.onError(err)
			continue
		}
		value, err := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
		if err != nil {
			lifecycle.onError(err)
			continue
		}
		deadline := executionDeadline(value, envelope.GetLeaseSeconds(), at)
		if !deadline.After(at) {
			continue
		}
		if err := lifecycle.dispatchRepository.RenewCommandLease(ctx, message.Scope, message.ID, at, deadline); err != nil && !errors.Is(err, ErrNotFound) {
			lifecycle.onError(err)
		}
	}
}

func (lifecycle *CommandLifecycle) Acknowledged(ctx context.Context, agentID string, acknowledgement *agentv1.CommandAcknowledgement) {
	if acknowledgement == nil || strings.TrimSpace(acknowledgement.GetCommandId()) == "" {
		lifecycle.onError(ErrInvalidCommandPayload)
		return
	}
	message, err := lifecycle.dispatchRepository.LookupCommand(ctx, acknowledgement.GetCommandId())
	if err != nil {
		lifecycle.onError(err)
		return
	}
	envelope, err := decodeUnsignedCommand(ctx, message, lifecycle.targetAuthorizer)
	if err != nil {
		lifecycle.onError(err)
		return
	}
	if envelope.GetAgentId() != agentID || message.TargetID != agentID {
		value, getErr := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
		if getErr != nil {
			lifecycle.onError(getErr)
			return
		}
		recordErr := lifecycle.recordAudit(ctx, value, message, "command.rejected", "failure", map[string]any{"reason": "agent_mismatch"})
		lifecycle.onError(errors.Join(ErrCommandAgentMismatch, recordErr))
		return
	}
	var target TargetResult
	auditResult := "success"
	commandStatus := CommandActive
	at := lifecycle.currentTime()
	switch acknowledgement.GetState() {
	case agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED, agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_DUPLICATE:
		target = TargetResult{Status: TargetRunning}
	case agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED:
		target = TargetResult{Status: TargetFailed, ErrorSummary: acknowledgement.GetReasonCode(), FinishedAt: timePointer(at)}
		auditResult = "failure"
		commandStatus = CommandRejected
	default:
		lifecycle.onError(ErrInvalidCommandPayload)
		return
	}
	target.TargetID = message.TargetID
	value, _, err := lifecycle.applyTarget(ctx, message, target, at)
	if err != nil {
		lifecycle.onError(err)
		return
	}
	detail := map[string]any{"state": "accepted"}
	if commandStatus == CommandRejected {
		detail = map[string]any{"state": "rejected", "reason_code": acknowledgement.GetReasonCode()}
	}
	event := lifecycle.auditEvent(value, message, "command.acknowledged", auditResult, detail, at, "command.acknowledged:"+message.ID)
	if _, err := lifecycle.audit.RecordOnce(ctx, event); err != nil {
		lifecycle.onError(err)
		return
	}
	var deadline *time.Time
	if commandStatus == CommandActive {
		computed := executionDeadline(value, envelope.GetLeaseSeconds(), at)
		if !computed.After(at) {
			lifecycle.onError(ErrInvalidCommandPayload)
			return
		}
		deadline = &computed
	}
	if err := lifecycle.dispatchRepository.AcknowledgeCommand(ctx, message.Scope, message.ID, commandStatus, at, deadline); err != nil {
		lifecycle.onError(err)
	}
}

func (lifecycle *CommandLifecycle) Progress(ctx context.Context, agentID string, progress *agentv1.CommandProgress) {
	if progress == nil || strings.TrimSpace(progress.GetCommandId()) == "" || progress.GetPercent() > 100 {
		lifecycle.onError(ErrInvalidCommandPayload)
		return
	}
	lifecycle.observe(ctx, agentID, progress.GetCommandId(), "command.progress", "success", TargetResult{Status: TargetRunning}, map[string]any{"percent": progress.GetPercent()})
}

func (lifecycle *CommandLifecycle) Result(ctx context.Context, agentID string, result *agentv1.CommandResult) (agentcontrol.ResultPersistence, error) {
	if result == nil || strings.TrimSpace(result.GetCommandId()) == "" || len(result.GetSummary()) > maximumInlineResultSummary {
		return agentcontrol.ResultPersistence{}, ErrInvalidCommandPayload
	}
	target := TargetResult{ResultSummary: result.GetSummary(), FinishedAt: timePointer(lifecycle.currentTime())}
	auditResult := "success"
	commandStatus := CommandSucceeded
	switch result.GetState() {
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED:
		target.Status = TargetSucceeded
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED:
		target.Status, target.ErrorSummary, auditResult = TargetFailed, result.GetErrorCode(), "failure"
		commandStatus = CommandFailed
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED:
		target.Status, auditResult = TargetCancelled, "failure"
		commandStatus = CommandCancelled
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT:
		target.Status, auditResult = TargetTimedOut, "failure"
		commandStatus = CommandTimedOut
	default:
		return agentcontrol.ResultPersistence{}, ErrInvalidCommandPayload
	}
	for _, reference := range result.GetArtifacts() {
		if reference == nil || strings.TrimSpace(reference.GetArtifactId()) == "" || strings.TrimSpace(reference.GetKind()) == "" {
			return agentcontrol.ResultPersistence{}, ErrInvalidCommandPayload
		}
		target.Artifacts = append(target.Artifacts, ArtifactReference{ArtifactID: reference.GetArtifactId(), Kind: reference.GetKind()})
	}
	message, err := lifecycle.dispatchRepository.LookupCommand(ctx, result.GetCommandId())
	if err != nil {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId()}, err
	}
	envelope, err := decodeUnsignedCommand(ctx, message, lifecycle.targetAuthorizer)
	if err != nil {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId()}, err
	}
	value, err := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
	if err != nil {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId()}, err
	}
	if envelope.GetAgentId() != agentID || message.TargetID != agentID {
		recordErr := lifecycle.recordAudit(ctx, value, message, "command.rejected", "failure", map[string]any{"reason": "agent_mismatch"})
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId()}, errors.Join(ErrCommandAgentMismatch, recordErr)
	}
	target.TargetID = message.TargetID
	at := lifecycle.currentTime()
	value, _, err = lifecycle.applyTarget(ctx, message, target, at)
	if err != nil {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId()}, err
	}
	detail := map[string]any{"state": result.GetState().String(), "artifact_count": len(target.Artifacts)}
	event := lifecycle.auditEvent(value, message, "command.result", auditResult, detail, at, "command.result:"+message.ID)
	if _, err := lifecycle.audit.RecordOnce(ctx, event); err != nil {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId()}, err
	}
	if err := lifecycle.dispatchRepository.MarkCommandTerminal(ctx, message.Scope, message.ID, commandStatus, at); err != nil {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId()}, err
	}
	return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), Persisted: true}, nil
}

func (lifecycle *CommandLifecycle) observe(ctx context.Context, agentID, commandID, action, result string, target TargetResult, detail map[string]any) {
	message, err := lifecycle.dispatchRepository.LookupCommand(ctx, commandID)
	if err != nil {
		lifecycle.onError(err)
		return
	}
	envelope, err := decodeUnsignedCommand(ctx, message, lifecycle.targetAuthorizer)
	if err != nil {
		lifecycle.onError(err)
		return
	}
	value, getErr := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
	if getErr != nil {
		lifecycle.onError(getErr)
		return
	}
	if envelope.GetAgentId() != agentID || message.TargetID != agentID {
		recordErr := lifecycle.recordAudit(ctx, value, message, "command.rejected", "failure", map[string]any{"reason": "agent_mismatch"})
		lifecycle.onError(errors.Join(ErrCommandAgentMismatch, recordErr))
		return
	}
	target.TargetID = message.TargetID
	at := lifecycle.currentTime()
	value, mutated, err := lifecycle.applyTarget(ctx, message, target, at)
	if err != nil {
		lifecycle.onError(err)
		return
	}
	if !mutated {
		result = "duplicate"
		detail["duplicate"] = true
	}
	if err := lifecycle.recordAudit(ctx, value, message, action, result, detail); err != nil {
		lifecycle.onError(err)
	}
}

func (lifecycle *CommandLifecycle) applyTarget(ctx context.Context, message OutboxMessage, target TargetResult, at time.Time) (Job, bool, error) {
	mutated := false
	for attempt := 0; attempt < commandTransitionAttempts; attempt++ {
		current, err := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
		if err != nil {
			return Job{}, mutated, err
		}
		if current.ID != message.JobID || current.Scope != message.Scope || !containsTarget(current.TargetResourceIDs, message.TargetID) {
			return Job{}, mutated, ErrInvalidCommandPayload
		}
		if isTerminal(current.Status) {
			return current, mutated, nil
		}
		if current.Status == StatusQueued {
			_, err = lifecycle.jobs.Transition(ctx, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusDispatched, At: at})
			if errors.Is(err, ErrConflict) {
				continue
			}
			if err != nil {
				return Job{}, mutated, err
			}
			mutated = true
			continue
		}
		existing, found := targetFor(current.TargetResults, message.TargetID)
		if found && isTerminalTarget(existing.Status) {
			if isTerminalTarget(target.Status) {
				final, finalMutated, finalErr := lifecycle.finalize(ctx, current, at)
				return final, mutated || finalMutated, finalErr
			}
			return current, mutated, nil
		}
		if found && existing.Status == TargetRunning && target.Status == TargetRunning {
			return current, mutated, nil
		}
		if current.Status != StatusDispatched && current.Status != StatusRunning && current.Status != StatusCancelling {
			return Job{}, mutated, ErrInvalidTransition
		}
		transitionTo := StatusRunning
		actor := ""
		if current.Status == StatusCancelling {
			transitionTo = StatusCancelling
			actor = current.CancelRequestedBy
		}
		next, err := lifecycle.jobs.Transition(ctx, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: transitionTo, TargetResults: []TargetResult{target}, Actor: actor, At: at})
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return Job{}, mutated, err
		}
		mutated = true
		if !isTerminalTarget(target.Status) {
			return next, mutated, nil
		}
		final, _, finalErr := lifecycle.finalize(ctx, next, at)
		return final, true, finalErr
	}
	return Job{}, mutated, ErrConflict
}

func (lifecycle *CommandLifecycle) finalize(ctx context.Context, candidate Job, at time.Time) (Job, bool, error) {
	mutated := false
	for attempt := 0; attempt < commandTransitionAttempts; attempt++ {
		current := candidate
		if attempt > 0 {
			var err error
			current, err = lifecycle.jobs.Get(ctx, candidate.Scope, candidate.ID)
			if err != nil {
				return Job{}, mutated, err
			}
		}
		if isTerminal(current.Status) {
			return current, mutated, nil
		}
		if !allTargetsTerminal(current) {
			return current, mutated, nil
		}
		to := StatusFailed
		if current.Progress.CompletedTargets > 0 {
			to = StatusSucceeded
		} else if allTargetsCancelled(current.TargetResults) {
			to = StatusCancelled
		} else if hasTimedOutTarget(current.TargetResults) {
			to = StatusTimedOut
		}
		next, err := lifecycle.jobs.Transition(ctx, Transition{
			Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: to,
			Artifacts: collectArtifacts(current.TargetResults), ResultSummary: "Agent commands completed", At: at,
		})
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return Job{}, mutated, err
		}
		return next, true, nil
	}
	return Job{}, mutated, ErrConflict
}

func (lifecycle *CommandLifecycle) recordAudit(ctx context.Context, value Job, message OutboxMessage, action, result string, detail map[string]any) error {
	return lifecycle.recordAuditAt(ctx, value, message, action, result, detail, lifecycle.currentTime())
}

func (lifecycle *CommandLifecycle) recordAuditAt(ctx context.Context, value Job, message OutboxMessage, action, result string, detail map[string]any, at time.Time) error {
	_, err := lifecycle.audit.Record(ctx, lifecycle.auditEvent(value, message, action, result, detail, at, ""))
	return err
}

func (lifecycle *CommandLifecycle) auditEvent(value Job, message OutboxMessage, action, result string, detail map[string]any, at time.Time, dedupeKey string) audit.Event {
	return audit.Event{
		Scope: message.Scope, OccurredAt: at.UTC(), Action: action,
		Actor: audit.Actor{Type: "system", ID: "agent-control"}, Resource: audit.Resource{Type: "job_target", ID: message.TargetID},
		Result: result, RequestID: value.RequestID, TraceID: value.TraceID, JobID: message.JobID, CommandID: message.ID, DedupeKey: dedupeKey, Detail: detail,
	}
}

func hasTimedOutTarget(results []TargetResult) bool {
	for _, result := range results {
		if result.Status == TargetTimedOut {
			return true
		}
	}
	return false
}

func allTargetsCancelled(results []TargetResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, result := range results {
		if result.Status != TargetCancelled {
			return false
		}
	}
	return true
}

func executionDeadline(value Job, leaseSeconds uint32, at time.Time) time.Time {
	deadline := at.UTC().Add(time.Duration(leaseSeconds) * time.Second)
	if value.TimeoutAt != nil && value.TimeoutAt.Before(deadline) {
		deadline = value.TimeoutAt.UTC()
	}
	return deadline
}

func commandStatusForJob(status Status) CommandStatus {
	switch status {
	case StatusSucceeded:
		return CommandSucceeded
	case StatusCancelled:
		return CommandCancelled
	case StatusTimedOut:
		return CommandTimedOut
	default:
		return CommandFailed
	}
}

func (lifecycle *CommandLifecycle) currentTime() time.Time { return lifecycle.now().UTC() }

func containsTarget(targets []string, target string) bool {
	for _, value := range targets {
		if value == target {
			return true
		}
	}
	return false
}

func targetFor(results []TargetResult, target string) (TargetResult, bool) {
	for _, result := range results {
		if result.TargetID == target {
			return result, true
		}
	}
	return TargetResult{}, false
}

func allTargetsTerminal(value Job) bool {
	if len(value.TargetResourceIDs) == 0 || len(value.TargetResults) != len(value.TargetResourceIDs) {
		return false
	}
	for _, result := range value.TargetResults {
		if !isTerminalTarget(result.Status) {
			return false
		}
	}
	return true
}

func collectArtifacts(results []TargetResult) []ArtifactReference {
	artifacts := make([]ArtifactReference, 0)
	for _, result := range results {
		artifacts = append(artifacts, result.Artifacts...)
	}
	return artifacts
}

var _ agentcontrol.Observer = (*CommandLifecycle)(nil)
