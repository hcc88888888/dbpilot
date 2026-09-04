package job

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agentcontrol"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/commandvalidation"
	"dbpilot.local/platform/internal/platformscope"
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
	DispatchRepository      DispatchRepository
	Jobs                    Repository
	Agents                  agentcontrol.Dispatcher
	Signer                  CommandSigner
	Audit                   CommandAuditRecorder
	ClaimLimit              int
	Now                     func() time.Time
	NonceReader             io.Reader
	TokenReader             io.Reader
	TokenProtector          TokenProtector
	OnError                 func(error)
	TargetAuthorizer        commandvalidation.TargetAuthorizer
	TypedResultRecorder     CommandTypedResultRecorder
	DatabaseInstanceResults CommandDatabaseInstanceResultRecorder
}

type CommandTypedResultRecorder interface {
	ClassifyMetricTemplateTrial(context.Context, platformscope.Scope, string, *agentv1.CollectDatabaseMetrics, *agentv1.CommandResult) (bool, error)
	RecordMetricTemplateTrial(context.Context, platformscope.Scope, string, string, *agentv1.CollectDatabaseMetrics, *agentv1.CommandResult, time.Time) error
}

type CommandDatabaseInstanceResultRecorder interface {
	RecordDatabaseInstanceValidationProgress(context.Context, platformscope.Scope, string, string, *agentv1.ValidateDatabaseInstance, time.Time) error
	FinalizeDatabaseInstanceValidationResult(context.Context, platformscope.Scope, string, string, *agentv1.ValidateDatabaseInstance, *agentv1.CommandResult, time.Time) (*agentv1.CommandResult, error)
	ReconcileDatabaseInstanceValidationTerminals(context.Context, time.Time, int) (int, error)
}

// CommandLifecycle is both the periodic transactional-outbox worker and the
// AgentControl observer. Every callback resolves command correlation from the
// durable outbox row; no process-local command map is authoritative.
type CommandLifecycle struct {
	dispatchRepository      DispatchRepository
	jobs                    Repository
	agents                  agentcontrol.Dispatcher
	signer                  CommandSigner
	audit                   CommandAuditRecorder
	claimLimit              int
	now                     func() time.Time
	nonceReader             io.Reader
	tokenReader             io.Reader
	tokenProtector          TokenProtector
	onError                 func(error)
	targetAuthorizer        commandvalidation.TargetAuthorizer
	typedResultRecorder     CommandTypedResultRecorder
	databaseInstanceResults CommandDatabaseInstanceResultRecorder
	transitionStripes       [64]sync.Mutex
}

func NewCommandLifecycle(config CommandLifecycleConfig) (*CommandLifecycle, error) {
	if config.DispatchRepository == nil || config.Jobs == nil || config.Agents == nil || config.Signer == nil || config.Audit == nil || config.TokenProtector == nil {
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
	if config.TokenReader == nil {
		config.TokenReader = rand.Reader
	}
	if config.OnError == nil {
		config.OnError = func(error) {}
	}
	return &CommandLifecycle{
		dispatchRepository: config.DispatchRepository, jobs: config.Jobs, agents: config.Agents,
		signer: config.Signer, audit: config.Audit, claimLimit: config.ClaimLimit,
		now: config.Now, nonceReader: config.NonceReader, tokenReader: config.TokenReader, tokenProtector: config.TokenProtector, onError: config.OnError,
		targetAuthorizer:        config.TargetAuthorizer,
		typedResultRecorder:     config.TypedResultRecorder,
		databaseInstanceResults: config.DatabaseInstanceResults,
	}, nil
}

// HasTargetAuthorizer reports whether instance-bound commands are validated
// again at dispatch, after their durable Outbox payload is decoded.
func (lifecycle *CommandLifecycle) HasTargetAuthorizer() bool {
	return lifecycle != nil && lifecycle.targetAuthorizer != nil
}

func (lifecycle *CommandLifecycle) DispatchPending(ctx context.Context, at time.Time) (int, error) {
	if lifecycle == nil || at.IsZero() {
		return 0, errors.New("command lifecycle and dispatch time are required")
	}
	at = at.UTC()
	var maintenanceErrors []error
	if err := lifecycle.recoverPreparedCommands(ctx, at); err != nil {
		maintenanceErrors = append(maintenanceErrors, err)
	}
	if err := lifecycle.dispatchCancellations(ctx, at); err != nil {
		maintenanceErrors = append(maintenanceErrors, err)
	}
	if err := lifecycle.expireExecutions(ctx, at); err != nil {
		maintenanceErrors = append(maintenanceErrors, err)
	}
	if lifecycle.databaseInstanceResults != nil {
		if _, err := lifecycle.databaseInstanceResults.ReconcileDatabaseInstanceValidationTerminals(ctx, at, lifecycle.claimLimit); err != nil {
			maintenanceErrors = append(maintenanceErrors, err)
		}
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
	if current.TimeoutAt != nil && !current.TimeoutAt.After(at) {
		return false, lifecycle.timeoutUndelivered(ctx, message, at)
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
	reserved, err := lifecycle.dispatchRepository.ReservePrepareSlot(ctx, message.Scope, message.ID, at)
	if err != nil {
		return false, err
	}
	if !reserved {
		return false, nil
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

func (lifecycle *CommandLifecycle) timeoutUndelivered(ctx context.Context, message OutboxMessage, at time.Time) error {
	target := TargetResult{TargetID: message.TargetID, Status: TargetTimedOut, ErrorSummary: "Job timeout elapsed before delivery", FinishedAt: timePointer(at)}
	if err := lifecycle.dispatchRepository.MarkCommandTerminal(ctx, message.Scope, message.ID, CommandTimedOut, at); err != nil {
		return err
	}
	value, _, err := lifecycle.applyTarget(ctx, message, target, at)
	if err != nil {
		return err
	}
	event := lifecycle.auditEvent(value, message, "command.undelivered_timed_out", "failure", map[string]any{"phase": string(message.Phase)}, at, "command.undelivered_timed_out:"+message.ID)
	if _, err := lifecycle.audit.RecordOnce(ctx, event); err != nil {
		return err
	}
	return nil
}

func (lifecycle *CommandLifecycle) recoverPreparedCommands(ctx context.Context, at time.Time) error {
	messages, err := lifecycle.dispatchRepository.ClaimPreparedCommands(ctx, lifecycle.claimLimit, at)
	if err != nil {
		return err
	}
	var result []error
	for _, message := range messages {
		if err := lifecycle.recoverPreparedCommand(ctx, message.ID, at); err != nil {
			result = append(result, fmt.Errorf("recover prepared command %q: %w", message.ID, err))
		}
	}
	return errors.Join(result...)
}

func (lifecycle *CommandLifecycle) recoverPreparedCommand(ctx context.Context, commandID string, at time.Time) error {
	unlock := lifecycle.lockCommandTransition(commandID)
	defer unlock()
	message, err := lifecycle.dispatchRepository.LookupCommand(ctx, commandID)
	if err != nil {
		return err
	}
	value, err := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
	if err != nil {
		return err
	}
	if message.Phase == CommandPhasePrepared {
		cancelled := value.Status == StatusCancelled || (!isTerminal(value.Status) && (message.CancellationRequestedAt != nil || value.Status == StatusCancelling))
		timedOut := value.Status == StatusTimedOut || (!isTerminal(value.Status) && value.TimeoutAt != nil && !value.TimeoutAt.After(at))
		if cancelled || timedOut {
			return lifecycle.terminalizePreparedCommand(ctx, message, cancelled, at)
		}
		if isTerminal(value.Status) {
			if err := lifecycle.agents.CancelPrepared(ctx, message.TargetID, message.ID, "Job is already terminal"); err != nil {
				lifecycle.onError(err)
			}
			event := lifecycle.auditEvent(value, message, "command.prepared_terminal_job", "success", map[string]any{"job_status": string(value.Status)}, at, "command.prepared_terminal_job:"+message.ID)
			if _, err := lifecycle.audit.RecordOnce(ctx, event); err != nil {
				return err
			}
			return lifecycle.dispatchRepository.MarkCommandTerminal(ctx, message.Scope, message.ID, commandStatusForJob(value.Status), at)
		}
	}
	return lifecycle.startOrReplayCommandLocked(ctx, message, at)
}

func (lifecycle *CommandLifecycle) terminalizePreparedCommand(ctx context.Context, message OutboxMessage, cancelled bool, at time.Time) error {
	status := TargetTimedOut
	commandStatus := CommandTimedOut
	action := "command.prepared_timed_out"
	summary := "prepared command timed out before Start"
	auditResult := "failure"
	if cancelled {
		status = TargetCancelled
		commandStatus = CommandCancelled
		action = "command.cancelled_before_start"
		summary = "prepared command cancelled before Start"
		auditResult = "success"
	}
	if err := lifecycle.agents.CancelPrepared(ctx, message.TargetID, message.ID, message.CancellationReason); err != nil {
		lifecycle.onError(err)
	}
	target := TargetResult{TargetID: message.TargetID, Status: status, ResultSummary: summary, FinishedAt: timePointer(at)}
	if status == TargetTimedOut {
		target.ErrorSummary = "Job timeout elapsed before Start"
	}
	if err := lifecycle.dispatchRepository.MarkCommandTerminal(ctx, message.Scope, message.ID, commandStatus, at); err != nil {
		return err
	}
	updated, _, err := lifecycle.applyTarget(ctx, message, target, at)
	if err != nil {
		return err
	}
	event := lifecycle.auditEvent(updated, message, action, auditResult, map[string]any{"phase": string(message.Phase)}, at, action+":"+message.ID)
	if _, err := lifecycle.audit.RecordOnce(ctx, event); err != nil {
		return err
	}
	return nil
}

func (lifecycle *CommandLifecycle) dispatchCancellations(ctx context.Context, at time.Time) error {
	messages, err := lifecycle.dispatchRepository.ClaimPendingCancellations(ctx, lifecycle.claimLimit, at)
	if err != nil {
		return err
	}
	var result []error
	for _, message := range messages {
		preStart := message.Phase == "" || message.Phase == CommandPhasePending || message.Phase == CommandPhasePreparing || message.Phase == CommandPhasePrepared
		if preStart && message.PublishedAt == nil && message.PreparedAt == nil {
			if err := lifecycle.cancelUndelivered(ctx, message, at); err != nil {
				result = append(result, fmt.Errorf("cancel undelivered command %q: %w", message.ID, err))
			}
			continue
		}
		if err := lifecycle.dispatchCancellation(ctx, message); err != nil {
			result = append(result, fmt.Errorf("dispatch command cancellation %q: %w", message.ID, err))
			continue
		}
		if preStart {
			if err := lifecycle.cancelUndelivered(ctx, message, at); err != nil {
				result = append(result, fmt.Errorf("terminalize prepared command cancellation %q: %w", message.ID, err))
			}
			continue
		}
		if err := lifecycle.dispatchRepository.DeferCancellation(ctx, message.Scope, message.ID, at.Add(DefaultCancellationRetry)); err != nil && !errors.Is(err, ErrNotFound) {
			result = append(result, fmt.Errorf("defer command cancellation %q: %w", message.ID, err))
		}
	}
	return errors.Join(result...)
}

func (lifecycle *CommandLifecycle) dispatchCancellation(ctx context.Context, message OutboxMessage) error {
	unlock := lifecycle.lockCommandTransition(message.ID)
	defer unlock()
	started := message.Phase == CommandPhaseStartAuthorized || message.Phase == CommandPhaseRunning || message.Phase == CommandPhaseCancelling
	if !started {
		return lifecycle.agents.CancelPrepared(ctx, message.TargetID, message.ID, message.CancellationReason)
	}
	start, token, err := lifecycle.persistedCommandStart(ctx, message)
	if err != nil {
		return err
	}
	defer clearSensitiveBytes(token)
	if err := lifecycle.agents.ReplayStart(ctx, message.TargetID, start); err != nil {
		return err
	}
	if err := lifecycle.dispatchRepository.MarkStartEnqueued(ctx, message.Scope, message.ID, message.ExecutionRevision, lifecycle.currentTime()); err != nil {
		lifecycle.onError(err)
	}
	return lifecycle.agents.CancelExecution(ctx, message.TargetID, message.ID, token, message.ExecutionRevision, message.CancellationReason)
}

func (lifecycle *CommandLifecycle) cancelUndelivered(ctx context.Context, message OutboxMessage, at time.Time) error {
	target := TargetResult{TargetID: message.TargetID, Status: TargetCancelled, ResultSummary: "cancelled before Agent execution", FinishedAt: timePointer(at)}
	if err := lifecycle.dispatchRepository.MarkCommandTerminal(ctx, message.Scope, message.ID, CommandCancelled, at); err != nil {
		return err
	}
	value, _, err := lifecycle.applyTarget(ctx, message, target, at)
	if err != nil {
		return err
	}
	event := lifecycle.auditEvent(value, message, "command.cancelled_before_dispatch", "success", map[string]any{"reason": "job_cancellation"}, at, "command.cancelled_before_dispatch:"+message.ID)
	if _, err := lifecycle.audit.RecordOnce(ctx, event); err != nil {
		return err
	}
	return nil
}

func (lifecycle *CommandLifecycle) expireExecutions(ctx context.Context, at time.Time) error {
	claims, err := lifecycle.dispatchRepository.ClaimExpiredExecution(ctx, lifecycle.claimLimit, at)
	if err != nil {
		return err
	}
	var result []error
	for _, claim := range claims {
		if err := lifecycle.dispatchRepository.FinalizeExpiredExecution(ctx, claim, at); err != nil {
			if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
				continue
			}
			result = append(result, fmt.Errorf("fence expired command %q: %w", claim.CommandID, err))
			continue
		}
		message, lookupErr := lifecycle.dispatchRepository.LookupCommand(ctx, claim.CommandID)
		if lookupErr != nil {
			result = append(result, fmt.Errorf("load expired command %q: %w", claim.CommandID, lookupErr))
			continue
		}
		if _, terminalErr := lifecycle.finalizeDatabaseInstanceValidationTarget(ctx, message, TargetResult{TargetID: message.TargetID, Status: TargetTimedOut}, at); terminalErr != nil {
			result = append(result, fmt.Errorf("finalize expired database validation %q: %w", claim.CommandID, terminalErr))
		}
	}
	if err := lifecycle.repairPendingTerminalAudits(ctx, at); err != nil {
		result = append(result, err)
	}
	return errors.Join(result...)
}

func matchingRecoveryClaim(message OutboxMessage, claim RecoveryClaim) bool {
	active := message.Phase == CommandPhaseStartAuthorized || message.Phase == CommandPhaseRunning || message.Phase == CommandPhaseCancelling
	return active && message.ExecutionDeadline != nil && message.RecoveryClaimedDeadline != nil &&
		message.ExecutionDeadline.Equal(claim.ClaimedDeadline) && message.RecoveryClaimedDeadline.Equal(claim.ClaimedDeadline) &&
		message.RecoveryRevision == claim.ClaimedRecoveryRevision && message.RecoveryClaimedRevision == claim.ClaimedRecoveryRevision &&
		len(message.RecoveryClaimToken) == len(claim.ClaimToken) && subtle.ConstantTimeCompare(message.RecoveryClaimToken, claim.ClaimToken[:]) == 1
}

func (lifecycle *CommandLifecycle) repairPendingTerminalAudits(ctx context.Context, at time.Time) error {
	messages, err := lifecycle.dispatchRepository.ClaimPendingTerminalAudits(ctx, lifecycle.claimLimit, at)
	if err != nil {
		return err
	}
	return lifecycle.repairTerminalAuditMessages(ctx, messages, at)
}

func (lifecycle *CommandLifecycle) repairTerminalAuditMessages(ctx context.Context, messages []OutboxMessage, at time.Time) error {
	var result []error
	for _, message := range messages {
		if !message.TerminalAuditPending || message.TerminalAt == nil || strings.TrimSpace(message.TerminalAuditDedupeKey) == "" || strings.TrimSpace(message.TerminalAuditAction) == "" || strings.TrimSpace(message.TerminalAuditResult) == "" {
			result = append(result, fmt.Errorf("repair terminal Audit %q: %w", message.ID, ErrInvalidCommandPayload))
			continue
		}
		value, err := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
		if err != nil {
			result = append(result, fmt.Errorf("load terminal Audit Job %q: %w", message.ID, err))
			continue
		}
		detail := make(map[string]any, len(message.TerminalAuditDetail))
		for key, item := range message.TerminalAuditDetail {
			detail[key] = item
		}
		event := lifecycle.auditEvent(value, message, message.TerminalAuditAction, message.TerminalAuditResult, detail, message.TerminalAt.UTC(), message.TerminalAuditDedupeKey)
		if _, err := lifecycle.audit.RecordOnce(ctx, event); err != nil {
			result = append(result, fmt.Errorf("record terminal Audit %q: %w", message.ID, err))
			continue
		}
		if err := lifecycle.dispatchRepository.MarkTerminalAuditRecorded(ctx, message.Scope, message.ID, message.TerminalAuditDedupeKey, at); err != nil {
			result = append(result, fmt.Errorf("mark terminal Audit %q recorded: %w", message.ID, err))
		}
	}
	return errors.Join(result...)
}

func (lifecycle *CommandLifecycle) expireDelivery(ctx context.Context, message OutboxMessage, at time.Time) error {
	target := TargetResult{TargetID: message.TargetID, Status: TargetTimedOut, ErrorSummary: "delivery deadline exceeded", FinishedAt: timePointer(at)}
	if err := lifecycle.dispatchRepository.MarkCommandTerminal(ctx, message.Scope, message.ID, CommandTimedOut, at); err != nil {
		return err
	}
	value, _, err := lifecycle.applyTarget(ctx, message, target, at)
	if err != nil {
		return err
	}
	if _, err := lifecycle.audit.RecordOnce(ctx, lifecycle.auditEvent(value, message, "command.delivery_timed_out", "failure", map[string]any{"reason": "delivery_deadline"}, at, "command.delivery_timed_out:"+message.ID)); err != nil {
		return err
	}
	return nil
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
	envelope, err := decodeUnsignedCommandShape(message)
	if err != nil {
		return nil, err
	}
	if err := commandvalidation.Validate(ctx, envelope, authorizer); err != nil {
		return nil, ErrInvalidCommandPayload
	}
	return envelope, nil
}

func decodeUnsignedCommandShape(message OutboxMessage) (*agentv1.CommandEnvelope, error) {
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
	if err := commandvalidation.ValidateShape(envelope); err != nil {
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

func (lifecycle *CommandLifecycle) Prepared(ctx context.Context, agentID string, prepared *agentv1.CommandPrepared) (*agentv1.CommandStart, error) {
	if lifecycle == nil || prepared == nil || strings.TrimSpace(prepared.GetCommandId()) == "" || len(prepared.GetEnvelopeDigest()) != sha256.Size {
		return nil, ErrInvalidCommandPayload
	}
	message, err := lifecycle.dispatchRepository.LookupCommand(ctx, prepared.GetCommandId())
	if err != nil {
		return nil, err
	}
	if message.TargetID != agentID {
		return nil, ErrCommandAgentMismatch
	}
	if len(message.PreparedEnvelope) == 0 {
		return nil, ErrInvalidCommandPayload
	}
	envelopeDigest := sha256.Sum256(message.PreparedEnvelope)
	if subtle.ConstantTimeCompare(envelopeDigest[:], prepared.GetEnvelopeDigest()) != 1 {
		return nil, ErrConflict
	}
	unlock := lifecycle.lockCommandTransition(message.ID)
	defer unlock()
	var digest [sha256.Size]byte
	copy(digest[:], prepared.GetEnvelopeDigest())
	at := lifecycle.currentTime()
	if err := lifecycle.dispatchRepository.MarkPrepared(ctx, message.Scope, message.ID, digest, at); err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, lifecycle.agents.CancelPrepared(ctx, message.TargetID, message.ID, message.CancellationReason)
		}
		return nil, err
	}
	message, err = lifecycle.dispatchRepository.LookupCommand(ctx, message.ID)
	if err != nil {
		return nil, err
	}
	return nil, lifecycle.startOrReplayCommandLocked(ctx, message, at)
}

func (lifecycle *CommandLifecycle) startOrReplayCommandLocked(ctx context.Context, message OutboxMessage, at time.Time) error {
	freshAuthorization := false
	if message.Phase == CommandPhasePrepared {
		unsigned, err := decodeUnsignedCommand(ctx, message, lifecycle.targetAuthorizer)
		if err != nil {
			return err
		}
		prepared, err := decodePreparedCommand(message, unsigned, message.PreparedEnvelope)
		if err != nil {
			return err
		}
		if !prepared.GetExpiresAt().AsTime().UTC().After(at.UTC()) {
			return lifecycle.expirePreparedEnvelopeLocked(ctx, message, prepared.GetExpiresAt().AsTime().UTC(), at.UTC())
		}
		value, err := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
		if err != nil {
			return err
		}
		deadline := executionDeadline(value, unsigned.GetLeaseSeconds(), at)
		if !deadline.After(at) {
			return nil
		}
		if len(message.PrepareDigest) != sha256.Size {
			return ErrInvalidCommandPayload
		}
		var digest [sha256.Size]byte
		copy(digest[:], message.PrepareDigest)
		token := make([]byte, sha256.Size)
		if _, err := io.ReadFull(lifecycle.tokenReader, token); err != nil {
			return fmt.Errorf("generate execution token: %w", err)
		}
		defer clearSensitiveBytes(token)
		tokenHash := sha256.Sum256(token)
		ciphertext, err := lifecycle.tokenProtector.Protect(ctx, token)
		if err != nil {
			return fmt.Errorf("protect execution token: %w", err)
		}
		if _, err := lifecycle.dispatchRepository.AuthorizeStart(ctx, message.Scope, message.ID, digest, tokenHash, ciphertext, at, deadline); err != nil {
			if errors.Is(err, ErrConflict) {
				return nil
			}
			return err
		}
		message, err = lifecycle.dispatchRepository.LookupCommand(ctx, message.ID)
		if err != nil {
			return err
		}
		freshAuthorization = true
	}
	if message.Phase != CommandPhaseStartAuthorized && message.Phase != CommandPhaseRunning && message.Phase != CommandPhaseCancelling {
		return nil
	}
	start, token, err := lifecycle.persistedCommandStart(ctx, message)
	if err != nil {
		return err
	}
	defer clearSensitiveBytes(token)
	if freshAuthorization {
		err = lifecycle.agents.Start(ctx, message.TargetID, start)
	} else {
		err = lifecycle.agents.ReplayStart(ctx, message.TargetID, start)
	}
	if err != nil {
		return err
	}
	return lifecycle.dispatchRepository.MarkStartEnqueued(ctx, message.Scope, message.ID, message.ExecutionRevision, lifecycle.currentTime())
}

func (lifecycle *CommandLifecycle) expirePreparedEnvelopeLocked(ctx context.Context, message OutboxMessage, expiresAt, at time.Time) error {
	if len(message.PrepareDigest) != sha256.Size || expiresAt.IsZero() || expiresAt.After(at) {
		return ErrInvalidCommandPayload
	}
	var digest [sha256.Size]byte
	copy(digest[:], message.PrepareDigest)
	if err := lifecycle.dispatchRepository.FinalizeExpiredPrepared(ctx, message.Scope, message.ID, digest, expiresAt, at); err != nil {
		if errors.Is(err, ErrConflict) {
			return nil
		}
		return err
	}
	if err := lifecycle.agents.CancelPrepared(ctx, message.TargetID, message.ID, "prepared envelope expired"); err != nil {
		lifecycle.onError(err)
	}
	terminal, err := lifecycle.dispatchRepository.LookupCommand(ctx, message.ID)
	if err != nil {
		return err
	}
	return lifecycle.repairTerminalAuditMessages(ctx, []OutboxMessage{terminal}, at)
}

func (lifecycle *CommandLifecycle) persistedCommandStart(ctx context.Context, message OutboxMessage) (*agentv1.CommandStart, []byte, error) {
	if message.ExecutionRevision == 0 || len(message.ExecutionTokenHash) != sha256.Size || len(message.ExecutionTokenCiphertext) == 0 || message.StartDeadline == nil {
		return nil, nil, ErrInvalidCommandPayload
	}
	unsigned, err := decodeUnsignedCommand(ctx, message, lifecycle.targetAuthorizer)
	if err != nil {
		return nil, nil, err
	}
	token, err := lifecycle.tokenProtector.Unprotect(ctx, message.ExecutionTokenCiphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("recover persisted execution token: %w", err)
	}
	hash := sha256.Sum256(token)
	if subtle.ConstantTimeCompare(hash[:], message.ExecutionTokenHash) != 1 {
		clearSensitiveBytes(token)
		return nil, nil, ErrInvalidCommandPayload
	}
	start := &agentv1.CommandStart{
		CommandId: message.ID, ExecutionToken: append([]byte(nil), token...), LeaseRevision: message.ExecutionRevision,
		LeaseSeconds: unsigned.GetLeaseSeconds(), StartDeadline: timestamppb.New(message.StartDeadline.UTC()),
	}
	return start, token, nil
}

func (lifecycle *CommandLifecycle) lockCommandTransition(commandID string) func() {
	digest := sha256.Sum256([]byte(commandID))
	stripe := &lifecycle.transitionStripes[int(digest[0])%len(lifecycle.transitionStripes)]
	stripe.Lock()
	return stripe.Unlock
}

func clearSensitiveBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (lifecycle *CommandLifecycle) Connected(ctx context.Context, session agentcontrol.SessionInfo) {
	active := make([]executionLeaseFence, 0, len(session.ActiveCommands))
	for _, state := range session.ActiveCommands {
		if state != nil && strings.TrimSpace(state.GetCommandId()) != "" && (state.GetState() == agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_ACCEPTED || state.GetState() == agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_RUNNING) {
			active = append(active, executionLeaseFence{commandID: state.GetCommandId(), token: append([]byte(nil), state.GetExecutionToken()...), executionRevision: state.GetLeaseRevision()})
		}
	}
	lifecycle.renewExecutionLeases(ctx, session.AgentID, active, lifecycle.currentTime())
	pendingAudits, err := lifecycle.dispatchRepository.PendingTerminalAuditsForAgent(ctx, session.AgentID, lifecycle.claimLimit)
	if err != nil {
		lifecycle.onError(err)
	} else if err := lifecycle.repairTerminalAuditMessages(ctx, pendingAudits, lifecycle.currentTime()); err != nil {
		lifecycle.onError(err)
	}
	prepared, err := lifecycle.dispatchRepository.PreparedCommandsForAgent(ctx, session.AgentID, lifecycle.claimLimit)
	if err != nil {
		lifecycle.onError(err)
		return
	}
	for _, message := range prepared {
		if err := lifecycle.recoverPreparedCommand(ctx, message.ID, lifecycle.currentTime()); err != nil {
			lifecycle.onError(err)
		}
	}
	messages, err := lifecycle.dispatchRepository.PendingCancellationsForAgent(ctx, session.AgentID, lifecycle.claimLimit)
	if err != nil {
		lifecycle.onError(err)
		return
	}
	for _, message := range messages {
		if err := lifecycle.dispatchCancellation(ctx, message); err != nil {
			lifecycle.onError(err)
		}
	}
}

func (lifecycle *CommandLifecycle) Heartbeat(ctx context.Context, agentID string, heartbeat *agentv1.Heartbeat) {
	if heartbeat == nil || heartbeat.GetAgentId() != agentID {
		lifecycle.onError(ErrCommandAgentMismatch)
		return
	}
	active := make([]executionLeaseFence, 0, len(heartbeat.GetActiveCommands()))
	for _, command := range heartbeat.GetActiveCommands() {
		if command != nil {
			active = append(active, executionLeaseFence{commandID: command.GetCommandId(), token: append([]byte(nil), command.GetExecutionToken()...), executionRevision: command.GetLeaseRevision()})
		}
	}
	lifecycle.renewExecutionLeases(ctx, agentID, active, lifecycle.currentTime())
}

type executionLeaseFence struct {
	commandID         string
	token             []byte
	executionRevision uint64
}

func (lifecycle *CommandLifecycle) renewExecutionLeases(ctx context.Context, agentID string, commands []executionLeaseFence, at time.Time) {
	seen := make(map[string]struct{}, len(commands))
	for _, command := range commands {
		if strings.TrimSpace(command.commandID) == "" || len(command.token) != sha256.Size || command.executionRevision == 0 {
			continue
		}
		if _, duplicate := seen[command.commandID]; duplicate {
			continue
		}
		seen[command.commandID] = struct{}{}
		message, err := lifecycle.dispatchRepository.LookupCommand(ctx, command.commandID)
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
		tokenHash := sha256.Sum256(command.token)
		if _, err := lifecycle.dispatchRepository.RenewExecutionLease(ctx, message.Scope, message.ID, tokenHash, command.executionRevision, at, deadline); err != nil && !errors.Is(err, ErrNotFound) {
			lifecycle.onError(err)
		}
	}
}

func (lifecycle *CommandLifecycle) Acknowledged(ctx context.Context, agentID string, acknowledgement *agentv1.CommandAcknowledgement) {
	if commandvalidation.ValidateAcknowledgement(acknowledgement) != nil {
		lifecycle.onError(ErrInvalidCommandPayload)
		return
	}
	message, err := lifecycle.dispatchRepository.LookupCommand(ctx, acknowledgement.GetCommandId())
	if err != nil {
		lifecycle.onError(err)
		return
	}
	envelope, err := decodeUnsignedCommandShape(message)
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
	if acknowledgement.GetState() == agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED || acknowledgement.GetState() == agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_DUPLICATE {
		value, getErr := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
		if getErr != nil {
			lifecycle.onError(getErr)
			return
		}
		event := lifecycle.auditEvent(value, message, "command.acknowledgement_ignored", "success", map[string]any{"reason": "Prepared and fenced execution messages own state"}, lifecycle.currentTime(), "command.acknowledgement_ignored:"+message.ID)
		if _, err := lifecycle.audit.RecordOnce(ctx, event); err != nil {
			lifecycle.onError(err)
		}
		return
	}
	unlock := lifecycle.lockCommandTransition(message.ID)
	defer unlock()
	message, err = lifecycle.dispatchRepository.LookupCommand(ctx, message.ID)
	if err != nil {
		lifecycle.onError(err)
		return
	}
	var target TargetResult
	auditResult := "failure"
	commandStatus := CommandRejected
	at := lifecycle.currentTime()
	switch acknowledgement.GetState() {
	case agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED:
		if message.CancellationRequestedAt != nil {
			return
		}
		if message.Phase != "" && message.Phase != CommandPhasePending && message.Phase != CommandPhasePreparing && message.Phase != CommandPhasePrepared {
			lifecycle.onError(ErrConflict)
			return
		}
		reasonCode := acknowledgement.GetReasonCode()
		if reasonCode == "" {
			reasonCode = "command_rejected"
		}
		target = TargetResult{Status: TargetFailed, ErrorSummary: reasonCode, FinishedAt: timePointer(at)}
		if envelope.GetValidateDatabaseInstance() != nil {
			target.ErrorSummary = "plugin_failed"
			target.ResultSummary = "database instance connection validation failed"
		}
	default:
		lifecycle.onError(ErrInvalidCommandPayload)
		return
	}
	target.TargetID = message.TargetID
	if err := lifecycle.dispatchRepository.AcknowledgeCommand(ctx, message.Scope, message.ID, commandStatus, at, nil); err != nil {
		lifecycle.onError(err)
		return
	}
	value, _, err := lifecycle.applyTarget(ctx, message, target, at)
	if err != nil {
		lifecycle.onError(err)
		return
	}
	reasonCode := target.ErrorSummary
	detail := map[string]any{"state": "rejected", "reason_code": reasonCode}
	event := lifecycle.auditEvent(value, message, "command.acknowledged", auditResult, detail, at, "command.acknowledged:"+message.ID)
	if _, err := lifecycle.audit.RecordOnce(ctx, event); err != nil {
		lifecycle.onError(err)
		return
	}
}

func (lifecycle *CommandLifecycle) Progress(ctx context.Context, agentID string, progress *agentv1.CommandProgress) {
	if progress == nil || strings.TrimSpace(progress.GetCommandId()) == "" || progress.GetPercent() > 100 {
		lifecycle.onError(ErrInvalidCommandPayload)
		return
	}
	message, err := lifecycle.dispatchRepository.LookupCommand(ctx, progress.GetCommandId())
	if err != nil {
		lifecycle.onError(err)
		return
	}
	if message.Phase != "" {
		if message.Phase != CommandPhaseStartAuthorized && message.Phase != CommandPhaseRunning && message.Phase != CommandPhaseCancelling {
			lifecycle.onError(ErrConflict)
			return
		}
		if len(progress.GetExecutionToken()) != sha256.Size || progress.GetLeaseRevision() != message.ExecutionRevision || message.ExecutionRevision == 0 || len(message.ExecutionTokenHash) != sha256.Size {
			lifecycle.onError(ErrConflict)
			return
		}
		hash := sha256.Sum256(progress.GetExecutionToken())
		if subtle.ConstantTimeCompare(hash[:], message.ExecutionTokenHash) != 1 {
			lifecycle.onError(ErrConflict)
			return
		}
	}
	envelope, decodeErr := decodeUnsignedCommand(ctx, message, lifecycle.targetAuthorizer)
	if decodeErr != nil {
		lifecycle.onError(decodeErr)
		return
	}
	if envelope.GetAgentId() != agentID || message.TargetID != agentID {
		lifecycle.onError(ErrCommandAgentMismatch)
		return
	}
	if command := envelope.GetValidateDatabaseInstance(); command != nil {
		if lifecycle.databaseInstanceResults == nil {
			lifecycle.onError(ErrInvalidCommandPayload)
			return
		}
		if err := lifecycle.databaseInstanceResults.RecordDatabaseInstanceValidationProgress(ctx, message.Scope, message.JobID, message.ID, command, lifecycle.currentTime()); err != nil {
			lifecycle.onError(err)
			return
		}
	}
	lifecycle.observe(ctx, agentID, progress.GetCommandId(), "command.progress", "success", TargetResult{Status: TargetRunning}, map[string]any{"percent": progress.GetPercent()})
}

func (lifecycle *CommandLifecycle) Result(ctx context.Context, agentID string, result *agentv1.CommandResult) (agentcontrol.ResultPersistence, error) {
	if result == nil || strings.TrimSpace(result.GetCommandId()) == "" || len(result.GetSummary()) > maximumInlineResultSummary {
		return agentcontrol.ResultPersistence{}, ErrInvalidCommandPayload
	}
	encodedResult, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	if err != nil {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId()}, ErrInvalidCommandPayload
	}
	resultDigest := sha256.Sum256(encodedResult)
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
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED:
		target.Status, target.ErrorSummary, auditResult = TargetTimedOut, result.GetErrorCode(), "failure"
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
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, err
	}
	envelope, err := decodeUnsignedCommandShape(message)
	if err != nil {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, err
	}
	if envelope.GetAgentId() != agentID || message.TargetID != agentID {
		value, getErr := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
		if getErr != nil {
			return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, getErr
		}
		recordErr := lifecycle.recordAudit(ctx, value, message, "command.rejected", "failure", map[string]any{"reason": "agent_mismatch"})
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, errors.Join(ErrCommandAgentMismatch, recordErr)
	}
	if len(result.GetExecutionToken()) != sha256.Size || result.GetLeaseRevision() == 0 {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, ErrInvalidCommandPayload
	}
	tokenHash := sha256.Sum256(result.GetExecutionToken())
	target.TargetID = message.TargetID
	at := lifecycle.currentTime()
	trialCommand := envelope.GetCollectDatabaseMetrics()
	validationCommand := envelope.GetValidateDatabaseInstance()
	if validationCommand != nil && (lifecycle.databaseInstanceResults == nil || !validDatabaseInstanceValidationResult(result)) {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, ErrInvalidCommandPayload
	}
	validationResult := result
	if validationCommand != nil {
		validationResult = canonicalDatabaseInstanceValidationResult(result)
		target = databaseInstanceValidationTarget(message.TargetID, validationResult, at)
	}
	if trialCommand != nil && trialCommand.GetTrial() {
		if lifecycle.typedResultRecorder == nil {
			return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, ErrInvalidCommandPayload
		}
		succeeded, classifyErr := lifecycle.typedResultRecorder.ClassifyMetricTemplateTrial(ctx, message.Scope, message.JobID, trialCommand, result)
		if classifyErr != nil {
			return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, classifyErr
		}
		if result.GetState() == agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED && !succeeded {
			commandStatus = CommandFailed
			target.Status = TargetFailed
			target.ErrorSummary = "metric_template_trial_invalid_result"
			auditResult = "failure"
		}
	} else if result.GetMetricTemplateTrialResult() != nil {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, ErrInvalidCommandPayload
	}
	terminal, err := lifecycle.dispatchRepository.PersistTerminalResult(ctx, TerminalResultCAS{
		Scope: message.Scope, CommandID: message.ID, TokenHash: tokenHash,
		ExpectedExecutionRevision: result.GetLeaseRevision(), Status: commandStatus, ResultDigest: resultDigest,
		AllowTimedOutDigestAttach: result.GetState() == agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED, At: at,
	})
	if err != nil {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, err
	}
	if terminal.Conflict {
		value, getErr := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
		if getErr != nil {
			return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, getErr
		}
		event := lifecycle.auditEvent(value, message, "command.result_conflict", "failure", map[string]any{"stored_status": string(terminal.Status), "incoming_status": string(commandStatus)}, at, "command.result_conflict:"+message.ID+":"+fmt.Sprintf("%x", resultDigest[:]))
		if _, recordErr := lifecycle.audit.RecordOnce(ctx, event); recordErr != nil {
			return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, recordErr
		}
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:], ReasonCode: "RESULT_CONFLICT"}, nil
	}
	if validationCommand != nil {
		persistedStatus := commandStatus
		validationResult, err = lifecycle.databaseInstanceResults.FinalizeDatabaseInstanceValidationResult(ctx, message.Scope, message.JobID, message.ID, validationCommand, validationResult, at)
		if err != nil {
			return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, err
		}
		target = databaseInstanceValidationTarget(message.TargetID, validationResult, at)
		switch target.Status {
		case TargetSucceeded:
			commandStatus, auditResult = CommandSucceeded, "success"
		case TargetCancelled:
			commandStatus, auditResult = CommandCancelled, "failure"
		case TargetTimedOut:
			commandStatus, auditResult = CommandTimedOut, "failure"
		default:
			commandStatus, auditResult = CommandFailed, "failure"
		}
		if commandStatus != persistedStatus {
			if err := lifecycle.dispatchRepository.CorrectValidationTerminalStatus(ctx, message.Scope, message.ID, resultDigest, persistedStatus, commandStatus, at); err != nil {
				return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, err
			}
		}
	}
	if trialCommand != nil && trialCommand.GetTrial() {
		if err := lifecycle.typedResultRecorder.RecordMetricTemplateTrial(ctx, message.Scope, message.JobID, message.ID, trialCommand, result, at); err != nil {
			return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, err
		}
	}
	if terminal.Duplicate && terminal.Status == CommandTimedOut && result.GetState() == agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED {
		value, getErr := lifecycle.jobs.Get(ctx, message.Scope, message.JobID)
		if getErr != nil {
			return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, getErr
		}
		storedTarget, found := targetFor(value.TargetResults, message.TargetID)
		if !found || storedTarget.Status != TargetTimedOut {
			return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, ErrConflict
		}
		event := lifecycle.auditEvent(value, message, "command.execution_interrupted", "failure", map[string]any{"state": result.GetState().String()}, at, "command.execution_interrupted:"+message.ID)
		if _, recordErr := lifecycle.audit.RecordOnce(ctx, event); recordErr != nil {
			return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, recordErr
		}
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:], Persisted: true, ReasonCode: "PERSISTED"}, nil
	}
	applyTarget := lifecycle.applyTarget
	if validationCommand != nil {
		applyTarget = lifecycle.applyEffectiveTarget
	}
	value, _, err := applyTarget(ctx, message, target, at)
	if err != nil {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, err
	}
	storedTarget, found := targetFor(value.TargetResults, message.TargetID)
	if !found || !matchingTerminalTarget(storedTarget, target) {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, ErrConflict
	}
	detail := map[string]any{"state": result.GetState().String(), "artifact_count": len(target.Artifacts)}
	event := lifecycle.auditEvent(value, message, "command.result", auditResult, detail, at, "command.result:"+message.ID)
	if _, err := lifecycle.audit.RecordOnce(ctx, event); err != nil {
		return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:]}, err
	}
	return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: resultDigest[:], Persisted: true, ReasonCode: "PERSISTED"}, nil
}

func validDatabaseInstanceValidationResult(result *agentv1.CommandResult) bool {
	if result == nil || len(result.GetArtifacts()) != 0 || result.GetMetricTemplateTrialResult() != nil {
		return false
	}
	switch result.GetState() {
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED:
		return result.GetErrorCode() == ""
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED:
		switch result.GetErrorCode() {
		case "instance_authentication_failed", "instance_tls_failed", "instance_unreachable", "database_version_unsupported", "plugin_failed":
			return true
		default:
			return false
		}
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED, agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT:
		return result.GetErrorCode() == ""
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED:
		return result.GetErrorCode() == "" || result.GetErrorCode() == "EXECUTION_INTERRUPTED"
	default:
		return false
	}
}

func canonicalDatabaseInstanceValidationResult(result *agentv1.CommandResult) *agentv1.CommandResult {
	canonical := &agentv1.CommandResult{CommandId: result.GetCommandId(), State: result.GetState(), ErrorCode: result.GetErrorCode(), ExecutionToken: append([]byte(nil), result.GetExecutionToken()...), LeaseRevision: result.GetLeaseRevision()}
	switch result.GetState() {
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED:
		canonical.Summary = "database instance connection validation succeeded"
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED:
		canonical.Summary = "database instance connection validation failed"
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED:
		canonical.Summary = "database instance connection validation cancelled"
		canonical.ErrorCode = ""
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT, agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED:
		canonical.Summary = "database instance connection validation timed out"
		canonical.ErrorCode = ""
	}
	return canonical
}

func databaseInstanceValidationTarget(targetID string, result *agentv1.CommandResult, at time.Time) TargetResult {
	target := TargetResult{TargetID: targetID, ResultSummary: result.GetSummary(), FinishedAt: timePointer(at)}
	switch result.GetState() {
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED:
		target.Status = TargetSucceeded
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED:
		target.Status, target.ErrorSummary = TargetFailed, result.GetErrorCode()
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED:
		target.Status = TargetCancelled
	default:
		target.Status = TargetTimedOut
	}
	return target
}

func (lifecycle *CommandLifecycle) finalizeDatabaseInstanceValidationTarget(ctx context.Context, message OutboxMessage, target TargetResult, at time.Time) (TargetResult, error) {
	if !isTerminalTarget(target.Status) {
		return target, nil
	}
	envelope, err := decodeUnsignedCommandShape(message)
	if err != nil {
		return TargetResult{}, err
	}
	command := envelope.GetValidateDatabaseInstance()
	if command == nil {
		return target, nil
	}
	if lifecycle.databaseInstanceResults == nil {
		return TargetResult{}, ErrInvalidCommandPayload
	}
	result := &agentv1.CommandResult{CommandId: message.ID}
	switch target.Status {
	case TargetSucceeded:
		result.State = agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED
	case TargetFailed:
		result.State = agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED
		result.ErrorCode = fixedDatabaseInstanceValidationError(target.ErrorSummary)
	case TargetCancelled:
		result.State = agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED
	case TargetTimedOut:
		result.State = agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT
	}
	result = canonicalDatabaseInstanceValidationResult(result)
	effective, err := lifecycle.databaseInstanceResults.FinalizeDatabaseInstanceValidationResult(ctx, message.Scope, message.JobID, message.ID, command, result, at)
	if err != nil {
		return TargetResult{}, err
	}
	return databaseInstanceValidationTarget(message.TargetID, effective, at), nil
}

func fixedDatabaseInstanceValidationError(value string) string {
	switch value {
	case "instance_authentication_failed", "instance_tls_failed", "instance_unreachable", "database_version_unsupported", "plugin_failed":
		return value
	default:
		return "plugin_failed"
	}
}

func matchingTerminalTarget(stored, incoming TargetResult) bool {
	if stored.TargetID != incoming.TargetID || stored.Status != incoming.Status || stored.ErrorSummary != incoming.ErrorSummary || stored.ResultSummary != incoming.ResultSummary || len(stored.Artifacts) != len(incoming.Artifacts) {
		return false
	}
	for index := range stored.Artifacts {
		if stored.Artifacts[index] != incoming.Artifacts[index] {
			return false
		}
	}
	return true
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
	return lifecycle.applyTargetWithProjection(ctx, message, target, at, true)
}

func (lifecycle *CommandLifecycle) applyEffectiveTarget(ctx context.Context, message OutboxMessage, target TargetResult, at time.Time) (Job, bool, error) {
	return lifecycle.applyTargetWithProjection(ctx, message, target, at, false)
}

func (lifecycle *CommandLifecycle) applyTargetWithProjection(ctx context.Context, message OutboxMessage, target TargetResult, at time.Time, finalizeProjection bool) (Job, bool, error) {
	if finalizeProjection {
		effective, err := lifecycle.finalizeDatabaseInstanceValidationTarget(ctx, message, target, at)
		if err != nil {
			return Job{}, false, err
		}
		target = effective
	}
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
var _ agentcontrol.PreparedObserver = (*CommandLifecycle)(nil)
