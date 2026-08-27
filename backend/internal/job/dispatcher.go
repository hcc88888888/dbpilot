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
	}, nil
}

func (lifecycle *CommandLifecycle) DispatchPending(ctx context.Context, at time.Time) (int, error) {
	if lifecycle == nil || at.IsZero() {
		return 0, errors.New("command lifecycle and dispatch time are required")
	}
	messages, err := lifecycle.dispatchRepository.ClaimOutbox(ctx, lifecycle.claimLimit, at.UTC())
	if err != nil {
		return 0, err
	}
	dispatched := 0
	var dispatchErrors []error
	for _, message := range messages {
		if err := lifecycle.dispatchOne(ctx, message, at.UTC()); err != nil {
			dispatchErrors = append(dispatchErrors, fmt.Errorf("dispatch command %q: %w", message.ID, err))
			continue
		}
		dispatched++
	}
	return dispatched, errors.Join(dispatchErrors...)
}

func (lifecycle *CommandLifecycle) dispatchOne(ctx context.Context, message OutboxMessage, at time.Time) error {
	envelope, err := decodeUnsignedCommand(message)
	if err != nil {
		return err
	}
	envelope.CommandId = message.ID
	envelope.JobId = message.JobID
	envelope.IssuedAt = timestamppb.New(at)
	envelope.ExpiresAt = timestamppb.New(at.Add(time.Duration(envelope.GetLeaseSeconds()) * time.Second))
	envelope.Nonce = make([]byte, commandNonceBytes)
	if _, err := io.ReadFull(lifecycle.nonceReader, envelope.Nonce); err != nil {
		return fmt.Errorf("generate command nonce: %w", err)
	}
	if err := lifecycle.signer.Sign(ctx, envelope); err != nil {
		return err
	}
	if err := lifecycle.agents.Dispatch(ctx, envelope.GetAgentId(), envelope); err != nil {
		return err
	}
	if err := lifecycle.dispatchRepository.MarkOutboxPublished(ctx, message.Scope, message.ID, at); err != nil {
		return err
	}
	value, err := lifecycle.ensureDispatched(ctx, message, at)
	if err != nil {
		return err
	}
	return lifecycle.recordAudit(ctx, value, message, "command.dispatched", "success", map[string]any{"state": "dispatched"})
}

func decodeUnsignedCommand(message OutboxMessage) (*agentv1.CommandEnvelope, error) {
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
	if envelope.GetCommand() == nil || envelope.GetLeaseSeconds() == 0 || strings.TrimSpace(envelope.GetAgentId()) == "" || envelope.GetAgentId() != message.TargetID {
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

func (lifecycle *CommandLifecycle) Connected(context.Context, agentcontrol.SessionInfo)   {}
func (lifecycle *CommandLifecycle) Heartbeat(context.Context, string, *agentv1.Heartbeat) {}

func (lifecycle *CommandLifecycle) Acknowledged(ctx context.Context, agentID string, acknowledgement *agentv1.CommandAcknowledgement) {
	if acknowledgement == nil || strings.TrimSpace(acknowledgement.GetCommandId()) == "" {
		lifecycle.onError(ErrInvalidCommandPayload)
		return
	}
	var target TargetResult
	result := "success"
	switch acknowledgement.GetState() {
	case agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED, agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_DUPLICATE:
		target = TargetResult{Status: TargetRunning}
	case agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED:
		target = TargetResult{Status: TargetFailed, ErrorSummary: acknowledgement.GetReasonCode(), FinishedAt: timePointer(lifecycle.currentTime())}
		result = "failure"
	default:
		lifecycle.onError(ErrInvalidCommandPayload)
		return
	}
	lifecycle.observe(ctx, agentID, acknowledgement.GetCommandId(), "command.acknowledged", result, target, map[string]any{"state": acknowledgement.GetState().String()})
}

func (lifecycle *CommandLifecycle) Progress(ctx context.Context, agentID string, progress *agentv1.CommandProgress) {
	if progress == nil || strings.TrimSpace(progress.GetCommandId()) == "" || progress.GetPercent() > 100 {
		lifecycle.onError(ErrInvalidCommandPayload)
		return
	}
	lifecycle.observe(ctx, agentID, progress.GetCommandId(), "command.progress", "success", TargetResult{Status: TargetRunning}, map[string]any{"percent": progress.GetPercent()})
}

func (lifecycle *CommandLifecycle) Result(ctx context.Context, agentID string, result *agentv1.CommandResult) {
	if result == nil || strings.TrimSpace(result.GetCommandId()) == "" || len(result.GetSummary()) > maximumInlineResultSummary {
		lifecycle.onError(ErrInvalidCommandPayload)
		return
	}
	target := TargetResult{ResultSummary: result.GetSummary(), FinishedAt: timePointer(lifecycle.currentTime())}
	auditResult := "success"
	switch result.GetState() {
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED:
		target.Status = TargetSucceeded
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED:
		target.Status, target.ErrorSummary, auditResult = TargetFailed, result.GetErrorCode(), "failure"
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED:
		target.Status, auditResult = TargetCancelled, "failure"
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT:
		target.Status, auditResult = TargetTimedOut, "failure"
	default:
		lifecycle.onError(ErrInvalidCommandPayload)
		return
	}
	for _, reference := range result.GetArtifacts() {
		if reference == nil || strings.TrimSpace(reference.GetArtifactId()) == "" || strings.TrimSpace(reference.GetKind()) == "" {
			lifecycle.onError(ErrInvalidCommandPayload)
			return
		}
		target.Artifacts = append(target.Artifacts, ArtifactReference{ArtifactID: reference.GetArtifactId(), Kind: reference.GetKind()})
	}
	lifecycle.observe(ctx, agentID, result.GetCommandId(), "command.result", auditResult, target, map[string]any{"state": result.GetState().String(), "artifact_count": len(target.Artifacts)})
}

func (lifecycle *CommandLifecycle) observe(ctx context.Context, agentID, commandID, action, result string, target TargetResult, detail map[string]any) {
	message, err := lifecycle.dispatchRepository.LookupCommand(ctx, commandID)
	if err != nil {
		lifecycle.onError(err)
		return
	}
	envelope, err := decodeUnsignedCommand(message)
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
	value, mutated, err := lifecycle.applyTarget(ctx, message, target)
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

func (lifecycle *CommandLifecycle) applyTarget(ctx context.Context, message OutboxMessage, target TargetResult) (Job, bool, error) {
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
			_, err = lifecycle.jobs.Transition(ctx, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusDispatched, At: lifecycle.currentTime()})
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
				final, finalMutated, finalErr := lifecycle.finalize(ctx, current)
				return final, mutated || finalMutated, finalErr
			}
			return current, mutated, nil
		}
		if found && existing.Status == TargetRunning && target.Status == TargetRunning {
			return current, mutated, nil
		}
		if current.Status != StatusDispatched && current.Status != StatusRunning {
			return Job{}, mutated, ErrInvalidTransition
		}
		next, err := lifecycle.jobs.Transition(ctx, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{target}, At: lifecycle.currentTime()})
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
		final, _, finalErr := lifecycle.finalize(ctx, next)
		return final, true, finalErr
	}
	return Job{}, mutated, ErrConflict
}

func (lifecycle *CommandLifecycle) finalize(ctx context.Context, candidate Job) (Job, bool, error) {
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
		}
		next, err := lifecycle.jobs.Transition(ctx, Transition{
			Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: to,
			Artifacts: collectArtifacts(current.TargetResults), ResultSummary: "Agent commands completed", At: lifecycle.currentTime(),
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
	_, err := lifecycle.audit.Record(ctx, audit.Event{
		Scope: message.Scope, OccurredAt: lifecycle.currentTime(), Action: action,
		Actor: audit.Actor{Type: "system", ID: "agent-control"}, Resource: audit.Resource{Type: "job_target", ID: message.TargetID},
		Result: result, RequestID: value.RequestID, TraceID: value.TraceID, JobID: message.JobID, CommandID: message.ID, Detail: detail,
	})
	return err
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
