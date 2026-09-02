package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/commandvalidation"
	"google.golang.org/protobuf/proto"
)

var (
	ErrInvalidCommandEnvelope       = errors.New("command envelope is invalid")
	ErrInvalidCommandSignature      = errors.New("command signature is invalid")
	ErrCommandExpired               = errors.New("command has expired")
	ErrCommandAgentMismatch         = errors.New("command Agent ID does not match this Agent")
	ErrCommandCapabilityUnavailable = errors.New("command capability is not advertised")
	ErrCommandNonceReplay           = errors.New("command nonce was already used")
	ErrCommandTargetUnauthorized    = errors.New("command target is not authorized for this Agent")
)

type CommandKind string

const (
	CommandKindCollectNow               CommandKind = "collect_now"
	CommandKindInspectInstance          CommandKind = "inspect_instance"
	CommandKindExecuteSQL               CommandKind = "execute_sql"
	CommandKindExecuteRegisteredProcess CommandKind = "execute_registered_process"
	CommandKindCollectDiagnostic        CommandKind = "collect_diagnostic"
	CommandKindDiscoverDatabases        CommandKind = "discover_databases"
	CommandKindReconcilePlugin          CommandKind = "plugin.reconcile.v1"
	CommandKindCollectDatabaseMetrics   CommandKind = "plugin.metrics.collect.v1"
)

type nonceRecord struct {
	commandID string
	expiresAt time.Time
}

type CommandVerifier struct {
	agentID          string
	publicKey        ed25519.PublicKey
	capabilities     map[CommandKind]struct{}
	now              func() time.Time
	mu               sync.Mutex
	nonces           map[string]nonceRecord
	targetAuthorizer commandvalidation.TargetAuthorizer
}

func (v *CommandVerifier) SetTargetAuthorizer(authorizer commandvalidation.TargetAuthorizer) {
	v.mu.Lock()
	v.targetAuthorizer = authorizer
	v.mu.Unlock()
}

func NewCommandVerifier(agentID string, publicKey ed25519.PublicKey, capabilities []string) (*CommandVerifier, error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, errors.New("command verifier Agent ID is required")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("command verifier requires an Ed25519 public key")
	}
	allowed := make(map[CommandKind]struct{}, len(capabilities))
	for _, raw := range capabilities {
		kind := CommandKind(raw)
		if !knownCommandKind(kind) {
			if knownMetadataCapability(raw) {
				continue
			}
			return nil, fmt.Errorf("unknown command capability %q", raw)
		}
		allowed[kind] = struct{}{}
	}
	return &CommandVerifier{agentID: agentID, publicKey: append(ed25519.PublicKey(nil), publicKey...), capabilities: allowed, now: time.Now, nonces: make(map[string]nonceRecord)}, nil
}

func knownMetadataCapability(value string) bool {
	switch value {
	case CapabilityCollectNowDependenciesV1, CapabilityCollectNowHostV1, PluginReconcileInstanceDescriptorsCapability,
		"metric_template_lease.v1", CapabilityDiscoverySourceResultsV1, CapabilityDiscoverySourceResultsPendingLegacyV1,
		"docker_discovery_v1", "native_discovery_v1", "docker_discovery_configured", "docker_discovery_unavailable":
		return true
	default:
		return false
	}
}

func (v *CommandVerifier) Verify(ctx context.Context, envelope *agentv1.CommandEnvelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if envelope == nil || strings.TrimSpace(envelope.GetCommandId()) == "" || envelope.GetCommand() == nil || envelope.GetLeaseSeconds() == 0 || envelope.GetLeaseSeconds() > commandvalidation.MaximumTimeoutSeconds || len(envelope.GetNonce()) == 0 || envelope.GetIssuedAt() == nil || !envelope.GetIssuedAt().IsValid() || envelope.GetExpiresAt() == nil || !envelope.GetExpiresAt().IsValid() {
		return ErrInvalidCommandEnvelope
	}
	if subtle.ConstantTimeCompare([]byte(v.agentID), []byte(envelope.GetAgentId())) != 1 {
		return ErrCommandAgentMismatch
	}
	now := v.now()
	issuedAt := envelope.GetIssuedAt().AsTime()
	expiresAt := envelope.GetExpiresAt().AsTime()
	if !expiresAt.After(now) || !expiresAt.After(issuedAt) {
		return ErrCommandExpired
	}
	if issuedAt.After(now.Add(5 * time.Minute)) {
		return ErrInvalidCommandEnvelope
	}
	kind, ok := envelopeCommandKind(envelope)
	if !ok {
		return ErrInvalidCommandEnvelope
	}
	if _, allowed := v.capabilities[kind]; !allowed {
		return fmt.Errorf("%w: %s", ErrCommandCapabilityUnavailable, kind)
	}
	payload, err := CommandSigningBytes(envelope)
	if err != nil {
		return err
	}
	if len(envelope.GetSignature()) != ed25519.SignatureSize || !ed25519.Verify(v.publicKey, payload, envelope.GetSignature()) {
		return ErrInvalidCommandSignature
	}
	v.mu.Lock()
	targetAuthorizer := v.targetAuthorizer
	v.mu.Unlock()
	if reconcile := envelope.GetReconcilePlugin(); reconcile != nil {
		targetAuthorizer = signedPluginMembership{agentID: v.agentID, instanceIDs: append([]string(nil), reconcile.GetInstanceIds()...), delegate: targetAuthorizer}
	}
	if collection := envelope.GetCollectDatabaseMetrics(); collection != nil {
		targetAuthorizer = signedPluginMembership{agentID: v.agentID, instanceIDs: append([]string(nil), collection.GetInstanceIds()...), delegate: targetAuthorizer}
	}
	if err := commandvalidation.Validate(ctx, envelope, targetAuthorizer); err != nil {
		if errors.Is(err, commandvalidation.ErrTargetUnauthorized) {
			return ErrCommandTargetUnauthorized
		}
		return ErrInvalidCommandEnvelope
	}

	nonceKey := string(envelope.GetNonce())
	v.mu.Lock()
	defer v.mu.Unlock()
	for key, seen := range v.nonces {
		if !seen.expiresAt.After(now) {
			delete(v.nonces, key)
		}
	}
	if seen, exists := v.nonces[nonceKey]; exists && seen.commandID != envelope.GetCommandId() {
		return ErrCommandNonceReplay
	}
	v.nonces[nonceKey] = nonceRecord{commandID: envelope.GetCommandId(), expiresAt: expiresAt}
	return nil
}

type signedPluginMembership struct {
	agentID     string
	instanceIDs []string
	delegate    commandvalidation.TargetAuthorizer
}

func (membership signedPluginMembership) AuthorizeTarget(ctx context.Context, agentID, targetID string) error {
	if subtle.ConstantTimeCompare([]byte(membership.agentID), []byte(agentID)) != 1 {
		return ErrCommandTargetUnauthorized
	}
	for _, allowed := range membership.instanceIDs {
		if subtle.ConstantTimeCompare([]byte(allowed), []byte(targetID)) == 1 {
			if membership.delegate != nil {
				return membership.delegate.AuthorizeTarget(ctx, agentID, targetID)
			}
			return nil
		}
	}
	return ErrCommandTargetUnauthorized
}

func CommandSigningBytes(envelope *agentv1.CommandEnvelope) ([]byte, error) {
	if envelope == nil {
		return nil, ErrInvalidCommandEnvelope
	}
	unsigned := proto.Clone(envelope).(*agentv1.CommandEnvelope)
	unsigned.Signature = nil
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("marshal command signing payload: %w", err)
	}
	return encoded, nil
}

func envelopeCommandKind(envelope *agentv1.CommandEnvelope) (CommandKind, bool) {
	if envelope == nil {
		return "", false
	}
	switch envelope.GetCommand().(type) {
	case *agentv1.CommandEnvelope_CollectNow:
		return CommandKindCollectNow, true
	case *agentv1.CommandEnvelope_InspectInstance:
		return CommandKindInspectInstance, true
	case *agentv1.CommandEnvelope_ExecuteSql:
		return CommandKindExecuteSQL, true
	case *agentv1.CommandEnvelope_ExecuteRegisteredProcess:
		return CommandKindExecuteRegisteredProcess, true
	case *agentv1.CommandEnvelope_CollectDiagnostic:
		return CommandKindCollectDiagnostic, true
	case *agentv1.CommandEnvelope_DiscoverDatabases:
		return CommandKindDiscoverDatabases, true
	case *agentv1.CommandEnvelope_ReconcilePlugin:
		return CommandKindReconcilePlugin, true
	case *agentv1.CommandEnvelope_CollectDatabaseMetrics:
		return CommandKindCollectDatabaseMetrics, true
	default:
		return "", false
	}
}

func knownCommandKind(kind CommandKind) bool {
	switch kind {
	case CommandKindCollectNow, CommandKindInspectInstance, CommandKindExecuteSQL, CommandKindExecuteRegisteredProcess, CommandKindCollectDiagnostic, CommandKindDiscoverDatabases, CommandKindReconcilePlugin, CommandKindCollectDatabaseMetrics:
		return true
	default:
		return false
	}
}
