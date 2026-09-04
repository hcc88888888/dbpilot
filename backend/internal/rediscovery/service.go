// Package rediscovery schedules manual host database discovery through the
// existing durable Agent command and discovery-report paths.
package rediscovery

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	discoverydomain "dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"google.golang.org/protobuf/proto"
)

const (
	rediscoveryLease   = 2 * time.Minute
	rediscoveryTimeout = 5 * time.Minute
)

var (
	ErrInvalid                = errors.New("invalid host rediscovery request")
	ErrHostNotOnline          = errors.New("host is not online")
	ErrRediscoveryUnavailable = errors.New("host rediscovery is unavailable")
	identifierPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	fingerprintPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type HostReader interface {
	Get(context.Context, platformscope.Scope, string) (hostinventory.Host, error)
}

type JobStore interface {
	CreateWithOutbox(context.Context, job.Job, []job.OutboxMessage) error
	Get(context.Context, platformscope.Scope, string) (job.Job, error)
	GetOperation(context.Context, platformscope.Scope, string, string) (job.Job, job.OutboxMessage, error)
}

type CapabilitySource interface {
	Supports(string, ...string) bool
}

type RediscoveryRequest struct {
	Actor              string
	IdempotencyKey     string
	RequestFingerprint string
	RequestID          string
	TraceID            string
}

func (request RediscoveryRequest) valid() bool {
	return boundedText(request.Actor, 256) && boundedText(request.IdempotencyKey, 128) && fingerprintPattern.MatchString(request.RequestFingerprint) && boundedText(request.RequestID, 256) && boundedText(request.TraceID, 256)
}

type RediscoveryCoordinator struct {
	Hosts        HostReader
	Jobs         JobStore
	Capabilities CapabilitySource
	Policies     []discoverydomain.RuleAttestation
	RuleKeys     map[string]ed25519.PublicKey
	Now          func() time.Time
}

func (service *RediscoveryCoordinator) Start(ctx context.Context, scope platformscope.Scope, hostID string, request RediscoveryRequest) (job.Job, error) {
	if service == nil || ctx == nil || service.Jobs == nil || scope.Validate() != nil || !identifierPattern.MatchString(hostID) || !request.valid() {
		return job.Job{}, ErrInvalid
	}
	jobID, commandID, _ := rediscoveryOperationIdentity(scope, hostID, request)
	if stored, found, err := service.resolveImmutableOperation(ctx, scope, hostID, jobID, commandID, request); err != nil {
		return job.Job{}, err
	} else if found {
		return stored, nil
	}
	if service.Hosts == nil || service.Capabilities == nil {
		return job.Job{}, ErrRediscoveryUnavailable
	}
	now := time.Now().UTC()
	if service.Now != nil {
		now = service.Now()
	}
	if now.IsZero() || now.Location() != time.UTC {
		return job.Job{}, ErrInvalid
	}
	host, err := service.Hosts.Get(ctx, scope, hostID)
	if err != nil {
		return job.Job{}, err
	}
	if host.Validate() != nil || host.Scope != scope || host.ID != hostID {
		return job.Job{}, ErrInvalid
	}
	if host.Status != hostinventory.HostOnline {
		return job.Job{}, ErrHostNotOnline
	}
	policy, err := service.currentPolicy(now)
	if err != nil {
		return job.Job{}, err
	}
	includeNative := hostCapability(host, "native_discovery_v1") && service.Capabilities.Supports(host.AgentID, "discover_databases", "native_discovery_v1", "discovery_policy_attestation_v1", "discovery_report_ack_v1")
	includeDocker := hostCapability(host, "docker_discovery_v1") && service.Capabilities.Supports(host.AgentID, "discover_databases", "docker_discovery_v1", "discovery_source_results_v1", "discovery_policy_attestation_v1", "discovery_report_ack_v1")
	if !includeNative && !includeDocker {
		return job.Job{}, ErrRediscoveryUnavailable
	}
	value, message, err := buildRediscoveryJob(host, policy.Revision, includeNative, includeDocker, request, now)
	if err != nil {
		return job.Job{}, err
	}
	if err := service.Jobs.CreateWithOutbox(ctx, value, []job.OutboxMessage{message}); err != nil {
		stored, found, resolveErr := service.resolveImmutableOperation(ctx, scope, hostID, value.ID, message.ID, request)
		if resolveErr == nil && found {
			return stored, nil
		}
		if resolveErr != nil && !errors.Is(resolveErr, job.ErrNotFound) {
			return job.Job{}, resolveErr
		}
		return job.Job{}, err
	}
	return value, nil
}

func (service *RediscoveryCoordinator) resolveImmutableOperation(ctx context.Context, scope platformscope.Scope, hostID, jobID, commandID string, request RediscoveryRequest) (job.Job, bool, error) {
	value, message, err := service.Jobs.GetOperation(ctx, scope, jobID, commandID)
	if errors.Is(err, job.ErrNotFound) {
		return job.Job{}, false, nil
	}
	if errors.Is(err, job.ErrConflict) {
		return job.Job{}, false, ErrRediscoveryUnavailable
	}
	if err != nil {
		return job.Job{}, false, err
	}
	if !sameRediscoveryOperation(value, message, scope, hostID, jobID, commandID, request) {
		return job.Job{}, false, ErrRediscoveryUnavailable
	}
	return value, true, nil
}

func (service *RediscoveryCoordinator) currentPolicy(now time.Time) (discoverydomain.RuleAttestation, error) {
	var current discoverydomain.RuleAttestation
	for _, candidate := range service.Policies {
		key := service.RuleKeys[candidate.KeyID]
		if candidate.Version != discoverydomain.RuleAttestationVersion || candidate.Algorithm != discoverydomain.RuleAttestationAlgorithm || candidate.Revision == 0 || candidate.Digest == ([sha256.Size]byte{}) || len(key) != ed25519.PublicKeySize || candidate.IssuedAt.Location() != time.UTC || candidate.ExpiresAt.Location() != time.UTC || now.Before(candidate.IssuedAt) || !candidate.ExpiresAt.After(now) || candidate.DisappearanceGrace < time.Minute || candidate.DisappearanceGrace > 24*time.Hour {
			continue
		}
		if candidate.Revision > current.Revision {
			current = candidate
			continue
		}
		if candidate.Revision == current.Revision && current.Revision != 0 && (candidate.KeyID != current.KeyID || candidate.Digest != current.Digest) {
			return discoverydomain.RuleAttestation{}, ErrRediscoveryUnavailable
		}
	}
	if current.Revision == 0 {
		return discoverydomain.RuleAttestation{}, ErrRediscoveryUnavailable
	}
	return current, nil
}

func buildRediscoveryJob(host hostinventory.Host, ruleRevision uint64, includeNative, includeDocker bool, request RediscoveryRequest, at time.Time) (job.Job, job.OutboxMessage, error) {
	if host.Validate() != nil || host.Status != hostinventory.HostOnline || ruleRevision == 0 || (!includeNative && !includeDocker) || !request.valid() || at.IsZero() || at.Location() != time.UTC {
		return job.Job{}, job.OutboxMessage{}, ErrInvalid
	}
	jobID, commandID, suffix := rediscoveryOperationIdentity(host.Scope, host.ID, request)
	envelope := &agentv1.CommandEnvelope{AgentId: host.AgentID, LeaseSeconds: uint32(rediscoveryLease / time.Second), Command: &agentv1.CommandEnvelope_DiscoverDatabases{DiscoverDatabases: &agentv1.DiscoverDatabases{HostId: host.ID, RuleRevision: ruleRevision, IncludeNative: includeNative, IncludeDocker: includeDocker}}}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		return job.Job{}, job.OutboxMessage{}, ErrInvalid
	}
	timeout := at.Add(rediscoveryTimeout)
	value := job.Job{ID: jobID, Type: "host.rediscover", Scope: host.Scope, Status: job.StatusQueued, Outcome: job.OutcomeNone, TargetResourceIDs: []string{host.AgentID}, InitiatedBy: request.Actor, SourceResource: job.ResourceReference{ResourceType: "host", ResourceID: host.ID}, IdempotencyKey: "host-rediscover-" + suffix, Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: at, TimeoutAt: &timeout, MaxConcurrency: 1, TargetTimeout: rediscoveryLease, RequestID: request.RequestID, TraceID: request.TraceID}
	message := job.OutboxMessage{ID: commandID, Scope: host.Scope, JobID: jobID, TargetID: host.AgentID, Type: "agent.command", Payload: payload, AvailableAt: at, CreatedAt: at}
	return value, message, nil
}

func rediscoveryOperationIdentity(scope platformscope.Scope, hostID string, request RediscoveryRequest) (string, string, string) {
	identity := scope.Key() + "\x00" + hostID + "\x00" + request.Actor + "\x00" + request.IdempotencyKey + "\x00" + request.RequestFingerprint
	digest := sha256.Sum256([]byte(identity))
	suffix := hex.EncodeToString(digest[:16])
	return "job-host-rediscover-" + suffix, "command-host-rediscover-" + suffix, suffix
}

func sameRediscoveryOperation(value job.Job, message job.OutboxMessage, scope platformscope.Scope, hostID, jobID, commandID string, request RediscoveryRequest) bool {
	if value.ID != jobID || value.Type != "host.rediscover" || value.Scope != scope || value.InitiatedBy != request.Actor || value.SourceResource != (job.ResourceReference{ResourceType: "host", ResourceID: hostID}) || value.IdempotencyKey != "host-rediscover-"+strings.TrimPrefix(jobID, "job-host-rediscover-") || value.Version < 1 || value.RequestID != request.RequestID || value.TraceID != request.TraceID || len(value.TargetResourceIDs) != 1 ||
		message.ID != commandID || message.Scope != scope || message.JobID != jobID || message.TargetID != value.TargetResourceIDs[0] || message.Type != "agent.command" {
		return false
	}
	envelope := new(agentv1.CommandEnvelope)
	if proto.Unmarshal(message.Payload, envelope) != nil || envelope.GetAgentId() != message.TargetID {
		return false
	}
	command := envelope.GetDiscoverDatabases()
	return command != nil && command.GetHostId() == hostID && command.GetRuleRevision() > 0 && (command.GetIncludeNative() || command.GetIncludeDocker())
}

func boundedText(value string, maximum int) bool {
	return value != "" && value == strings.TrimSpace(value) && utf8.ValidString(value) && utf8.RuneCountInString(value) <= maximum && len(value) <= maximum*4 && !strings.ContainsAny(value, "\r\n\t")
}

func hostCapability(host hostinventory.Host, name string) bool {
	for _, capability := range host.Capabilities {
		if capability.Name == name {
			return capability.Available
		}
	}
	return false
}
