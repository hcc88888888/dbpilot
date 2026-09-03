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
	"time"

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
	return identifierPattern.MatchString(request.Actor) && identifierPattern.MatchString(request.IdempotencyKey) && fingerprintPattern.MatchString(request.RequestFingerprint) && identifierPattern.MatchString(request.RequestID) && identifierPattern.MatchString(request.TraceID)
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
	if service == nil || ctx == nil || service.Hosts == nil || service.Jobs == nil || service.Capabilities == nil || scope.Validate() != nil || !identifierPattern.MatchString(hostID) || !request.valid() {
		return job.Job{}, ErrInvalid
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
		stored, getErr := service.Jobs.Get(ctx, scope, value.ID)
		if getErr == nil && sameRediscoveryJob(stored, value) {
			return stored, nil
		}
		return job.Job{}, err
	}
	return value, nil
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
	identity := host.Scope.Key() + "\x00" + host.ID + "\x00" + request.Actor + "\x00" + request.IdempotencyKey + "\x00" + request.RequestFingerprint
	digest := sha256.Sum256([]byte(identity))
	suffix := hex.EncodeToString(digest[:16])
	jobID, commandID := "job-host-rediscover-"+suffix, "command-host-rediscover-"+suffix
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

func sameRediscoveryJob(left, right job.Job) bool {
	return left.ID == right.ID && left.Type == right.Type && left.Scope == right.Scope && left.InitiatedBy == right.InitiatedBy && left.SourceResource == right.SourceResource && left.IdempotencyKey == right.IdempotencyKey && len(left.TargetResourceIDs) == 1 && len(right.TargetResourceIDs) == 1 && left.TargetResourceIDs[0] == right.TargetResourceIDs[0]
}

func hostCapability(host hostinventory.Host, name string) bool {
	for _, capability := range host.Capabilities {
		if capability.Name == name {
			return capability.Available
		}
	}
	return false
}
