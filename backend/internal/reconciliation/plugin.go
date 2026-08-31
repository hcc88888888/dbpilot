package reconciliation

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/pluginassignment"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultClaimLease                          = 45 * time.Second
	PluginExecutionLeaseSeconds         uint32 = 900
	PluginJobTimeout                           = 20 * time.Minute
	PluginReconcileCapability                  = "plugin.reconcile.v1"
	PluginInstanceDescriptorsCapability        = "plugin_reconcile.instance_descriptors.v1"
	PluginCapabilityWaitingReason              = "instance_descriptors_capability_unavailable"
)

type AssignmentRepository interface {
	ClaimDue(context.Context, time.Time, int, time.Duration) ([]pluginassignment.ReconcileClaim, error)
	ClaimOne(context.Context, pluginassignment.Assignment, time.Time, time.Duration) (pluginassignment.ReconcileClaim, error)
	MarkConverged(context.Context, pluginassignment.ReconcileClaim) error
	MarkConflict(context.Context, pluginassignment.ReconcileClaim) error
	MarkWaiting(context.Context, pluginassignment.ReconcileClaim, string) error
	Schedule(context.Context, pluginassignment.ReconcileClaim, job.Job, job.OutboxMessage) (job.Job, bool, error)
	FindScheduledJob(context.Context, pluginassignment.Assignment) (job.Job, bool, error)
}

// InstanceDescriptorLoader supplies the current non-secret Task6 routing
// facts at scheduling time; Assignment deliberately stores only membership.
type InstanceDescriptorLoader interface {
	LoadPluginInstanceDescriptors(context.Context, pluginassignment.Assignment) ([]*agentv1.PluginInstanceDescriptor, error)
}

func (reconciler *PluginReconciler) ReconcileAssignment(ctx context.Context, assignment pluginassignment.Assignment, at time.Time) (job.Job, error) {
	if reconciler == nil || reconciler.repository == nil || ctx == nil || assignment.Validate() != nil || at.IsZero() {
		return job.Job{}, pluginassignment.ErrInvalid
	}
	if stored, found, err := reconciler.repository.FindScheduledJob(ctx, assignment); err != nil {
		return job.Job{}, err
	} else if found {
		return stored, nil
	}
	claim, err := reconciler.repository.ClaimOne(ctx, assignment, at.UTC(), DefaultClaimLease)
	if err != nil {
		return job.Job{}, err
	}
	if claim.Assignment.HasObservedRevisionConflict() {
		if err := reconciler.repository.MarkConflict(ctx, claim); err != nil {
			return job.Job{}, err
		}
		return job.Job{}, pluginassignment.ErrConflict
	}
	if !rolloutEligible(claim.Assignment) {
		if err := reconciler.repository.MarkWaiting(ctx, claim, "rollout_pending"); err != nil {
			return job.Job{}, err
		}
		return job.Job{}, pluginassignment.ErrConflict
	}
	if !claim.Assignment.NeedsReconcile() {
		if err := reconciler.repository.MarkConverged(ctx, claim); err != nil {
			return job.Job{}, err
		}
		return job.Job{}, pluginassignment.ErrConflict
	}
	if !reconciler.supportsDescriptorReconcile(claim.Assignment.AgentID) {
		if err := reconciler.repository.MarkWaiting(ctx, claim, PluginCapabilityWaitingReason); err != nil {
			return job.Job{}, err
		}
		return job.Job{}, pluginassignment.ErrConflict
	}
	descriptors, err := reconciler.loadDescriptors(ctx, claim.Assignment)
	if err != nil {
		return job.Job{}, err
	}
	value, message, err := buildPluginJobWithDescriptors(claim.Assignment, descriptors, at.UTC())
	if err != nil {
		return job.Job{}, err
	}
	stored, _, err := reconciler.repository.Schedule(ctx, claim, value, message)
	if err != nil {
		return job.Job{}, err
	}
	return stored, nil
}

type ReconcileResult struct{ Claimed, Enqueued, Converged, Blocked, Waiting int }

type Reconciler interface {
	Reconcile(context.Context, time.Time, int) (ReconcileResult, error)
}

type PluginReconciler struct {
	repository   AssignmentRepository
	descriptors  InstanceDescriptorLoader
	capabilities AgentCapabilitySource
}

type AgentCapabilitySource interface {
	Supports(string, ...string) bool
}

func NewPluginReconciler(repository AssignmentRepository, sources ...AgentCapabilitySource) *PluginReconciler {
	loader, _ := repository.(InstanceDescriptorLoader)
	var source AgentCapabilitySource
	if len(sources) > 0 {
		source = sources[0]
	}
	return &PluginReconciler{repository: repository, descriptors: loader, capabilities: source}
}

func (reconciler *PluginReconciler) FindScheduledJob(ctx context.Context, assignment pluginassignment.Assignment) (job.Job, bool, error) {
	if reconciler == nil || reconciler.repository == nil {
		return job.Job{}, false, pluginassignment.ErrInvalid
	}
	return reconciler.repository.FindScheduledJob(ctx, assignment)
}

func (reconciler *PluginReconciler) Reconcile(ctx context.Context, at time.Time, limit int) (ReconcileResult, error) {
	if reconciler == nil || reconciler.repository == nil || ctx == nil || at.IsZero() || limit < 1 || limit > 100 {
		return ReconcileResult{}, pluginassignment.ErrInvalid
	}
	claims, err := reconciler.repository.ClaimDue(ctx, at.UTC(), limit, DefaultClaimLease)
	if err != nil {
		return ReconcileResult{}, err
	}
	result := ReconcileResult{Claimed: len(claims)}
	var failures []error
	for _, claim := range claims {
		if claim.Validate() != nil {
			failures = append(failures, pluginassignment.ErrInvalid)
			continue
		}
		if claim.Assignment.HasObservedRevisionConflict() {
			if err := reconciler.repository.MarkConflict(ctx, claim); err != nil {
				failures = append(failures, err)
			}
			continue
		}
		if !rolloutEligible(claim.Assignment) {
			if err := reconciler.repository.MarkWaiting(ctx, claim, "rollout_pending"); err != nil {
				failures = append(failures, err)
			} else {
				result.Waiting++
			}
			continue
		}
		if !claim.Assignment.NeedsReconcile() {
			if err := reconciler.repository.MarkConverged(ctx, claim); err != nil {
				failures = append(failures, err)
			} else {
				result.Converged++
			}
			continue
		}
		if !reconciler.supportsDescriptorReconcile(claim.Assignment.AgentID) {
			if err := reconciler.repository.MarkWaiting(ctx, claim, PluginCapabilityWaitingReason); err != nil {
				failures = append(failures, err)
			} else {
				result.Waiting++
			}
			continue
		}
		descriptors, err := reconciler.loadDescriptors(ctx, claim.Assignment)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		value, message, err := buildPluginJobWithDescriptors(claim.Assignment, descriptors, at.UTC())
		if err != nil {
			failures = append(failures, err)
			continue
		}
		_, created, err := reconciler.repository.Schedule(ctx, claim, value, message)
		if errors.Is(err, pluginassignment.ErrVersionRevoked) {
			result.Blocked++
			continue
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if created {
			result.Enqueued++
		}
	}
	return result, errors.Join(failures...)
}

func (reconciler *PluginReconciler) supportsDescriptorReconcile(agentID string) bool {
	return reconciler.capabilities == nil || reconciler.capabilities.Supports(agentID, PluginReconcileCapability, PluginInstanceDescriptorsCapability)
}

func rolloutEligible(value pluginassignment.Assignment) bool {
	if value.DesiredState == pluginassignment.DesiredStopped || value.DesiredState == pluginassignment.DesiredAbsent || value.RolloutPercentage >= 100 {
		return true
	}
	digest := sha256.Sum256([]byte(value.Scope.Key() + "\x00" + value.ID))
	bucket := int(binary.BigEndian.Uint16(digest[:2])%100) + 1
	return bucket <= value.RolloutPercentage
}

func buildPluginJob(assignment pluginassignment.Assignment, at time.Time) (job.Job, job.OutboxMessage, error) {
	return buildPluginJobWithDescriptors(assignment, nil, at)
}

func (reconciler *PluginReconciler) loadDescriptors(ctx context.Context, assignment pluginassignment.Assignment) ([]*agentv1.PluginInstanceDescriptor, error) {
	if reconciler == nil || reconciler.descriptors == nil {
		return nil, pluginassignment.ErrInvalid
	}
	values, err := reconciler.descriptors.LoadPluginInstanceDescriptors(ctx, assignment)
	if err != nil || validateDescriptors(assignment, values) != nil {
		return nil, pluginassignment.ErrInvalid
	}
	sort.Slice(values, func(left, right int) bool { return values[left].GetInstanceId() < values[right].GetInstanceId() })
	return values, nil
}

func buildPluginJobWithDescriptors(assignment pluginassignment.Assignment, descriptors []*agentv1.PluginInstanceDescriptor, at time.Time) (job.Job, job.OutboxMessage, error) {
	if assignment.Validate() != nil || at.IsZero() || !assignment.NeedsReconcile() {
		return job.Job{}, job.OutboxMessage{}, pluginassignment.ErrInvalid
	}
	if len(descriptors) != 0 && validateDescriptors(assignment, descriptors) != nil {
		return job.Job{}, job.OutboxMessage{}, pluginassignment.ErrInvalid
	}
	artifactDigest, err := hex.DecodeString(assignment.ArtifactSHA256)
	if err != nil || len(artifactDigest) != 32 {
		return job.Job{}, job.OutboxMessage{}, pluginassignment.ErrInvalid
	}
	manifestDigest, err := hex.DecodeString(assignment.ManifestDigest)
	if err != nil || len(manifestDigest) != 32 {
		return job.Job{}, job.OutboxMessage{}, pluginassignment.ErrInvalid
	}
	state, ok := protoDesiredState(assignment.DesiredState)
	if !ok {
		return job.Job{}, job.OutboxMessage{}, pluginassignment.ErrInvalid
	}
	command := &agentv1.CommandEnvelope{AgentId: assignment.AgentID, LeaseSeconds: PluginExecutionLeaseSeconds, Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{AssignmentId: assignment.ID, PluginId: assignment.PluginID, DatabaseFamily: assignment.DatabaseFamily, DesiredVersion: assignment.DesiredVersion, DesiredState: state, ArtifactId: assignment.ArtifactID, ArtifactSha256: artifactDigest, ManifestDigest: manifestDigest, ConfigurationRevision: assignment.ConfigurationRevision, OperationRevision: assignment.OperationRevision, InstanceIds: append([]string(nil), assignment.InstanceIDs...), TemplateIds: append([]string(nil), assignment.TemplateRevisionIDs...), InstanceDescriptors: cloneDescriptors(descriptors)}}}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return job.Job{}, job.OutboxMessage{}, fmt.Errorf("marshal ReconcilePlugin: %w", err)
	}
	identity := fmt.Sprintf("%s:%d:%d", assignment.ID, assignment.ConfigurationRevision, assignment.OperationRevision)
	jobID := pluginassignment.DeterministicID("job-plugin-", assignment.Scope.Key(), identity)
	commandID := pluginassignment.DeterministicID("command-plugin-", assignment.Scope.Key(), identity)
	timeout := at.UTC().Add(PluginJobTimeout)
	value := job.Job{ID: jobID, Type: "plugin.reconcile", Scope: assignment.Scope, Status: job.StatusQueued, Outcome: job.OutcomeNone, TargetResourceIDs: []string{assignment.AgentID}, InitiatedBy: "plugin-reconciler", SourceResource: job.ResourceReference{ResourceType: "plugin_assignment", ResourceID: assignment.ID}, IdempotencyKey: "plugin-reconcile:" + identity, Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: at.UTC(), TimeoutAt: &timeout, MaxConcurrency: 1, TargetTimeout: PluginJobTimeout - time.Minute, RequestID: "plugin-reconcile-" + assignment.ID, TraceID: pluginassignment.DeterministicID("trace-", assignment.Scope.Key(), identity)}
	message := job.OutboxMessage{ID: commandID, Scope: assignment.Scope, JobID: jobID, TargetID: assignment.AgentID, Type: "agent.command", Payload: payload, AvailableAt: at.UTC(), CreatedAt: at.UTC()}
	return value, message, nil
}

func validateDescriptors(assignment pluginassignment.Assignment, values []*agentv1.PluginInstanceDescriptor) error {
	if len(values) != len(assignment.InstanceIDs) || len(values) > 128 {
		return pluginassignment.ErrInvalid
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == nil || !containsAssignmentID(assignment.InstanceIDs, value.GetInstanceId()) || value.GetDatabaseVariant() == "" || len(value.GetDatabaseVariant()) > 128 || (value.GetEndpoint() == "") == (value.GetUnixSocket() == "") || len(value.GetEndpoint()) > 512 || len(value.GetUnixSocket()) > 512 {
			return pluginassignment.ErrInvalid
		}
		if _, duplicate := seen[value.GetInstanceId()]; duplicate {
			return pluginassignment.ErrInvalid
		}
		seen[value.GetInstanceId()] = struct{}{}
	}
	return nil
}

func containsAssignmentID(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func cloneDescriptors(values []*agentv1.PluginInstanceDescriptor) []*agentv1.PluginInstanceDescriptor {
	result := make([]*agentv1.PluginInstanceDescriptor, len(values))
	for index := range values {
		result[index] = &agentv1.PluginInstanceDescriptor{InstanceId: values[index].GetInstanceId(), DatabaseVariant: values[index].GetDatabaseVariant(), Endpoint: values[index].GetEndpoint(), UnixSocket: values[index].GetUnixSocket()}
	}
	return result
}

func protoDesiredState(value pluginassignment.DesiredState) (agentv1.PluginDesiredState, bool) {
	switch value {
	case pluginassignment.DesiredAbsent:
		return agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_ABSENT, true
	case pluginassignment.DesiredInstalled:
		return agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_INSTALLED, true
	case pluginassignment.DesiredRunning:
		return agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_RUNNING, true
	case pluginassignment.DesiredStopped:
		return agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_STOPPED, true
	default:
		return agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_UNSPECIFIED, false
	}
}

var _ Reconciler = (*PluginReconciler)(nil)
