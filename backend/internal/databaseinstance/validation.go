package databaseinstance

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/job"
	"google.golang.org/protobuf/proto"
)

const (
	validationLease   = 30 * time.Second
	validationTimeout = 2 * time.Minute
)

type ValidationTarget struct {
	AssignmentID          string
	ConfigurationRevision uint64
	OperationRevision     uint64
}

func (target ValidationTarget) Validate() error {
	if !identifierPattern.MatchString(target.AssignmentID) || target.ConfigurationRevision == 0 || target.OperationRevision == 0 {
		return ErrInvalid
	}
	return nil
}

type ValidationRequest struct{ Audit MutationAudit }

func (request ValidationRequest) Validate() error {
	if request.Audit.Validate() != nil || request.Audit.OperationID != "testDatabaseInstanceConnection" {
		return ErrInvalid
	}
	return nil
}

func BuildValidationJob(instance Instance, target ValidationTarget, request ValidationRequest, at time.Time) (job.Job, job.OutboxMessage, error) {
	if instance.Validate() != nil || target.Validate() != nil || request.Validate() != nil || at.IsZero() || at.Location() != time.UTC || instance.PluginID == "" || instance.PluginAssignmentRevision != target.ConfigurationRevision || instance.CapabilityState != CapabilityPluginAvailable || instance.ManagementStatus == StatusRetired {
		return job.Job{}, job.OutboxMessage{}, ErrInvalid
	}
	identity := instance.Scope.Key() + "\x00" + instance.ID + "\x00" + request.Audit.Actor + "\x00" + request.Audit.IdempotencyKey + "\x00" + request.Audit.RequestFingerprint
	digest := sha256.Sum256([]byte(identity))
	suffix := hex.EncodeToString(digest[:16])
	jobID, commandID := "job-database-validate-"+suffix, "command-database-validate-"+suffix
	envelope := &agentv1.CommandEnvelope{AgentId: instance.AgentID, LeaseSeconds: uint32(validationLease / time.Second), Command: &agentv1.CommandEnvelope_ValidateDatabaseInstance{ValidateDatabaseInstance: &agentv1.ValidateDatabaseInstance{AssignmentId: target.AssignmentID, InstanceId: instance.ID, ConfigurationRevision: target.ConfigurationRevision}}}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		return job.Job{}, job.OutboxMessage{}, ErrInvalid
	}
	timeout := at.Add(validationTimeout)
	value := job.Job{ID: jobID, Type: "database_instance.validate", Scope: instance.Scope, Status: job.StatusQueued, Outcome: job.OutcomeNone, InstanceID: instance.ID, TargetResourceIDs: []string{instance.AgentID}, InitiatedBy: request.Audit.Actor, SourceResource: job.ResourceReference{ResourceType: "database_instance", ResourceID: instance.ID}, IdempotencyKey: "database-validate-" + suffix, Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: at, TimeoutAt: &timeout, MaxConcurrency: 1, TargetTimeout: validationLease, RequestID: request.Audit.RequestID, TraceID: request.Audit.TraceID}
	message := job.OutboxMessage{ID: commandID, Scope: instance.Scope, JobID: jobID, TargetID: instance.AgentID, Type: "agent.command", Payload: payload, AvailableAt: at, CreatedAt: at}
	return value, message, nil
}
