package credentiallease

import (
	"context"
	"time"
)

type AuditResult string
type ExpiryClass string

const (
	AuditResultIssued   AuditResult = "issued"
	AuditResultRejected AuditResult = "rejected"
	ExpiryClassShort    ExpiryClass = "short"
)

type AuditRecord struct {
	TenantID              string      `json:"tenant_id"`
	ProjectID             string      `json:"project_id"`
	AgentID               string      `json:"agent_id"`
	HostID                string      `json:"host_id"`
	AssignmentID          string      `json:"assignment_id"`
	InstanceID            string      `json:"instance_id"`
	ConfigurationRevision uint64      `json:"configuration_revision"`
	OperationRevision     uint64      `json:"operation_revision"`
	InstanceRevision      uint64      `json:"instance_revision"`
	CredentialRevision    uint64      `json:"credential_revision,omitempty"`
	Result                AuditResult `json:"result"`
	ExpiryClass           ExpiryClass `json:"expiry_class"`
	OccurredAt            time.Time   `json:"occurred_at"`
}

func (value AuditRecord) Validate() error {
	if !identifier.MatchString(value.TenantID) || !identifier.MatchString(value.ProjectID) || !identifier.MatchString(value.AgentID) || !identifier.MatchString(value.HostID) || !identifier.MatchString(value.AssignmentID) || !identifier.MatchString(value.InstanceID) || value.ConfigurationRevision == 0 || value.OperationRevision == 0 || value.InstanceRevision == 0 || value.Result != AuditResultIssued && value.Result != AuditResultRejected || value.ExpiryClass != ExpiryClassShort || value.OccurredAt.IsZero() || value.OccurredAt.Location() != time.UTC {
		return ErrLeaseRejected
	}
	if value.Result == AuditResultIssued && value.CredentialRevision == 0 {
		return ErrLeaseRejected
	}
	return nil
}

type AuditRecorder interface {
	Record(context.Context, AuditRecord) error
}
