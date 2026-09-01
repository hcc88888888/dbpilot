package credentiallease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	CredentialRefHash     string      `json:"credential_ref_hash,omitempty"`
	CredentialRevision    uint64      `json:"credential_revision,omitempty"`
	LeaseIDHash           string      `json:"lease_id_hash,omitempty"`
	Result                AuditResult `json:"result"`
	ExpiryClass           ExpiryClass `json:"expiry_class"`
	OccurredAt            time.Time   `json:"occurred_at"`
}

func (value AuditRecord) Validate() error {
	if !identifier.MatchString(value.TenantID) || !identifier.MatchString(value.ProjectID) || !identifier.MatchString(value.AgentID) || !identifier.MatchString(value.HostID) || !identifier.MatchString(value.AssignmentID) || !identifier.MatchString(value.InstanceID) || value.ConfigurationRevision == 0 || value.OperationRevision == 0 || value.InstanceRevision == 0 || value.Result != AuditResultIssued && value.Result != AuditResultRejected || value.ExpiryClass != ExpiryClassShort || value.OccurredAt.IsZero() || value.OccurredAt.Location() != time.UTC {
		return ErrLeaseRejected
	}
	if value.CredentialRefHash != "" && len(value.CredentialRefHash) != len("sha256:")+sha256.Size*2 {
		return ErrLeaseRejected
	}
	if value.Result == AuditResultIssued && (value.CredentialRefHash == "" || value.CredentialRevision == 0 || len(value.LeaseIDHash) != len("sha256:")+sha256.Size*2) {
		return ErrLeaseRejected
	}
	return nil
}

func LeaseIDAuditHash(leaseID string) string {
	digest := sha256.Sum256([]byte("dbpilot-credential-lease-audit-v1\x00" + leaseID))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func CredentialRefAuditHash(reference string) string {
	if reference == "" {
		return ""
	}
	digest := sha256.Sum256([]byte("dbpilot-credential-reference-audit-v1\x00" + reference))
	return "sha256:" + hex.EncodeToString(digest[:])
}

type AuditRecorder interface {
	Record(context.Context, AuditRecord) error
}
