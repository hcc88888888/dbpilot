package credentiallease

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuditRecordContainsOnlyIdentifiersRevisionsAndResult(t *testing.T) {
	credentialRef := "secret://database/instance-1"
	record := AuditRecord{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1", AssignmentID: "assignment-1", InstanceID: "instance-1", ConfigurationRevision: 5, OperationRevision: 7, InstanceRevision: 9, CredentialRefHash: CredentialRefAuditHash(credentialRef), CredentialRevision: 11, LeaseIDHash: LeaseIDAuditHash("lease-1"), Result: AuditResultIssued, ExpiryClass: ExpiryClassShort, OccurredAt: time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)}
	require.NoError(t, record.Validate())
	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), credentialRef)
	require.NotContains(t, string(encoded), "secret")
	require.NotContains(t, string(encoded), "username")
	require.NotContains(t, string(encoded), "lease-1")
	require.Contains(t, string(encoded), record.CredentialRefHash)
	require.NotEqual(t, LeaseIDAuditHash(credentialRef), record.CredentialRefHash, "credential references require a separate hash domain")
	require.Equal(t, LeaseIDAuditHash("lease-1"), LeaseIDAuditHash("lease-1"))
}

func TestIssuedAuditRequiresCredentialReferenceHash(t *testing.T) {
	record := AuditRecord{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1", AssignmentID: "assignment-1", InstanceID: "instance-1", ConfigurationRevision: 5, OperationRevision: 7, InstanceRevision: 9, CredentialRevision: 11, LeaseIDHash: LeaseIDAuditHash("lease-1"), Result: AuditResultIssued, ExpiryClass: ExpiryClassShort, OccurredAt: time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)}
	require.ErrorIs(t, record.Validate(), ErrLeaseRejected)
}
