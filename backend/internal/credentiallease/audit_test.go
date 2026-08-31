package credentiallease

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuditRecordContainsOnlyIdentifiersRevisionsAndResult(t *testing.T) {
	record := AuditRecord{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1", AssignmentID: "assignment-1", InstanceID: "instance-1", ConfigurationRevision: 5, OperationRevision: 7, InstanceRevision: 9, CredentialRevision: 11, Result: AuditResultIssued, ExpiryClass: ExpiryClassShort, OccurredAt: time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)}
	require.NoError(t, record.Validate())
	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "credential_ref")
	require.NotContains(t, string(encoded), "secret")
	require.NotContains(t, string(encoded), "username")
}
