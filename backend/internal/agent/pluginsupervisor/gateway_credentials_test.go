package pluginsupervisor

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLeaseInstancesUsesExactFencesAndReleasesSecretBuffers(t *testing.T) {
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	leaser := &recordingCredentialLeaser{lease: CredentialLease{LeaseID: "lease-1", AssignmentID: "assignment-1", InstanceID: "instance-1", DatabaseFamily: "mysql", CredentialRevision: 9, ConfigurationRevision: 5, OperationRevision: 7, ExpiresAt: now.Add(time.Minute), Username: "monitor", SecretBytes: []byte("fixture-password")}}
	request := HealthRequest{AssignmentID: "assignment-1", DatabaseFamily: "mysql", ConfigurationRevision: 5, OperationRevision: 7, InstanceIDs: []string{"instance-1"}, InstanceDescriptors: []InstanceDescriptor{{InstanceID: "instance-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306"}}}
	instances, releases, err := leaseInstances(context.Background(), leaser, request, now)
	require.NoError(t, err)
	require.Equal(t, CredentialLeaseRequest{AssignmentID: "assignment-1", InstanceID: "instance-1", DatabaseFamily: "mysql", ConfigurationRevision: 5, OperationRevision: 7}, leaser.request)
	require.Equal(t, []byte("fixture-password"), instances[0].GetCredentialLease().GetSecretBytes())
	retained := leaser.returned.SecretBytes
	for _, release := range releases {
		release()
	}
	require.Equal(t, make([]byte, len(retained)), retained)
}

type recordingCredentialLeaser struct {
	request  CredentialLeaseRequest
	lease    CredentialLease
	returned *CredentialLease
}

func (value *recordingCredentialLeaser) LeaseCredential(_ context.Context, request CredentialLeaseRequest) (CredentialLease, error) {
	value.request = request
	lease := value.lease.Clone()
	value.returned = &lease
	return lease, nil
}
