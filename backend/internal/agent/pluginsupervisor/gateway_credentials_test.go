package pluginsupervisor

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"github.com/stretchr/testify/require"
)

func TestLeaseInstancesUsesExactFencesAndReleasesSecretBuffers(t *testing.T) {
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	leaser := &recordingCredentialLeaser{lease: CredentialLease{LeaseID: "lease-1", AssignmentID: "assignment-1", InstanceID: "instance-1", DatabaseFamily: "mysql", CredentialRevision: 9, ConfigurationRevision: 5, OperationRevision: 7, ExpiresAt: now.Add(time.Minute), ValidFor: time.Minute, Username: "monitor", SecretBytes: []byte("fixture-password")}}
	request := HealthRequest{AssignmentID: "assignment-1", DatabaseFamily: "mysql", ConfigurationRevision: 5, OperationRevision: 7, InstanceIDs: []string{"instance-1"}, InstanceDescriptors: []InstanceDescriptor{{InstanceID: "instance-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306"}}}
	instances, releases, validFor, err := leaseInstances(context.Background(), leaser, request, now)
	require.NoError(t, err)
	require.Equal(t, time.Minute, validFor)
	require.Equal(t, CredentialLeaseRequest{AssignmentID: "assignment-1", InstanceID: "instance-1", DatabaseFamily: "mysql", ConfigurationRevision: 5, OperationRevision: 7}, leaser.request)
	require.Equal(t, []byte("fixture-password"), instances[0].GetCredentialLease().GetSecretBytes())
	retained := leaser.returned.SecretBytes
	for _, release := range releases {
		release()
	}
	require.Equal(t, make([]byte, len(retained)), retained)
}

func TestGatewayCredentialRemoteRequestIsSingleflight(t *testing.T) {
	now := time.Now().UTC()
	leaser := &slowCredentialLeaser{release: make(chan struct{}), lease: CredentialLease{LeaseID: "lease-1", AssignmentID: "assignment-1", InstanceID: "instance-1", DatabaseFamily: "mysql", CredentialRevision: 9, ConfigurationRevision: 5, OperationRevision: 7, ExpiresAt: now.Add(time.Minute), ValidFor: time.Minute, Username: "monitor", SecretBytes: []byte("singleflight-secret")}}
	checker := NewGatewayHealthCheckerWithCredentials(nil, leaser)
	request := CredentialLeaseRequest{AssignmentID: "assignment-1", InstanceID: "instance-1", DatabaseFamily: "mysql", ConfigurationRevision: 5, OperationRevision: 7}
	results := make(chan CredentialLease, 8)
	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			lease, _ := checker.leaseCredential(context.Background(), request)
			results <- lease
		}()
	}
	require.Eventually(t, func() bool { return leaser.calls.Load() == 1 }, time.Second, time.Millisecond)
	close(leaser.release)
	wait.Wait()
	close(results)
	require.Equal(t, int32(1), leaser.calls.Load())
	for lease := range results {
		require.Equal(t, []byte("singleflight-secret"), lease.SecretBytes)
		lease.Release()
	}
}

func TestGatewayUnexpectedExitZerosActiveCredentialsAndCancelsLifetimes(t *testing.T) {
	checker := NewGatewayHealthChecker(nil)
	process := &fakeProcess{pid: 4242}
	secret := []byte("unexpected-exit-secret")
	configuration := plugingateway.PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 5, Instances: []*pluginv1.PluginInstanceConfiguration{{InstanceId: "instance-1", CredentialLease: &pluginv1.CredentialLease{SecretBytes: secret}}}}
	checker.activeCredentials[process.pid] = activeCredentialConfiguration{configuration: configuration, deadline: time.Now().Add(time.Minute)}
	streamCancelled, renewalCancelled := false, false
	checker.streams[process.pid] = func() { streamCancelled = true }
	checker.expiries[process.pid] = func() { renewalCancelled = true }
	checker.CleanupUnexpectedExit(process)
	require.True(t, streamCancelled)
	require.True(t, renewalCancelled)
	require.Equal(t, make([]byte, len(secret)), secret)
	require.Empty(t, checker.activeCredentials)
	require.Empty(t, checker.streams)
	require.Empty(t, checker.expiries)
}

type slowCredentialLeaser struct {
	calls   atomic.Int32
	release chan struct{}
	lease   CredentialLease
}

func (value *slowCredentialLeaser) LeaseCredential(context.Context, CredentialLeaseRequest) (CredentialLease, error) {
	value.calls.Add(1)
	<-value.release
	return value.lease.Clone(), nil
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
