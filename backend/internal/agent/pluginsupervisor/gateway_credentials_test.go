package pluginsupervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/metrictemplatelease"
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

func TestLeaseMetricTemplatesKeepsDifferentPerInstanceBindingsAndReleasesQueries(t *testing.T) {
	now := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	refA := templateReferenceFor("template-a", "revision-a", "SELECT a")
	refB := templateReferenceFor("template-b", "revision-b", "SELECT b")
	leaser := &recordingTemplateLeaser{materials: map[string]metrictemplatelease.Material{"revision-a": templateMaterial(now, refA, "instance-a", "SELECT a"), "revision-b": templateMaterial(now, refB, "instance-b", "SELECT b")}}
	request := HealthRequest{AssignmentID: "assignment-a", ConfigurationRevision: 5, OperationRevision: 7, TemplateLeaseCommandID: "command-a", TemplateIDs: []string{"template-a", "template-b"}, TemplateReferences: []TemplateReference{refA, refB}, InstanceIDs: []string{"instance-a", "instance-b"}, InstanceTemplateRefs: []InstanceTemplateReferences{{InstanceID: "instance-a", Templates: []TemplateReference{refA}}, {InstanceID: "instance-b", Templates: []TemplateReference{refB}}}}
	configurations, releases, _, err := leaseMetricTemplates(context.Background(), leaser, request, now)
	require.NoError(t, err)
	require.Equal(t, "template-a", configurations["instance-a"][0].GetTemplateId())
	require.Equal(t, "template-b", configurations["instance-b"][0].GetTemplateId())
	retained := append([][]byte(nil), leaser.returned...)
	for _, release := range releases {
		release()
	}
	for _, query := range retained {
		require.Equal(t, make([]byte, len(query)), query)
	}
}

func TestCredentialRenewalReusesActivePerInstanceTemplates(t *testing.T) {
	checker := NewGatewayHealthChecker(nil)
	templateA := testTemplateConfiguration("template-a")
	templateB := testTemplateConfiguration("template-b")
	checker.activeCredentials[42] = activeCredentialConfiguration{configuration: plugingateway.PluginConfiguration{AssignmentID: "assignment-a", ConfigurationRevision: 5, Instances: []*pluginv1.PluginInstanceConfiguration{{InstanceId: "instance-a", Templates: []*pluginv1.MetricTemplateConfiguration{templateA}}, {InstanceId: "instance-b", Templates: []*pluginv1.MetricTemplateConfiguration{templateB}}}}}
	renewed := []*pluginv1.PluginInstanceConfiguration{{InstanceId: "instance-a"}, {InstanceId: "instance-b"}}
	require.True(t, checker.copyActiveTemplates(42, renewed))
	require.Equal(t, "template-a", renewed[0].Templates[0].GetTemplateId())
	require.Equal(t, "template-b", renewed[1].Templates[0].GetTemplateId())
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

func TestGatewayUnexpectedExitFencesBlockedLateLeaseSuccess(t *testing.T) {
	now := time.Now().UTC()
	leaser := &slowCredentialLeaser{release: make(chan struct{}), lease: CredentialLease{LeaseID: "lease-late", AssignmentID: "assignment-1", InstanceID: "instance-1", DatabaseFamily: "mysql", CredentialRevision: 9, ConfigurationRevision: 5, OperationRevision: 7, ExpiresAt: now.Add(time.Minute), ValidFor: time.Minute, Username: "monitor", SecretBytes: []byte("late-provider-secret")}}
	checker := NewGatewayHealthCheckerWithCredentials(nil, leaser)
	process := &fakeProcess{pid: 4343}
	checker.activeCredentials[process.pid] = activeCredentialConfiguration{configuration: plugingateway.PluginConfiguration{AssignmentID: "assignment-1"}, deadline: time.Now().Add(time.Minute)}
	done := make(chan error, 1)
	go func() {
		_, err := checker.leaseCredential(context.Background(), CredentialLeaseRequest{AssignmentID: "assignment-1", InstanceID: "instance-1", DatabaseFamily: "mysql", ConfigurationRevision: 5, OperationRevision: 7})
		done <- err
	}()
	require.Eventually(t, func() bool { return leaser.calls.Load() == 1 }, time.Second, time.Millisecond)
	checker.CleanupUnexpectedExit(process)
	close(leaser.release)
	require.Error(t, <-done)
	require.Equal(t, make([]byte, len(leaser.returned)), leaser.returned)
	require.Empty(t, checker.leaseFlights)
}

type slowCredentialLeaser struct {
	calls    atomic.Int32
	release  chan struct{}
	lease    CredentialLease
	returned []byte
}

func (value *slowCredentialLeaser) LeaseCredential(context.Context, CredentialLeaseRequest) (CredentialLease, error) {
	value.calls.Add(1)
	<-value.release
	lease := value.lease.Clone()
	value.returned = lease.SecretBytes
	return lease, nil
}

type recordingCredentialLeaser struct {
	request  CredentialLeaseRequest
	lease    CredentialLease
	returned *CredentialLease
}

type recordingTemplateLeaser struct {
	materials map[string]metrictemplatelease.Material
	returned  [][]byte
}

func (leaser *recordingTemplateLeaser) LeaseMetricTemplate(_ context.Context, request metrictemplatelease.Request) (metrictemplatelease.Material, error) {
	material := leaser.materials[request.RevisionID]
	material.StatementBytes = append([]byte(nil), material.StatementBytes...)
	leaser.returned = append(leaser.returned, material.StatementBytes)
	return material, nil
}

func templateReferenceFor(templateID, revisionID, statement string) TemplateReference {
	digest := sha256.Sum256([]byte(statement))
	return TemplateReference{TemplateID: templateID, RevisionID: revisionID, QueryDigest: digest[:], TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2, CardinalityLimit: 10}
}

func templateMaterial(now time.Time, reference TemplateReference, instanceID, statement string) metrictemplatelease.Material {
	return metrictemplatelease.Material{LeaseID: "lease-" + reference.RevisionID, AssignmentID: "assignment-a", InstanceID: instanceID, TemplateID: reference.TemplateID, RevisionID: reference.RevisionID, Revision: 1, ConfigurationRevision: 5, OperationRevision: 7, QueryDigest: hex.EncodeToString(reference.QueryDigest), ExpiresAt: now.Add(time.Minute), StatementBytes: []byte(statement), CollectionIntervalSeconds: 60, TimeoutSeconds: int(reference.TimeoutSeconds), MaxRows: int(reference.MaxRows), MaxColumns: int(reference.MaxColumns), CardinalityLimit: int(reference.CardinalityLimit), ValueMappings: []metrictemplatelease.ValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: "gauge", Unit: "1"}}}
}

func (value *recordingCredentialLeaser) LeaseCredential(_ context.Context, request CredentialLeaseRequest) (CredentialLease, error) {
	value.request = request
	lease := value.lease.Clone()
	value.returned = &lease
	return lease, nil
}
