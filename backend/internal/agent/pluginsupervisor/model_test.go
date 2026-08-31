package pluginsupervisor

import (
	"crypto/sha256"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"github.com/stretchr/testify/require"
)

func TestReconcileRequestRejectsUnsafeOrUnboundedAssignments(t *testing.T) {
	valid := validReconcileRequest()
	require.NoError(t, valid.Validate())

	tests := map[string]func(*ReconcileRequest){
		"family traversal":         func(value *ReconcileRequest) { value.DatabaseFamily = "../mysql" },
		"empty assignment":         func(value *ReconcileRequest) { value.AssignmentID = "" },
		"wrong package digest":     func(value *ReconcileRequest) { value.ArtifactSHA256 = []byte("short") },
		"wrong manifest digest":    func(value *ReconcileRequest) { value.ManifestDigest = []byte("short") },
		"zero operation":           func(value *ReconcileRequest) { value.OperationRevision = 0 },
		"duplicate instance":       func(value *ReconcileRequest) { value.InstanceIDs = []string{"instance-1", "instance-1"} },
		"too many instances":       func(value *ReconcileRequest) { value.InstanceIDs = make([]string, MaxAssignedInstances+1) },
		"unknown desired state":    func(value *ReconcileRequest) { value.DesiredState = DesiredState(99) },
		"partial artifact absent":  func(value *ReconcileRequest) { value.DesiredState = DesiredAbsent; value.ManifestDigest = nil },
		"missing artifact running": func(value *ReconcileRequest) { value.ArtifactID = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.InstanceIDs = append([]string(nil), valid.InstanceIDs...)
			mutate(&candidate)
			require.ErrorIs(t, candidate.Validate(), ErrInvalidRequest)
		})
	}

	absent := valid
	absent.DesiredState = DesiredAbsent
	absent.DesiredVersion = ""
	absent.ArtifactID = ""
	absent.ArtifactSHA256 = nil
	absent.ManifestDigest = nil
	require.NoError(t, absent.Validate())
	withTask8Metadata := valid
	withTask8Metadata.DesiredState = DesiredAbsent
	require.NoError(t, withTask8Metadata.Validate())
}

func TestExecutionFenceRequiresExactStartedCommandBoundary(t *testing.T) {
	fence := ExecutionFence{CommandID: "command-1", ExecutionToken: bytesOf(1, sha256.Size), LeaseRevision: 7, StartedAt: time.Now().UTC()}
	require.NoError(t, fence.Validate())

	fence.ExecutionToken = []byte("short")
	require.ErrorIs(t, fence.Validate(), ErrInvalidFence)
}

func validReconcileRequest() ReconcileRequest {
	return ReconcileRequest{
		AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql",
		DesiredVersion: "1.0.0", DesiredState: DesiredRunning, ArtifactID: "artifact-1",
		ArtifactSHA256: bytesOf(2, sha256.Size), ManifestDigest: bytesOf(3, sha256.Size),
		ConfigurationRevision: 1, OperationRevision: 1,
		InstanceIDs: []string{"mysql-1", "mysql-2"}, InstanceDescriptors: []InstanceDescriptor{{InstanceID: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306"}, {InstanceID: "mysql-2", DatabaseVariant: "mysql", UnixSocket: "/run/mysql-2.sock"}}, TemplateIDs: []string{"template-1"}, TemplateConfigurations: []*pluginv1.MetricTemplateConfiguration{testTemplateConfiguration("template-1")}, CredentialsComplete: true,
	}
}

func testTemplateConfiguration(id string) *pluginv1.MetricTemplateConfiguration {
	return &pluginv1.MetricTemplateConfiguration{TemplateId: id, Revision: 1, QueryDigest: bytesOf(4, sha256.Size), QueryKind: "sql", ReadOnlyStatement: "SELECT value", CollectionIntervalSeconds: 10, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, ValueMappings: []*pluginv1.MetricValueMapping{{SourceColumn: "value", MetricName: "mysql.connections.current", MetricType: "gauge", Unit: "1"}}}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
