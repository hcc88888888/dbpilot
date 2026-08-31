package plugingateway

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"github.com/stretchr/testify/require"
)

func TestOpenRejectsNonCanonicalRuntimePaths(t *testing.T) {
	client, err := NewClient(ClientConfig{RuntimeRoot: t.TempDir(), Scope: MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1"}})
	require.NoError(t, err)
	_, err = client.Open(ExpectedPlugin{RuntimeDirectory: "/tmp/not-under-runtime", AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", ConfigurationRevision: 1, OperationRevision: 1, InstanceIDs: []string{"mysql-1"}})
	require.Error(t, err)
}

func TestConfigurationRequiresTheCompleteAssignedInstanceSet(t *testing.T) {
	expected := ExpectedPlugin{AssignmentID: "assignment-1", ConfigurationRevision: 4, InstanceIDs: []string{"mysql-1", "mysql-2"}}
	valid := func(instanceID string) *pluginv1.PluginInstanceConfiguration {
		return &pluginv1.PluginInstanceConfiguration{InstanceId: instanceID, DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306"}
	}
	require.Error(t, PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{valid("mysql-1")}}.validate(expected))
	require.Error(t, PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{valid("mysql-1"), valid("mysql-1")}}.validate(expected))
	require.NoError(t, PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{valid("mysql-1"), valid("mysql-2")}}.validate(expected))
}

func TestSessionRejectsApplyBeforeHandshake(t *testing.T) {
	root := t.TempDir()
	client, err := NewClient(ClientConfig{RuntimeRoot: root, Scope: MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1"}})
	require.NoError(t, err)
	session, err := client.Open(ExpectedPlugin{PID: 10, ExpectedUserID: 1000, ExpectedGroupID: 1000, RuntimeDirectory: filepath.Join(root, "mysql"), ExecutablePath: filepath.Join(root, "plugin"), ExecutableSHA256: bytes.Repeat([]byte{1}, 32), LaunchNonce: bytes.Repeat([]byte{2}, 32), AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", ConfigurationRevision: 1, OperationRevision: 1, InstanceIDs: []string{"mysql-1"}})
	require.NoError(t, err)
	require.Error(t, session.ApplyConfiguration(context.Background(), PluginConfiguration{}))
}
