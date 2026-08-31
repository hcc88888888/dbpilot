package commandvalidation

import (
	"context"
	"crypto/sha256"
	"testing"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestValidateReconcilePluginRequiresCanonicalBoundedArtifactAndConfiguration(t *testing.T) {
	artifactDigest := sha256.Sum256([]byte("artifact"))
	manifestDigest := sha256.Sum256([]byte("manifest"))
	envelope := &agentv1.CommandEnvelope{
		AgentId: "agent-a",
		Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{
			AssignmentId: "assignment-a", PluginId: "dbpilot.mysql", DatabaseFamily: "mysql", DesiredVersion: "1.2.3",
			DesiredState: agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_RUNNING, ArtifactId: "artifact-a",
			ArtifactSha256: artifactDigest[:], ManifestDigest: manifestDigest[:], ConfigurationRevision: 7, OperationRevision: 9,
			InstanceIds: []string{"instance-a", "instance-b"}, TemplateIds: []string{"template-a:3"},
			InstanceDescriptors: []*agentv1.PluginInstanceDescriptor{
				{InstanceId: "instance-a", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306"},
				{InstanceId: "instance-b", DatabaseVariant: "mysql", UnixSocket: "/run/mysql/mysql.sock"},
			},
		}},
	}
	authorizer := &recordingAuthorizer{allowed: map[string]bool{"agent-a/instance-a": true, "agent-a/instance-b": true}}
	require.NoError(t, Validate(context.Background(), envelope, authorizer))
	require.Equal(t, []string{"agent-a/instance-a", "agent-a/instance-b"}, authorizer.calls)

	cases := map[string]func(*agentv1.ReconcilePlugin){
		"missing assignment":            func(value *agentv1.ReconcilePlugin) { value.AssignmentId = "" },
		"unknown desired state":         func(value *agentv1.ReconcilePlugin) { value.DesiredState = agentv1.PluginDesiredState(99) },
		"wrong artifact digest":         func(value *agentv1.ReconcilePlugin) { value.ArtifactSha256 = []byte("short") },
		"wrong manifest digest":         func(value *agentv1.ReconcilePlugin) { value.ManifestDigest = []byte("short") },
		"zero configuration revision":   func(value *agentv1.ReconcilePlugin) { value.ConfigurationRevision = 0 },
		"zero operation revision":       func(value *agentv1.ReconcilePlugin) { value.OperationRevision = 0 },
		"duplicate instance":            func(value *agentv1.ReconcilePlugin) { value.InstanceIds = []string{"instance-a", "instance-a"} },
		"secret template":               func(value *agentv1.ReconcilePlugin) { value.TemplateIds = []string{"secret://vault/password"} },
		"descriptor ownership mismatch": func(value *agentv1.ReconcilePlugin) { value.InstanceDescriptors[1].InstanceId = "other" },
		"descriptor duplicate":          func(value *agentv1.ReconcilePlugin) { value.InstanceDescriptors[1].InstanceId = "instance-a" },
		"missing field20 descriptors":   func(value *agentv1.ReconcilePlugin) { value.InstanceDescriptors = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := proto.Clone(envelope).(*agentv1.CommandEnvelope)
			mutate(candidate.GetReconcilePlugin())
			require.ErrorIs(t, Validate(context.Background(), candidate, authorizer), ErrInvalidCommand)
		})
	}
	require.ErrorIs(t, Validate(context.Background(), envelope, nil), ErrTargetUnauthorized)
}
