package commandvalidation

import (
	"context"
	"crypto/sha256"
	"testing"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestValidatePluginRuntimeCommandsRequireExactSafeFences(t *testing.T) {
	templates := []*agentv1.PluginTemplateRevision{{TemplateId: "template-a", Revision: 3, QueryDigest: bytesOfValidation(1, sha256.Size)}}
	apply := &agentv1.CommandEnvelope{AgentId: "agent-a", Command: &agentv1.CommandEnvelope_ApplyPluginConfiguration{ApplyPluginConfiguration: &agentv1.ApplyPluginConfiguration{AssignmentId: "assignment-a", ConfigurationRevision: 8, Instances: []*agentv1.PluginInstanceConfiguration{{InstanceId: "instance-a", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", CredentialRevision: 5, Templates: templates}}}}}
	validate := &agentv1.CommandEnvelope{AgentId: "agent-a", Command: &agentv1.CommandEnvelope_ValidateDatabaseInstance{ValidateDatabaseInstance: &agentv1.ValidateDatabaseInstance{AssignmentId: "assignment-a", InstanceId: "instance-a", ConfigurationRevision: 8}}}
	drain := &agentv1.CommandEnvelope{AgentId: "agent-a", Command: &agentv1.CommandEnvelope_DrainPlugin{DrainPlugin: &agentv1.DrainPlugin{AssignmentId: "assignment-a", OperationRevision: 11, TimeoutSeconds: 30}}}
	authorizer := &recordingAuthorizer{allowed: map[string]bool{"agent-a/instance-a": true}}

	require.NoError(t, Validate(context.Background(), apply, authorizer))
	require.NoError(t, Validate(context.Background(), validate, authorizer))
	require.NoError(t, Validate(context.Background(), drain, nil))
	require.Equal(t, []string{"agent-a/instance-a", "agent-a/instance-a"}, authorizer.calls)

	invalidApply := proto.Clone(apply).(*agentv1.CommandEnvelope)
	invalidApply.GetApplyPluginConfiguration().Instances[0].CredentialRevision = 0
	require.ErrorIs(t, Validate(context.Background(), invalidApply, authorizer), ErrInvalidCommand)
	invalidApply = proto.Clone(apply).(*agentv1.CommandEnvelope)
	invalidApply.GetApplyPluginConfiguration().Instances = append(invalidApply.GetApplyPluginConfiguration().Instances, proto.Clone(invalidApply.GetApplyPluginConfiguration().Instances[0]).(*agentv1.PluginInstanceConfiguration))
	require.ErrorIs(t, Validate(context.Background(), invalidApply, authorizer), ErrInvalidCommand)
	invalidApply = proto.Clone(apply).(*agentv1.CommandEnvelope)
	invalidApply.GetApplyPluginConfiguration().Instances[0].Templates[0].QueryDigest = []byte("not-sha256")
	require.ErrorIs(t, Validate(context.Background(), invalidApply, authorizer), ErrInvalidCommand)

	invalidValidate := proto.Clone(validate).(*agentv1.CommandEnvelope)
	invalidValidate.GetValidateDatabaseInstance().ConfigurationRevision = 0
	require.ErrorIs(t, Validate(context.Background(), invalidValidate, authorizer), ErrInvalidCommand)
	require.ErrorIs(t, Validate(context.Background(), validate, nil), ErrTargetUnauthorized)

	invalidDrain := proto.Clone(drain).(*agentv1.CommandEnvelope)
	invalidDrain.GetDrainPlugin().TimeoutSeconds = 0
	require.ErrorIs(t, Validate(context.Background(), invalidDrain, nil), ErrInvalidCommand)
	invalidDrain = proto.Clone(drain).(*agentv1.CommandEnvelope)
	invalidDrain.GetDrainPlugin().TimeoutSeconds = 61
	require.ErrorIs(t, Validate(context.Background(), invalidDrain, nil), ErrInvalidCommand)
}
