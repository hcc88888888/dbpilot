package commandvalidation

import (
	"context"
	"crypto/sha256"
	"testing"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestValidateExecuteSQLRequiresCompleteReviewedPayloadAndOwnership(t *testing.T) {
	digest := sha256.Sum256([]byte("select 1"))
	envelope := &agentv1.CommandEnvelope{
		AgentId: "agent-a",
		Command: &agentv1.CommandEnvelope_ExecuteSql{ExecuteSql: &agentv1.ExecuteSQL{
			InstanceId: "instance-a", WorkorderId: "workorder-a", ReviewRevision: 3,
			SqlDigest: digest[:], TransactionPolicy: agentv1.TransactionPolicy_TRANSACTION_POLICY_REQUIRED,
			TimeoutSeconds: 30,
		}},
	}
	authorizer := &recordingAuthorizer{allowed: map[string]bool{"agent-a/instance-a": true}}
	require.NoError(t, Validate(context.Background(), envelope, authorizer))
	require.Equal(t, []string{"agent-a/instance-a"}, authorizer.calls)

	cases := map[string]func(*agentv1.ExecuteSQL){
		"blank instance":      func(value *agentv1.ExecuteSQL) { value.InstanceId = " " },
		"blank workorder":     func(value *agentv1.ExecuteSQL) { value.WorkorderId = "" },
		"missing revision":    func(value *agentv1.ExecuteSQL) { value.ReviewRevision = 0 },
		"wrong digest length": func(value *agentv1.ExecuteSQL) { value.SqlDigest = []byte("not-sha256") },
		"unspecified policy": func(value *agentv1.ExecuteSQL) {
			value.TransactionPolicy = agentv1.TransactionPolicy_TRANSACTION_POLICY_UNSPECIFIED
		},
		"unknown policy":    func(value *agentv1.ExecuteSQL) { value.TransactionPolicy = agentv1.TransactionPolicy(99) },
		"zero timeout":      func(value *agentv1.ExecuteSQL) { value.TimeoutSeconds = 0 },
		"oversized timeout": func(value *agentv1.ExecuteSQL) { value.TimeoutSeconds = MaximumTimeoutSeconds + 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := proto.Clone(envelope).(*agentv1.CommandEnvelope)
			mutate(candidate.GetExecuteSql())
			require.ErrorIs(t, Validate(context.Background(), candidate, authorizer), ErrInvalidCommand)
		})
	}
	require.ErrorIs(t, Validate(context.Background(), envelope, nil), ErrTargetUnauthorized)
}

func TestValidateTypedCommandsRejectsUnsafeOrEmptyStructuredInput(t *testing.T) {
	tests := []struct {
		name     string
		envelope *agentv1.CommandEnvelope
	}{
		{name: "empty collect kinds", envelope: &agentv1.CommandEnvelope{AgentId: "agent-a", Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{}}}},
		{name: "blank inspect kind", envelope: &agentv1.CommandEnvelope{AgentId: "agent-a", Command: &agentv1.CommandEnvelope_InspectInstance{InspectInstance: &agentv1.InspectInstance{InstanceId: "instance-a", InspectionKinds: []string{" "}}}}},
		{name: "unsafe process id", envelope: &agentv1.CommandEnvelope{AgentId: "agent-a", Command: &agentv1.CommandEnvelope_ExecuteRegisteredProcess{ExecuteRegisteredProcess: &agentv1.ExecuteRegisteredProcess{ProcessId: "sh -c", Parameters: map[string]string{"mode": "safe"}}}}},
		{name: "unsafe parameter key", envelope: &agentv1.CommandEnvelope{AgentId: "agent-a", Command: &agentv1.CommandEnvelope_ExecuteRegisteredProcess{ExecuteRegisteredProcess: &agentv1.ExecuteRegisteredProcess{ProcessId: "collector.health", Parameters: map[string]string{"bad key": "safe"}}}}},
		{name: "control character value", envelope: &agentv1.CommandEnvelope{AgentId: "agent-a", Command: &agentv1.CommandEnvelope_ExecuteRegisteredProcess{ExecuteRegisteredProcess: &agentv1.ExecuteRegisteredProcess{ProcessId: "collector.health", Parameters: map[string]string{"mode": "bad\nvalue"}}}}},
		{name: "empty diagnostic kind", envelope: &agentv1.CommandEnvelope{AgentId: "agent-a", Command: &agentv1.CommandEnvelope_CollectDiagnostic{CollectDiagnostic: &agentv1.CollectDiagnostic{InstanceId: "instance-a"}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.ErrorIs(t, Validate(context.Background(), test.envelope, allowAllAuthorizer{}), ErrInvalidCommand)
		})
	}

	valid := &agentv1.CommandEnvelope{AgentId: "agent-a", Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"health"}}}}
	require.NoError(t, Validate(context.Background(), valid, nil), "foundation CollectNow without instance targets remains allowed")
}

type recordingAuthorizer struct {
	allowed map[string]bool
	calls   []string
}

func (authorizer *recordingAuthorizer) AuthorizeTarget(_ context.Context, agentID, targetID string) error {
	key := agentID + "/" + targetID
	authorizer.calls = append(authorizer.calls, key)
	if !authorizer.allowed[key] {
		return ErrTargetUnauthorized
	}
	return nil
}

type allowAllAuthorizer struct{}

func (allowAllAuthorizer) AuthorizeTarget(context.Context, string, string) error { return nil }
