package commandvalidation

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestStartValidationRequiresFencingTokenRevisionLeaseAndFutureDeadline(t *testing.T) {
	now := time.Unix(1_725_000_000, 0).UTC()
	valid := &agentv1.CommandStart{
		CommandId: "command-a", ExecutionToken: make([]byte, sha256.Size), LeaseRevision: 7,
		LeaseSeconds: 30, StartDeadline: timestamppb.New(now.Add(time.Minute)),
	}
	require.NoError(t, ValidateStart(valid, now))

	tests := map[string]func(*agentv1.CommandStart){
		"blank command ID": func(start *agentv1.CommandStart) { start.CommandId = " " },
		"short token":      func(start *agentv1.CommandStart) { start.ExecutionToken = []byte("short") },
		"zero revision":    func(start *agentv1.CommandStart) { start.LeaseRevision = 0 },
		"zero lease":       func(start *agentv1.CommandStart) { start.LeaseSeconds = 0 },
		"expired deadline": func(start *agentv1.CommandStart) { start.StartDeadline = timestamppb.New(now) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := proto.Clone(valid).(*agentv1.CommandStart)
			mutate(candidate)
			require.ErrorIs(t, ValidateStart(candidate, now), ErrInvalidCommand)
		})
	}
}

func TestStartShapeAllowsExpiredDeadlineButRejectsMalformedStructure(t *testing.T) {
	now := time.Unix(1_725_000_000, 0).UTC()
	expired := &agentv1.CommandStart{
		CommandId: "command-expired", ExecutionToken: make([]byte, sha256.Size), LeaseRevision: 2,
		LeaseSeconds: 30, StartDeadline: timestamppb.New(now.Add(-time.Second)),
	}
	require.NoError(t, ValidateStartShape(expired))
	require.ErrorIs(t, ValidateStart(expired, now), ErrInvalidCommand)

	malformed := proto.Clone(expired).(*agentv1.CommandStart)
	malformed.ExecutionToken = []byte("short")
	require.ErrorIs(t, ValidateStartShape(malformed), ErrInvalidCommand)
}

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

func TestValidateCollectDatabaseMetricsRequiresBoundedInstancesAndTemplateRevisions(t *testing.T) {
	valid := &agentv1.CommandEnvelope{AgentId: "agent-a", Command: &agentv1.CommandEnvelope_CollectDatabaseMetrics{CollectDatabaseMetrics: &agentv1.CollectDatabaseMetrics{AssignmentId: "assignment-a", ConfigurationRevision: 7, OperationRevision: 9, InstanceIds: []string{"instance-a"}, TemplateIds: []string{"template-a"}, Trial: true, TemplateRevisions: []*agentv1.MetricTemplateCommandReference{{TemplateId: "template-a", RevisionId: "revision-a", QueryDigest: make([]byte, sha256.Size), TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2, CardinalityLimit: 10}}}}}
	authorizer := &recordingAuthorizer{allowed: map[string]bool{"agent-a/instance-a": true}}
	require.NoError(t, Validate(context.Background(), valid, authorizer))

	invalid := proto.Clone(valid).(*agentv1.CommandEnvelope)
	invalid.GetCollectDatabaseMetrics().InstanceIds = append(invalid.GetCollectDatabaseMetrics().InstanceIds, "instance-a")
	require.ErrorIs(t, Validate(context.Background(), invalid, allowAllAuthorizer{}), ErrInvalidCommand)
	invalid = proto.Clone(valid).(*agentv1.CommandEnvelope)
	invalid.GetCollectDatabaseMetrics().TemplateIds = nil
	require.ErrorIs(t, Validate(context.Background(), invalid, allowAllAuthorizer{}), ErrInvalidCommand)
	invalid = proto.Clone(valid).(*agentv1.CommandEnvelope)
	invalid.GetCollectDatabaseMetrics().TemplateRevisions[0].QueryDigest = []byte("short")
	require.ErrorIs(t, Validate(context.Background(), invalid, allowAllAuthorizer{}), ErrInvalidCommand)
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
