package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestReconcilePluginVerifierUsesExactAdvertisedCapability(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	verifier, err := NewCommandVerifier("agent-a", private.Public().(ed25519.PublicKey), []string{"plugin.reconcile.v1"})
	require.NoError(t, err)
	require.Contains(t, verifier.capabilities, CommandKind("plugin.reconcile.v1"))

	kind, ok := envelopeCommandKind(&agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{}}})
	require.True(t, ok)
	require.Equal(t, CommandKind("plugin.reconcile.v1"), kind)
}

func TestCollectDatabaseMetricsVerifierUsesExactAdvertisedCapability(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	verifier, err := NewCommandVerifier("agent-a", private.Public().(ed25519.PublicKey), []string{"plugin.metrics.collect.v1"})
	require.NoError(t, err)
	require.Contains(t, verifier.capabilities, CommandKind("plugin.metrics.collect.v1"))
	kind, ok := envelopeCommandKind(&agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_CollectDatabaseMetrics{CollectDatabaseMetrics: &agentv1.CollectDatabaseMetrics{}}})
	require.True(t, ok)
	require.Equal(t, CommandKind("plugin.metrics.collect.v1"), kind)
}

func TestCollectDatabaseMetricsVerifierAuthorizesExactSignedMembership(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	now := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	verifier, err := NewCommandVerifier("agent-a", publicKey, []string{"plugin.metrics.collect.v1"})
	require.NoError(t, err)
	verifier.now = func() time.Time { return now }
	envelope := &agentv1.CommandEnvelope{
		CommandId: "command-trial", JobId: "job-trial", AgentId: "agent-a", Nonce: []byte("trial-nonce"), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Minute)), LeaseSeconds: 30,
		Command: &agentv1.CommandEnvelope_CollectDatabaseMetrics{CollectDatabaseMetrics: &agentv1.CollectDatabaseMetrics{
			AssignmentId: "assignment-a", ConfigurationRevision: 2, OperationRevision: 2, InstanceIds: []string{"instance-a"}, TemplateIds: []string{"template-a"}, Trial: true,
			TemplateRevisions: []*agentv1.MetricTemplateCommandReference{{TemplateId: "template-a", RevisionId: "revision-a", QueryDigest: make([]byte, sha256.Size), TimeoutSeconds: 5, MaxRows: 10, MaxColumns: 4, CardinalityLimit: 20}},
		}},
	}
	signEnvelope(t, privateKey, envelope)

	require.NoError(t, verifier.Verify(context.Background(), envelope))
}
