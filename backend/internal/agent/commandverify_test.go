package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCommandVerifierRejectsInvalidEnvelopeBeforeReservingNonce(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Unix(1_725_000_000, 0).UTC()
	verifier, err := NewCommandVerifier("agent-a", publicKey, []string{"collect_now"})
	require.NoError(t, err)
	verifier.now = func() time.Time { return now }

	invalid := signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("nonce-a"), now, now.Add(time.Minute))
	invalid.Signature[0] ^= 0xff
	require.ErrorIs(t, verifier.Verify(context.Background(), invalid), ErrInvalidCommandSignature)

	valid := signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("nonce-a"), now, now.Add(time.Minute))
	require.NoError(t, verifier.Verify(context.Background(), valid), "an invalid signature must not consume its nonce")
}

func TestCommandVerifierRejectsExpiredMismatchedAndUnadvertisedCommands(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Unix(1_725_000_000, 0).UTC()
	verifier, err := NewCommandVerifier("agent-a", publicKey, []string{"collect_now"})
	require.NoError(t, err)
	verifier.now = func() time.Time { return now }

	tests := []struct {
		name     string
		envelope *agentv1.CommandEnvelope
		want     error
	}{
		{name: "expired", envelope: signedCollectNowEnvelope(t, privateKey, "expired", "agent-a", []byte("nonce-expired"), now.Add(-time.Minute), now), want: ErrCommandExpired},
		{name: "Agent mismatch", envelope: signedCollectNowEnvelope(t, privateKey, "mismatch", "agent-b", []byte("nonce-mismatch"), now, now.Add(time.Minute)), want: ErrCommandAgentMismatch},
		{name: "unadvertised capability", envelope: signedInspectEnvelope(t, privateKey, "inspect", "agent-a", []byte("nonce-inspect"), now, now.Add(time.Minute)), want: ErrCommandCapabilityUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.ErrorIs(t, verifier.Verify(context.Background(), test.envelope), test.want)
		})
	}
}

func TestCommandVerifierRejectsNonceReuseAcrossCommandIDsButAllowsCommandReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Unix(1_725_000_000, 0).UTC()
	verifier, err := NewCommandVerifier("agent-a", publicKey, []string{"collect_now"})
	require.NoError(t, err)
	verifier.now = func() time.Time { return now }

	first := signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("shared-nonce"), now, now.Add(time.Minute))
	require.NoError(t, verifier.Verify(context.Background(), first))
	require.NoError(t, verifier.Verify(context.Background(), first), "at-least-once replay of the same command ID reaches journal deduplication")
	second := signedCollectNowEnvelope(t, privateKey, "command-b", "agent-a", []byte("shared-nonce"), now, now.Add(time.Minute))
	require.ErrorIs(t, verifier.Verify(context.Background(), second), ErrCommandNonceReplay)
}

func TestCommandVerifierUsesSharedSemanticAndTargetAuthorization(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Unix(1_725_000_000, 0).UTC()
	verifier, err := NewCommandVerifier("agent-a", publicKey, []string{"collect_now", "inspect_instance"})
	require.NoError(t, err)
	verifier.now = func() time.Time { return now }

	invalid := signedCollectNowEnvelope(t, privateKey, "invalid", "agent-a", []byte("nonce-invalid"), now, now.Add(time.Minute))
	invalid.GetCollectNow().CollectionKinds = nil
	signEnvelope(t, privateKey, invalid)
	require.ErrorIs(t, verifier.Verify(context.Background(), invalid), ErrInvalidCommandEnvelope)

	instanceBound := signedInspectEnvelope(t, privateKey, "inspect", "agent-a", []byte("nonce-inspect"), now, now.Add(time.Minute))
	require.ErrorIs(t, verifier.Verify(context.Background(), instanceBound), ErrCommandTargetUnauthorized)
	verifier.SetTargetAuthorizer(staticTargetAuthorizer{allowed: true})
	require.NoError(t, verifier.Verify(context.Background(), instanceBound))
}

type staticTargetAuthorizer struct{ allowed bool }

func (authorizer staticTargetAuthorizer) AuthorizeTarget(context.Context, string, string) error {
	if authorizer.allowed {
		return nil
	}
	return ErrCommandTargetUnauthorized
}

func signedCollectNowEnvelope(t *testing.T, privateKey ed25519.PrivateKey, commandID, agentID string, nonce []byte, issuedAt, expiresAt time.Time) *agentv1.CommandEnvelope {
	t.Helper()
	envelope := &agentv1.CommandEnvelope{
		CommandId: commandID, JobId: "job-" + commandID, AgentId: agentID, Nonce: append([]byte(nil), nonce...),
		IssuedAt: timestamppb.New(issuedAt), ExpiresAt: timestamppb.New(expiresAt), LeaseSeconds: 30,
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"host"}}},
	}
	signEnvelope(t, privateKey, envelope)
	return envelope
}

func signedInspectEnvelope(t *testing.T, privateKey ed25519.PrivateKey, commandID, agentID string, nonce []byte, issuedAt, expiresAt time.Time) *agentv1.CommandEnvelope {
	t.Helper()
	envelope := &agentv1.CommandEnvelope{
		CommandId: commandID, JobId: "job-" + commandID, AgentId: agentID, Nonce: append([]byte(nil), nonce...),
		IssuedAt: timestamppb.New(issuedAt), ExpiresAt: timestamppb.New(expiresAt), LeaseSeconds: 30,
		Command: &agentv1.CommandEnvelope_InspectInstance{InspectInstance: &agentv1.InspectInstance{InstanceId: "instance-a", InspectionKinds: []string{"health"}}},
	}
	signEnvelope(t, privateKey, envelope)
	return envelope
}

func signEnvelope(t *testing.T, privateKey ed25519.PrivateKey, envelope *agentv1.CommandEnvelope) {
	t.Helper()
	payload, err := CommandSigningBytes(envelope)
	require.NoError(t, err)
	envelope.Signature = ed25519.Sign(privateKey, payload)
}
