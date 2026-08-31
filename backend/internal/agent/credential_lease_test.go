package agent

import (
	"context"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestControlClientCorrelatesCredentialLeaseAndClearsWireSecret(t *testing.T) {
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	client := newTransportTestClient(t, (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	require.Eventually(t, func() bool { return len(stream.sentMessages()) > 1 }, time.Second, time.Millisecond)

	result := make(chan struct {
		Lease CredentialLease
		Err   error
	}, 1)
	go func() {
		lease, err := client.LeaseCredential(ctx, CredentialLeaseRequest{AssignmentID: "assignment-1", InstanceID: "instance-1", DatabaseFamily: "mysql", ConfigurationRevision: 5, OperationRevision: 7})
		result <- struct {
			Lease CredentialLease
			Err   error
		}{Lease: lease, Err: err}
	}()
	var request *agentv1.CredentialLeaseRequest
	require.Eventually(t, func() bool {
		for _, message := range stream.sentMessages() {
			if value := message.GetCredentialLeaseRequest(); value != nil {
				request = value
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond)
	secret := []byte("fixture-password")
	response := &agentv1.CredentialLeaseResponse{RequestNonce: request.GetRequestNonce(), LeaseId: "lease-1", InstanceId: "instance-1", AssignmentId: "assignment-1", CredentialRevision: 9, ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)), Credential: &agentv1.CredentialMaterial{Username: "monitor", SecretBytes: secret}}
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_CredentialLeaseResponse{CredentialLeaseResponse: response}}

	got := <-result
	require.NoError(t, got.Err)
	require.Equal(t, uint64(5), got.Lease.ConfigurationRevision)
	require.Equal(t, uint64(7), got.Lease.OperationRevision)
	require.Equal(t, []byte("fixture-password"), got.Lease.SecretBytes)
	require.Equal(t, make([]byte, len(secret)), secret)
	got.Lease.Release()
	cancel()
	require.NoError(t, <-done)
}

func TestControlClientRejectsMismatchedCredentialLeaseWithoutSecretInError(t *testing.T) {
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	client := newTransportTestClient(t, (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	require.Eventually(t, func() bool { return len(stream.sentMessages()) > 1 }, time.Second, time.Millisecond)

	result := make(chan error, 1)
	go func() {
		_, err := client.LeaseCredential(ctx, CredentialLeaseRequest{AssignmentID: "assignment-1", InstanceID: "instance-1", DatabaseFamily: "mysql", ConfigurationRevision: 5, OperationRevision: 7})
		result <- err
	}()
	var request *agentv1.CredentialLeaseRequest
	require.Eventually(t, func() bool {
		for _, message := range stream.sentMessages() {
			if value := message.GetCredentialLeaseRequest(); value != nil {
				request = value
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond)
	secret := []byte("credential-must-not-appear")
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_CredentialLeaseResponse{CredentialLeaseResponse: &agentv1.CredentialLeaseResponse{RequestNonce: request.GetRequestNonce(), LeaseId: "lease-1", InstanceId: "instance-other", AssignmentId: "assignment-1", CredentialRevision: 9, ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)), Credential: &agentv1.CredentialMaterial{Username: "monitor", SecretBytes: secret}}}}
	err := <-result
	require.ErrorIs(t, err, ErrCredentialLease)
	require.NotContains(t, err.Error(), "credential-must-not-appear")
	cancel()
	require.NoError(t, <-done)
}
