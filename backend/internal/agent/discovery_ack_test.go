package agent

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

func TestReportDiscoveryCompletesOnlyAfterMatchingPersistenceAcknowledgement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &controlSession{ctx: ctx, outgoing: make(chan controlSendRequest, 1)}
	client := &ControlClient{agentID: "agent-1", session: session, discoveryWaiters: make(map[uint64]*discoveryAckWaiter)}
	report := &agentv1.DiscoveryReport{HostId: "host-1", AgentId: "agent-1", ObservationRevision: 7, RuleRevision: 4, ObservedAt: timestamppb.New(time.Now().UTC())}
	handled := make(chan struct{})
	go func() {
		request := <-session.outgoing
		request.result <- nil
		wire := request.message.GetDiscoveryReport()
		encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(wire)
		digest := sha256.Sum256(encoded)
		require.NoError(t, client.handleDiscoveryAcknowledgement(&agentv1.DiscoveryReportAcknowledgement{HostId: "host-1", AgentId: "agent-1", ObservationRevision: 7, ReportDigest: digest[:], Persisted: true}))
		close(handled)
	}()
	require.NoError(t, client.ReportDiscovery(ctx, report))
	<-handled
}

func TestReportDiscoveryRejectsMismatchedAcknowledgementDigest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	session := &controlSession{ctx: ctx, outgoing: make(chan controlSendRequest, 1)}
	client := &ControlClient{agentID: "agent-1", session: session, discoveryWaiters: make(map[uint64]*discoveryAckWaiter)}
	report := &agentv1.DiscoveryReport{HostId: "host-1", AgentId: "agent-1", ObservationRevision: 8, RuleRevision: 4, ObservedAt: timestamppb.New(time.Now().UTC())}
	go func() {
		request := <-session.outgoing
		request.result <- nil
		_ = client.handleDiscoveryAcknowledgement(&agentv1.DiscoveryReportAcknowledgement{HostId: "host-1", AgentId: "agent-1", ObservationRevision: 8, ReportDigest: make([]byte, sha256.Size), Persisted: true})
	}()
	require.Error(t, client.ReportDiscovery(ctx, report))
}
