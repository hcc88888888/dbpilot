package ingest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"sync"
	"testing"

	telemetryv1 "dbpilot.local/platform/gen/telemetry/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestIngestRejectsClaimedAgentMismatch(t *testing.T) {
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup())
	batch := validLogBatch("b1", "agent-b", []byte("x"))

	_, err := service.PushLogBatch(contextWithSPIFFEAgent(t, "agent-a"), batch)

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestIngestRejectsUnknownVerifiedAgent(t *testing.T) {
	service := NewService(knownAgents{}, newMemoryDedup())

	_, err := service.PushLogBatch(contextWithSPIFFEAgent(t, "agent-a"), validLogBatch("b1", "agent-a", []byte("x")))

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestIngestRejectsUnverifiedCertificate(t *testing.T) {
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup())

	_, err := service.PushLogBatch(contextWithUnverifiedSPIFFEAgent(t, "agent-a"), validLogBatch("b1", "agent-a", []byte("x")))

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestIngestRejectsChecksumMismatchAndOversizedPayload(t *testing.T) {
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup())
	checksumMismatch := validLogBatch("bad-checksum", "agent-a", []byte("x"))
	checksumMismatch.Checksum = []byte("incorrect")

	_, err := service.PushLogBatch(contextWithSPIFFEAgent(t, "agent-a"), checksumMismatch)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	overSize := validLogBatch("too-large", "agent-a", make([]byte, MaxBatchPayloadBytes+1))
	_, err = service.PushLogBatch(contextWithSPIFFEAgent(t, "agent-a"), overSize)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestIngestReturnsSameAcceptedAckForDuplicateBatch(t *testing.T) {
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup())
	ctx := contextWithSPIFFEAgent(t, "agent-a")
	batch := validLogBatch("duplicate", "agent-a", []byte("payload"))

	first, err := service.PushLogBatch(ctx, batch)
	require.NoError(t, err)
	second, err := service.PushLogBatch(ctx, batch)
	require.NoError(t, err)

	assert.True(t, first.Accepted)
	assert.Equal(t, first, second)
	assert.Len(t, service.ReceivedBatches(), 1)
}

func validLogBatch(id, agentID string, payload []byte) *telemetryv1.LogBatch {
	checksum := sha256.Sum256(payload)
	return &telemetryv1.LogBatch{BatchId: id, AgentId: agentID, SourceId: "source", Payload: payload, Checksum: checksum[:]}
}

func contextWithSPIFFEAgent(t *testing.T, agentID string) context.Context {
	t.Helper()
	uri, err := url.Parse("spiffe://dbpilot/agent/" + agentID)
	require.NoError(t, err)
	cert := &x509.Certificate{URIs: []*url.URL{uri}}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: state}})
}

func contextWithUnverifiedSPIFFEAgent(t *testing.T, agentID string) context.Context {
	t.Helper()
	uri, err := url.Parse("spiffe://dbpilot/agent/" + agentID)
	require.NoError(t, err)
	cert := &x509.Certificate{URIs: []*url.URL{uri}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}})
}

type knownAgents map[string]bool

func (agents knownAgents) KnownAgent(_ context.Context, agentID string) bool { return agents[agentID] }

type memoryDedup struct {
	mu   sync.Mutex
	acks map[string]*telemetryv1.BatchAck
}

func newMemoryDedup() *memoryDedup { return &memoryDedup{acks: make(map[string]*telemetryv1.BatchAck)} }

func (d *memoryDedup) Lookup(agentID, batchID string) (*telemetryv1.BatchAck, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ack, ok := d.acks[agentID+"/"+batchID]
	if !ok {
		return nil, false
	}
	copy := *ack
	return &copy, true
}

func (d *memoryDedup) Remember(agentID, batchID string, ack *telemetryv1.BatchAck) {
	d.mu.Lock()
	defer d.mu.Unlock()
	copy := *ack
	d.acks[agentID+"/"+batchID] = &copy
}
