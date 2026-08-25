// Package ingest implements the deliberately small, test-only DBPilot ingest
// contract. Authentication is derived exclusively from the TLS connection
// state established by gRPC; callers cannot assert an identity in metadata.
package ingest

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	telemetryv1 "dbpilot.local/platform/gen/telemetry/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const MaxBatchPayloadBytes = 1 << 20

var errMissingVerifiedIdentity = errors.New("missing verified client certificate identity")

// AgentIdentityResolver authorizes the Agent ID obtained from a verified mTLS
// certificate. It must not trust a value supplied by the request message.
type AgentIdentityResolver interface {
	KnownAgent(ctx context.Context, agentID string) bool
}

// BatchDeduplicator persists accepted acknowledgements by authenticated agent
// and batch ID. Returning the original acknowledgement makes client retries
// idempotent after a response is lost.
type BatchDeduplicator interface {
	Lookup(agentID, batchID string) (*telemetryv1.BatchAck, bool)
	Remember(agentID, batchID string, ack *telemetryv1.BatchAck)
}

// Service validates and acknowledges DBPilot telemetry batches.
type Service struct {
	telemetryv1.UnimplementedTelemetryIngestServer
	identities AgentIdentityResolver
	dedup      BatchDeduplicator
	receivedMu sync.Mutex
	received   []BatchMetadata
}

// BatchMetadata is the test gateway's in-memory receipt record. Payloads are
// intentionally excluded from the test gateway's retained state.
type BatchMetadata struct {
	BatchID      string
	AgentID      string
	SourceID     string
	PayloadBytes int
	ReceivedAt   time.Time
}

func NewService(identities AgentIdentityResolver, dedup BatchDeduplicator) *Service {
	return &Service{identities: identities, dedup: dedup}
}

func (s *Service) PushLogBatch(ctx context.Context, batch *telemetryv1.LogBatch) (*telemetryv1.BatchAck, error) {
	if batch == nil {
		return nil, status.Error(codes.InvalidArgument, "log batch is required")
	}
	return s.accept(ctx, batch.BatchId, batch.AgentId, batch.SourceId, batch.Payload, batch.Checksum)
}

func (s *Service) PushMetricBatch(ctx context.Context, batch *telemetryv1.MetricBatch) (*telemetryv1.BatchAck, error) {
	if batch == nil {
		return nil, status.Error(codes.InvalidArgument, "metric batch is required")
	}
	return s.accept(ctx, batch.BatchId, batch.AgentId, batch.SourceId, batch.Payload, batch.Checksum)
}

func (s *Service) ReportPolicyStatus(_ context.Context, _ *telemetryv1.PolicyStatus) (*telemetryv1.PolicyStatusAck, error) {
	return &telemetryv1.PolicyStatusAck{Accepted: true}, nil
}

func (s *Service) accept(ctx context.Context, batchID, claimedAgentID, sourceID string, payload, checksum []byte) (*telemetryv1.BatchAck, error) {
	authenticatedAgentID, err := verifiedSPIFFEAgent(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if claimedAgentID == "" || subtle.ConstantTimeCompare([]byte(authenticatedAgentID), []byte(claimedAgentID)) != 1 {
		return nil, status.Error(codes.PermissionDenied, "claimed agent does not match verified certificate identity")
	}
	if s.identities == nil || !s.identities.KnownAgent(ctx, authenticatedAgentID) {
		return nil, status.Error(codes.PermissionDenied, "unknown agent")
	}
	if batchID == "" || sourceID == "" {
		return nil, status.Error(codes.InvalidArgument, "batch_id and source_id are required")
	}
	if len(payload) > MaxBatchPayloadBytes {
		return nil, status.Error(codes.ResourceExhausted, "batch payload exceeds maximum size")
	}
	expected := sha256.Sum256(payload)
	if len(checksum) != len(expected) || subtle.ConstantTimeCompare(expected[:], checksum) != 1 {
		return nil, status.Error(codes.InvalidArgument, "batch checksum is invalid")
	}
	if s.dedup == nil {
		return nil, status.Error(codes.Internal, "batch deduplicator is unavailable")
	}
	if ack, ok := s.dedup.Lookup(authenticatedAgentID, batchID); ok {
		return ack, nil
	}
	ack := &telemetryv1.BatchAck{BatchId: batchID, Accepted: true}
	s.dedup.Remember(authenticatedAgentID, batchID, ack)
	s.receivedMu.Lock()
	s.received = append(s.received, BatchMetadata{BatchID: batchID, AgentID: authenticatedAgentID, SourceID: sourceID, PayloadBytes: len(payload), ReceivedAt: time.Now().UTC()})
	s.receivedMu.Unlock()
	return ack, nil
}

// ReceivedBatches returns the local contract gateway's metadata view.
func (s *Service) ReceivedBatches() []BatchMetadata {
	s.receivedMu.Lock()
	defer s.receivedMu.Unlock()
	return append([]BatchMetadata(nil), s.received...)
}

func verifiedSPIFFEAgent(ctx context.Context) (string, error) {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo.AuthInfo == nil {
		return "", errMissingVerifiedIdentity
	}
	tlsInfo, ok := peerInfo.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", errMissingVerifiedIdentity
	}
	return spiffeAgentFromTLS(tlsInfo.State)
}

func spiffeAgentFromTLS(state tls.ConnectionState) (string, error) {
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return "", errMissingVerifiedIdentity
	}
	const prefix = "spiffe://dbpilot/agent/"
	for _, uri := range state.PeerCertificates[0].URIs {
		if uri == nil {
			continue
		}
		value := uri.String()
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) && !strings.Contains(value[len(prefix):], "/") {
			return value[len(prefix):], nil
		}
	}
	return "", fmt.Errorf("%w: required SPIFFE URI absent", errMissingVerifiedIdentity)
}

// AllowAnyVerifiedAgent is appropriate only for the local contract-test
// gateway. Production deployments provide an inventory-backed resolver.
type AllowAnyVerifiedAgent struct{}

func (AllowAnyVerifiedAgent) KnownAgent(context.Context, string) bool { return true }

// MemoryDeduplicator is a process-local deduplication store for the
// contract-test gateway. Production services must use durable shared state.
type MemoryDeduplicator struct {
	mu   sync.Mutex
	acks map[string]*telemetryv1.BatchAck
}

func NewMemoryDeduplicator() *MemoryDeduplicator {
	return &MemoryDeduplicator{acks: make(map[string]*telemetryv1.BatchAck)}
}

func (d *MemoryDeduplicator) Lookup(agentID, batchID string) (*telemetryv1.BatchAck, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ack, ok := d.acks[agentID+"\x00"+batchID]
	if !ok {
		return nil, false
	}
	copy := *ack
	return &copy, true
}

func (d *MemoryDeduplicator) Remember(agentID, batchID string, ack *telemetryv1.BatchAck) {
	d.mu.Lock()
	defer d.mu.Unlock()
	copy := *ack
	d.acks[agentID+"\x00"+batchID] = &copy
}
