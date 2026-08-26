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
	"google.golang.org/genproto/googleapis/rpc/errdetails"
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

// DurableBatchDeduplicator atomically accepts an opaque batch identity in
// shared storage. It is used by production log ingestion; failures prevent an
// acknowledgement. Metric ingestion uses AtomicMetricBatchConsumer instead so
// its payload write shares the reservation transaction.
type DurableBatchDeduplicator interface {
	AcceptBatchOnce(context.Context, string, string) (bool, error)
}

// MetricBatchConsumer receives a verified, checksum-valid, newly accepted
// metric batch. It is optional so the local telemetry test gateway remains a
// payload-opaque contract server.
type MetricBatchConsumer interface {
	ConsumeMetricBatch(context.Context, string, []byte, time.Time) error
}

// AtomicMetricBatchConsumer durably reserves a batch identity and commits its
// metric samples in one storage transaction. The boolean reports whether this
// call committed the batch; false means a prior call already committed it.
type AtomicMetricBatchConsumer interface {
	ConsumeMetricBatchOnce(context.Context, string, string, []byte, time.Time) (bool, error)
}

// Service validates and acknowledges DBPilot telemetry batches.
type Service struct {
	telemetryv1.UnimplementedTelemetryIngestServer
	identities AgentIdentityResolver
	dedup      BatchDeduplicator
	durable    DurableBatchDeduplicator
	metrics    MetricBatchConsumer
	dedupMu    sync.Mutex
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

func NewService(identities AgentIdentityResolver, dedup BatchDeduplicator, metrics ...MetricBatchConsumer) *Service {
	service := &Service{identities: identities, dedup: dedup}
	if len(metrics) > 0 {
		service.metrics = metrics[0]
	}
	return service
}

func NewDurableService(identities AgentIdentityResolver, dedup DurableBatchDeduplicator, metrics ...MetricBatchConsumer) *Service {
	service := &Service{identities: identities, durable: dedup}
	if len(metrics) > 0 {
		service.metrics = metrics[0]
	}
	return service
}

func (s *Service) PushLogBatch(ctx context.Context, batch *telemetryv1.LogBatch) (*telemetryv1.BatchAck, error) {
	if batch == nil {
		return nil, status.Error(codes.InvalidArgument, "log batch is required")
	}
	return s.accept(ctx, batch.BatchId, batch.AgentId, batch.SourceId, batch.Payload, batch.Checksum, nil)
}

func (s *Service) PushMetricBatch(ctx context.Context, batch *telemetryv1.MetricBatch) (*telemetryv1.BatchAck, error) {
	if batch == nil {
		return nil, status.Error(codes.InvalidArgument, "metric batch is required")
	}
	return s.accept(ctx, batch.BatchId, batch.AgentId, batch.SourceId, batch.Payload, batch.Checksum, s.metrics)
}

func (s *Service) ReportPolicyStatus(ctx context.Context, report *telemetryv1.PolicyStatus) (*telemetryv1.PolicyStatusAck, error) {
	if report == nil {
		return nil, status.Error(codes.InvalidArgument, "policy status is required")
	}
	if _, err := s.authorize(ctx, report.AgentId); err != nil {
		return nil, err
	}
	return &telemetryv1.PolicyStatusAck{Accepted: true}, nil
}

func (s *Service) accept(ctx context.Context, batchID, claimedAgentID, sourceID string, payload, checksum []byte, metricConsumer MetricBatchConsumer) (*telemetryv1.BatchAck, error) {
	authenticatedAgentID, err := s.authorize(ctx, claimedAgentID)
	if err != nil {
		return nil, err
	}
	if batchID == "" || sourceID == "" {
		return nil, status.Error(codes.InvalidArgument, "batch_id and source_id are required")
	}
	if len(payload) > MaxBatchPayloadBytes {
		return nil, batchTooLargeError()
	}
	expected := sha256.Sum256(payload)
	if len(checksum) != len(expected) || subtle.ConstantTimeCompare(expected[:], checksum) != 1 {
		return nil, status.Error(codes.InvalidArgument, "batch checksum is invalid")
	}
	if atomicConsumer, ok := metricConsumer.(AtomicMetricBatchConsumer); ok {
		first, err := atomicConsumer.ConsumeMetricBatchOnce(ctx, authenticatedAgentID, batchID, payload, time.Now().UTC())
		if err != nil {
			return nil, metricConsumerFailure(err)
		}
		ack := &telemetryv1.BatchAck{BatchId: batchID, Accepted: true}
		if first {
			s.recordReceipt(batchID, authenticatedAgentID, sourceID, len(payload))
		}
		return ack, nil
	}
	if s.durable != nil && metricConsumer == nil {
		first, err := s.durable.AcceptBatchOnce(ctx, authenticatedAgentID, batchID)
		if err != nil {
			return nil, sanitizedMetricConsumerError(codes.Unavailable, "batch processing is temporarily unavailable", err)
		}
		ack := &telemetryv1.BatchAck{BatchId: batchID, Accepted: true}
		if first {
			s.recordReceipt(batchID, authenticatedAgentID, sourceID, len(payload))
		}
		return ack, nil
	}
	if s.dedup == nil {
		return nil, status.Error(codes.Unavailable, "batch deduplicator is temporarily unavailable")
	}
	s.dedupMu.Lock()
	defer s.dedupMu.Unlock()
	if ack, ok := s.dedup.Lookup(authenticatedAgentID, batchID); ok {
		return ack, nil
	}
	if metricConsumer != nil {
		if err := metricConsumer.ConsumeMetricBatch(ctx, authenticatedAgentID, payload, time.Now().UTC()); err != nil {
			return nil, metricConsumerFailure(err)
		}
	}
	ack := &telemetryv1.BatchAck{BatchId: batchID, Accepted: true}
	s.dedup.Remember(authenticatedAgentID, batchID, ack)
	s.recordReceipt(batchID, authenticatedAgentID, sourceID, len(payload))
	return ack, nil
}

func (s *Service) recordReceipt(batchID, agentID, sourceID string, payloadBytes int) {
	s.receivedMu.Lock()
	defer s.receivedMu.Unlock()
	s.received = append(s.received, BatchMetadata{BatchID: batchID, AgentID: agentID, SourceID: sourceID, PayloadBytes: payloadBytes, ReceivedAt: time.Now().UTC()})
}

type metricBatchValidationFailure interface {
	error
	IsMetricBatchValidation() bool
}

func metricConsumerFailure(err error) error {
	if errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled {
		return sanitizedMetricConsumerError(codes.Canceled, "metric batch processing canceled", err)
	}
	if errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.DeadlineExceeded {
		return sanitizedMetricConsumerError(codes.DeadlineExceeded, "metric batch processing deadline exceeded", err)
	}
	var validation metricBatchValidationFailure
	if errors.As(err, &validation) && validation.IsMetricBatchValidation() {
		return sanitizedMetricConsumerError(codes.InvalidArgument, "metric batch is invalid", err)
	}
	return sanitizedMetricConsumerError(codes.Unavailable, "metric batch processing is temporarily unavailable", err)
}

// metricConsumerStatusError keeps the original cause available to local
// observability while GRPCStatus exposes only a stable, non-sensitive message.
type metricConsumerStatusError struct {
	status *status.Status
	cause  error
}

func sanitizedMetricConsumerError(code codes.Code, message string, cause error) error {
	return &metricConsumerStatusError{status: status.New(code, message), cause: cause}
}

func (e *metricConsumerStatusError) Error() string              { return e.status.Err().Error() }
func (e *metricConsumerStatusError) Unwrap() error              { return e.cause }
func (e *metricConsumerStatusError) GRPCStatus() *status.Status { return e.status }

func (s *Service) authorize(ctx context.Context, claimedAgentID string) (string, error) {
	authenticatedAgentID, err := verifiedSPIFFEAgent(ctx)
	if err != nil {
		return "", status.Error(codes.Unauthenticated, err.Error())
	}
	if claimedAgentID == "" || subtle.ConstantTimeCompare([]byte(authenticatedAgentID), []byte(claimedAgentID)) != 1 {
		return "", status.Error(codes.PermissionDenied, "claimed agent does not match verified certificate identity")
	}
	if s.identities == nil || !s.identities.KnownAgent(ctx, authenticatedAgentID) {
		return "", status.Error(codes.PermissionDenied, "unknown agent")
	}
	return authenticatedAgentID, nil
}

func batchTooLargeError() error {
	st, err := status.New(codes.ResourceExhausted, "batch payload exceeds maximum size").WithDetails(&errdetails.ErrorInfo{Reason: "BATCH_TOO_LARGE", Domain: "dbpilot.telemetry"})
	if err != nil {
		return status.Error(codes.ResourceExhausted, "batch payload exceeds maximum size")
	}
	return st.Err()
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
	return cloneBatchAck(ack), true
}

func (d *MemoryDeduplicator) Remember(agentID, batchID string, ack *telemetryv1.BatchAck) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.acks[agentID+"\x00"+batchID] = cloneBatchAck(ack)
}

func cloneBatchAck(ack *telemetryv1.BatchAck) *telemetryv1.BatchAck {
	if ack == nil {
		return nil
	}
	return &telemetryv1.BatchAck{BatchId: ack.BatchId, Accepted: ack.Accepted, Retryable: ack.Retryable, ErrorCode: ack.ErrorCode}
}
