package exporter

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	telemetryv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSendPendingAcknowledgesAcceptedBatchesOldestFirst(t *testing.T) {
	store := &fakeStore{pending: map[spool.DataClass][]spool.Batch{
		spool.Log:    {testBatch("newer", time.Unix(20, 0))},
		spool.Metric: {testBatch("older", time.Unix(10, 0))},
	}}
	api := &fakeIngest{acks: map[string]*telemetryv1.BatchAck{
		"older": {BatchId: "older", Accepted: true},
		"newer": {BatchId: "newer", Accepted: true},
	}}

	require.NoError(t, NewClient(api, store, "agent-a").SendPending(context.Background()))

	assert.Equal(t, []string{"older", "newer"}, api.sent)
	assert.Equal(t, []ackCall{{spool.Metric, "older"}, {spool.Log, "newer"}}, store.acks)
}

func TestSendPendingRetainsRetryableRejectionAndBacksOffUntilCancellation(t *testing.T) {
	store := &fakeStore{pending: map[spool.DataClass][]spool.Batch{spool.Log: {testBatch("retry", time.Now())}}}
	api := &fakeIngest{acks: map[string]*telemetryv1.BatchAck{"retry": {BatchId: "retry", Retryable: true, ErrorCode: "TEMPORARY"}}}
	client := NewClient(api, store, "agent-a")
	client.initialBackoff = time.Millisecond
	client.maxBackoff = 2 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := client.SendPending(ctx)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Empty(t, store.acks)
	assert.GreaterOrEqual(t, len(api.sent), 2)
}

func TestSendPendingRecordsPermanentRejectionWithoutAcknowledging(t *testing.T) {
	store := &fakeStore{pending: map[spool.DataClass][]spool.Batch{spool.Log: {testBatch("rejected", time.Now())}}}
	api := &fakeIngest{acks: map[string]*telemetryv1.BatchAck{"rejected": {BatchId: "rejected", ErrorCode: "CHECKSUM_INVALID"}}}

	err := NewClient(api, store, "agent-a").SendPending(context.Background())

	require.ErrorIs(t, err, ErrPermanentRejection)
	assert.Empty(t, store.acks)
	assert.Equal(t, []healthFinding{{"TELEMETRY_PERMANENT_REJECTION", "CHECKSUM_INVALID"}}, store.findings)
}

func TestSendPendingTreatsTypedGatewayOversizeAsPermanent(t *testing.T) {
	store := &fakeStore{pending: map[spool.DataClass][]spool.Batch{spool.Log: {testBatch("oversize", time.Now())}}}
	api := &fakeIngest{err: gatewayOversizeError()}

	err := NewClient(api, store, "agent-a").SendPending(context.Background())

	var permanent *PermanentRejectionError
	require.ErrorAs(t, err, &permanent)
	assert.Equal(t, codes.ResourceExhausted, permanent.StatusCode)
	assert.Equal(t, "BATCH_TOO_LARGE", permanent.Reason)
	assert.Empty(t, store.acks)
	assert.Len(t, api.sent, 1)
	assert.Equal(t, []healthFinding{{"TELEMETRY_PERMANENT_REJECTION", "BATCH_TOO_LARGE"}}, store.findings)
}

func TestSendPendingRetriesUntypedResourceExhaustion(t *testing.T) {
	store := &fakeStore{pending: map[spool.DataClass][]spool.Batch{spool.Log: {testBatch("transient-capacity", time.Now())}}}
	api := &fakeIngest{err: status.Error(codes.ResourceExhausted, "upstream temporarily saturated")}
	client := NewClient(api, store, "agent-a")
	client.initialBackoff = time.Millisecond
	client.maxBackoff = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := client.SendPending(ctx)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Empty(t, store.acks)
	assert.Empty(t, store.findings)
	assert.GreaterOrEqual(t, len(api.sent), 2)
}

func TestSendPendingRetriesUnavailableMetricIngestFailure(t *testing.T) {
	store := &fakeStore{pending: map[spool.DataClass][]spool.Batch{spool.Metric: {testBatch("metric-unavailable", time.Now())}}}
	api := &fakeIngest{err: status.Error(codes.Unavailable, "metric batch processing is temporarily unavailable")}
	client := NewClient(api, store, "agent-a")
	client.initialBackoff = time.Millisecond
	client.maxBackoff = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := client.SendPending(ctx)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.NotErrorIs(t, err, ErrPermanentRejection)
	assert.Empty(t, store.acks)
	assert.Empty(t, store.findings)
	assert.GreaterOrEqual(t, len(api.sent), 2)
}

func TestSendPendingRetainsBatchForMalformedAcceptedAcknowledgement(t *testing.T) {
	store := &fakeStore{pending: map[spool.DataClass][]spool.Batch{spool.Log: {testBatch("expected", time.Now())}}}
	api := &fakeIngest{acks: map[string]*telemetryv1.BatchAck{"expected": {BatchId: "different", Accepted: true}}}

	err := NewClient(api, store, "agent-a").SendPending(context.Background())

	require.ErrorIs(t, err, ErrPermanentRejection)
	assert.Empty(t, store.acks)
	assert.Equal(t, []healthFinding{{"TELEMETRY_INVALID_ACK", "ack batch_id does not match sent batch"}}, store.findings)
}

func TestSendPendingStopsOnCancellationBeforeRead(t *testing.T) {
	store := &fakeStore{pending: map[spool.DataClass][]spool.Batch{spool.Log: {testBatch("cancelled", time.Now())}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := NewClient(&fakeIngest{}, store, "agent-a").SendPending(ctx)

	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, store.acks)
}

type fakeStore struct {
	mu       sync.Mutex
	pending  map[spool.DataClass][]spool.Batch
	acks     []ackCall
	findings []healthFinding
}

type ackCall struct {
	class spool.DataClass
	id    string
}
type healthFinding struct{ code, detail string }

func (s *fakeStore) Pending(ctx context.Context, class spool.DataClass, limit int) ([]spool.Batch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	values := append([]spool.Batch(nil), s.pending[class]...)
	if limit > 0 && len(values) > limit {
		values = values[:limit]
	}
	return values, nil
}
func (s *fakeStore) Ack(ctx context.Context, class spool.DataClass, batchID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acks = append(s.acks, ackCall{class, batchID})
	for index, batch := range s.pending[class] {
		if batch.ID == batchID {
			s.pending[class] = append(s.pending[class][:index], s.pending[class][index+1:]...)
			break
		}
	}
	return nil
}
func (s *fakeStore) RecordHealthFinding(code, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = append(s.findings, healthFinding{code, detail})
}

type fakeIngest struct {
	telemetryv1.UnimplementedTelemetryIngestServer
	mu   sync.Mutex
	acks map[string]*telemetryv1.BatchAck
	sent []string
	err  error
}

func gatewayOversizeError() error {
	st, err := status.New(codes.ResourceExhausted, "batch payload exceeds maximum size").WithDetails(&errdetails.ErrorInfo{Reason: "BATCH_TOO_LARGE", Domain: "dbpilot.telemetry"})
	if err != nil {
		panic(err)
	}
	return st.Err()
}

func (f *fakeIngest) PushLogBatch(_ context.Context, batch *telemetryv1.LogBatch, _ ...grpc.CallOption) (*telemetryv1.BatchAck, error) {
	return f.ack(batch.BatchId)
}
func (f *fakeIngest) PushMetricBatch(_ context.Context, batch *telemetryv1.MetricBatch, _ ...grpc.CallOption) (*telemetryv1.BatchAck, error) {
	return f.ack(batch.BatchId)
}
func (f *fakeIngest) ReportPolicyStatus(context.Context, *telemetryv1.PolicyStatus, ...grpc.CallOption) (*telemetryv1.PolicyStatusAck, error) {
	return nil, errors.New("not implemented")
}
func (f *fakeIngest) ack(id string) (*telemetryv1.BatchAck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, id)
	if f.err != nil {
		return nil, f.err
	}
	ack := f.acks[id]
	if ack == nil {
		return nil, errors.New("unexpected batch")
	}
	return &telemetryv1.BatchAck{BatchId: ack.BatchId, Accepted: ack.Accepted, Retryable: ack.Retryable, ErrorCode: ack.ErrorCode}, nil
}

func testBatch(id string, created time.Time) spool.Batch {
	return spool.Batch{ID: id, SourceID: "source", CreatedAt: created, Payload: []byte(id)}
}
