package ingest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

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

func TestIngestDeliversNewMetricBatchToConsumerOnlyOnce(t *testing.T) {
	consumer := &metricConsumerSpy{}
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup(), consumer)
	ctx := contextWithSPIFFEAgent(t, "agent-a")
	payload := []byte(`{"samples":[]}`)
	batch := validMetricBatch("metric-duplicate", "agent-a", payload)

	_, err := service.PushMetricBatch(ctx, batch)
	require.NoError(t, err)
	_, err = service.PushMetricBatch(ctx, batch)
	require.NoError(t, err)
	require.Equal(t, 1, consumer.calls)
}

func TestIngestDoesNotAcceptMetricBatchWhenConsumerFails(t *testing.T) {
	consumer := &metricConsumerSpy{err: errors.New("metric store unavailable")}
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup(), consumer)
	ctx := contextWithSPIFFEAgent(t, "agent-a")
	batch := validMetricBatch("metric-failure", "agent-a", []byte(`{"samples":[]}`))

	_, err := service.PushMetricBatch(ctx, batch)
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Equal(t, "metric batch processing is temporarily unavailable", status.Convert(err).Message())
	require.Empty(t, service.ReceivedBatches())
}

func TestIngestMapsMetricValidationToSanitizedInvalidArgument(t *testing.T) {
	consumer := &metricConsumerSpy{err: metricValidationFailure{}}
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup(), consumer)
	_, err := service.PushMetricBatch(contextWithSPIFFEAgent(t, "agent-a"), validMetricBatch("metric-invalid", "agent-a", []byte(`{"samples":[]}`)))
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, "metric batch is invalid", status.Convert(err).Message())
}

func TestIngestMapsOperationalMetricFailureToSanitizedUnavailable(t *testing.T) {
	rawCause := errors.New("postgres://operator:secret@database.internal:5432/alerts unavailable")
	consumer := &metricConsumerSpy{err: rawCause}
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup(), consumer)
	_, err := service.PushMetricBatch(contextWithSPIFFEAgent(t, "agent-a"), validMetricBatch("metric-unavailable", "agent-a", []byte(`{"samples":[]}`)))
	require.Error(t, err)
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Equal(t, "metric batch processing is temporarily unavailable", status.Convert(err).Message())
	require.NotContains(t, status.Convert(err).Message(), "database.internal")
	require.ErrorIs(t, err, rawCause)
	require.Empty(t, service.ReceivedBatches())
}

func TestIngestPreservesMetricConsumerCancellationAndDeadline(t *testing.T) {
	for _, want := range []codes.Code{codes.Canceled, codes.DeadlineExceeded} {
		t.Run(want.String(), func(t *testing.T) {
			consumerErr := context.Canceled
			if want == codes.DeadlineExceeded {
				consumerErr = context.DeadlineExceeded
			}
			service := NewService(knownAgents{"agent-a": true}, newMemoryDedup(), &metricConsumerSpy{err: consumerErr})
			_, err := service.PushMetricBatch(contextWithSPIFFEAgent(t, "agent-a"), validMetricBatch("metric-"+want.String(), "agent-a", []byte(`{"samples":[]}`)))
			require.Equal(t, want, status.Code(err))
		})
	}
}

func TestIngestNeverCallsMetricConsumerBeforeTLSAndChecksumValidation(t *testing.T) {
	consumer := &metricConsumerSpy{}
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup(), consumer)
	valid := validMetricBatch("metric-validate", "agent-a", []byte(`{"samples":[]}`))
	_, err := service.PushMetricBatch(contextWithUnverifiedSPIFFEAgent(t, "agent-a"), valid)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	invalidChecksum := validMetricBatch("metric-checksum", "agent-a", []byte(`{"samples":[]}`))
	invalidChecksum.Checksum = []byte("bad")
	_, err = service.PushMetricBatch(contextWithSPIFFEAgent(t, "agent-a"), invalidChecksum)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, 0, consumer.calls)
}

func TestIngestRetriesMetricConsumerAfterFirstFailure(t *testing.T) {
	consumer := &scriptedMetricConsumer{errors: []error{errors.New("temporary store failure"), nil}}
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup(), consumer)
	ctx := contextWithSPIFFEAgent(t, "agent-a")
	batch := validMetricBatch("metric-retry", "agent-a", []byte(`{"samples":[]}`))
	_, err := service.PushMetricBatch(ctx, batch)
	require.Equal(t, codes.Unavailable, status.Code(err))
	ack, err := service.PushMetricBatch(ctx, batch)
	require.NoError(t, err)
	require.True(t, ack.Accepted)
	require.Equal(t, 2, consumer.calls)
	require.Len(t, service.ReceivedBatches(), 1)
}

func TestIngestDelegatesMetricDeduplicationToAtomicConsumer(t *testing.T) {
	consumer := &atomicMetricConsumer{results: []bool{true, false}}
	service := NewService(knownAgents{"agent-a": true}, nil, consumer)
	ctx := contextWithSPIFFEAgent(t, "agent-a")
	batch := validMetricBatch("metric-atomic", "agent-a", []byte(`{"samples":[]}`))

	first, err := service.PushMetricBatch(ctx, batch)
	require.NoError(t, err)
	second, err := service.PushMetricBatch(ctx, batch)
	require.NoError(t, err)
	require.True(t, first.Accepted)
	require.Equal(t, first, second)
	require.Equal(t, 2, consumer.calls)
	require.Len(t, service.ReceivedBatches(), 1)
}

func TestIngestDoesNotAcknowledgeFailedAtomicMetricCommit(t *testing.T) {
	consumer := &atomicMetricConsumer{errors: []error{errors.New("commit failed"), nil}, results: []bool{false, true}}
	service := NewService(knownAgents{"agent-a": true}, nil, consumer)
	ctx := contextWithSPIFFEAgent(t, "agent-a")
	batch := validMetricBatch("metric-atomic-retry", "agent-a", []byte(`{"samples":[]}`))

	ack, err := service.PushMetricBatch(ctx, batch)
	require.Nil(t, ack)
	require.Equal(t, codes.Unavailable, status.Code(err))
	ack, err = service.PushMetricBatch(ctx, batch)
	require.NoError(t, err)
	require.True(t, ack.Accepted)
	require.Equal(t, 2, consumer.calls)
}

func TestIngestDoesNotAcknowledgeDurableLogDedupFailure(t *testing.T) {
	dedup := &durableDedupSpy{err: errors.New("postgres unavailable")}
	service := NewDurableService(knownAgents{"agent-a": true}, dedup)

	ack, err := service.PushLogBatch(contextWithSPIFFEAgent(t, "agent-a"), validLogBatch("log-a", "agent-a", []byte("payload")))
	require.Nil(t, ack)
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Empty(t, service.ReceivedBatches())
}

func TestIngestDeduplicatesConcurrentRequestsAtomically(t *testing.T) {
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup())
	batch := validLogBatch("concurrent", "agent-a", []byte("payload"))
	var wait sync.WaitGroup
	errors := make(chan error, 16)
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := service.PushLogBatch(contextWithSPIFFEAgent(t, "agent-a"), batch)
			errors <- err
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	assert.Len(t, service.ReceivedBatches(), 1)
}

func TestReportPolicyStatusUsesVerifiedSPIFFEIdentity(t *testing.T) {
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup())

	ack, err := service.ReportPolicyStatus(contextWithSPIFFEAgent(t, "agent-a"), &telemetryv1.PolicyStatus{AgentId: "agent-a"})
	require.NoError(t, err)
	assert.True(t, ack.Accepted)

	_, err = service.ReportPolicyStatus(contextWithSPIFFEAgent(t, "agent-a"), &telemetryv1.PolicyStatus{AgentId: "agent-b"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = service.ReportPolicyStatus(contextWithSPIFFEAgent(t, "agent-b"), &telemetryv1.PolicyStatus{AgentId: "agent-b"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestReportPolicyStatusObservesOnlyAuthenticatedAcceptedReports(t *testing.T) {
	service := NewService(knownAgents{"agent-a": true}, newMemoryDedup())
	var observed []PolicyStatusMetadata
	service.SetPolicyStatusObserver(PolicyStatusObserverFunc(func(value PolicyStatusMetadata) {
		observed = append(observed, value)
	}))

	ack, err := service.ReportPolicyStatus(contextWithSPIFFEAgent(t, "agent-a"), &telemetryv1.PolicyStatus{AgentId: "agent-a", Version: 7, State: "ACTIVE", ErrorCode: "", ReportedAtUnix: 1_725_000_000})
	require.NoError(t, err)
	require.True(t, ack.Accepted)
	require.Equal(t, []PolicyStatusMetadata{{AgentID: "agent-a", Version: 7, State: "ACTIVE", ErrorCode: "", ReportedAt: time.Unix(1_725_000_000, 0).UTC()}}, observed)

	_, err = service.ReportPolicyStatus(contextWithSPIFFEAgent(t, "agent-a"), &telemetryv1.PolicyStatus{AgentId: "agent-b", Version: 8, State: "ACTIVE"})
	require.Error(t, err)
	require.Len(t, observed, 1, "a rejected claimed identity must not become server-observable")
}

func validLogBatch(id, agentID string, payload []byte) *telemetryv1.LogBatch {
	checksum := sha256.Sum256(payload)
	return &telemetryv1.LogBatch{BatchId: id, AgentId: agentID, SourceId: "source", Payload: payload, Checksum: checksum[:]}
}

func validMetricBatch(id, agentID string, payload []byte) *telemetryv1.MetricBatch {
	checksum := sha256.Sum256(payload)
	return &telemetryv1.MetricBatch{BatchId: id, AgentId: agentID, SourceId: "source", Payload: payload, Checksum: checksum[:]}
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

type metricConsumerSpy struct {
	calls int
	err   error
}

func (c *metricConsumerSpy) ConsumeMetricBatch(context.Context, string, []byte, time.Time) error {
	c.calls++
	return c.err
}

type metricValidationFailure struct{}

func (metricValidationFailure) Error() string                 { return "untrusted raw validation detail" }
func (metricValidationFailure) IsMetricBatchValidation() bool { return true }

type scriptedMetricConsumer struct {
	errors []error
	calls  int
}

type atomicMetricConsumer struct {
	results []bool
	errors  []error
	calls   int
}

type durableDedupSpy struct{ err error }

func (d *durableDedupSpy) AcceptBatchOnce(context.Context, string, string) (bool, error) {
	return d.err == nil, d.err
}

func (c *atomicMetricConsumer) ConsumeMetricBatch(context.Context, string, []byte, time.Time) error {
	panic("atomic consumer must not use the non-atomic path")
}

func (c *atomicMetricConsumer) ConsumeMetricBatchOnce(_ context.Context, _, _ string, _ []byte, _ time.Time) (bool, error) {
	index := c.calls
	c.calls++
	var err error
	if index < len(c.errors) {
		err = c.errors[index]
	}
	var first bool
	if index < len(c.results) {
		first = c.results[index]
	}
	return first, err
}

func (c *scriptedMetricConsumer) ConsumeMetricBatch(context.Context, string, []byte, time.Time) error {
	err := c.errors[c.calls]
	c.calls++
	return err
}

func newMemoryDedup() *memoryDedup { return &memoryDedup{acks: make(map[string]*telemetryv1.BatchAck)} }

func (d *memoryDedup) Lookup(agentID, batchID string) (*telemetryv1.BatchAck, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ack, ok := d.acks[agentID+"/"+batchID]
	if !ok {
		return nil, false
	}
	return &telemetryv1.BatchAck{BatchId: ack.BatchId, Accepted: ack.Accepted, Retryable: ack.Retryable, ErrorCode: ack.ErrorCode}, true
}

func (d *memoryDedup) Remember(agentID, batchID string, ack *telemetryv1.BatchAck) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.acks[agentID+"/"+batchID] = &telemetryv1.BatchAck{BatchId: ack.BatchId, Accepted: ack.Accepted, Retryable: ack.Retryable, ErrorCode: ack.ErrorCode}
}
