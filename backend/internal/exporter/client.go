// Package exporter delivers spooled telemetry through DBPilot's acknowledged
// gRPC contract. It deliberately owns neither credentials nor a raw network
// dialer: callers supply an already mTLS-configured generated client.
package exporter

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	telemetryv1 "dbpilot.local/platform/gen/telemetry/v1"
	"dbpilot.local/platform/internal/spool"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const pendingScanLimit = 1

var ErrPermanentRejection = errors.New("telemetry batch permanently rejected")

// PermanentRejectionError exposes the gateway's typed rejection information
// to the runtime while retaining ErrPermanentRejection for simple callers.
type PermanentRejectionError struct {
	BatchID    string
	Reason     string
	StatusCode codes.Code
	Err        error
}

func (e *PermanentRejectionError) Error() string {
	return fmt.Sprintf("%v: batch=%s reason=%s status=%s", ErrPermanentRejection, e.BatchID, e.Reason, e.StatusCode)
}
func (e *PermanentRejectionError) Unwrap() error { return errors.Join(ErrPermanentRejection, e.Err) }

// PendingStore is the narrow spool view needed by the exporter.
type PendingStore interface {
	Pending(ctx context.Context, class spool.DataClass, limit int) ([]spool.Batch, error)
	Ack(ctx context.Context, class spool.DataClass, batchID string) error
	RecordHealthFinding(code string, detail string)
}

// Client sends every batch with the durable acknowledgement rule: local data
// is removed only after the gateway explicitly returns Accepted=true.
type Client struct {
	api            telemetryv1.TelemetryIngestClient
	store          PendingStore
	agentID        string
	initialBackoff time.Duration
	maxBackoff     time.Duration
}

func NewClient(api telemetryv1.TelemetryIngestClient, store PendingStore, agentID string) *Client {
	return &Client{api: api, store: store, agentID: agentID, initialBackoff: 100 * time.Millisecond, maxBackoff: 30 * time.Second}
}

// SendPending drains currently pending work one bounded batch at a time. A
// retryable service or transport failure keeps the same batch durable and
// retries it with cancellation-aware exponential backoff. A permanent reject
// records a finding, leaves the batch intact for diagnosis, and returns.
func (c *Client) SendPending(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.api == nil || c.store == nil || c.agentID == "" {
		return errors.New("exporter requires API, store, and agent ID")
	}
	for {
		candidate, ok, err := c.oldestPending(ctx)
		if err != nil || !ok {
			return err
		}
		if err := c.deliver(ctx, candidate); err != nil {
			return err
		}
	}
}

type pendingBatch struct {
	class spool.DataClass
	batch spool.Batch
}

func (c *Client) oldestPending(ctx context.Context) (pendingBatch, bool, error) {
	var oldest pendingBatch
	found := false
	for _, class := range []spool.DataClass{spool.AuditLog, spool.Log, spool.Metric, spool.JobResult} {
		pending, err := c.store.Pending(ctx, class, pendingScanLimit)
		if err != nil {
			return pendingBatch{}, false, err
		}
		if len(pending) == 0 {
			continue
		}
		candidate := pendingBatch{class: class, batch: pending[0]}
		if !found || candidate.batch.CreatedAt.Before(oldest.batch.CreatedAt) {
			oldest, found = candidate, true
		}
	}
	return oldest, found, nil
}

func (c *Client) deliver(ctx context.Context, item pendingBatch) error {
	backoff := c.initialBackoff
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ack, err := c.push(ctx, item)
		if err == nil && ack == nil {
			return c.invalidAck(item.batch.ID, "empty acknowledgement")
		}
		if err == nil && ack.BatchId != item.batch.ID {
			return c.invalidAck(item.batch.ID, "ack batch_id does not match sent batch")
		}
		if err == nil && ack.Accepted {
			return c.store.Ack(ctx, item.class, item.batch.ID)
		}
		if err == nil && !ack.Retryable {
			detail := ack.ErrorCode
			if detail == "" {
				detail = "gateway rejected batch"
			}
			c.store.RecordHealthFinding("TELEMETRY_PERMANENT_REJECTION", detail)
			return c.permanent(item.batch.ID, detail, codes.OK, nil)
		}
		if err != nil {
			if reason, permanent := permanentGatewayReason(err); permanent {
				c.store.RecordHealthFinding("TELEMETRY_PERMANENT_REJECTION", reason)
				return c.permanent(item.batch.ID, reason, status.Code(err), err)
			}
			if isPermanentRPC(err) {
				reason := status.Code(err).String()
				c.store.RecordHealthFinding("TELEMETRY_PERMANENT_REJECTION", reason)
				return c.permanent(item.batch.ID, reason, status.Code(err), err)
			}
		}
		if err := wait(ctx, backoff); err != nil {
			return err
		}
		backoff *= 2
		if backoff > c.maxBackoff {
			backoff = c.maxBackoff
		}
	}
}

func (c *Client) invalidAck(batchID, detail string) error {
	c.store.RecordHealthFinding("TELEMETRY_INVALID_ACK", detail)
	return c.permanent(batchID, "INVALID_ACK", codes.Unknown, errors.New(detail))
}

func (c *Client) permanent(batchID, reason string, code codes.Code, err error) error {
	return &PermanentRejectionError{BatchID: batchID, Reason: reason, StatusCode: code, Err: err}
}

func (c *Client) push(ctx context.Context, item pendingBatch) (*telemetryv1.BatchAck, error) {
	checksum := sha256.Sum256(item.batch.Payload)
	if item.class == spool.Metric {
		return c.api.PushMetricBatch(ctx, &telemetryv1.MetricBatch{BatchId: item.batch.ID, AgentId: c.agentID, SourceId: item.batch.SourceID, Payload: item.batch.Payload, Checksum: checksum[:], CreatedAtUnix: item.batch.CreatedAt.Unix()})
	}
	return c.api.PushLogBatch(ctx, &telemetryv1.LogBatch{BatchId: item.batch.ID, AgentId: c.agentID, SourceId: item.batch.SourceID, Category: string(item.class), Payload: item.batch.Payload, Checksum: checksum[:], CreatedAtUnix: item.batch.CreatedAt.Unix()})
}

func isPermanentRPC(err error) bool {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Unauthenticated, codes.InvalidArgument, codes.FailedPrecondition:
		return true
	default:
		return false
	}
}

func permanentGatewayReason(err error) (string, bool) {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		return "", false
	}
	for _, detail := range st.Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if ok && info.Domain == "dbpilot.telemetry" && info.Reason == "BATCH_TOO_LARGE" {
			return info.Reason, true
		}
	}
	return "", false
}

func wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
