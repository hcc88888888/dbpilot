package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestPostgresReconcileAmbiguousAuditAndMarkFailureUsesOriginalAuditPayload(t *testing.T) {
	if os.Getenv("DBPILOT_HTTP_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_HTTP_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_HTTP_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_HTTP_POSTGRES_DSN is required")
	}
	for _, failure := range []string{"audit commit acknowledgement", "mark audited"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			database := openHTTPIntegrationDatabase(t, ctx, dsn, strings.ReplaceAll(failure, " ", "_"))
			realAudit := audit.NewService(audit.NewPostgresStore(database))
			var auditService AuditService = realAudit
			var idempotencyStore idempotency.Store = idempotency.NewPostgresStore(database)
			if failure == "audit commit acknowledgement" {
				auditService = &postCommitErrorAuditService{inner: realAudit, fail: true}
			} else {
				idempotencyStore = &markAuditedErrorStore{inner: idempotencyStore, fail: true}
			}
			jobs := &recordingJobService{transitionValue: func() job.Job {
				value := validPlatformJob()
				value.Status = job.StatusCancelling
				value.Version = 8
				return value
			}()}
			services := Services{Jobs: jobs, Audit: auditService, Idempotency: idempotency.NewService(idempotencyStore)}
			principal := principalWith(platformTestScope, openapi.PermissionCancelJob)

			firstRequest := newCancelRequest(`"7"`, "postgres-audit-repair-1")
			firstRequest.Header.Set("X-Request-ID", "request-postgres-original")
			firstRequest.Header.Set("traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
			first := servePlatformRequest(services, principal, firstRequest)
			requireProblem(t, first, http.StatusInternalServerError, "internal_error", "request-postgres-original")
			require.Len(t, jobs.transitions, 1)
			var originalResponse []byte
			require.NoError(t, database.QueryRowContext(ctx, "SELECT response_json FROM idempotency_records WHERE tenant_id = $1 AND project_id = $2 AND idempotency_key = $3", platformTestScope.TenantID, platformTestScope.ProjectID, "postgres-audit-repair-1").Scan(&originalResponse))

			retryRequest := newCancelRequest(`"7"`, "postgres-audit-repair-1")
			retryRequest.Header.Set("X-Request-ID", "request-postgres-retry")
			retryRequest.Header.Set("traceparent", "00-33333333333333333333333333333333-4444444444444444-01")
			retry := servePlatformRequest(services, principal, retryRequest)

			require.Equal(t, http.StatusAccepted, retry.Code, retry.Body.String())
			require.Equal(t, originalResponse, retry.Body.Bytes())
			require.Len(t, jobs.transitions, 1)
			var auditCount int
			var requestID, traceID string
			require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*), min(request_id), min(trace_id) FROM audit_events WHERE tenant_id = $1 AND project_id = $2", platformTestScope.TenantID, platformTestScope.ProjectID).Scan(&auditCount, &requestID, &traceID))
			require.Equal(t, 1, auditCount)
			require.Equal(t, "request-postgres-original", requestID)
			require.Equal(t, "11111111111111111111111111111111", traceID)
			var state string
			require.NoError(t, database.QueryRowContext(ctx, "SELECT state FROM idempotency_records WHERE tenant_id = $1 AND project_id = $2 AND idempotency_key = $3", platformTestScope.TenantID, platformTestScope.ProjectID, "postgres-audit-repair-1").Scan(&state))
			require.Equal(t, string(idempotency.StateCompleted), state)
		})
	}
}

func TestPostgresBareProcessingReconciliationPreservesOriginalHTTPAndAuditEvidence(t *testing.T) {
	if os.Getenv("DBPILOT_HTTP_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_HTTP_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_HTTP_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_HTTP_POSTGRES_DSN is required")
	}

	t.Run("Job cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		database := openHTTPIntegrationDatabase(t, ctx, dsn, "bare_processing_cancel")
		require.NoError(t, job.RunMigrations(ctx, database))
		now := time.Date(2026, 8, 28, 6, 0, 0, 0, time.UTC)
		repository := job.NewPostgresRepository(database)
		value := job.Job{
			ID: "job-bare-processing", Type: "inspection.run", Scope: platformTestScope,
			Status: job.StatusQueued, Outcome: job.OutcomeNone, TargetResourceIDs: []string{"agent-a"},
			SourceResource: job.ResourceReference{ResourceType: "inspection", ResourceID: "inspection-bare-processing"},
			IdempotencyKey: "create-bare-processing", Version: 1, Progress: job.Progress{TotalTargets: 1},
			Artifacts: []job.ArtifactReference{}, CreatedAt: now.Add(-time.Minute), RequestID: "request-create-job", TraceID: "trace-create-job",
		}
		require.NoError(t, repository.CreateWithOutbox(ctx, value, nil))
		jobs := &countingCancellationJobService{inner: repository}
		audits := audit.NewService(audit.NewPostgresStore(database))
		gap := &commitSideEffectGapStore{inner: idempotency.NewPostgresStore(database), fail: true}
		services := Services{Jobs: jobs, Audit: audits, Idempotency: idempotency.NewService(gap), Now: func() time.Time { return now }}
		principal := principalWith(platformTestScope, openapi.PermissionCancelJob)

		firstRequest := newCancelRequest(`"1"`, "cancel-bare-processing")
		firstRequest.URL.Path = platformBasePath + "/jobs/" + value.ID + "/actions/cancel"
		firstRequest.Header.Set("X-Request-ID", "request-cancel-original")
		firstRequest.Header.Set("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
		first := servePlatformRequest(services, principal, firstRequest)
		requireProblem(t, first, http.StatusInternalServerError, "internal_error", "request-cancel-original")
		require.Equal(t, 1, jobs.cancelCalls)
		require.NotNil(t, gap.attempted)
		var snapshotCount int
		require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM job_cancellation_snapshots WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3`, platformTestScope.TenantID, platformTestScope.ProjectID, value.ID).Scan(&snapshotCount))
		require.Equal(t, 1, snapshotCount)

		gap.fail = false
		retryRequest := newCancelRequest(`"1"`, "cancel-bare-processing")
		retryRequest.URL.Path = firstRequest.URL.Path
		retryRequest.Header.Set("X-Request-ID", "request-cancel-retry")
		retryRequest.Header.Set("traceparent", "00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01")
		retry := servePlatformRequest(services, principal, retryRequest)
		require.Equal(t, http.StatusAccepted, retry.Code, retry.Body.String())
		require.Equal(t, gap.attempted.Body, retry.Body.Bytes())
		require.Equal(t, gap.attempted.Header.Get("ETag"), retry.Header().Get("ETag"))
		require.Equal(t, gap.attempted.Header.Get("Location"), retry.Header().Get("Location"))
		require.Equal(t, 1, jobs.cancelCalls)
		assertHTTPReconciliationRows(t, ctx, database, "cancel-bare-processing", "request-cancel-original", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

		for _, migration := range []string{"job/migrations/0006_cancellation_response_snapshot.sql", "platformdb/migrations/0006_processing_reconciliation.sql"} {
			var applied int
			require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM dbpilot_schema_migrations WHERE name = $1`, migration).Scan(&applied))
			require.Equal(t, 1, applied)
		}
	})

	t.Run("Artifact descriptor", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		database := openHTTPIntegrationDatabase(t, ctx, dsn, "bare_processing_artifact")
		audits := audit.NewService(audit.NewPostgresStore(database))
		gap := &commitSideEffectGapStore{inner: idempotency.NewPostgresStore(database), fail: true}
		artifacts := &recordingArtifactService{downloadValue: artifact.Download{
			URL: "https://downloads.example/deterministic?expires=1787893500&signature=safe", ExpiresAt: time.Date(2026, 8, 28, 5, 5, 0, 0, time.UTC),
		}}
		services := Services{Artifacts: artifacts, Audit: audits, Idempotency: idempotency.NewService(gap)}
		principal := principalWith(platformTestScope, openapi.PermissionCreateArtifactDownload)
		firstRequest := newDownloadRequest("artifact-bare-processing")
		firstRequest.Header.Set("X-Request-ID", "request-artifact-original")
		firstRequest.Header.Set("traceparent", "00-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-ffffffffffffffff-01")
		first := servePlatformRequest(services, principal, firstRequest)
		requireProblem(t, first, http.StatusInternalServerError, "internal_error", "request-artifact-original")
		require.NotNil(t, gap.attempted)

		gap.fail = false
		retryRequest := newDownloadRequest("artifact-bare-processing")
		retryRequest.Header.Set("X-Request-ID", "request-artifact-retry")
		retryRequest.Header.Set("traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
		retry := servePlatformRequest(services, principal, retryRequest)
		require.Equal(t, http.StatusOK, retry.Code, retry.Body.String())
		require.Equal(t, gap.attempted.Body, retry.Body.Bytes())
		require.Equal(t, 2, artifacts.downloadCalls)
		require.Equal(t, artifacts.downloadIssuedAt[0], artifacts.downloadIssuedAt[1])
		assertHTTPReconciliationRows(t, ctx, database, "artifact-bare-processing", "request-artifact-original", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	})
}

func assertHTTPReconciliationRows(t *testing.T, ctx context.Context, database *sql.DB, idempotencyKey, requestID, traceID string) {
	t.Helper()
	var state string
	require.NoError(t, database.QueryRowContext(ctx, `SELECT state FROM idempotency_records WHERE tenant_id = $1 AND project_id = $2 AND idempotency_key = $3`, platformTestScope.TenantID, platformTestScope.ProjectID, idempotencyKey).Scan(&state))
	require.Equal(t, string(idempotency.StateCompleted), state)
	var auditCount int
	var storedRequestID, storedTraceID string
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*), min(request_id), min(trace_id) FROM audit_events WHERE tenant_id = $1 AND project_id = $2`, platformTestScope.TenantID, platformTestScope.ProjectID).Scan(&auditCount, &storedRequestID, &storedTraceID))
	require.Equal(t, 1, auditCount)
	require.Equal(t, requestID, storedRequestID)
	require.Equal(t, traceID, storedTraceID)
}

type postCommitErrorAuditService struct {
	inner *audit.Service
	fail  bool
}

func (service *postCommitErrorAuditService) RecordOnce(ctx context.Context, event audit.Event) (audit.Event, error) {
	recorded, err := service.inner.RecordOnce(ctx, event)
	if err != nil {
		return audit.Event{}, err
	}
	if service.fail {
		service.fail = false
		return audit.Event{}, errors.New("audit commit acknowledgement lost")
	}
	return recorded, nil
}

func (service *postCommitErrorAuditService) List(ctx context.Context, scope platformscope.Scope, query audit.ListQuery) (audit.Page, error) {
	return service.inner.List(ctx, scope, query)
}

type markAuditedErrorStore struct {
	inner idempotency.Store
	fail  bool
}

type commitSideEffectGapStore struct {
	inner     idempotency.Store
	fail      bool
	attempted *idempotency.Response
}

func (store *commitSideEffectGapStore) Claim(ctx context.Context, request idempotency.ClaimRequest) (idempotency.Claim, error) {
	return store.inner.Claim(ctx, request)
}

func (store *commitSideEffectGapStore) CommitSideEffect(ctx context.Context, key idempotency.Key, fingerprint, owner string, response idempotency.Response, reconciliation []byte, at time.Time) (idempotency.Response, error) {
	copyResponse := idempotency.Response{Status: response.Status, Header: response.Header.Clone(), Body: append([]byte(nil), response.Body...)}
	store.attempted = &copyResponse
	if store.fail {
		return idempotency.Response{}, errors.New("injected crash before CommitSideEffect")
	}
	return store.inner.CommitSideEffect(ctx, key, fingerprint, owner, response, reconciliation, at)
}

func (store *commitSideEffectGapStore) MarkAudited(ctx context.Context, key idempotency.Key, fingerprint, owner string, at time.Time) error {
	return store.inner.MarkAudited(ctx, key, fingerprint, owner, at)
}

func (store *commitSideEffectGapStore) Complete(ctx context.Context, key idempotency.Key, fingerprint, owner string, response idempotency.Response, at time.Time) (idempotency.Response, error) {
	return store.inner.Complete(ctx, key, fingerprint, owner, response, at)
}

func (store *commitSideEffectGapStore) Abort(ctx context.Context, key idempotency.Key, fingerprint, owner string) error {
	return store.inner.Abort(ctx, key, fingerprint, owner)
}

type countingCancellationJobService struct {
	inner       *job.PostgresRepository
	cancelCalls int
}

func (service *countingCancellationJobService) Get(ctx context.Context, scope platformscope.Scope, id string) (job.Job, error) {
	return service.inner.Get(ctx, scope, id)
}

func (service *countingCancellationJobService) RequestCancelWithSnapshot(ctx context.Context, scope platformscope.Scope, id, actor string, version int64, at time.Time, input job.CancellationSnapshotInput) (job.Job, error) {
	service.cancelCalls++
	return service.inner.RequestCancelWithSnapshot(ctx, scope, id, actor, version, at, input)
}

func (service *countingCancellationJobService) GetCancellationSnapshot(ctx context.Context, scope platformscope.Scope, id string, key job.CancellationSnapshotKey) (job.CancellationSnapshot, error) {
	return service.inner.GetCancellationSnapshot(ctx, scope, id, key)
}

func (store *markAuditedErrorStore) Claim(ctx context.Context, request idempotency.ClaimRequest) (idempotency.Claim, error) {
	return store.inner.Claim(ctx, request)
}

func (store *markAuditedErrorStore) CommitSideEffect(ctx context.Context, key idempotency.Key, fingerprint, owner string, response idempotency.Response, reconciliation []byte, at time.Time) (idempotency.Response, error) {
	return store.inner.CommitSideEffect(ctx, key, fingerprint, owner, response, reconciliation, at)
}

func (store *markAuditedErrorStore) MarkAudited(ctx context.Context, key idempotency.Key, fingerprint, owner string, at time.Time) error {
	if store.fail {
		store.fail = false
		return errors.New("mark audited acknowledgement lost")
	}
	return store.inner.MarkAudited(ctx, key, fingerprint, owner, at)
}

func (store *markAuditedErrorStore) Complete(ctx context.Context, key idempotency.Key, fingerprint, owner string, response idempotency.Response, at time.Time) (idempotency.Response, error) {
	return store.inner.Complete(ctx, key, fingerprint, owner, response, at)
}

func (store *markAuditedErrorStore) Abort(ctx context.Context, key idempotency.Key, fingerprint, owner string) error {
	return store.inner.Abort(ctx, key, fingerprint, owner)
}

func openHTTPIntegrationDatabase(t *testing.T, ctx context.Context, dsn, suffix string) *sql.DB {
	t.Helper()
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, admin.PingContext(ctx))
	schema := fmt.Sprintf("http_audit_%s_%d", suffix, time.Now().UnixNano())
	quotedSchema := pq.QuoteIdentifier(schema)
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := admin.ExecContext(context.Background(), "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE")
		require.NoError(t, cleanupErr)
		require.NoError(t, admin.Close())
	})
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	database, err := sql.Open("postgres", parsed.String())
	require.NoError(t, err)
	require.NoError(t, database.PingContext(ctx))
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	return database
}
