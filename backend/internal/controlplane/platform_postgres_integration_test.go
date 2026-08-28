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
