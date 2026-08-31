package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/pluginassignment"
	"dbpilot.local/platform/internal/plugincatalog"
	"dbpilot.local/platform/internal/reconciliation"
	"github.com/stretchr/testify/require"
)

func TestPluginAssignmentReconcileConcurrentExactRetriesUsePostgresResponse(t *testing.T) {
	if os.Getenv("DBPILOT_HTTP_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_HTTP_POSTGRES_INTEGRATION=1")
	}
	ctx := context.Background()
	database := openHTTPIntegrationDatabase(t, ctx, os.Getenv("DBPILOT_HTTP_POSTGRES_DSN"), "plugin_reconcile_concurrent")
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	assignment := validControlPlaneAssignment(now)
	service := &recordingPluginAssignmentService{value: assignment}
	timeout := now.Add(time.Hour)
	authoritative := job.Job{ID: "job-plugin-pg", Type: "plugin.reconcile", Scope: platformTestScope, Status: job.StatusQueued, Outcome: job.OutcomeNone, TargetResourceIDs: []string{"agent-a"}, InitiatedBy: "plugin-reconciler", SourceResource: job.ResourceReference{ResourceType: "plugin_assignment", ResourceID: assignment.ID}, IdempotencyKey: "plugin-reconcile:pg", Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: now, TimeoutAt: &timeout, MaxConcurrency: 1, TargetTimeout: time.Minute, RequestID: "request-job-pg", TraceID: "trace-job-pg"}
	reconciler := &recordingPluginAssignmentReconciler{value: authoritative, after: func() { service.setReconcileState(pluginassignment.ReconcileWaiting, "operation_in_flight", 5) }}
	gap := &commitSideEffectGapStore{inner: idempotency.NewPostgresStore(database), fail: true, commitThenFail: true}
	services := Services{PluginAssignments: service, PluginReconciler: reconciler, Idempotency: idempotency.NewService(gap), Now: func() time.Time { return now }}
	request := func() *http.Request {
		value := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-assignments/assignment-a/actions/reconcile", nil)
		value.Header.Set("Idempotency-Key", "reconcile-pg")
		return value
	}
	failed := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request())
	require.Equal(t, http.StatusInternalServerError, failed.Code)
	gap.fail = false
	const consumers = 24
	responses := make(chan *httptest.ResponseRecorder, consumers)
	var wait sync.WaitGroup
	for index := 0; index < consumers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses <- servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request())
		}()
	}
	wait.Wait()
	close(responses)
	var body string
	for response := range responses {
		require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
		require.Equal(t, `"1"`, response.Header().Get("ETag"))
		if body == "" {
			body = response.Body.String()
		} else {
			require.JSONEq(t, body, response.Body.String())
		}
	}
}

func TestPluginAssignmentReconcileLost202PrefersRealPersistedJobOverLaterState(t *testing.T) {
	if os.Getenv("DBPILOT_HTTP_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_HTTP_POSTGRES_INTEGRATION=1")
	}
	ctx := context.Background()
	database := openHTTPIntegrationDatabase(t, ctx, os.Getenv("DBPILOT_HTTP_POSTGRES_DSN"), "plugin_reconcile_real_job")
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, job.RunMigrations(ctx, database))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	require.NoError(t, discovery.RunMigrations(ctx, database))
	require.NoError(t, databaseinstance.RunMigrations(ctx, database))
	require.NoError(t, plugincatalog.RunMigrations(ctx, database))
	require.NoError(t, pluginassignment.RunMigrations(ctx, database))
	now := time.Now().UTC().Truncate(time.Microsecond)
	hostID, agentID := "host-real", "agent-real"
	hostRepo := hostinventory.NewPostgresRepository(database)
	_, err := hostRepo.RecordObservation(ctx, platformTestScope, hostinventory.Observation{HostID: hostID, AgentID: agentID, Revision: 1, AgentVersion: "test", Hostname: "real.test", OS: "linux", Architecture: "amd64", LogicalCPUCount: 2, MemoryCapacityBytes: 1024, NetworkAddresses: []string{}, Capabilities: []string{"plugin.reconcile.v1"}, ObservedAt: now}, now)
	require.NoError(t, err)
	_, err = hostRepo.RecordHeartbeat(ctx, platformTestScope, agentID, now)
	require.NoError(t, err)
	_, err = database.Exec(`INSERT INTO artifacts (id,tenant_id,project_id,kind,content_type,size_bytes,checksum,created_by,created_at,storage_reference) VALUES ('artifact-real',$1,$2,'plugin_package','application/gzip',1,$3,'test',$4,'sha256/test')`, platformTestScope.TenantID, platformTestScope.ProjectID, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now)
	require.NoError(t, err)
	_, err = database.Exec(`INSERT INTO plugin_definitions (tenant_id,project_id,plugin_id,name,database_family,protocol_version,supported_variants,capabilities) VALUES ($1,$2,'dbpilot.mysql','MySQL','mysql','1','["mysql"]'::jsonb,'["metrics"]'::jsonb)`, platformTestScope.TenantID, platformTestScope.ProjectID)
	require.NoError(t, err)
	_, err = database.Exec(`INSERT INTO plugin_versions (version_id,tenant_id,project_id,plugin_id,semantic_version,status,artifact_id,package_sha256,manifest_digest,publisher_id,signing_key_id,protocol_version,minimum_agent_protocol_version,maximum_agent_protocol_version,supported_variants,database_version_range,capabilities,metric_template_schema_version,platforms,revision,created_at,approved_at) VALUES ('version-real',$1,$2,'dbpilot.mysql','1.0.0','available','artifact-real',$3,$4,'publisher','key','1','1','1','["mysql"]'::jsonb,'>=5.7','["metrics"]'::jsonb,1,'[{"operating_system":"linux","architecture":"amd64","sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","size_bytes":1}]'::jsonb,1,$5,$5)`, platformTestScope.TenantID, platformTestScope.ProjectID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now)
	require.NoError(t, err)
	fingerprint := sha256.Sum256([]byte("candidate-real"))
	digest := make([]byte, 32)
	_, err = database.Exec(`INSERT INTO discovery_scan_state (tenant_id,project_id,host_id,agent_id,observation_revision,rule_revision,report_digest,observed_at,received_at,rule_set_digest,disappearance_grace_seconds,agent_observed_at) VALUES ($1,$2,$3,$4,1,1,$5,$6,$6,$5,600,$6)`, platformTestScope.TenantID, platformTestScope.ProjectID, hostID, agentID, digest, now)
	require.NoError(t, err)
	_, err = database.Exec(`INSERT INTO discovery_scan_sources (tenant_id,project_id,host_id,discovery_source,result_status,reason_code,observation_revision,rule_revision,rule_set_digest,observed_at,updated_at) VALUES ($1,$2,$3,'native','completed','healthy',1,1,$4,$5,$5)`, platformTestScope.TenantID, platformTestScope.ProjectID, hostID, digest, now)
	require.NoError(t, err)
	_, err = database.Exec(`INSERT INTO discovery_candidates (candidate_id,tenant_id,project_id,host_id,agent_id,observation_id,discovery_source,database_family,database_variant,normalized_endpoint,process_identity,confidence,evidence_summary,fingerprint,rule_revision,observation_revision,first_seen_at,last_seen_at,status,updated_at) VALUES ('candidate-real',$1,$2,$3,$4,'candidate-real','native','mysql','mysql','127.0.0.1:3306','mysql-real',0.9,'[]'::jsonb,$5,1,1,$6,$6,'awaiting_confirmation',$6)`, platformTestScope.TenantID, platformTestScope.ProjectID, hostID, agentID, fingerprint[:], now)
	require.NoError(t, err)
	jobRepo := job.NewPostgresRepositoryWithTargetAuthorizer(database, pluginassignment.InstanceTargetAuthorizer{Database: database})
	assignmentRepo := pluginassignment.NewPostgresRepository(database, jobRepo)
	instanceRepo := databaseinstance.NewPostgresRepositoryWithProvisioner(database, assignmentRepo)
	_, err = instanceRepo.AcceptCandidate(ctx, platformTestScope, "candidate-real", databaseinstance.AcceptCandidateRequest{DisplayName: "real", DatabaseFamily: "mysql", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", CredentialRef: "secret://vault/mysql", Labels: map[string]string{}, ExpectedCandidateRevision: 1, CandidateFingerprint: fmt.Sprintf("%x", fingerprint[:]), Audit: databaseinstance.MutationAudit{Actor: "operator", OperationID: "acceptDiscoveryCandidate", IdempotencyKey: "accept-real", RequestFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RequestID: "request-accept-real"}})
	require.NoError(t, err)
	page, err := assignmentRepo.List(ctx, platformTestScope, pluginassignment.Filter{})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	assignmentService := pluginassignment.NewService(assignmentRepo)
	pluginReconciler := reconciliation.NewPluginReconciler(assignmentRepo)
	gap := &commitSideEffectGapStore{inner: idempotency.NewPostgresStore(database), fail: true, commitThenFail: true}
	services := Services{PluginAssignments: assignmentService, PluginReconciler: pluginReconciler, Idempotency: idempotency.NewService(gap), Now: func() time.Time { return now }}
	request := func() *http.Request {
		value := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-assignments/"+page.Items[0].ID+"/actions/reconcile", nil)
		value.Header.Set("Idempotency-Key", "reconcile-real-lost")
		value.Header.Set("X-Request-ID", "request-real-original")
		return value
	}
	first := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request())
	require.Equal(t, http.StatusInternalServerError, first.Code)
	var storedStatus int
	var storedETag, storedLocation string
	require.NoError(t, database.QueryRow(`SELECT response_status,response_headers->'ETag'->>0,response_headers->'Location'->>0 FROM idempotency_records WHERE tenant_id=$1 AND project_id=$2 AND operation_id='reconcilePluginAssignment' AND idempotency_key='reconcile-real-lost'`, platformTestScope.TenantID, platformTestScope.ProjectID).Scan(&storedStatus, &storedETag, &storedLocation))
	require.Equal(t, http.StatusAccepted, storedStatus)
	require.Equal(t, `"1"`, storedETag)
	require.NotEmpty(t, storedLocation)
	_, err = database.Exec(`UPDATE plugin_assignments SET reconcile_state='converged',blocked_reason='',revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, platformTestScope.TenantID, platformTestScope.ProjectID, page.Items[0].ID)
	require.NoError(t, err)
	gap.fail = false
	services.Now = func() time.Time { return now.Add(8 * time.Hour) }
	const consumers = 24
	responses := make(chan *httptest.ResponseRecorder, consumers)
	var wait sync.WaitGroup
	for index := 0; index < consumers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses <- servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request())
		}()
	}
	wait.Wait()
	close(responses)
	var body []byte
	var location string
	var etag string
	for response := range responses {
		require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
		if body == nil {
			body = append([]byte(nil), response.Body.Bytes()...)
			location = response.Header().Get("Location")
			etag = response.Header().Get("ETag")
			require.NotEmpty(t, location)
			require.Equal(t, `"1"`, etag)
		} else {
			require.Equal(t, body, response.Body.Bytes())
			require.Equal(t, location, response.Header().Get("Location"))
			require.Equal(t, etag, response.Header().Get("ETag"))
		}
	}
	_, err = database.Exec(`UPDATE plugin_assignments SET reconcile_state='state_conflict',blocked_reason='',revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, platformTestScope.TenantID, platformTestScope.ProjectID, page.Items[0].ID)
	require.NoError(t, err)
	conflicted := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request())
	require.Equal(t, http.StatusAccepted, conflicted.Code, conflicted.Body.String())
	require.Equal(t, body, conflicted.Body.Bytes())
	require.Equal(t, location, conflicted.Header().Get("Location"))
	require.Equal(t, etag, conflicted.Header().Get("ETag"))
	var jobCount, outboxCount int
	require.NoError(t, database.QueryRow(`SELECT count(*) FROM jobs WHERE tenant_id=$1 AND project_id=$2 AND job_type='plugin.reconcile'`, platformTestScope.TenantID, platformTestScope.ProjectID).Scan(&jobCount))
	require.NoError(t, database.QueryRow(`SELECT count(*) FROM command_outbox WHERE tenant_id=$1 AND project_id=$2`, platformTestScope.TenantID, platformTestScope.ProjectID).Scan(&outboxCount))
	require.Equal(t, 1, jobCount)
	require.Equal(t, 1, outboxCount)
}

func TestPluginAssignmentReconcileLostResponseRecoversExactAuthoritativeJob(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	assignment := validControlPlaneAssignment(now)
	service := &recordingPluginAssignmentService{value: assignment}
	timeout := now.Add(time.Hour)
	authoritative := job.Job{ID: "job-plugin-a", Type: "plugin.reconcile", Scope: platformTestScope, Status: job.StatusQueued, Outcome: job.OutcomeNone, TargetResourceIDs: []string{"agent-a"}, InitiatedBy: "plugin-reconciler", SourceResource: job.ResourceReference{ResourceType: "plugin_assignment", ResourceID: assignment.ID}, IdempotencyKey: "plugin-reconcile:a", Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: now, TimeoutAt: &timeout, MaxConcurrency: 1, TargetTimeout: time.Minute, RequestID: "request-job", TraceID: "trace-job"}
	reconciler := &recordingPluginAssignmentReconciler{value: authoritative}
	store := newHTTPIdempotencyStore()
	store.completeErr = errors.New("lost HTTP response after durable Job")
	services := Services{PluginAssignments: service, PluginReconciler: reconciler, Idempotency: idempotency.NewService(store), Now: func() time.Time { return now }}
	request := func() *http.Request {
		value := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-assignments/assignment-a/actions/reconcile", bytes.NewReader(nil))
		value.Header.Set("Idempotency-Key", "reconcile-lost")
		return value
	}
	first := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request())
	require.Equal(t, http.StatusInternalServerError, first.Code)
	service.setReconcileState(pluginassignment.ReconcileConverged, "", 6)
	store.completeErr = nil
	services.Now = func() time.Time { return now.Add(8 * time.Hour) }
	var wait sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 2)
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses <- servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request())
		}()
	}
	wait.Wait()
	close(responses)
	var body string
	for retry := range responses {
		require.Equal(t, http.StatusAccepted, retry.Code, retry.Body.String())
		require.Equal(t, `"1"`, retry.Header().Get("ETag"))
		require.Contains(t, retry.Body.String(), now.Format(time.RFC3339))
		if body == "" {
			body = retry.Body.String()
		} else {
			require.JSONEq(t, body, retry.Body.String())
		}
	}
	require.Equal(t, authoritative.ID, reconciler.value.ID)
	require.Equal(t, 1, reconciler.callCount(), "exact recovery must load persisted Job before current assignment state or a second reconcile")
}

func TestPluginAssignmentReconcileCompletesDurableConflictProblemForExactRetry(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		state  pluginassignment.ReconcileState
		reason string
		err    error
		code   string
	}{
		{name: "agent offline", state: pluginassignment.ReconcileWaiting, reason: "agent_offline", err: pluginassignment.ErrConflict, code: "conflict"},
		{name: "observation stale", state: pluginassignment.ReconcileWaiting, reason: "observation_stale", err: pluginassignment.ErrConflict, code: "conflict"},
		{name: "rollout pending", state: pluginassignment.ReconcileWaiting, reason: "rollout_pending", err: pluginassignment.ErrConflict, code: "conflict"},
		{name: "version revoked", state: pluginassignment.ReconcileBlocked, reason: "version_revoked", err: pluginassignment.ErrVersionRevoked, code: "plugin_version_revoked"},
		{name: "future revision conflict", state: pluginassignment.ReconcileConflict, err: pluginassignment.ErrConflict, code: "conflict"},
		{name: "already converged", state: pluginassignment.ReconcileConverged, err: pluginassignment.ErrConflict, code: "conflict"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectedReason := test.reason
			if expectedReason == "" {
				if test.state == pluginassignment.ReconcileConflict {
					expectedReason = "state_conflict"
				} else {
					expectedReason = "already_converged"
				}
			}
			assignment := validControlPlaneAssignment(now)
			service := &recordingPluginAssignmentService{value: assignment}
			reconciler := &recordingPluginAssignmentReconciler{err: test.err, after: func() {
				service.setReconcileState(test.state, test.reason, 6)
			}}
			store := newHTTPIdempotencyStore()
			services := Services{PluginAssignments: service, PluginReconciler: reconciler, Idempotency: idempotency.NewService(store), Now: func() time.Time { return now }}
			request := func(requestID string) *http.Request {
				value := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-assignments/assignment-a/actions/reconcile", nil)
				value.Header.Set("Idempotency-Key", "reconcile-fixed-"+expectedReason)
				value.Header.Set("X-Request-ID", requestID)
				return value
			}

			firstRequest := request("request-original-" + expectedReason)
			first := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), firstRequest)
			firstProblem := requireProblem(t, first, http.StatusConflict, test.code, "request-original-"+expectedReason)
			require.NotNil(t, firstProblem.Detail)
			require.Equal(t, expectedReason, *firstProblem.Detail)
			require.Equal(t, `"6"`, first.Header().Get("ETag"))
			requireOpenAPIResponse(t, firstRequest, first)

			retryRequest := request("request-retry-" + expectedReason)
			retry := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), retryRequest)
			require.Equal(t, first.Code, retry.Code)
			require.Equal(t, first.Header().Get("Content-Type"), retry.Header().Get("Content-Type"))
			require.Equal(t, first.Header().Get("ETag"), retry.Header().Get("ETag"))
			require.Equal(t, first.Body.Bytes(), retry.Body.Bytes())
			requireOpenAPIResponse(t, retryRequest, retry)
			require.Equal(t, 1, service.forceCallCount())
			require.Equal(t, 1, reconciler.callCount(), "a waiting or blocked assignment must not be claimed again")
			require.Equal(t, 0, store.abortCalls)
		})
	}
}

func TestPluginAssignmentReconcileLostProblemResponseReplaysWithoutClaimingWaitingAssignment(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	service := &recordingPluginAssignmentService{value: validControlPlaneAssignment(now)}
	reconciler := &recordingPluginAssignmentReconciler{err: pluginassignment.ErrConflict, after: func() {
		service.setReconcileState(pluginassignment.ReconcileWaiting, "agent_offline", 7)
	}}
	store := newHTTPIdempotencyStore()
	store.commitUnknownErr = errors.New("lost response after durable Problem marker")
	services := Services{PluginAssignments: service, PluginReconciler: reconciler, Idempotency: idempotency.NewService(store), Now: func() time.Time { return now }}
	request := func(requestID string) *http.Request {
		value := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-assignments/assignment-a/actions/reconcile", nil)
		value.Header.Set("Idempotency-Key", "reconcile-lost-problem")
		value.Header.Set("X-Request-ID", requestID)
		return value
	}

	first := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request("request-lost-problem"))
	require.Equal(t, http.StatusInternalServerError, first.Code, first.Body.String())
	store.commitUnknownErr = nil

	const consumers = 2
	responses := make(chan *httptest.ResponseRecorder, consumers)
	var wait sync.WaitGroup
	for index := 0; index < consumers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			responses <- servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request(fmt.Sprintf("request-lost-problem-retry-%d", index)))
		}(index)
	}
	wait.Wait()
	close(responses)
	var body []byte
	for response := range responses {
		problem := requireProblem(t, response, http.StatusConflict, "conflict", "request-lost-problem")
		require.NotNil(t, problem.Detail)
		require.Equal(t, "agent_offline", *problem.Detail)
		require.Equal(t, `"7"`, response.Header().Get("ETag"))
		if body == nil {
			body = append([]byte(nil), response.Body.Bytes()...)
		} else {
			require.Equal(t, body, response.Body.Bytes())
		}
	}
	require.Equal(t, 1, service.forceCallCount())
	require.Equal(t, 1, reconciler.callCount(), "lost-response recovery must not call ClaimOne on waiting state")
}

func TestPluginAssignmentReconcileConcurrentProcessingRetryDoesNotClaimWaitingAssignment(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	service := &recordingPluginAssignmentService{value: validControlPlaneAssignment(now)}
	started := make(chan struct{})
	release := make(chan struct{})
	reconciler := &recordingPluginAssignmentReconciler{
		err:          pluginassignment.ErrConflict,
		firstStarted: started,
		releaseFirst: release,
		after: func() {
			service.setReconcileState(pluginassignment.ReconcileWaiting, "observation_stale", 8)
		},
	}
	services := Services{PluginAssignments: service, PluginReconciler: reconciler, Idempotency: idempotency.NewService(newHTTPIdempotencyStore()), Now: func() time.Time { return now }}
	request := func(requestID string) *http.Request {
		value := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-assignments/assignment-a/actions/reconcile", nil)
		value.Header.Set("Idempotency-Key", "reconcile-concurrent-waiting")
		value.Header.Set("X-Request-ID", requestID)
		return value
	}

	firstResponses := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstResponses <- servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request("request-concurrent-original"))
	}()
	<-started
	second := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request("request-concurrent-retry"))
	close(release)
	first := <-firstResponses

	for _, response := range []*httptest.ResponseRecorder{first, second} {
		problem := requireProblem(t, response, http.StatusConflict, "conflict", "request-concurrent-original")
		require.NotNil(t, problem.Detail)
		require.Equal(t, "observation_stale", *problem.Detail)
		require.Equal(t, `"8"`, response.Header().Get("ETag"))
		require.Equal(t, "request-concurrent-original", response.Header().Get("X-Request-ID"))
	}
	require.Equal(t, first.Body.Bytes(), second.Body.Bytes())
	require.Equal(t, 1, reconciler.callCount(), "processing recovery must load the waiting Assignment before invoking ClaimOne")
}

func TestPluginAssignmentReconcileAbortsPreMutationNotFoundClaim(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	service := &recordingPluginAssignmentService{forceErr: pluginassignment.ErrNotFound}
	reconciler := &recordingPluginAssignmentReconciler{}
	store := newHTTPIdempotencyStore()
	services := Services{PluginAssignments: service, PluginReconciler: reconciler, Idempotency: idempotency.NewService(store), Now: func() time.Time { return now }}
	request := func() *http.Request {
		value := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-assignments/missing-assignment/actions/reconcile", nil)
		value.Header.Set("Idempotency-Key", "reconcile-missing")
		value.Header.Set("X-Request-ID", "request-reconcile-missing")
		return value
	}

	firstRequest := request()
	first := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), firstRequest)
	requireProblem(t, first, http.StatusNotFound, "not_found", "request-reconcile-missing")
	requireOpenAPIResponse(t, firstRequest, first)
	retryRequest := request()
	retry := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), retryRequest)
	requireProblem(t, retry, http.StatusNotFound, "not_found", "request-reconcile-missing")
	require.Equal(t, first.Body.Bytes(), retry.Body.Bytes())
	requireOpenAPIResponse(t, retryRequest, retry)
	require.Equal(t, 2, service.forceCallCount(), "aborting the failed claim must permit a fresh exact-key attempt")
	require.Equal(t, 0, reconciler.callCount())
	require.Equal(t, 2, store.abortCalls)
}

type recordingPluginAssignmentReconciler struct {
	value        job.Job
	err          error
	after        func()
	firstStarted chan struct{}
	releaseFirst chan struct{}
	calls        int
	mu           sync.Mutex
	scheduled    *job.Job
}

func (value *recordingPluginAssignmentReconciler) ReconcileAssignment(context.Context, pluginassignment.Assignment, time.Time) (job.Job, error) {
	value.mu.Lock()
	value.calls++
	call := value.calls
	result, err, after := value.value, value.err, value.after
	if err == nil && result.ID != "" {
		copy := result
		value.scheduled = &copy
	}
	firstStarted, releaseFirst := value.firstStarted, value.releaseFirst
	value.mu.Unlock()
	if after != nil {
		after()
	}
	if call == 1 && firstStarted != nil {
		close(firstStarted)
		<-releaseFirst
	}
	return result, err
}
func (value *recordingPluginAssignmentReconciler) FindScheduledJob(_ context.Context, _ pluginassignment.Assignment) (job.Job, bool, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.scheduled == nil {
		return job.Job{}, false, nil
	}
	return *value.scheduled, true, nil
}
func (value *recordingPluginAssignmentReconciler) callCount() int {
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.calls
}

func validControlPlaneAssignment(now time.Time) pluginassignment.Assignment {
	return pluginassignment.Assignment{ID: "assignment-a", Scope: platformTestScope, HostID: "host-a", AgentID: "agent-a", PluginID: "dbpilot.mysql", DatabaseFamily: "mysql", DesiredVersionID: "mysql-version-1", DesiredVersion: "1.2.3", ArtifactID: "artifact-a", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DesiredState: pluginassignment.DesiredRunning, ConfigurationRevision: 2, OperationRevision: 3, RolloutPercentage: 100, InstanceIDs: []string{"instance-a"}, TemplateRevisionIDs: []string{}, ReconcileState: pluginassignment.ReconcilePending, Revision: 4, CreatedAt: now, UpdatedAt: now}
}

func TestPluginAssignmentProblemsAreStableAndRedacted(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{{pluginassignment.ErrInvalid, http.StatusBadRequest, "invalid_request"}, {pluginassignment.ErrNotFound, http.StatusNotFound, "not_found"}, {pluginassignment.ErrConflict, http.StatusConflict, "conflict"}, {pluginassignment.ErrPrecondition, http.StatusPreconditionFailed, "state_revision_conflict"}, {pluginassignment.ErrVersionUnavailable, http.StatusUnprocessableEntity, "plugin_version_unavailable"}, {pluginassignment.ErrVersionRevoked, http.StatusConflict, "plugin_version_revoked"}}
	for _, test := range tests {
		problem := problemForError(test.err, "request-a", "/plugin-assignments/assignment-a")
		require.Equal(t, test.status, problem.Status)
		require.Equal(t, test.code, problem.Code)
		require.NotContains(t, problem.Title, test.err.Error())
	}
}

func TestPluginAssignmentGetUsesGeneratedPermissionScopeAndETag(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	value := pluginassignment.Assignment{ID: "assignment-a", Scope: platformTestScope, HostID: "host-a", AgentID: "agent-a", PluginID: "dbpilot.mysql", DatabaseFamily: "mysql", DesiredVersionID: "mysql-version-1", DesiredVersion: "1.2.3", ArtifactID: "artifact-a", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DesiredState: pluginassignment.DesiredRunning, ConfigurationRevision: 2, OperationRevision: 3, RolloutPercentage: 100, InstanceIDs: []string{"instance-a"}, TemplateRevisionIDs: []string{}, ReconcileState: pluginassignment.ReconcilePending, Revision: 4, CreatedAt: now, UpdatedAt: now}
	service := &recordingPluginAssignmentService{value: value}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/plugin-assignments/assignment-a", nil)
	response := servePlatformRequest(Services{PluginAssignments: service}, principalWith(platformTestScope, openapi.PermissionGetPluginAssignment), request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, `"4"`, response.Header().Get("ETag"))
	require.Contains(t, response.Body.String(), `"assignment_id":"assignment-a"`)
	require.Equal(t, platformTestScope, service.scope)
	requireOpenAPIResponse(t, request, response)
}

type recordingPluginAssignmentService struct {
	value      pluginassignment.Assignment
	forceErr   error
	scope      platformscope.Scope
	forceCalls int
	mu         sync.Mutex
}

func (service *recordingPluginAssignmentService) EnsureForInstance(context.Context, databaseinstance.Instance) (pluginassignment.Assignment, error) {
	return service.value, nil
}
func (service *recordingPluginAssignmentService) List(_ context.Context, scope platformscope.Scope, _ pluginassignment.Filter) (pluginassignment.Page, error) {
	service.scope = scope
	return pluginassignment.Page{Items: []pluginassignment.Assignment{service.value}}, nil
}
func (service *recordingPluginAssignmentService) Get(_ context.Context, scope platformscope.Scope, _ string) (pluginassignment.Assignment, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.scope = scope
	return service.value, nil
}
func (service *recordingPluginAssignmentService) SetDesiredState(context.Context, platformscope.Scope, string, uint64, pluginassignment.DesiredUpdate) (pluginassignment.Assignment, error) {
	return service.value, nil
}
func (service *recordingPluginAssignmentService) RecordObservation(context.Context, pluginassignment.ObservationReport) error {
	return nil
}
func (service *recordingPluginAssignmentService) ForceReconcile(context.Context, platformscope.Scope, string, pluginassignment.MutationAudit) (pluginassignment.Assignment, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.forceCalls++
	return service.value, service.forceErr
}
func (service *recordingPluginAssignmentService) setReconcileState(state pluginassignment.ReconcileState, reason string, revision uint64) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.value.ReconcileState = state
	service.value.BlockedReason = reason
	service.value.Revision = revision
}
func (service *recordingPluginAssignmentService) forceCallCount() int {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.forceCalls
}
