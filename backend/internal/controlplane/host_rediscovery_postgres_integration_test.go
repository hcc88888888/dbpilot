package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/audit"
	discoverydomain "dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/rediscovery"
	"github.com/stretchr/testify/require"
)

func TestPostgresRediscoverHostLostResponseReplaysOneJobOutboxAndAudit(t *testing.T) {
	if os.Getenv("DBPILOT_HTTP_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_HTTP_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_HTTP_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_HTTP_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database := openHTTPIntegrationDatabase(t, ctx, dsn, "host_rediscovery")
	require.NoError(t, job.RunMigrations(ctx, database))
	now := time.Now().UTC().Truncate(time.Millisecond)
	host := validManagedHost()
	host.Status, host.ContainerRuntime = hostinventory.HostOnline, hostinventory.ContainerRuntimeDocker
	host.Capabilities = []hostinventory.Capability{{Name: "native_discovery_v1", Available: true}, {Name: "docker_discovery_v1", Available: true}}
	host.LastHeartbeatAt = now
	hosts := &recordingHostService{getValue: host}
	policy := discoverydomain.RuleAttestation{Version: discoverydomain.RuleAttestationVersion, Algorithm: discoverydomain.RuleAttestationAlgorithm, KeyID: "key-a", Revision: 7, Digest: sha256.Sum256([]byte("rules")), IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), DisappearanceGrace: 10 * time.Minute}
	jobRepository := job.NewPostgresRepository(database)
	lost := &lostRediscoveryJobStore{inner: jobRepository, failOnce: true}
	application := &rediscovery.RediscoveryCoordinator{Hosts: hosts, Jobs: lost, Capabilities: rediscoveryCapabilities{}, Policies: []discoverydomain.RuleAttestation{policy}, RuleKeys: map[string]ed25519.PublicKey{"key-a": make(ed25519.PublicKey, ed25519.PublicKeySize)}, Now: func() time.Time { return now }}
	services := Services{HostRediscovery: application, Idempotency: idempotency.NewService(idempotency.NewPostgresStore(database)), Audit: audit.NewService(audit.NewPostgresStore(database))}
	principal := principalWith(platformTestScope, openapi.PermissionRediscoverHost)

	first := servePlatformRequest(services, principal, newRediscoverHostRequest("rediscover-pg-lost"))
	var committedJobID, committedCommandID string
	require.NoError(t, database.QueryRowContext(ctx, `SELECT value.id,outbox.id FROM jobs value JOIN command_outbox outbox ON outbox.tenant_id=value.tenant_id AND outbox.project_id=value.project_id AND outbox.job_id=value.id WHERE value.job_type='host.rediscover'`).Scan(&committedJobID, &committedCommandID))
	committedJob, committedMessage, snapshotErr := jobRepository.GetOperation(ctx, platformTestScope, committedJobID, committedCommandID)
	require.NoError(t, snapshotErr)
	require.Equal(t, committedJob.ID, committedMessage.JobID)
	hosts.getValue.Status = hostinventory.HostOffline
	retry := servePlatformRequest(services, principal, newRediscoverHostRequest("rediscover-pg-lost"))
	var idempotencyState string
	var responseStatus int
	require.NoError(t, database.QueryRowContext(ctx, `SELECT state,response_status FROM idempotency_records WHERE operation_id='rediscoverHost'`).Scan(&idempotencyState, &responseStatus))
	require.Equal(t, "completed", idempotencyState)
	require.Equal(t, 202, responseStatus)

	require.Equal(t, 500, first.Code, first.Body.String())
	require.Equal(t, 202, retry.Code, retry.Body.String())
	for table := range map[string]struct{}{"jobs": {}, "command_outbox": {}, "audit_events": {}} {
		var count int
		require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count))
		require.Equal(t, 1, count, table)
	}
}

type lostRediscoveryJobStore struct {
	inner             *job.PostgresRepository
	failOnce          bool
	hideOperationOnce bool
}

func (store *lostRediscoveryJobStore) CreateWithOutbox(ctx context.Context, value job.Job, messages []job.OutboxMessage) error {
	err := store.inner.CreateWithOutbox(ctx, value, messages)
	if err == nil && store.failOnce {
		store.failOnce = false
		store.hideOperationOnce = true
		return errors.New("simulated lost PostgreSQL commit response")
	}
	return err
}
func (store *lostRediscoveryJobStore) Get(ctx context.Context, scope platformscope.Scope, id string) (job.Job, error) {
	return store.inner.Get(ctx, scope, id)
}
func (store *lostRediscoveryJobStore) GetOperation(ctx context.Context, scope platformscope.Scope, jobID, commandID string) (job.Job, job.OutboxMessage, error) {
	if store.hideOperationOnce {
		store.hideOperationOnce = false
		return job.Job{}, job.OutboxMessage{}, errors.New("simulated operation snapshot loss")
	}
	return store.inner.GetOperation(ctx, scope, jobID, commandID)
}

type rediscoveryCapabilities struct{}

func (rediscoveryCapabilities) Supports(_ string, _ ...string) bool { return true }
