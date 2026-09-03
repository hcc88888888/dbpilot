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
	retry := servePlatformRequest(services, principal, newRediscoverHostRequest("rediscover-pg-lost"))

	require.Equal(t, 202, first.Code, first.Body.String())
	require.Equal(t, first.Body.String(), retry.Body.String())
	require.Equal(t, first.Header().Get("ETag"), retry.Header().Get("ETag"))
	require.Equal(t, first.Header().Get("Location"), retry.Header().Get("Location"))
	for table := range map[string]struct{}{"jobs": {}, "command_outbox": {}, "audit_events": {}} {
		var count int
		require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count))
		require.Equal(t, 1, count, table)
	}
}

type lostRediscoveryJobStore struct {
	inner    *job.PostgresRepository
	failOnce bool
}

func (store *lostRediscoveryJobStore) CreateWithOutbox(ctx context.Context, value job.Job, messages []job.OutboxMessage) error {
	err := store.inner.CreateWithOutbox(ctx, value, messages)
	if err == nil && store.failOnce {
		store.failOnce = false
		return errors.New("simulated lost PostgreSQL commit response")
	}
	return err
}
func (store *lostRediscoveryJobStore) Get(ctx context.Context, scope platformscope.Scope, id string) (job.Job, error) {
	return store.inner.Get(ctx, scope, id)
}

type rediscoveryCapabilities struct{}

func (rediscoveryCapabilities) Supports(_ string, _ ...string) bool { return true }
