package enrollment

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/platformscope"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestEnrollmentPostgresIntegrationConcurrentCompletionExpiryAndLostResponseRecovery(t *testing.T) {
	if os.Getenv("DBPILOT_ENROLLMENT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ENROLLMENT_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_ENROLLMENT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ENROLLMENT_POSTGRES_DSN is required")
	}
	database, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	ctx := context.Background()
	require.NoError(t, database.PingContext(ctx))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scope := platformscope.Scope{TenantID: "tenant-enroll-" + suffix, ProjectID: "project-enroll-" + suffix}
	hostID, agentID := "host-enroll-"+suffix, "agent-enroll-"+suffix
	issuedBy := "integration-" + suffix
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), "DELETE FROM agent_enrollment_issuances WHERE tenant_id = $1 AND project_id = $2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM host_observations WHERE tenant_id = $1 AND project_id = $2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM managed_hosts WHERE tenant_id = $1 AND project_id = $2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM agent_enrollment_tokens WHERE tenant_id = $1 AND project_id = $2", scope.TenantID, scope.ProjectID)
	})
	now := time.Now().UTC().Truncate(time.Microsecond)
	raw := sha256.Sum256([]byte("token-" + suffix))
	token := EnrollmentToken{
		TokenHash: HashToken(raw[:]), Scope: scope, HostID: hostID, AgentID: agentID, DisplayName: "Integration Host", Labels: map[string]string{"test": "enrollment"},
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, EnrollmentRevision: 1, IssuedBy: issuedBy, IdempotencyKey: "create", RequestFingerprint: "sha256:" + fmt.Sprintf("%064x", 1), Generation: 1,
	}
	repository := NewPostgresRepository(database)
	creation, err := repository.Create(ctx, token)
	require.NoError(t, err)
	require.Equal(t, uint64(1), creation.Generation)
	oldHash := token.TokenHash
	replacementRaw := sha256.Sum256([]byte("replacement-token-" + suffix))
	token.TokenHash = HashToken(replacementRaw[:])
	creation, err = repository.Create(ctx, token)
	require.NoError(t, err)
	require.True(t, creation.Replaced)
	require.Equal(t, uint64(2), creation.Generation)
	csrDigest := sha256.Sum256([]byte("csr-" + suffix))
	key := EnrollmentAttemptKey{TokenHash: token.TokenHash, CSRDigest: csrDigest, AgentID: agentID, HostID: hostID}
	_, err = repository.Resolve(ctx, EnrollmentAttemptKey{TokenHash: oldHash, CSRDigest: csrDigest, AgentID: agentID, HostID: hostID})
	require.ErrorIs(t, err, ErrEnrollmentTokenInvalid, "replacement must atomically invalidate the unreachable token")
	grant := token.Grant()
	observation := hostinventory.Observation{
		HostID: hostID, AgentID: agentID, Revision: 1, AgentVersion: "integration", Hostname: "integration.example",
		OS: "linux", Architecture: "amd64", LogicalCPUCount: 2, MemoryCapacityBytes: 1 << 30,
		NetworkAddresses: []string{"127.0.0.1"}, Capabilities: []string{"host.inventory.v1"}, ObservedAt: now,
	}
	want := EnrollResult{
		HostID: hostID, AgentID: agentID, CertificatePEM: []byte("public-certificate"), CertificateChainPEM: []byte("public-chain"),
		ExpiresAt: now.Add(24 * time.Hour), EnrollmentRevision: 1,
	}
	completion := EnrollmentCompletion{Key: key, Grant: grant, Observation: observation, Result: want, CompletedAt: now}

	const consumers = 24
	results := make(chan EnrollResult, consumers)
	errorsChannel := make(chan error, consumers)
	var wait sync.WaitGroup
	for index := 0; index < consumers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, completeErr := repository.Complete(ctx, completion)
			if completeErr != nil {
				resolved, resolveErr := repository.Resolve(ctx, key)
				if resolveErr != nil || resolved.Response == nil {
					errorsChannel <- errors.Join(completeErr, resolveErr)
					return
				}
				result = *resolved.Response
			}
			results <- result
		}()
	}
	wait.Wait()
	close(results)
	close(errorsChannel)
	for completeErr := range errorsChannel {
		require.NoError(t, completeErr)
	}
	count := 0
	for result := range results {
		count++
		require.Equal(t, want, result)
	}
	require.Equal(t, consumers, count)
	var issuanceCount, hostCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM agent_enrollment_issuances WHERE token_hash = $1", token.TokenHash[:]).Scan(&issuanceCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM managed_hosts WHERE tenant_id = $1 AND project_id = $2 AND host_id = $3", scope.TenantID, scope.ProjectID, hostID).Scan(&hostCount))
	require.Equal(t, 1, issuanceCount)
	require.Equal(t, 1, hostCount)
	// Simulate a lost RPC response after COMMIT: exact Resolve returns the public response.
	recovered, err := repository.Resolve(ctx, key)
	require.NoError(t, err)
	require.Equal(t, want, *recovered.Response)

	expiredRaw := sha256.Sum256([]byte("expired-" + suffix))
	expired := token
	expired.TokenHash, expired.AgentID, expired.HostID, expired.IdempotencyKey = HashToken(expiredRaw[:]), agentID+"-expired", hostID+"-expired", "expired"
	expired.CreatedAt, expired.ExpiresAt = now.Add(-2*time.Hour), now.Add(-time.Hour)
	_, err = repository.Create(ctx, expired)
	require.NoError(t, err)
	expiredKey := EnrollmentAttemptKey{TokenHash: expired.TokenHash, CSRDigest: csrDigest, AgentID: expired.AgentID, HostID: expired.HostID}
	_, err = repository.Resolve(ctx, expiredKey)
	require.ErrorIs(t, err, ErrEnrollmentTokenInvalid, "database CURRENT_TIMESTAMP controls the expiry boundary")
}
