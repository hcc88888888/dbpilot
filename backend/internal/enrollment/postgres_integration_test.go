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
	"dbpilot.local/platform/internal/platformdb"
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
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scope := platformscope.Scope{TenantID: "tenant-enroll-" + suffix, ProjectID: "project-enroll-" + suffix}
	hostID, agentID := "host-enroll-"+suffix, "agent-enroll-"+suffix
	issuedBy := "integration-" + suffix
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), "DELETE FROM audit_events WHERE tenant_id = $1 AND project_id = $2", scope.TenantID, scope.ProjectID)
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
		Audit: EnrollmentAudit{Actor: issuedBy, RequestID: "request-" + suffix, OperationID: "createHostEnrollment", IdempotencyKey: "create"},
	}
	repository := NewPostgresRepository(database)
	creation, err := repository.Create(ctx, token)
	require.NoError(t, err)
	require.Equal(t, uint64(1), creation.Generation)
	oldHash := token.TokenHash
	type replacementAttempt struct {
		token    EnrollmentToken
		creation EnrollmentTokenCreation
		err      error
	}
	const replacementConsumers = 24
	replacements := make(chan replacementAttempt, replacementConsumers)
	var replacementWait sync.WaitGroup
	for index := 0; index < replacementConsumers; index++ {
		candidate := token
		replacementRaw := sha256.Sum256([]byte(fmt.Sprintf("replacement-token-%s-%d", suffix, index)))
		candidate.TokenHash = HashToken(replacementRaw[:])
		candidate.IdempotencyKey = fmt.Sprintf("replace-%d", index)
		candidate.RequestFingerprint = "sha256:" + fmt.Sprintf("%064x", index+10)
		candidate.Audit = EnrollmentAudit{Actor: issuedBy, RequestID: fmt.Sprintf("request-%s-%d", suffix, index), OperationID: "replaceHostEnrollment", IdempotencyKey: candidate.IdempotencyKey}
		replacementWait.Add(1)
		go func() {
			defer replacementWait.Done()
			value, replaceErr := repository.Replace(ctx, candidate, 1)
			replacements <- replacementAttempt{token: candidate, creation: value, err: replaceErr}
		}()
	}
	replacementWait.Wait()
	close(replacements)
	winners := 0
	var losingHashes [][sha256.Size]byte
	for attempt := range replacements {
		if attempt.err == nil {
			winners++
			token = attempt.token
			require.Equal(t, EnrollmentTokenCreation{Generation: 2, Replaced: true}, attempt.creation)
			continue
		}
		require.ErrorIs(t, attempt.err, ErrEnrollmentGenerationConflict)
		losingHashes = append(losingHashes, attempt.token.TokenHash)
	}
	require.Equal(t, 1, winners, "generation CAS must return at most one replacement token")
	csrDigest := sha256.Sum256([]byte("csr-" + suffix))
	key := EnrollmentAttemptKey{TokenHash: token.TokenHash, CSRDigest: csrDigest, AgentID: agentID, HostID: hostID}
	_, err = repository.Resolve(ctx, EnrollmentAttemptKey{TokenHash: oldHash, CSRDigest: csrDigest, AgentID: agentID, HostID: hostID})
	require.ErrorIs(t, err, ErrEnrollmentTokenInvalid, "replacement must atomically invalidate the unreachable token")
	for _, losingHash := range losingHashes {
		_, err = repository.Resolve(ctx, EnrollmentAttemptKey{TokenHash: losingHash, CSRDigest: csrDigest, AgentID: agentID, HostID: hostID})
		require.ErrorIs(t, err, ErrEnrollmentTokenInvalid, "a losing replacement must never produce a valid token")
	}
	var enrollmentAuditCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND action IN ('host.enrollment_created', 'host.enrollment_replaced')", scope.TenantID, scope.ProjectID).Scan(&enrollmentAuditCount))
	require.Equal(t, 2, enrollmentAuditCount, "the committed create and sole replacement must each have atomic Audit")
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

func TestEnrollmentPostgresUpgradeFromOriginal0001(t *testing.T) {
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
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	_, err = database.ExecContext(ctx, `
        DROP TABLE IF EXISTS agent_enrollment_issuances;
        DROP TABLE IF EXISTS agent_enrollment_tokens;
        DELETE FROM dbpilot_schema_migrations WHERE name LIKE 'enrollment/%';`)
	require.NoError(t, err)
	original, err := os.ReadFile("testdata/0001_agent_enrollment_original.sql")
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, string(original))
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)", "enrollment/migrations/0001_agent_enrollment.sql")
	require.NoError(t, err)
	legacyScope := platformscope.Scope{TenantID: "tenant-legacy", ProjectID: "project-legacy"}
	legacyCreated := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	for index := 0; index < 2; index++ {
		hash := sha256.Sum256([]byte(fmt.Sprintf("legacy-duplicate-%d", index)))
		_, err = database.ExecContext(ctx, `INSERT INTO agent_enrollment_tokens (
            token_hash, tenant_id, project_id, host_id, agent_id, display_name, labels,
            expires_at, created_at, enrollment_revision, issued_by, idempotency_key
        ) VALUES ($1,$2,$3,'host-legacy','agent-legacy','Legacy','{}'::jsonb,$4,$5,1,'legacy-operator',$6)`,
			hash[:], legacyScope.TenantID, legacyScope.ProjectID, legacyCreated.Add(2*time.Hour), legacyCreated.Add(time.Duration(index)*time.Minute), fmt.Sprintf("legacy-%d", index))
		require.NoError(t, err)
	}

	require.NoError(t, RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database), "migration rerun must be idempotent")
	var generationColumn, issuanceTable bool
	require.NoError(t, database.QueryRowContext(ctx, `SELECT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'agent_enrollment_tokens' AND column_name = 'generation'
    )`).Scan(&generationColumn))
	require.NoError(t, database.QueryRowContext(ctx, `SELECT to_regclass('agent_enrollment_issuances') IS NOT NULL`).Scan(&issuanceTable))
	require.True(t, generationColumn)
	require.True(t, issuanceTable)
	var activeLegacy int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM agent_enrollment_tokens WHERE tenant_id = $1 AND project_id = $2 AND consumed_at IS NULL", legacyScope.TenantID, legacyScope.ProjectID).Scan(&activeLegacy))
	require.Equal(t, 1, activeLegacy, "0002 must deterministically revoke duplicate legacy active grants before adding uniqueness")

	suffix := fmt.Sprintf("upgrade-%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Microsecond)
	raw := sha256.Sum256([]byte("upgrade-token-" + suffix))
	token := EnrollmentToken{
		TokenHash: HashToken(raw[:]), Scope: platformscope.Scope{TenantID: "tenant-" + suffix, ProjectID: "project-" + suffix},
		HostID: "host-" + suffix, AgentID: "agent-" + suffix, DisplayName: "Upgrade Host", Labels: map[string]string{},
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, EnrollmentRevision: 1, IssuedBy: "operator-" + suffix,
		IdempotencyKey: "upgrade", RequestFingerprint: "sha256:" + fmt.Sprintf("%064x", 2), Generation: 1,
		Audit: EnrollmentAudit{Actor: "operator-" + suffix, RequestID: "request-" + suffix, OperationID: "createHostEnrollment", IdempotencyKey: "upgrade"},
	}
	repository := NewPostgresRepository(database)
	_, err = repository.Create(ctx, token)
	require.NoError(t, err)
	csrDigest := sha256.Sum256([]byte("upgrade-csr"))
	key := EnrollmentAttemptKey{TokenHash: token.TokenHash, CSRDigest: csrDigest, AgentID: token.AgentID, HostID: token.HostID}
	resolved, err := repository.Resolve(ctx, key)
	require.NoError(t, err)
	result := EnrollResult{HostID: token.HostID, AgentID: token.AgentID, CertificatePEM: []byte("certificate"), CertificateChainPEM: []byte("chain"), ExpiresAt: now.Add(time.Hour), EnrollmentRevision: 1}
	observation := hostinventory.Observation{HostID: token.HostID, AgentID: token.AgentID, Revision: 1, AgentVersion: "upgrade", Hostname: "upgrade.example", OS: "linux", Architecture: "amd64", LogicalCPUCount: 1, MemoryCapacityBytes: 1 << 20, NetworkAddresses: []string{}, Capabilities: []string{}, ObservedAt: now}
	completed, err := repository.Complete(ctx, EnrollmentCompletion{Key: key, Grant: resolved.Grant, Observation: observation, Result: result, CompletedAt: now})
	require.NoError(t, err)
	require.Equal(t, result, completed)
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), "DELETE FROM audit_events WHERE tenant_id = $1 AND project_id = $2", token.Scope.TenantID, token.Scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM agent_enrollment_issuances WHERE token_hash = $1", token.TokenHash[:])
		_, _ = database.ExecContext(context.Background(), "DELETE FROM host_observations WHERE tenant_id = $1 AND project_id = $2", token.Scope.TenantID, token.Scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM managed_hosts WHERE tenant_id = $1 AND project_id = $2", token.Scope.TenantID, token.Scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM agent_enrollment_tokens WHERE token_hash = $1", token.TokenHash[:])
		_, _ = database.ExecContext(context.Background(), "DELETE FROM agent_enrollment_tokens WHERE tenant_id = $1 AND project_id = $2", legacyScope.TenantID, legacyScope.ProjectID)
	})
}
