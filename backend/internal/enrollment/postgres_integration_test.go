package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
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
			token.Generation = attempt.creation.Generation
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
	certificate, _ := testCertificateAuthority(t, now)
	want := EnrollResult{
		HostID: hostID, AgentID: agentID, CertificatePEM: certificate, CertificateChainPEM: certificate,
		ExpiresAt: now.Add(24 * time.Hour), EnrollmentRevision: 1,
	}
	want, err = normalizeEnrollmentResult(want, grant)
	require.NoError(t, err)
	completion := EnrollmentCompletion{Key: key, Grant: grant, Observation: observation, Result: want, CompletedAt: now}

	const consumers = 24
	results := make(chan EnrollResult, consumers)
	errorsChannel := make(chan error, consumers)
	var wait sync.WaitGroup
	for index := 0; index < consumers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			completed, completeErr := repository.Complete(ctx, completion)
			if completeErr != nil {
				resolved, resolveErr := repository.Resolve(ctx, key)
				if resolveErr != nil || resolved.Response == nil {
					errorsChannel <- errors.Join(completeErr, resolveErr)
					return
				}
				completed.Response = *resolved.Response
			}
			results <- completed.Response
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

func TestEnrollmentPostgresCredentialGenerationRejectsOldLeafAfterReplacementAndDecommission(t *testing.T) {
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
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	suffix := fmt.Sprintf("generation-%d", time.Now().UnixNano())
	scope := platformscope.Scope{TenantID: "tenant-" + suffix, ProjectID: "project-" + suffix}
	hostID, agentID := "host-"+suffix, "agent-"+suffix
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), "DELETE FROM audit_events WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM agent_enrollment_issuances WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM host_observations WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM managed_hosts WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM agent_enrollment_tokens WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
	})
	now := time.Now().UTC().Truncate(time.Microsecond)
	caCertificate, caKey := testCertificateAuthority(t, now)
	issuer, err := NewAgentCertificateIssuer(caCertificate, caKey, time.Hour, func() time.Time { return now }, rand.Reader)
	require.NoError(t, err)
	repository := NewPostgresRepository(database)
	sessions := &recordingCredentialSessions{}
	service := ApplicationService{Tokens: repository, Certificates: issuer, Sessions: sessions, Random: bytes.NewReader(bytes.Repeat([]byte{1}, EnrollmentTokenBytes)), Now: func() time.Time { return now }}
	createRequest := CreateRequest{HostID: hostID, AgentID: agentID, DisplayName: "Generation Host", Labels: map[string]string{}, ExpiresIn: time.Hour, IssuedBy: "operator", IdempotencyKey: "create-generation", RequestFingerprint: "sha256:" + fmt.Sprintf("%064x", 101), Audit: EnrollmentAudit{Actor: "operator", RequestID: "request-create", OperationID: "createHostEnrollment", IdempotencyKey: "create-generation"}}
	created, err := service.Create(ctx, scope, createRequest)
	require.NoError(t, err)
	firstRequest := signedEnrollRequest(t, created.Token, agentID, now)
	first, err := service.Enroll(ctx, firstRequest)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.CredentialGeneration)
	require.NoError(t, repository.AuthorizeAgentCredential(ctx, agentID, first.CertificateFingerprint, first.CertificateSerial))

	service.Random = bytes.NewReader(bytes.Repeat([]byte{2}, EnrollmentTokenBytes))
	createRequest.IdempotencyKey = "replace-generation"
	createRequest.RequestFingerprint = "sha256:" + fmt.Sprintf("%064x", 102)
	createRequest.Audit = EnrollmentAudit{Actor: "operator", RequestID: "request-replace", OperationID: "replaceHostEnrollment", IdempotencyKey: "replace-generation"}
	replacement, err := service.Replace(ctx, scope, createRequest, 1)
	require.NoError(t, err)
	require.Equal(t, uint64(2), replacement.Generation)
	second, err := service.Enroll(ctx, signedEnrollRequest(t, replacement.Token, agentID, now))
	require.NoError(t, err)
	require.Equal(t, uint64(2), second.CredentialGeneration)
	_, err = service.Enroll(ctx, firstRequest)
	require.ErrorIs(t, err, ErrEnrollmentTokenInvalid, "a revoked issuance must never be replayed after replacement")
	require.Error(t, repository.AuthorizeAgentCredential(ctx, agentID, first.CertificateFingerprint, first.CertificateSerial))
	require.NoError(t, repository.AuthorizeAgentCredential(ctx, agentID, second.CertificateFingerprint, second.CertificateSerial))
	require.Error(t, repository.AuthorizeAgentCredential(ctx, "agent-other-"+suffix, second.CertificateFingerprint, second.CertificateSerial), "a leaf must not authorize another tenant or Agent identity")
	var oldRevoked bool
	require.NoError(t, database.QueryRowContext(ctx, `SELECT revoked_at IS NOT NULL FROM agent_enrollment_issuances WHERE credential_generation=1 AND tenant_id=$1 AND project_id=$2 AND host_id=$3`, scope.TenantID, scope.ProjectID, hostID).Scan(&oldRevoked))
	require.True(t, oldRevoked)

	hostRepository := hostinventory.NewPostgresRepository(database)
	host, err := hostRepository.Get(ctx, scope, hostID)
	require.NoError(t, err)
	transition := hostinventory.DecommissionTransition{Actor: "operator", OperationID: "decommissionHost", IdempotencyKey: "decommission-generation", Fingerprint: "sha256:" + fmt.Sprintf("%064x", 103), OwnerToken: "owner-" + fmt.Sprintf("%064x", 104)}
	decommissioned, err := hostRepository.Decommission(hostinventory.WithDecommissionTransition(ctx, transition), scope, hostID, host.Version, now.Add(time.Second), transition)
	require.NoError(t, err)
	require.Equal(t, uint64(3), decommissioned.CredentialGeneration)
	require.NotNil(t, decommissioned.CredentialRevokedAt)
	require.Error(t, repository.AuthorizeAgentCredential(ctx, agentID, second.CertificateFingerprint, second.CertificateSerial))
	var currentRevoked bool
	require.NoError(t, database.QueryRowContext(ctx, `SELECT revoked_at IS NOT NULL FROM agent_enrollment_issuances WHERE credential_generation=2 AND tenant_id=$1 AND project_id=$2 AND host_id=$3`, scope.TenantID, scope.ProjectID, hostID).Scan(&currentRevoked))
	require.True(t, currentRevoked, "decommission must revoke the current issuance in the same database transaction")
	require.Equal(t, []string{agentID}, sessions.agents, "only the exact database-confirmed prior leaf is terminated")
	require.Equal(t, [][32]byte{first.CertificateFingerprint}, sessions.fingerprints)
	require.Equal(t, []string{first.CertificateSerial}, sessions.serials)
}

func TestEnrollmentPostgresUpgradeFromOriginal0001(t *testing.T) {
	if os.Getenv("DBPILOT_ENROLLMENT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ENROLLMENT_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_ENROLLMENT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ENROLLMENT_POSTGRES_DSN is required")
	}
	ctx := context.Background()
	database, schema := openEnrollmentUpgradeDatabase(t, ctx, dsn)
	var currentSchema string
	require.NoError(t, database.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&currentSchema))
	require.Equal(t, schema, currentSchema)
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
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
	var generationColumn, issuanceTable, importTable bool
	require.NoError(t, database.QueryRowContext(ctx, `SELECT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'agent_enrollment_tokens' AND column_name = 'generation'
    )`).Scan(&generationColumn))
	require.NoError(t, database.QueryRowContext(ctx, `SELECT to_regclass('agent_enrollment_issuances') IS NOT NULL`).Scan(&issuanceTable))
	require.NoError(t, database.QueryRowContext(ctx, `SELECT to_regclass('agent_credential_imports') IS NOT NULL`).Scan(&importTable))
	require.True(t, generationColumn)
	require.True(t, issuanceTable)
	require.True(t, importTable)
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
	certificate, _ := testCertificateAuthority(t, now)
	result := EnrollResult{HostID: token.HostID, AgentID: token.AgentID, CertificatePEM: certificate, CertificateChainPEM: certificate, ExpiresAt: now.Add(time.Hour), EnrollmentRevision: 1}
	result, err = normalizeEnrollmentResult(result, resolved.Grant)
	require.NoError(t, err)
	observation := hostinventory.Observation{HostID: token.HostID, AgentID: token.AgentID, Revision: 1, AgentVersion: "upgrade", Hostname: "upgrade.example", OS: "linux", Architecture: "amd64", LogicalCPUCount: 1, MemoryCapacityBytes: 1 << 20, NetworkAddresses: []string{}, Capabilities: []string{}, ObservedAt: now}
	completed, err := repository.Complete(ctx, EnrollmentCompletion{Key: key, Grant: resolved.Grant, Observation: observation, Result: result, CompletedAt: now})
	require.NoError(t, err)
	require.Equal(t, result, completed.Response)
}

func TestEnrollmentPostgresGenerationZeroImportIsScopedAtomicAuditedAndPersistent(t *testing.T) {
	if os.Getenv("DBPILOT_ENROLLMENT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ENROLLMENT_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_ENROLLMENT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ENROLLMENT_POSTGRES_DSN is required")
	}
	database, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	ctx := context.Background()
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	suffix := fmt.Sprintf("generation-zero-%d", time.Now().UnixNano())
	scope := platformscope.Scope{TenantID: "tenant-" + suffix, ProjectID: "project-" + suffix}
	now := time.Now().UTC().Truncate(time.Microsecond)
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), "DELETE FROM audit_events WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM agent_credential_imports WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM agent_enrollment_issuances WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM host_observations WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM managed_hosts WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM agent_enrollment_tokens WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
	})
	recordGenerationZeroHost := func(targetScope platformscope.Scope, hostID, agentID string) {
		observation := hostinventory.Observation{HostID: hostID, AgentID: agentID, Revision: 1, AgentVersion: "legacy", Hostname: hostID + ".example", OS: "linux", Architecture: "amd64", LogicalCPUCount: 1, MemoryCapacityBytes: 1 << 20, NetworkAddresses: []string{}, Capabilities: []string{}, ObservedAt: now}
		_, recordErr := hostinventory.NewPostgresRepository(database).RecordEnrollment(ctx, targetScope, hostinventory.Enrollment{HostID: hostID, AgentID: agentID, DisplayName: "Legacy host", Labels: map[string]string{}, Revision: 1, EnrolledAt: now}, observation, now)
		require.NoError(t, recordErr)
	}

	repository := NewPostgresRepository(database)
	configurer, ok := any(repository).(interface {
		ConfigureGenerationZeroImport(string, platformscope.Scope, string) error
		ValidateGenerationZeroImports(context.Context) error
	})
	require.True(t, ok, "enrollment repository must expose an explicit generation-zero import window")
	if !ok {
		return
	}
	hostID, agentID := "host-current-"+suffix, "agent-current-"+suffix
	recordGenerationZeroHost(scope, hostID, agentID)
	require.NoError(t, configurer.ConfigureGenerationZeroImport(agentID, scope, hostID))
	require.NoError(t, configurer.ValidateGenerationZeroImports(ctx))
	certificate, caKey := testCertificateAuthority(t, now)
	fingerprint, serial, err := enrollmentCertificateIdentity(certificate)
	require.NoError(t, err)
	require.NoError(t, repository.AuthorizeAgentCredential(ctx, agentID, fingerprint, serial))

	var generation int64
	var storedFingerprint []byte
	var storedSerial string
	require.NoError(t, database.QueryRowContext(ctx, `SELECT credential_generation,active_certificate_fingerprint,active_certificate_serial FROM managed_hosts WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3 AND agent_id=$4`, scope.TenantID, scope.ProjectID, hostID, agentID).Scan(&generation, &storedFingerprint, &storedSerial))
	require.Equal(t, int64(1), generation)
	require.Equal(t, fingerprint[:], storedFingerprint)
	require.Equal(t, serial, storedSerial)
	var importCount, auditCount int
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM agent_credential_imports WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3 AND agent_id=$4`, scope.TenantID, scope.ProjectID, hostID, agentID).Scan(&importCount))
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND project_id=$2 AND resource_id=$3 AND action='host.credential_generation_zero_imported'`, scope.TenantID, scope.ProjectID, hostID).Scan(&auditCount))
	require.Equal(t, 1, importCount)
	require.Equal(t, 1, auditCount)
	require.NoError(t, configurer.ValidateGenerationZeroImports(ctx), "an already imported exact target must survive a restart during the bounded window")
	require.NoError(t, NewPostgresRepository(database).AuthorizeAgentCredential(ctx, agentID, fingerprint, serial), "exact leaf admission must persist after restart with the import window closed")
	competing := sha256.Sum256([]byte("competing-current-leaf"))
	require.Error(t, NewPostgresRepository(database).AuthorizeAgentCredential(ctx, agentID, competing, "02"))

	issuer, err := NewAgentCertificateIssuer(certificate, caKey, time.Hour, func() time.Time { return now }, rand.Reader)
	require.NoError(t, err)
	sessions := &recordingCredentialSessions{}
	service := ApplicationService{Tokens: repository, Certificates: issuer, Sessions: sessions, Random: bytes.NewReader(bytes.Repeat([]byte{7}, EnrollmentTokenBytes)), Now: func() time.Time { return now }}
	replacementRequest := CreateRequest{HostID: hostID, AgentID: agentID, DisplayName: "Legacy host", Labels: map[string]string{}, ExpiresIn: time.Hour, IssuedBy: "operator", IdempotencyKey: "replace-imported", RequestFingerprint: "sha256:" + fmt.Sprintf("%064x", 501), Audit: EnrollmentAudit{Actor: "operator", RequestID: "request-replace-imported", OperationID: "replaceHostEnrollment", IdempotencyKey: "replace-imported"}}
	replacement, err := service.Replace(ctx, scope, replacementRequest, 1)
	require.NoError(t, err)
	require.Equal(t, uint64(2), replacement.Generation)
	replaced, err := service.Enroll(ctx, signedEnrollRequest(t, replacement.Token, agentID, now))
	require.NoError(t, err)
	require.Equal(t, uint64(2), replaced.CredentialGeneration)
	require.Error(t, repository.AuthorizeAgentCredential(ctx, agentID, fingerprint, serial))
	require.NoError(t, repository.AuthorizeAgentCredential(ctx, agentID, replaced.CertificateFingerprint, replaced.CertificateSerial))
	require.Equal(t, [][sha256.Size]byte{fingerprint}, sessions.fingerprints, "canonical replacement must terminate the exact imported leaf")
	require.Equal(t, []string{serial}, sessions.serials)
	require.Error(t, configurer.ValidateGenerationZeroImports(ctx), "a later generation requires closing and removing the migration target")

	concurrentHost, concurrentAgent := "host-concurrent-"+suffix, "agent-concurrent-"+suffix
	recordGenerationZeroHost(scope, concurrentHost, concurrentAgent)
	require.NoError(t, configurer.ConfigureGenerationZeroImport(concurrentAgent, scope, concurrentHost))
	firstFingerprint := sha256.Sum256([]byte("first-import-leaf-" + suffix))
	secondFingerprint := sha256.Sum256([]byte("second-import-leaf-" + suffix))
	type importAttempt struct {
		fingerprint [sha256.Size]byte
		err         error
	}
	attempts := make(chan importAttempt, 24)
	start := make(chan struct{})
	for index := 0; index < 24; index++ {
		candidate, candidateSerial := firstFingerprint, "11"
		if index%2 == 1 {
			candidate, candidateSerial = secondFingerprint, "12"
		}
		go func() {
			<-start
			attempts <- importAttempt{fingerprint: candidate, err: repository.AuthorizeAgentCredential(ctx, concurrentAgent, candidate, candidateSerial)}
		}()
	}
	close(start)
	completedAttempts := make([]importAttempt, 0, 24)
	for index := 0; index < 24; index++ {
		completedAttempts = append(completedAttempts, <-attempts)
	}
	var concurrentGeneration int64
	require.NoError(t, database.QueryRowContext(ctx, `SELECT credential_generation,active_certificate_fingerprint FROM managed_hosts WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3 AND agent_id=$4`, scope.TenantID, scope.ProjectID, concurrentHost, concurrentAgent).Scan(&concurrentGeneration, &storedFingerprint))
	successes := 0
	failed := map[string]int{}
	for _, attempt := range completedAttempts {
		if attempt.err == nil {
			successes++
			require.Equal(t, storedFingerprint, attempt.fingerprint[:])
		} else {
			failed[attempt.err.Error()]++
		}
	}
	require.Greater(t, successes, 0, "generation=%d fingerprint=%x failures=%v", concurrentGeneration, storedFingerprint, failed)
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM agent_credential_imports WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3`, scope.TenantID, scope.ProjectID, concurrentHost).Scan(&importCount))
	require.Equal(t, 1, importCount)

	crossScope := platformscope.Scope{TenantID: scope.TenantID + "-other", ProjectID: scope.ProjectID + "-other"}
	crossHost, crossAgent := "host-cross-"+suffix, "agent-cross-"+suffix
	recordGenerationZeroHost(crossScope, crossHost, crossAgent)
	require.NoError(t, configurer.ConfigureGenerationZeroImport(crossAgent, crossScope, crossHost))
	winnerFingerprint, winnerSerial := firstFingerprint, "11"
	if bytes.Equal(storedFingerprint, secondFingerprint[:]) {
		winnerFingerprint, winnerSerial = secondFingerprint, "12"
	}
	require.Error(t, repository.AuthorizeAgentCredential(ctx, crossAgent, winnerFingerprint, winnerSerial), "one imported leaf cannot be claimed by another tenant or Agent")

	decommissionedHost, decommissionedAgent := "host-decommissioned-"+suffix, "agent-decommissioned-"+suffix
	recordGenerationZeroHost(scope, decommissionedHost, decommissionedAgent)
	require.NoError(t, configurer.ConfigureGenerationZeroImport(decommissionedAgent, scope, decommissionedHost))
	_, err = database.ExecContext(ctx, `UPDATE managed_hosts SET status='decommissioned',credential_generation=1,active_certificate_fingerprint=''::bytea,active_certificate_serial='',credential_revoked_at=$1,version=version+1,updated_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND host_id=$4`, now.Add(time.Second), scope.TenantID, scope.ProjectID, decommissionedHost)
	require.NoError(t, err)
	decommissionedFingerprint := sha256.Sum256([]byte("decommissioned-leaf"))
	require.Error(t, repository.AuthorizeAgentCredential(ctx, decommissionedAgent, decommissionedFingerprint, "21"))
}

func openEnrollmentUpgradeDatabase(t *testing.T, ctx context.Context, dsn string) (*sql.DB, string) {
	t.Helper()
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, admin.PingContext(ctx))
	schema := fmt.Sprintf("enrollment_upgrade_%d", time.Now().UnixNano())
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
	return database, schema
}
