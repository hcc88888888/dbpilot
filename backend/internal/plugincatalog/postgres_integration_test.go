package plugincatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestPluginCatalogPostgres16Integration(t *testing.T) {
	if os.Getenv("DBPILOT_PLUGIN_CATALOG_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_PLUGIN_CATALOG_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_PLUGIN_CATALOG_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_PLUGIN_CATALOG_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin := openPluginCatalogIntegrationDB(t, ctx, dsn)
	schema := fmt.Sprintf("plugin_catalog_%d", time.Now().UnixNano())
	quotedSchema := pq.QuoteIdentifier(schema)
	_, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, cleanupErr := admin.ExecContext(cleanupContext, "DROP SCHEMA "+quotedSchema+" CASCADE")
		require.NoError(t, cleanupErr)
		require.NoError(t, admin.Close())
	})
	database := openPluginCatalogIntegrationDB(t, ctx, pluginCatalogIntegrationDSN(t, dsn, schema))
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	publishers, err := NewStaticPublisherKeyStore([]PublisherKey{{PublisherID: "publisher-ready", KeyID: "key-ready", PublicKey: public}})
	require.NoError(t, err)
	verifier, err := NewStreamingPackageVerifier(PackageVerifierConfig{Publishers: publishers, TemporaryDirectory: t.TempDir(), Limits: testPackageLimits()})
	require.NoError(t, err)
	application, err := NewService(NewPostgresRepository(database), &recordingArtifactWriter{}, verifier, time.Now)
	require.NoError(t, err)
	require.NoError(t, application.Ready(ctx))

	for _, table := range []string{"plugin_definitions", "plugin_versions", "plugin_catalog_operations"} {
		var actual string
		require.NoError(t, database.QueryRowContext(ctx, "SELECT $1::regclass::text", table).Scan(&actual))
		require.Equal(t, table, actual)
	}
	var migrations int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM dbpilot_schema_migrations WHERE name LIKE 'plugincatalog/%'").Scan(&migrations))
	require.Equal(t, 4, migrations)

	scope := platformscope.Scope{TenantID: "tenant-pg16", ProjectID: "project-pg16"}
	definition := PluginDefinition{Scope: scope, PluginID: "mysql", Name: "mysql", DatabaseFamily: "mysql", ProtocolVersion: "v1", SupportedVariants: []string{"mysql"}, Capabilities: []string{"metrics.collect"}}
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	first := integrationVersion(scope, "plugin-version-pg16-1", "plugin-artifact-pg16-1", "1.0.0", strings.Repeat("1", 64), createdAt)
	second := integrationVersion(scope, "plugin-version-pg16-2", "plugin-artifact-pg16-2", "1.1.0", strings.Repeat("2", 64), createdAt.Add(time.Second))
	insertIntegrationArtifact(t, ctx, database, first.ArtifactID, scope, first.PackageSHA256, "plugin-version", first.ID)
	insertIntegrationArtifact(t, ctx, database, second.ArtifactID, scope, second.PackageSHA256, "plugin-version", second.ID)
	repository := NewPostgresRepositoryWithClock(database, func() time.Time { return createdAt.Add(2 * time.Second) })
	_, err = repository.Create(ctx, definition, first)
	require.NoError(t, err)
	_, err = repository.Create(ctx, definition, second)
	require.NoError(t, err)
	postgresDefinition := PluginDefinition{Scope: scope, PluginID: "postgres", Name: "postgres", DatabaseFamily: "postgres", ProtocolVersion: "v1", SupportedVariants: []string{"postgres"}, Capabilities: []string{"metrics.collect"}}
	postgresVersion := integrationVersion(scope, "plugin-version-pg16-postgres", "plugin-artifact-pg16-postgres", "1.0.0", strings.Repeat("6", 64), createdAt.Add(2*time.Second))
	postgresVersion.PluginID = "postgres"
	postgresVersion.SupportedVariants = []string{"postgres"}
	insertIntegrationArtifact(t, ctx, database, postgresVersion.ArtifactID, scope, postgresVersion.PackageSHA256, "plugin-version", postgresVersion.ID)
	_, err = repository.Create(ctx, postgresDefinition, postgresVersion)
	require.NoError(t, err)

	page1, err := repository.ListVersions(ctx, scope, VersionFilter{PluginID: "mysql", Limit: 1})
	require.NoError(t, err)
	require.True(t, page1.More)
	require.NotEmpty(t, page1.NextCursor)
	require.Equal(t, second.ID, page1.Items[0].ID)
	page2, err := repository.ListVersions(ctx, scope, VersionFilter{PluginID: "mysql", Cursor: page1.NextCursor, Limit: 1})
	require.NoError(t, err)
	require.False(t, page2.More)
	require.Equal(t, first.ID, page2.Items[0].ID)
	wrongScope := platformscope.Scope{TenantID: scope.TenantID, ProjectID: "project-other"}
	wrongPage, err := repository.ListVersions(ctx, wrongScope, VersionFilter{Limit: 10})
	require.NoError(t, err)
	require.Empty(t, wrongPage.Items)
	approveKey := OperationKey{Scope: scope, Actor: "approver-pg16", OperationID: "approvePluginVersion", IdempotencyKey: "approve-pg16", Fingerprint: "sha256:" + strings.Repeat("7", 64), OwnerToken: "owner-" + strings.Repeat("8", 64)}
	approveSnapshot, err := repository.TransitionOperation(ctx, TransitionOperationRequest{Key: approveKey, Transition: TransitionRequest{Scope: scope, VersionID: first.ID, ExpectedRevision: 1, AllowedFrom: []Status{StatusVerified}, To: StatusApproved}, AuditEventJSON: []byte(`{"action":"plugin.version_approved"}`)}, func(value PluginVersion) (OperationResponse, error) {
		return OperationResponse{Status: 200, ETag: value.ETag(), Body: []byte(`{"status":"approved"}`)}, nil
	})
	require.NoError(t, err)
	require.Equal(t, uint64(2), approveSnapshot.Version.Revision)
	_, err = repository.Transition(ctx, TransitionRequest{Scope: scope, VersionID: first.ID, ExpectedRevision: 2, AllowedFrom: []Status{StatusApproved}, To: StatusAvailable})
	require.NoError(t, err)
	recoveredApprove, err := repository.GetOperation(ctx, approveKey)
	require.NoError(t, err)
	require.Equal(t, StatusApproved, recoveredApprove.Version.Status)
	require.Equal(t, uint64(2), recoveredApprove.Version.Revision)
	definitionPage1, err := repository.ListDefinitions(ctx, scope, DefinitionFilter{Limit: 1})
	require.NoError(t, err)
	require.True(t, definitionPage1.More)
	require.Equal(t, "mysql", definitionPage1.Items[0].PluginID)
	definitionPage2, err := repository.ListDefinitions(ctx, scope, DefinitionFilter{Cursor: definitionPage1.NextCursor, Limit: 1})
	require.NoError(t, err)
	require.False(t, definitionPage2.More)
	require.Equal(t, "postgres", definitionPage2.Items[0].PluginID)
	mysqlDefinitions, err := repository.ListDefinitions(ctx, scope, DefinitionFilter{DatabaseFamily: "mysql", Limit: 10})
	require.NoError(t, err)
	require.Len(t, mysqlDefinitions.Items, 1)

	approved, err := repository.Transition(ctx, TransitionRequest{Scope: scope, VersionID: second.ID, ExpectedRevision: 1, AllowedFrom: []Status{StatusVerified}, To: StatusApproved})
	require.NoError(t, err)
	require.Equal(t, uint64(2), approved.Revision)
	_, err = repository.Transition(ctx, TransitionRequest{Scope: scope, VersionID: second.ID, ExpectedRevision: 1, AllowedFrom: []Status{StatusVerified}, To: StatusApproved})
	require.ErrorIs(t, err, ErrRevisionConflict)
	available, err := repository.Transition(ctx, TransitionRequest{Scope: scope, VersionID: second.ID, ExpectedRevision: 2, AllowedFrom: []Status{StatusApproved}, To: StatusAvailable})
	require.NoError(t, err)
	require.Equal(t, StatusAvailable, available.Status)
	availablePage, err := repository.ListVersions(ctx, scope, VersionFilter{Status: StatusAvailable, Limit: 10})
	require.NoError(t, err)
	require.Len(t, availablePage.Items, 2)
	require.Equal(t, second.ID, availablePage.Items[0].ID)
	definitions, err := repository.ListDefinitions(ctx, scope, DefinitionFilter{Limit: 10})
	require.NoError(t, err)
	require.Equal(t, "1.1.0", definitions.Items[0].LatestAvailableVersion)

	third := integrationVersion(scope, "plugin-version-pg16-3", "plugin-artifact-pg16-3", "1.2.0", strings.Repeat("3", 64), createdAt.Add(3*time.Second))
	key := OperationKey{Scope: scope, Actor: "publisher-pg16", OperationID: "uploadPluginVersionPackage", IdempotencyKey: "upload-pg16", Fingerprint: "sha256:" + strings.Repeat("4", 64), OwnerToken: "owner-" + strings.Repeat("5", 64)}
	auditJSON := []byte(`{"action":"plugin.version_uploaded"}`)
	pending, err := repository.BeginUploadOperation(ctx, UploadOperationRequest{Key: key, Definition: definition, Version: third, ArtifactID: third.ArtifactID, ArtifactSHA256: third.PackageSHA256, ArtifactBytes: 123, CreatedBy: key.Actor, CreatedAt: third.CreatedAt, LeaseExpiresAt: third.CreatedAt.Add(DefaultOperationLease), Response: OperationResponse{Status: 201, ETag: third.ETag(), Body: []byte(`{"version_id":"` + third.ID + `"}`)}, AuditEventJSON: auditJSON})
	require.NoError(t, err)
	require.Equal(t, OperationPending, pending.State)
	insertIntegrationArtifactSized(t, ctx, database, third.ArtifactID, scope, third.PackageSHA256, 123, "plugin_catalog_operation", key.RecordID())
	committed, err := repository.FinalizeUploadOperation(ctx, key, func(value PluginVersion) (OperationResponse, error) {
		return OperationResponse{Status: 201, ETag: value.ETag(), Body: []byte(`{"version_id":"` + value.ID + `"}`)}, nil
	})
	require.NoError(t, err)
	require.Equal(t, OperationCommitted, committed.State)
	recovered, err := repository.GetOperation(ctx, key)
	require.NoError(t, err)
	require.Equal(t, committed.Response, recovered.Response)
	_, err = database.ExecContext(ctx, "DELETE FROM plugin_catalog_operations WHERE tenant_id = $1 AND project_id = $2 AND operation_record_id = $3", scope.TenantID, scope.ProjectID, key.RecordID())
	require.ErrorContains(t, err, "immutable")
}

func TestPluginCatalogPostgres16ExpiredUploadLedgerReconciliation(t *testing.T) {
	if os.Getenv("DBPILOT_PLUGIN_CATALOG_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_PLUGIN_CATALOG_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_PLUGIN_CATALOG_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_PLUGIN_CATALOG_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin := openPluginCatalogIntegrationDB(t, ctx, dsn)
	schema := fmt.Sprintf("plugin_catalog_ledger_%d", time.Now().UnixNano())
	quotedSchema := pq.QuoteIdentifier(schema)
	_, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, cleanupErr := admin.ExecContext(cleanupContext, "DROP SCHEMA "+quotedSchema+" CASCADE")
		require.NoError(t, cleanupErr)
		require.NoError(t, admin.Close())
	})
	database := openPluginCatalogIntegrationDB(t, ctx, pluginCatalogIntegrationDSN(t, dsn, schema))
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	now := time.Now().UTC().Truncate(time.Microsecond)
	repository := NewPostgresRepositoryWithClock(database, func() time.Time { return now })
	scope := platformscope.Scope{TenantID: "tenant-ledger", ProjectID: "project-ledger"}
	definition := PluginDefinition{Scope: scope, PluginID: "mysql", Name: "mysql", DatabaseFamily: "mysql", ProtocolVersion: "v1", SupportedVariants: []string{"mysql"}, Capabilities: []string{"metrics.collect"}}
	version := integrationVersion(scope, "plugin-version-ledger-a", "plugin-artifact-ledger-a", "2.0.0", strings.Repeat("9", 64), now.Add(-time.Hour))
	response := OperationResponse{Status: 201, ETag: version.ETag(), Body: []byte(`{"status":"verified"}`)}
	oldKey := OperationKey{Scope: scope, Actor: "publisher-ledger", OperationID: "uploadPluginVersionPackage", IdempotencyKey: "abandoned-old", Fingerprint: "sha256:" + strings.Repeat("9", 64), OwnerToken: "owner-" + strings.Repeat("1", 64)}
	request := UploadOperationRequest{Key: oldKey, Definition: definition, Version: version, ArtifactID: version.ArtifactID, ArtifactSHA256: version.PackageSHA256, ArtifactBytes: 121, CreatedBy: oldKey.Actor, CreatedAt: now.Add(-time.Hour), LeaseExpiresAt: now.Add(-time.Minute), Response: response, AuditEventJSON: []byte(`{"action":"upload"}`)}
	oldPending, err := repository.BeginUploadOperation(ctx, request)
	require.NoError(t, err)
	require.Equal(t, OperationPending, oldPending.State)
	result, err := repository.ReconcileExpiredUploadOperations(ctx, now, 10)
	require.NoError(t, err)
	require.Equal(t, 1, result.Abandoned)
	require.Zero(t, result.Finalized)
	abandoned, err := repository.GetOperation(ctx, oldKey)
	require.NoError(t, err)
	require.Equal(t, OperationAbandoned, abandoned.State)

	different := request
	different.Key = OperationKey{Scope: scope, Actor: "publisher-ledger", OperationID: "uploadPluginVersionPackage", IdempotencyKey: "different-digest", Fingerprint: "sha256:" + strings.Repeat("8", 64), OwnerToken: "owner-" + strings.Repeat("2", 64)}
	different.Version.PackageSHA256, different.Version.ArtifactID, different.ArtifactSHA256 = strings.Repeat("8", 64), "plugin-artifact-ledger-different", strings.Repeat("8", 64)
	different.ArtifactID = different.Version.ArtifactID
	_, err = repository.BeginUploadOperation(ctx, different)
	require.ErrorIs(t, err, ErrConflict)

	adopted := request
	adopted.Key = OperationKey{Scope: scope, Actor: "publisher-ledger", OperationID: "uploadPluginVersionPackage", IdempotencyKey: "same-digest-adopt", Fingerprint: oldKey.Fingerprint, OwnerToken: "owner-" + strings.Repeat("3", 64)}
	adopted.CreatedAt, adopted.LeaseExpiresAt = now, now.Add(DefaultOperationLease)
	newPending, err := repository.BeginUploadOperation(ctx, adopted)
	require.NoError(t, err)
	require.Equal(t, OperationPending, newPending.State)
	insertIntegrationArtifact(t, ctx, database, version.ArtifactID, scope, version.PackageSHA256, "plugin_catalog_operation", oldKey.RecordID())
	adoptedFinal, err := repository.FinalizeUploadOperation(ctx, adopted.Key, func(value PluginVersion) (OperationResponse, error) { return adopted.Response, nil })
	require.NoError(t, err)
	require.Equal(t, OperationCommitted, adoptedFinal.State)

	artifactDefinition := PluginDefinition{Scope: scope, PluginID: "postgres", Name: "postgres", DatabaseFamily: "postgres", ProtocolVersion: "v1", SupportedVariants: []string{"postgres"}, Capabilities: []string{"metrics.collect"}}
	artifactVersion := integrationVersion(scope, "plugin-version-ledger-b", "plugin-artifact-ledger-b", "3.0.0", strings.Repeat("7", 64), now.Add(-time.Hour))
	artifactVersion.PluginID, artifactVersion.SupportedVariants = "postgres", []string{"postgres"}
	artifactKey := OperationKey{Scope: scope, Actor: "publisher-ledger", OperationID: "uploadPluginVersionPackage", IdempotencyKey: "artifact-expired", Fingerprint: "sha256:" + strings.Repeat("7", 64), OwnerToken: "owner-" + strings.Repeat("4", 64)}
	artifactRequest := UploadOperationRequest{Key: artifactKey, Definition: artifactDefinition, Version: artifactVersion, ArtifactID: artifactVersion.ArtifactID, ArtifactSHA256: artifactVersion.PackageSHA256, ArtifactBytes: 121, CreatedBy: artifactKey.Actor, CreatedAt: now.Add(-time.Hour), LeaseExpiresAt: now.Add(-time.Minute), Response: OperationResponse{Status: 201, ETag: artifactVersion.ETag(), Body: []byte(`{"status":"verified"}`)}, AuditEventJSON: []byte(`{"action":"upload"}`)}
	_, err = repository.BeginUploadOperation(ctx, artifactRequest)
	require.NoError(t, err)
	insertIntegrationArtifact(t, ctx, database, artifactVersion.ArtifactID, scope, artifactVersion.PackageSHA256, "plugin_catalog_operation", artifactKey.RecordID())

	type outcome struct {
		result OperationReconcileResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	for range 2 {
		go func() {
			value, reconcileErr := repository.ReconcileExpiredUploadOperations(context.Background(), now, 1)
			outcomes <- outcome{result: value, err: reconcileErr}
		}()
	}
	totalFinalized := 0
	for range 2 {
		value := <-outcomes
		require.NoError(t, value.err)
		totalFinalized += value.result.Finalized
	}
	require.Equal(t, 1, totalFinalized)
	finalized, err := repository.GetOperation(ctx, artifactKey)
	require.NoError(t, err)
	require.Equal(t, OperationCommitted, finalized.State)
	require.Equal(t, artifactRequest.Response, finalized.Response)
	unreconciled, err := repository.ListUnreconciledCommittedOperations(ctx, 10)
	require.NoError(t, err)
	foundFinalized := false
	for _, operation := range unreconciled {
		if operation.Key == artifactKey {
			foundFinalized = true
		}
	}
	require.True(t, foundFinalized)
	require.NoError(t, repository.MarkOperationCompletionReconciled(ctx, artifactKey, now.Add(time.Second)))
	marked, err := repository.GetOperation(ctx, artifactKey)
	require.NoError(t, err)
	require.NotNil(t, marked.CompletionReconciledAt)
}

func TestPluginCatalogPostgres16ApplicationUploadCanonicalTimestampAndLostResponseReplay(t *testing.T) {
	if os.Getenv("DBPILOT_PLUGIN_CATALOG_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_PLUGIN_CATALOG_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_PLUGIN_CATALOG_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_PLUGIN_CATALOG_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin := openPluginCatalogIntegrationDB(t, ctx, dsn)
	schema := fmt.Sprintf("plugin_catalog_application_%d", time.Now().UnixNano())
	quotedSchema := pq.QuoteIdentifier(schema)
	_, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, cleanupErr := admin.ExecContext(cleanupContext, "DROP SCHEMA "+quotedSchema+" CASCADE")
		require.NoError(t, cleanupErr)
		require.NoError(t, admin.Close())
	})
	database := openPluginCatalogIntegrationDB(t, ctx, pluginCatalogIntegrationDSN(t, dsn, schema))
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	fixture := newSignedPackageFixture(t, "publisher-1", "key-1", private, nil)
	publishers, err := NewStaticPublisherKeyStore([]PublisherKey{{PublisherID: "publisher-1", KeyID: "key-1", PublicKey: public}})
	require.NoError(t, err)
	verifier, err := NewStreamingPackageVerifier(PackageVerifierConfig{Publishers: publishers, TemporaryDirectory: t.TempDir(), Limits: testPackageLimits()})
	require.NoError(t, err)
	blobs := artifact.NewLocalBlobStore(t.TempDir())
	require.NoError(t, blobs.Ready())
	t.Cleanup(func() { require.NoError(t, blobs.Close()) })
	now := time.Date(2026, 8, 30, 16, 30, 0, 123456789, time.UTC)
	baseRepository := NewPostgresRepositoryWithClock(database, func() time.Time { return now })
	repository := &failOnceFinalizeRepository{PostgresRepository: baseRepository, err: errors.New("injected finalize failure")}
	application, err := NewService(repository, artifact.NewPostgresStore(database, blobs), verifier, func() time.Time { return now })
	require.NoError(t, err)
	scope := platformscope.Scope{TenantID: "tenant-application", ProjectID: "project-application"}
	key := OperationKey{Scope: scope, Actor: "publisher-application", OperationID: "uploadPluginVersionPackage", IdempotencyKey: "application-upload", Fingerprint: "sha256:" + strings.Repeat("c", 64), OwnerToken: "owner-" + strings.Repeat("d", 64)}
	builder := func(value PluginVersion) (OperationResponse, error) {
		body, marshalErr := json.Marshal(map[string]any{"version_id": value.ID, "created_at": value.CreatedAt})
		return OperationResponse{Status: 201, ETag: value.ETag(), Body: body}, marshalErr
	}
	auditJSON := []byte(`{"action":"plugin.version_uploaded"}`)
	_, err = application.UploadOperation(ctx, scope, UploadMetadata{Actor: key.Actor, ContentLength: int64(len(fixture.Archive))}, key, auditJSON, builder, bytes.NewReader(fixture.Archive))
	require.EqualError(t, err, "injected finalize failure")
	pending, err := baseRepository.GetOperation(ctx, key)
	require.NoError(t, err)
	require.Equal(t, OperationPending, pending.State)
	originalResponse := pending.Response
	now = now.Add(5 * time.Minute)
	first, err := application.UploadOperation(ctx, scope, UploadMetadata{Actor: key.Actor, ContentLength: int64(len(fixture.Archive))}, key, auditJSON, builder, bytes.NewReader(fixture.Archive))
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 8, 30, 16, 30, 0, 123456000, time.UTC), first.Version.CreatedAt)
	require.Equal(t, originalResponse, first.Response)
	retry, err := application.UploadOperation(ctx, scope, UploadMetadata{Actor: key.Actor, ContentLength: int64(len(fixture.Archive))}, key, auditJSON, builder, bytes.NewReader(nil))
	require.NoError(t, err)
	require.Equal(t, first.Response, retry.Response)
	require.Equal(t, first.Version, retry.Version)
	conflictingKey := key
	conflictingKey.Fingerprint = "sha256:" + strings.Repeat("e", 64)
	_, err = application.UploadOperation(ctx, scope, UploadMetadata{Actor: key.Actor, ContentLength: int64(len(fixture.Archive))}, conflictingKey, auditJSON, builder, bytes.NewReader(nil))
	require.ErrorIs(t, err, ErrConflict)
	var versionCount, operationCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM plugin_versions WHERE tenant_id=$1 AND project_id=$2 AND version_id=$3", scope.TenantID, scope.ProjectID, first.Version.ID).Scan(&versionCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM plugin_catalog_operations WHERE tenant_id=$1 AND project_id=$2 AND operation_record_id=$3 AND audit_event_json=$4", scope.TenantID, scope.ProjectID, key.RecordID(), auditJSON).Scan(&operationCount))
	require.Equal(t, 1, versionCount)
	require.Equal(t, 1, operationCount)
}

type failOnceFinalizeRepository struct {
	*PostgresRepository
	err error
}

func (repository *failOnceFinalizeRepository) FinalizeUploadOperation(ctx context.Context, key OperationKey, builder OperationResponseBuilder) (OperationSnapshot, error) {
	if repository.err != nil {
		err := repository.err
		repository.err = nil
		return OperationSnapshot{}, err
	}
	return repository.PostgresRepository.FinalizeUploadOperation(ctx, key, builder)
}

func integrationVersion(scope platformscope.Scope, id, artifactID, version, digest string, createdAt time.Time) PluginVersion {
	return PluginVersion{ID: id, Scope: scope, PluginID: "mysql", Version: version, Status: StatusVerified, ArtifactID: artifactID, PackageSHA256: digest, ManifestDigest: strings.Repeat("a", 64), PublisherID: "publisher-pg16", SigningKeyID: "key-pg16", ProtocolVersion: "v1", MinimumAgentProtocolVersion: "v1", MaximumAgentProtocolVersion: "v1", SupportedVariants: []string{"mysql"}, DatabaseVersionRange: ">=8 <9", Capabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1, Platforms: []Platform{{OperatingSystem: "linux", Architecture: "amd64", SHA256: strings.Repeat("b", 64), SizeBytes: 121}}, Revision: 1, CreatedAt: createdAt}
}

func insertIntegrationArtifact(t *testing.T, ctx context.Context, database *sql.DB, id string, scope platformscope.Scope, digest, resourceType, resourceID string) {
	t.Helper()
	insertIntegrationArtifactSized(t, ctx, database, id, scope, digest, 121, resourceType, resourceID)
}

func insertIntegrationArtifactSized(t *testing.T, ctx context.Context, database *sql.DB, id string, scope platformscope.Scope, digest string, size int64, resourceType, resourceID string) {
	t.Helper()
	_, err := database.ExecContext(ctx, "INSERT INTO artifacts (id, tenant_id, project_id, kind, content_type, size_bytes, checksum, source_resource_type, source_resource_id, created_by, created_at, storage_reference) VALUES ($1,$2,$3,'plugin-package','application/gzip',$4,$5,$6,$7,'integration',NOW(),$8)", id, scope.TenantID, scope.ProjectID, size, "sha256:"+digest, resourceType, resourceID, "sha256/"+digest+".blob")
	require.NoError(t, err)
}

func openPluginCatalogIntegrationDB(t *testing.T, ctx context.Context, dsn string) *sql.DB {
	t.Helper()
	database, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, database.PingContext(ctx))
	return database
}

func pluginCatalogIntegrationDSN(t *testing.T, dsn, schema string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
