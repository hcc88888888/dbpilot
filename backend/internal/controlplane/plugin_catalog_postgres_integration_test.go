package controlplane

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/plugincatalog"
	"github.com/stretchr/testify/require"
)

func TestPluginCatalogPostgres16SplitClockRetryCompletesHTTPAuditAndIdempotency(t *testing.T) {
	// Break caught: when PostgreSQL observes expiry after the Application's
	// earlier clock check, the first exact HTTP retry must adopt and complete.
	if os.Getenv("DBPILOT_PLUGIN_CATALOG_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_PLUGIN_CATALOG_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_PLUGIN_CATALOG_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_PLUGIN_CATALOG_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	database := openHTTPIntegrationDatabase(t, ctx, dsn, "plugin_split_clock")
	require.NoError(t, plugincatalog.RunMigrations(ctx, database))

	archive, publicKey := pluginCatalogV1CorpusArchive(t)
	publishers, err := plugincatalog.NewStaticPublisherKeyStore([]plugincatalog.PublisherKey{{PublisherID: "fixture-publisher", KeyID: "fixture-key", PublicKey: publicKey}})
	require.NoError(t, err)
	verifier, err := plugincatalog.NewStreamingPackageVerifier(plugincatalog.PackageVerifierConfig{Publishers: publishers, TemporaryDirectory: t.TempDir(), Limits: plugincatalog.DefaultPackageLimits()})
	require.NoError(t, err)
	blobs := artifact.NewLocalBlobStore(t.TempDir())
	require.NoError(t, blobs.Ready())
	t.Cleanup(func() { require.NoError(t, blobs.Close()) })

	serviceNow := time.Date(2026, 8, 30, 18, 0, 0, 123456789, time.UTC)
	repositoryNow := serviceNow
	repository := plugincatalog.NewPostgresRepositoryWithClock(database, func() time.Time { return repositoryNow })
	artifactWriter := &failOncePluginArtifactWriter{delegate: artifact.NewPostgresStore(database, blobs), err: errors.New("injected Artifact publication failure")}
	catalog, err := plugincatalog.NewService(repository, artifactWriter, verifier, func() time.Time { return serviceNow })
	require.NoError(t, err)
	services := Services{
		PluginCatalog: catalog,
		Audit:         audit.NewService(audit.NewPostgresStore(database)),
		Idempotency:   idempotency.NewService(idempotency.NewPostgresStore(database)),
	}
	principal := principalWith(platformTestScope, openapi.PermissionUploadPluginVersionPackage)

	first := servePlatformRequest(services, principal, newPluginUploadRequest(archive, "split-clock-upload"))
	require.Equal(t, http.StatusServiceUnavailable, first.Code, first.Body.String())
	var leaseExpiresAt time.Time
	require.NoError(t, database.QueryRowContext(ctx, `SELECT lease_expires_at FROM plugin_catalog_operations WHERE tenant_id=$1 AND project_id=$2 AND idempotency_key=$3`, platformTestScope.TenantID, platformTestScope.ProjectID, "split-clock-upload").Scan(&leaseExpiresAt))
	serviceNow = leaseExpiresAt.Add(-time.Millisecond)
	repositoryNow = leaseExpiresAt.Add(time.Millisecond)

	retry := servePlatformRequest(services, principal, newPluginUploadRequest(archive, "split-clock-upload"))
	require.Equal(t, http.StatusCreated, retry.Code, retry.Body.String())
	replay := servePlatformRequest(services, principal, newPluginUploadRequest(archive, "split-clock-upload"))
	require.Equal(t, retry.Code, replay.Code)
	require.Equal(t, retry.Header().Get("ETag"), replay.Header().Get("ETag"))
	require.Equal(t, retry.Body.Bytes(), replay.Body.Bytes())

	conflicting := append([]byte(nil), archive...)
	conflicting[len(conflicting)-1] ^= 1
	conflict := servePlatformRequest(services, principal, newPluginUploadRequest(conflicting, "split-clock-upload"))
	requireProblem(t, conflict, http.StatusConflict, "idempotency_conflict", conflict.Header().Get("X-Request-ID"))

	var versionCount, operationCount, auditCount, idempotencyCount int
	var idempotencyState string
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM plugin_versions WHERE tenant_id=$1 AND project_id=$2`, platformTestScope.TenantID, platformTestScope.ProjectID).Scan(&versionCount))
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM plugin_catalog_operations WHERE tenant_id=$1 AND project_id=$2 AND idempotency_key=$3 AND state='committed'`, platformTestScope.TenantID, platformTestScope.ProjectID, "split-clock-upload").Scan(&operationCount))
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND project_id=$2 AND action='plugin.version_uploaded'`, platformTestScope.TenantID, platformTestScope.ProjectID).Scan(&auditCount))
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*), min(state) FROM idempotency_records WHERE tenant_id=$1 AND project_id=$2 AND idempotency_key=$3`, platformTestScope.TenantID, platformTestScope.ProjectID, "split-clock-upload").Scan(&idempotencyCount, &idempotencyState))
	require.Equal(t, 1, versionCount)
	require.Equal(t, 1, operationCount)
	require.Equal(t, 1, auditCount)
	require.Equal(t, 1, idempotencyCount)
	require.Equal(t, string(idempotency.StateCompleted), idempotencyState)
}

type failOncePluginArtifactWriter struct {
	delegate plugincatalog.ArtifactWriter
	err      error
}

func (writer *failOncePluginArtifactWriter) PutReader(ctx context.Context, value artifact.Artifact, source io.Reader) (artifact.Artifact, error) {
	if writer.err != nil {
		err := writer.err
		writer.err = nil
		return artifact.Artifact{}, err
	}
	return writer.delegate.PutReader(ctx, value, source)
}

func pluginCatalogV1CorpusArchive(t *testing.T) ([]byte, ed25519.PublicKey) {
	t.Helper()
	root := filepath.Join("..", "plugincatalog", "testdata", "package-v1")
	manifest := bytes.TrimSuffix(readPluginCatalogCorpusFile(t, filepath.Join(root, "manifest.json")), []byte("\n"))
	amd64Bytes, err := hex.DecodeString(string(bytes.TrimSpace(readPluginCatalogCorpusFile(t, filepath.Join(root, "linux-amd64.elf.hex")))))
	require.NoError(t, err)
	arm64Bytes, err := hex.DecodeString(string(bytes.TrimSpace(readPluginCatalogCorpusFile(t, filepath.Join(root, "linux-arm64.elf.hex")))))
	require.NoError(t, err)
	var vectors struct {
		PublicKeyHex string `json:"public_key_hex"`
		SignatureHex string `json:"signature_hex"`
	}
	require.NoError(t, json.Unmarshal(readPluginCatalogCorpusFile(t, filepath.Join(root, "vectors.json")), &vectors))
	publicKey, err := hex.DecodeString(vectors.PublicKeyHex)
	require.NoError(t, err)
	signature, err := hex.DecodeString(vectors.SignatureHex)
	require.NoError(t, err)

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range []struct {
		name string
		body []byte
	}{
		{name: "plugin-package/manifest.json", body: manifest},
		{name: "plugin-package/bin/linux-amd64/dbpilot-plugin-mysql", body: amd64Bytes},
		{name: "plugin-package/bin/linux-arm64/dbpilot-plugin-mysql", body: arm64Bytes},
		{name: "plugin-package/SIGNATURE.ed25519", body: signature},
	} {
		require.NoError(t, tarWriter.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o600, Size: int64(len(entry.body)), Typeflag: tar.TypeReg}))
		_, err := tarWriter.Write(entry.body)
		require.NoError(t, err)
	}
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzipWriter.Close())
	return buffer.Bytes(), ed25519.PublicKey(publicKey)
}

func readPluginCatalogCorpusFile(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	require.NoError(t, err)
	return value
}

var _ plugincatalog.ArtifactWriter = (*failOncePluginArtifactWriter)(nil)
