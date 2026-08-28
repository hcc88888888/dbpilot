package artifact

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestDownloadHandlerVerifiesClaimsAndStreamsExactLocalArtifact(t *testing.T) {
	root := t.TempDir()
	payload := []byte("durable artifact content\n")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "tenant-a"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "tenant-a", "artifact-1.bin"), payload, 0o600))
	digest := sha256.Sum256(payload)
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	metadata := Artifact{ID: "artifact-1", Scope: scope, Kind: "report", ContentType: "application/octet-stream", SizeBytes: int64(len(payload)), Checksum: fmt.Sprintf("sha256:%x", digest), CreatedAt: time.Now().UTC(), StorageReference: "tenant-a/artifact-1.bin"}
	signer := testDownloadSigner(t, scope, metadata)
	service := NewService(staticStore{artifact: metadata}, signer)
	handler, err := NewDownloadHandler(service, signer, NewLocalBlobStore(root))
	require.NoError(t, err)
	signed, err := signer.Sign(context.Background(), metadata, time.Minute)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, signed, nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, metadata.ContentType, response.Header().Get("Content-Type"))
	require.Equal(t, fmt.Sprint(len(payload)), response.Header().Get("Content-Length"))
	require.Equal(t, payload, response.Body.Bytes())
	require.NotContains(t, response.Body.String(), metadata.StorageReference)
}

func TestDownloadHandlerRejectsUnsafeReferenceAndIntegrityMismatchWithoutLeakingReference(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "artifact.bin"), []byte("actual"), 0o600))
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	tests := map[string]Artifact{
		"traversal": {ID: "artifact-1", Scope: scope, Kind: "report", ContentType: "text/plain", SizeBytes: 6, Checksum: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CreatedAt: time.Now().UTC(), StorageReference: "../outside-secret"},
		"size":      {ID: "artifact-1", Scope: scope, Kind: "report", ContentType: "text/plain", SizeBytes: 99, Checksum: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CreatedAt: time.Now().UTC(), StorageReference: "artifact.bin"},
		"checksum":  {ID: "artifact-1", Scope: scope, Kind: "report", ContentType: "text/plain", SizeBytes: 6, Checksum: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CreatedAt: time.Now().UTC(), StorageReference: "artifact.bin"},
	}
	for name, metadata := range tests {
		t.Run(name, func(t *testing.T) {
			signer := testDownloadSigner(t, scope, metadata)
			service := NewService(staticStore{artifact: metadata}, signer)
			handler, err := NewDownloadHandler(service, signer, NewLocalBlobStore(root))
			require.NoError(t, err)
			signed, err := signer.Sign(context.Background(), metadata, time.Minute)
			require.NoError(t, err)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, signed, nil))

			require.NotEqual(t, http.StatusOK, response.Code)
			require.NotContains(t, response.Body.String(), metadata.StorageReference)
		})
	}
}

func testDownloadSigner(t *testing.T, scope platformscope.Scope, metadata Artifact) *HMACDownloadSigner {
	t.Helper()
	resolver := database.StaticSecretResolver{"secret://download/key": []byte("0123456789abcdef0123456789abcdef")}
	signer, err := NewHMACDownloadSigner("https://downloads.example/api/v1/artifact-downloads", "secret://download/key", resolver)
	require.NoError(t, err)
	signer.now = func() time.Time { return time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC) }
	_ = scope
	_ = metadata
	return signer
}
