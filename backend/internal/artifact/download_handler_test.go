package artifact

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	blobs := NewLocalBlobStore(root)
	t.Cleanup(func() { require.NoError(t, blobs.Close()) })
	handler, err := NewDownloadHandler(service, signer, blobs)
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
			blobs := NewLocalBlobStore(root)
			t.Cleanup(func() { require.NoError(t, blobs.Close()) })
			handler, err := NewDownloadHandler(service, signer, blobs)
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

func TestSymlinkSwapCannotEscapeLocalRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	safe := filepath.Join(root, "safe")
	require.NoError(t, os.Mkdir(safe, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(safe, "payload.bin"), []byte("inside"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.bin"), []byte("outside-secret"), 0o600))
	require.NoError(t, os.Rename(filepath.Join(outside, "secret.bin"), filepath.Join(outside, "payload.bin")))
	current := filepath.Join(root, "current")
	alternate := filepath.Join(root, "alternate")
	if err := createTestDirectoryLink(safe, current); err != nil {
		t.Skipf("directory links unavailable: %v", err)
	}
	if err := createTestDirectoryLink(outside, alternate); err != nil {
		t.Skipf("directory links unavailable: %v", err)
	}
	store := NewLocalBlobStore(root)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	metadata := Artifact{StorageReference: filepath.Join("current", "payload.bin")}
	done := make(chan struct{})
	swaps := make(chan int, 1)
	go func() {
		defer close(done)
		completed := 0
		temporary := filepath.Join(root, "swapping")
		for range 4000 {
			if os.Rename(current, temporary) == nil && os.Rename(alternate, current) == nil && os.Rename(temporary, alternate) == nil {
				completed++
			}
		}
		swaps <- completed
	}()

	for range 4000 {
		reader, err := store.Open(context.Background(), metadata)
		if err != nil {
			continue
		}
		payload, readErr := io.ReadAll(reader)
		_ = reader.Close()
		require.NoError(t, readErr)
		require.NotEqual(t, "outside-secret", string(payload), "a symlink swap escaped the configured root")
	}
	<-done
	require.Positive(t, <-swaps, "the test must execute at least one link swap")
}

func TestReadyRootReplacementNeverReadsReplacementDirectory(t *testing.T) {
	parent := t.TempDir()
	configuredRoot := filepath.Join(parent, "artifacts")
	originalRoot := filepath.Join(parent, "original-artifacts")
	require.NoError(t, os.Mkdir(configuredRoot, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(configuredRoot, "payload.bin"), []byte("original"), 0o600))
	store := NewLocalBlobStore(configuredRoot)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	require.NoError(t, store.Ready())

	if err := os.Rename(configuredRoot, originalRoot); err != nil {
		reader, openErr := store.Open(context.Background(), Artifact{StorageReference: "payload.bin"})
		require.NoError(t, openErr)
		payload, readErr := io.ReadAll(reader)
		_ = reader.Close()
		require.NoError(t, readErr)
		require.Equal(t, "original", string(payload))
		return
	}
	require.NoError(t, os.Mkdir(configuredRoot, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(configuredRoot, "payload.bin"), []byte("replacement-secret"), 0o600))

	reader, err := store.Open(context.Background(), Artifact{StorageReference: "payload.bin"})
	if err != nil {
		require.ErrorIs(t, err, ErrInvalid)
		return
	}
	payload, readErr := io.ReadAll(reader)
	_ = reader.Close()
	require.NoError(t, readErr)
	require.Equal(t, "original", string(payload))
	require.NotEqual(t, "replacement-secret", string(payload))
}

func createTestDirectoryLink(target, link string) error {
	if err := os.Symlink(target, link); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}
	return exec.Command("cmd", "/c", "mklink", "/J", link, target).Run()
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
