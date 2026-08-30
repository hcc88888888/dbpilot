package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestLocalBlobStorePutReaderVerifiesRetrySourceWhenBlobAlreadyExists(t *testing.T) {
	// Break caught: content-addressed existence must not turn PutReader into a
	// trust-caller shortcut; every supplied stream is independently verified.
	store := NewLocalBlobStore(t.TempDir())
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	payload := []byte("verified plugin bytes")
	checksum := testChecksum(payload)
	_, err := store.PutReader(context.Background(), checksum, int64(len(payload)), bytes.NewReader(payload))
	require.NoError(t, err)
	tampered := []byte("tampered plugin bytes")
	_, err = store.PutReader(context.Background(), checksum, int64(len(tampered)), bytes.NewReader(tampered))
	require.ErrorIs(t, err, ErrIntegrityMismatch)
}

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
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	signed, err := signer.Sign(context.Background(), metadata, now.Add(time.Minute))
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
			now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
			signer := testDownloadSigner(t, scope, metadata)
			service := NewService(staticStore{artifact: metadata}, signer)
			blobs := NewLocalBlobStore(root)
			t.Cleanup(func() { require.NoError(t, blobs.Close()) })
			handler, err := NewDownloadHandler(service, signer, blobs)
			require.NoError(t, err)
			signed, err := signer.Sign(context.Background(), metadata, now.Add(time.Minute))
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

func TestLocalBlobReadyProbesWritableRetainedRootAndCleansUniqueHiddenFiles(t *testing.T) {
	root := t.TempDir()
	sentinel := filepath.Join(root, "existing-report.blob")
	require.NoError(t, os.WriteFile(sentinel, []byte("do not alter"), 0o600))
	store := NewLocalBlobStore(root)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	require.NoError(t, store.Ready())
	require.NotNil(t, store.root)
	require.Equal(t, "do not alter", string(requireFileContents(t, sentinel)))
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Equal(t, []string{"existing-report.blob"}, []string{entries[0].Name()})
}

func TestLocalBlobReadyFailureBoundariesNeverRetainRootOrLeaveProbeFiles(t *testing.T) {
	for _, step := range []string{"create", "write", "file_sync", "publish", "remove", "directory_sync"} {
		t.Run(step, func(t *testing.T) {
			root := t.TempDir()
			sentinel := filepath.Join(root, "existing-report.blob")
			require.NoError(t, os.WriteFile(sentinel, []byte("unchanged"), 0o600))
			store := NewLocalBlobStore(root)
			t.Cleanup(func() { require.NoError(t, store.Close()) })
			store.readyProbeHook = func(current string) error {
				if current == step {
					return errors.New("injected " + step + " failure")
				}
				return nil
			}

			err := store.Ready()

			require.ErrorContains(t, err, "injected")
			require.Nil(t, store.root)
			entries, readErr := os.ReadDir(root)
			require.NoError(t, readErr)
			require.Len(t, entries, 1)
			require.Equal(t, "existing-report.blob", entries[0].Name())
			require.Equal(t, "unchanged", string(requireFileContents(t, sentinel)))
		})
	}
}

func TestLocalBlobReadyFallsBackToAtomicRenameWhenHardLinkUnavailable(t *testing.T) {
	root := t.TempDir()
	store := NewLocalBlobStore(root)
	store.readyLink = func(*os.Root, string, string) error { return errors.New("hard links unavailable") }
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	require.NoError(t, store.Ready())
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func requireFileContents(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	return contents
}

func TestLocalBlobPutUsesRetainedRootAfterConfiguredPathReplacement(t *testing.T) {
	// Break caught: reopening the configured path for writes after Ready lets a
	// path replacement redirect immutable report bytes outside the retained root.
	parent := t.TempDir()
	configuredRoot := filepath.Join(parent, "artifacts")
	originalRoot := filepath.Join(parent, "original-artifacts")
	require.NoError(t, os.Mkdir(configuredRoot, 0o700))
	store := NewLocalBlobStore(configuredRoot)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	require.NoError(t, store.Ready())
	if err := os.Rename(configuredRoot, originalRoot); err != nil {
		t.Skipf("root directory replacement unavailable: %v", err)
	}
	require.NoError(t, os.Mkdir(configuredRoot, 0o700))
	payload := []byte("durable retained-root report")
	digest := sha256.Sum256(payload)
	checksum := fmt.Sprintf("sha256:%x", digest)

	reference, err := store.Put(context.Background(), checksum, payload)

	require.NoError(t, err)
	require.FileExists(t, filepath.Join(originalRoot, filepath.FromSlash(reference)))
	require.NoFileExists(t, filepath.Join(configuredRoot, filepath.FromSlash(reference)))
}

func TestLocalBlobPutConcurrentWritersNeverClobber(t *testing.T) {
	// Break caught: separate control-plane processes do not share a Go mutex;
	// publication must use an atomic no-replace filesystem primitive.
	root := t.TempDir()
	first := NewLocalBlobStore(root)
	second := NewLocalBlobStore(root)
	t.Cleanup(func() { require.NoError(t, first.Close()); require.NoError(t, second.Close()) })

	t.Run("same content", func(t *testing.T) {
		payload := []byte("same immutable bytes")
		checksum := testChecksum(payload)
		type result struct {
			reference string
			err       error
		}
		results := make(chan result, 2)
		for _, store := range []*LocalBlobStore{first, second} {
			go func(store *LocalBlobStore) {
				reference, err := store.Put(context.Background(), checksum, payload)
				results <- result{reference: reference, err: err}
			}(store)
		}
		one, two := <-results, <-results
		require.NoError(t, one.err)
		require.NoError(t, two.err)
		require.Equal(t, one.reference, two.reference)
		stored, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(one.reference)))
		require.NoError(t, err)
		require.Equal(t, payload, stored)
	})

	t.Run("different content", func(t *testing.T) {
		payloads := [][]byte{[]byte("first immutable bytes"), []byte("second immutable bytes")}
		references := make(chan string, 2)
		errorsChannel := make(chan error, 2)
		for index, store := range []*LocalBlobStore{first, second} {
			go func(store *LocalBlobStore, payload []byte) {
				reference, err := store.Put(context.Background(), testChecksum(payload), payload)
				references <- reference
				errorsChannel <- err
			}(store, payloads[index])
		}
		firstReference, secondReference := <-references, <-references
		require.NoError(t, <-errorsChannel)
		require.NoError(t, <-errorsChannel)
		require.NotEqual(t, firstReference, secondReference)
	})
	temporary, err := filepath.Glob(filepath.Join(root, "sha256", ".tmp-*"))
	require.NoError(t, err)
	require.Empty(t, temporary)
}

func TestLocalBlobPutRepairsUncertainDirectorySyncOnRetry(t *testing.T) {
	// Break caught: publication may be visible even when directory fsync fails;
	// an identical retry must sync the containing directory before success.
	root := t.TempDir()
	store := NewLocalBlobStore(root)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	payload := []byte("durable after retry")
	checksum := testChecksum(payload)
	forced := errors.New("forced directory sync failure")
	store.syncDirectory = func(_ *os.Root, name string) error {
		if name == "sha256" {
			return forced
		}
		return nil
	}

	_, firstErr := store.Put(context.Background(), checksum, payload)
	require.Error(t, firstErr)
	store.syncDirectory = nil
	reference, secondErr := store.Put(context.Background(), checksum, payload)

	require.NoError(t, secondErr)
	stored, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(reference)))
	require.NoError(t, err)
	require.Equal(t, payload, stored)
}

func TestLocalBlobPutNeverReplacesConflictingExistingBytes(t *testing.T) {
	// Break caught: checksum-addressed publication must fail closed if storage
	// is corrupt; repair may not overwrite the bytes that exposed corruption.
	root := t.TempDir()
	payload := []byte("expected immutable bytes")
	checksum := testChecksum(payload)
	reference := filepath.Join("sha256", strings.TrimPrefix(checksum, "sha256:")+".blob")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sha256"), 0o700))
	conflicting := []byte("conflict immutable bytes")
	require.Equal(t, len(payload), len(conflicting))
	require.NoError(t, os.WriteFile(filepath.Join(root, reference), conflicting, 0o600))
	store := NewLocalBlobStore(root)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	_, err := store.Put(context.Background(), checksum, payload)

	require.ErrorIs(t, err, ErrIntegrityMismatch)
	stored, readErr := os.ReadFile(filepath.Join(root, reference))
	require.NoError(t, readErr)
	require.Equal(t, conflicting, stored)
}

func testChecksum(payload []byte) string {
	digest := sha256.Sum256(payload)
	return fmt.Sprintf("sha256:%x", digest)
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
