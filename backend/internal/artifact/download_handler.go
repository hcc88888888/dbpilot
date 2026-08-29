package artifact

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"dbpilot.local/platform/internal/platformscope"
)

type MetadataReader interface {
	Get(context.Context, platformscope.Scope, string) (Artifact, error)
}

type DownloadVerifier interface {
	VerifyRequest(context.Context, *http.Request) (DownloadClaims, error)
}

type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

type BlobStore interface {
	Open(context.Context, Artifact) (ReadSeekCloser, error)
}

type DownloadHandler struct {
	metadata MetadataReader
	verifier DownloadVerifier
	blobs    BlobStore
}

func NewDownloadHandler(metadata MetadataReader, verifier DownloadVerifier, blobs BlobStore) (*DownloadHandler, error) {
	if metadata == nil || verifier == nil || blobs == nil {
		return nil, ErrInvalid
	}
	return &DownloadHandler{metadata: metadata, verifier: verifier, blobs: blobs}, nil
}

func (handler *DownloadHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request == nil || request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, err := handler.verifier.VerifyRequest(request.Context(), request)
	if err != nil {
		http.Error(writer, "artifact download is not authorized", http.StatusForbidden)
		return
	}
	value, err := handler.metadata.Get(request.Context(), claims.Scope, claims.ArtifactID)
	if err != nil || value.ID != claims.ArtifactID || value.Scope != claims.Scope {
		http.Error(writer, "artifact is unavailable", http.StatusNotFound)
		return
	}
	reader, err := handler.blobs.Open(request.Context(), value)
	if err != nil {
		http.Error(writer, "artifact is unavailable", http.StatusNotFound)
		return
	}
	defer reader.Close()
	if err := verifyArtifactContent(request.Context(), reader, value); err != nil {
		http.Error(writer, "artifact failed integrity validation", http.StatusConflict)
		return
	}
	writer.Header().Set("Content-Type", value.ContentType)
	writer.Header().Set("Content-Length", strconv.FormatInt(value.SizeBytes, 10))
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(writer, reader, value.SizeBytes)
}

func verifyArtifactContent(ctx context.Context, reader ReadSeekCloser, value Artifact) error {
	if ctx == nil || value.SizeBytes < 0 || value.ContentType == "" || !strings.HasPrefix(value.Checksum, "sha256:") {
		return ErrIntegrityMismatch
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(value.Checksum, "sha256:"))
	if err != nil || len(expected) != sha256.Size {
		return ErrIntegrityMismatch
	}
	hash := sha256.New()
	written, err := io.Copy(hash, &contextReader{ctx: ctx, reader: reader})
	if err != nil || written != value.SizeBytes || !equalBytes(hash.Sum(nil), expected) {
		return ErrIntegrityMismatch
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return ErrIntegrityMismatch
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func equalBytes(first, second []byte) bool {
	if len(first) != len(second) {
		return false
	}
	var different byte
	for index := range first {
		different |= first[index] ^ second[index]
	}
	return different == 0
}

type LocalBlobStore struct {
	rootPath       string
	mu             sync.RWMutex
	root           *os.Root
	closed         bool
	syncDirectory  func(*os.Root, string) error
	readyProbeHook func(string) error
	readyLink      func(*os.Root, string, string) error
}

func NewLocalBlobStore(root string) *LocalBlobStore { return &LocalBlobStore{rootPath: root} }

func (store *LocalBlobStore) Ready() error {
	if store == nil || strings.TrimSpace(store.rootPath) == "" {
		return ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return ErrInvalid
	}
	if store.root != nil {
		return nil
	}
	root, err := os.OpenRoot(store.rootPath)
	if err != nil {
		return ErrInvalid
	}
	if err := store.probeWritableRoot(root); err != nil {
		_ = root.Close()
		return fmt.Errorf("artifact storage readiness probe: %w", err)
	}
	store.root = root
	return nil
}

func (store *LocalBlobStore) probeWritableRoot(root *os.Root) error {
	if root == nil {
		return ErrInvalid
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	base := ".dbpilot-ready-" + hex.EncodeToString(random)
	temporary, published := base+".tmp", base+".probe"
	var file *os.File
	defer func() {
		if file != nil {
			_ = file.Close()
		}
		_ = root.Remove(published)
		_ = root.Remove(temporary)
	}()
	if err := store.readyProbeStep("create"); err != nil {
		return err
	}
	created, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	file = created
	if err := store.readyProbeStep("write"); err != nil {
		return err
	}
	if _, err := file.Write([]byte("dbpilot artifact readiness\n")); err != nil {
		return err
	}
	if err := store.readyProbeStep("file_sync"); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	file = nil
	if err := store.readyProbeStep("publish"); err != nil {
		return err
	}
	link := root.Link
	if store.readyLink != nil {
		link = func(oldName, newName string) error { return store.readyLink(root, oldName, newName) }
	}
	linked := link(temporary, published) == nil
	if !linked {
		if err := root.Rename(temporary, published); err != nil {
			return err
		}
	}
	if err := store.readyProbeStep("remove"); err != nil {
		return err
	}
	if err := root.Remove(published); err != nil {
		return err
	}
	if linked {
		if err := root.Remove(temporary); err != nil {
			return err
		}
	}
	if err := store.readyProbeStep("directory_sync"); err != nil {
		return err
	}
	return store.syncRetainedDirectoryAt(root, ".")
}

func (store *LocalBlobStore) readyProbeStep(step string) error {
	if store.readyProbeHook == nil {
		return nil
	}
	return store.readyProbeHook(step)
}

func (store *LocalBlobStore) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	if store.root == nil {
		return nil
	}
	err := store.root.Close()
	store.root = nil
	return err
}

func (store *LocalBlobStore) Open(ctx context.Context, value Artifact) (ReadSeekCloser, error) {
	if store == nil || ctx == nil || ctx.Err() != nil || strings.TrimSpace(store.rootPath) == "" || strings.TrimSpace(value.StorageReference) == "" {
		return nil, ErrInvalid
	}
	reference := filepath.FromSlash(value.StorageReference)
	clean := filepath.Clean(reference)
	if !filepath.IsLocal(reference) || clean != reference || clean == "." || strings.ContainsRune(reference, 0) {
		return nil, ErrInvalid
	}
	if err := store.Ready(); err != nil {
		return nil, ErrInvalid
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed || store.root == nil {
		return nil, ErrInvalid
	}
	file, err := store.root.Open(clean)
	if err != nil {
		return nil, ErrNotFound
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrInvalid
	}
	return file, nil
}

// Put durably publishes checksum-addressed bytes beneath the already retained
// os.Root. The checksum is verified before any write and an existing blob is
// accepted only when its bytes are identical.
func (store *LocalBlobStore) Put(ctx context.Context, checksum string, contents []byte) (string, error) {
	if store == nil || ctx == nil || ctx.Err() != nil || len(contents) > 64<<20 || !strings.HasPrefix(checksum, "sha256:") {
		return "", ErrInvalid
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(checksum, "sha256:"))
	if err != nil || len(expected) != sha256.Size {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(contents)
	if !equalBytes(digest[:], expected) {
		return "", ErrIntegrityMismatch
	}
	if err := store.Ready(); err != nil {
		return "", err
	}
	hexDigest := hex.EncodeToString(expected)
	directory := "sha256"
	reference := filepath.Join(directory, hexDigest+".blob")
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed || store.root == nil {
		return "", ErrInvalid
	}
	if matches, exists, err := rootBlobMatches(store.root, reference, contents); err != nil {
		return "", safeBlobError("inspect", err)
	} else if exists {
		if !matches {
			return "", ErrIntegrityMismatch
		}
		if err := store.syncRetainedDirectory(directory); err != nil {
			return "", safeBlobError("sync directory", err)
		}
		return filepath.ToSlash(reference), nil
	}
	if err := store.root.MkdirAll(directory, 0o700); err != nil {
		return "", safeBlobError("create directory", err)
	}
	if err := store.syncRetainedDirectory("."); err != nil {
		return "", safeBlobError("sync root directory", err)
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", safeBlobError("create temporary name", err)
	}
	temporary := filepath.Join(directory, ".tmp-"+hex.EncodeToString(random))
	file, err := store.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", safeBlobError("create temporary", err)
	}
	cleanup := func() {
		_ = file.Close()
		_ = store.root.Remove(temporary)
	}
	for offset := 0; offset < len(contents); {
		if err := ctx.Err(); err != nil {
			cleanup()
			return "", err
		}
		written, writeErr := file.Write(contents[offset:])
		if writeErr == nil && written <= 0 {
			writeErr = io.ErrShortWrite
		}
		if writeErr != nil {
			cleanup()
			return "", safeBlobError("write temporary", writeErr)
		}
		offset += written
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return "", safeBlobError("sync temporary", err)
	}
	if err := file.Close(); err != nil {
		_ = store.root.Remove(temporary)
		return "", safeBlobError("close temporary", err)
	}
	if matches, exists, err := rootBlobMatches(store.root, reference, contents); err != nil {
		_ = store.root.Remove(temporary)
		return "", safeBlobError("inspect", err)
	} else if exists {
		_ = store.root.Remove(temporary)
		if !matches {
			return "", ErrIntegrityMismatch
		}
		if err := store.syncRetainedDirectory(directory); err != nil {
			return "", safeBlobError("sync directory", err)
		}
		return filepath.ToSlash(reference), nil
	}
	if err := store.root.Link(temporary, reference); err != nil {
		_ = store.root.Remove(temporary)
		matches, exists, inspectErr := rootBlobMatches(store.root, reference, contents)
		if inspectErr != nil {
			return "", safeBlobError("inspect collision", inspectErr)
		}
		if exists {
			if !matches {
				return "", ErrIntegrityMismatch
			}
			if syncErr := store.syncRetainedDirectory(directory); syncErr != nil {
				return "", safeBlobError("sync directory", syncErr)
			}
			return filepath.ToSlash(reference), nil
		}
		return "", safeBlobError("publish", err)
	}
	if err := store.root.Remove(temporary); err != nil {
		return "", safeBlobError("remove temporary", err)
	}
	if err := store.syncRetainedDirectory(directory); err != nil {
		return "", safeBlobError("sync directory", err)
	}
	return filepath.ToSlash(reference), nil
}

func (store *LocalBlobStore) syncRetainedDirectory(name string) error {
	return store.syncRetainedDirectoryAt(store.root, name)
}

func (store *LocalBlobStore) syncRetainedDirectoryAt(root *os.Root, name string) error {
	if store.syncDirectory != nil {
		return store.syncDirectory(root, name)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func rootBlobMatches(root *os.Root, reference string, contents []byte) (bool, bool, error) {
	file, err := root.Open(reference)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, true, err
	}
	if !info.Mode().IsRegular() || info.Size() != int64(len(contents)) {
		return false, true, nil
	}
	stored := make([]byte, len(contents))
	if _, err := io.ReadFull(file, stored); err != nil {
		return false, true, err
	}
	return bytes.Equal(stored, contents), true, nil
}

var _ http.Handler = (*DownloadHandler)(nil)
var _ BlobStore = (*LocalBlobStore)(nil)

// Keep error messages independent of StorageReference and filesystem paths.
func safeBlobError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalid) || errors.Is(err, ErrIntegrityMismatch) {
		return err
	}
	return fmt.Errorf("%s artifact blob", operation)
}
