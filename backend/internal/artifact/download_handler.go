package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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

type LocalBlobStore struct{ root string }

func NewLocalBlobStore(root string) *LocalBlobStore { return &LocalBlobStore{root: root} }

func (store *LocalBlobStore) Ready() error {
	if store == nil || strings.TrimSpace(store.root) == "" {
		return ErrInvalid
	}
	root, err := os.OpenRoot(store.root)
	if err != nil {
		return ErrInvalid
	}
	if err := root.Close(); err != nil {
		return ErrInvalid
	}
	return nil
}

func (store *LocalBlobStore) Open(ctx context.Context, value Artifact) (ReadSeekCloser, error) {
	if store == nil || ctx == nil || ctx.Err() != nil || strings.TrimSpace(store.root) == "" || strings.TrimSpace(value.StorageReference) == "" {
		return nil, ErrInvalid
	}
	reference := filepath.FromSlash(value.StorageReference)
	clean := filepath.Clean(reference)
	if !filepath.IsLocal(reference) || clean != reference || clean == "." || strings.ContainsRune(reference, 0) {
		return nil, ErrInvalid
	}
	root, err := os.OpenRoot(store.root)
	if err != nil {
		return nil, ErrInvalid
	}
	file, err := root.Open(clean)
	closeErr := root.Close()
	if err != nil {
		return nil, ErrNotFound
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, ErrInvalid
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrInvalid
	}
	return file, nil
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
