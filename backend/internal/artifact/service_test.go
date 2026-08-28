package artifact

import (
	"context"
	"errors"
	"testing"
	"time"

	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestGetRequiresExactArtifactScopeAndReturnsIntegrityMetadata(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	value := Artifact{ID: "artifact-1", Scope: scope, Kind: "inspection-report", ContentType: "application/json", SizeBytes: 37, Checksum: "sha256:abc", CreatedAt: time.Now()}
	service := NewService(staticStore{artifact: value}, staticSigner{})

	got, err := service.Get(context.Background(), scope, value.ID)
	require.NoError(t, err)
	require.Equal(t, int64(37), got.SizeBytes)
	require.Equal(t, "sha256:abc", got.Checksum)

	_, err = service.Get(context.Background(), platformscope.Scope{TenantID: scope.TenantID, ProjectID: "project-2"}, value.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestCreateDownloadRejectsExpiredArtifact(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	expires := now.Add(-time.Second)
	service := NewService(staticStore{artifact: Artifact{ID: "artifact-1", Scope: scope, ExpiresAt: &expires}}, staticSigner{})
	service.now = func() time.Time { return now }

	_, err := service.CreateDownload(context.Background(), scope, "artifact-1", time.Minute)
	require.ErrorIs(t, err, ErrExpired)
}

func TestCreateDownloadClampsTTLAndContainsNoStorageCredential(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	signer := &recordingSigner{url: "/api/v1/artifacts/artifact-1/content?signature=safe"}
	service := NewService(staticStore{artifact: Artifact{ID: "artifact-1", Scope: scope, StorageReference: "secret://storage/prod"}}, signer)
	service.now = func() time.Time { return now }

	download, err := service.CreateDownload(context.Background(), scope, "artifact-1", time.Hour)
	require.NoError(t, err)
	require.Equal(t, now.Add(MaximumDownloadTTL), signer.expiresAt)
	require.Equal(t, now.Add(MaximumDownloadTTL), download.ExpiresAt)
	require.NotContains(t, download.URL, "secret://")
	require.Empty(t, download.Headers)
}

func TestCreateDownloadClassifiesOnlyFailuresBeforeSignerInvocation(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	storeFailure := errors.New("artifact store unavailable")
	_, err := NewService(staticStore{err: storeFailure}, staticSigner{}).CreateDownload(context.Background(), scope, "artifact-1", time.Minute)
	require.ErrorIs(t, err, ErrBeforeDownloadSideEffect)
	require.ErrorIs(t, err, storeFailure)

	signerFailure := errors.New("signer outcome unknown")
	_, err = NewService(staticStore{artifact: Artifact{ID: "artifact-1", Scope: scope}}, failingSigner{err: signerFailure}).CreateDownload(context.Background(), scope, "artifact-1", time.Minute)
	require.ErrorIs(t, err, signerFailure)
	require.NotErrorIs(t, err, ErrBeforeDownloadSideEffect)
}

func TestCreateDownloadAtReconstructsIdenticalDescriptorFromPersistedClaimTime(t *testing.T) {
	issuedAt := time.Date(2026, 8, 28, 12, 0, 0, 987654321, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	signer, err := NewHMACDownloadSigner("https://downloads.example/api/v1/artifacts", "secret://download/key", database.StaticSecretResolver{
		"secret://download/key": []byte("0123456789abcdef0123456789abcdef"),
	})
	require.NoError(t, err)
	service := NewService(staticStore{artifact: Artifact{ID: "artifact-1", Scope: scope}}, signer)

	first, err := service.CreateDownloadAt(context.Background(), scope, "artifact-1", issuedAt, MaximumDownloadTTL)
	require.NoError(t, err)
	signer.now = func() time.Time { return issuedAt.Add(time.Hour) }
	second, err := service.CreateDownloadAt(context.Background(), scope, "artifact-1", issuedAt, MaximumDownloadTTL)
	require.NoError(t, err)

	require.Equal(t, first, second)
	require.Equal(t, issuedAt.Add(MaximumDownloadTTL).Truncate(time.Second), first.ExpiresAt)
}

type staticStore struct {
	artifact Artifact
	err      error
}

func (store staticStore) Get(_ context.Context, _ platformscope.Scope, _ string) (Artifact, error) {
	return store.artifact, store.err
}

type staticSigner struct{}

func (staticSigner) Sign(context.Context, Artifact, time.Time) (string, error) {
	return "/download", nil
}

type failingSigner struct{ err error }

func (signer failingSigner) Sign(context.Context, Artifact, time.Time) (string, error) {
	return "", signer.err
}

type recordingSigner struct {
	expiresAt time.Time
	url       string
}

func (signer *recordingSigner) Sign(_ context.Context, _ Artifact, expiresAt time.Time) (string, error) {
	signer.expiresAt = expiresAt
	return signer.url, nil
}
