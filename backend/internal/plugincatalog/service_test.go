package plugincatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestServiceUploadPersistsVerifiedBytesAsImmutableArtifactThenCatalogVersion(t *testing.T) {
	// Break caught: trusting upload metadata or inserting catalog state before
	// immutable bytes exist can publish an unverifiable/missing plugin version.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	fixture := newSignedPackageFixture(t, "publisher-1", "key-1", private, nil)
	verifier := newTestPackageVerifier(t, public, testPackageLimits())
	artifacts := &recordingArtifactWriter{}
	repository := &recordingCatalogRepository{}
	now := time.Date(2026, 8, 30, 4, 0, 0, 0, time.UTC)
	service, err := NewService(repository, artifacts, verifier, func() time.Time { return now })
	require.NoError(t, err)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}

	version, err := service.Upload(context.Background(), scope, UploadMetadata{Actor: "publisher-user", ContentLength: int64(len(fixture.Archive))}, bytes.NewReader(fixture.Archive))
	require.NoError(t, err)
	require.Equal(t, StatusVerified, version.Status)
	require.Equal(t, uint64(1), version.Revision)
	require.Equal(t, scope, version.Scope)
	require.Equal(t, "mysql", version.PluginID)
	require.Equal(t, now, version.CreatedAt)
	require.Len(t, artifacts.values, 1)
	require.Len(t, repository.created, 1)
	storedArtifact := artifacts.values[0]
	wantDigest := sha256.Sum256(fixture.Archive)
	require.Equal(t, "sha256:"+hex.EncodeToString(wantDigest[:]), storedArtifact.Checksum)
	require.Equal(t, int64(len(fixture.Archive)), storedArtifact.SizeBytes)
	require.Equal(t, "plugin-package", storedArtifact.Kind)
	require.Equal(t, "application/gzip", storedArtifact.ContentType)
	require.Equal(t, "plugin_catalog_operation", storedArtifact.SourceResource.ResourceType)
	require.True(t, strings.HasPrefix(storedArtifact.SourceResource.ResourceID, "plugin-operation-"))
	require.Equal(t, "publisher-user", storedArtifact.CreatedBy)
	require.Equal(t, fixture.Archive, artifacts.contents[0])
	require.Equal(t, storedArtifact.ID, repository.created[0].ArtifactID)
	require.Equal(t, []string{"artifact", "catalog"}, append(artifacts.order, repository.order...))
}

func TestServiceUploadRejectsBeforeArtifactSideEffectAndDoesNotPersistSignatures(t *testing.T) {
	// Break caught: signature failure must stop before Artifact publication, and
	// the accepted domain model must not retain detached signature bytes.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	fixture := newSignedPackageFixture(t, "publisher-1", "key-1", private, nil)
	for index := range fixture.Entries {
		if fixture.Entries[index].Name == signaturePath {
			fixture.Entries[index].Body[0] ^= 0xff
		}
	}
	fixture.Archive = writeTarGzip(t, fixture.Entries)
	artifacts := &recordingArtifactWriter{}
	repository := &recordingCatalogRepository{}
	service, err := NewService(repository, artifacts, newTestPackageVerifier(t, public, testPackageLimits()), time.Now)
	require.NoError(t, err)

	_, err = service.Upload(context.Background(), platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, UploadMetadata{Actor: "publisher-user", ContentLength: int64(len(fixture.Archive))}, bytes.NewReader(fixture.Archive))
	require.ErrorIs(t, err, ErrSignatureRejected)
	require.ErrorIs(t, err, ErrBeforeSideEffect)
	require.Empty(t, artifacts.values)
	require.Empty(t, repository.created)
}

func TestServiceLifecycleUsesScopedRevisionCAS(t *testing.T) {
	// Break caught: skipping status/from-state or revision checks permits stale
	// approvals and revoked versions to become available again.
	repository := &recordingCatalogRepository{transitionValue: validServiceVersion()}
	service, err := NewService(repository, &recordingArtifactWriter{}, &recordingPackageVerifier{}, time.Now)
	require.NoError(t, err)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}

	_, err = service.Approve(context.Background(), scope, "plugin-version-1", 7)
	require.NoError(t, err)
	_, err = service.Publish(context.Background(), scope, "plugin-version-1", 8)
	require.NoError(t, err)
	_, err = service.Revoke(context.Background(), scope, "plugin-version-1", 9, "publisher_compromise")
	require.NoError(t, err)

	require.Equal(t, []TransitionRequest{
		{Scope: scope, VersionID: "plugin-version-1", ExpectedRevision: 7, AllowedFrom: []Status{StatusVerified}, To: StatusApproved},
		{Scope: scope, VersionID: "plugin-version-1", ExpectedRevision: 8, AllowedFrom: []Status{StatusApproved}, To: StatusAvailable},
		{Scope: scope, VersionID: "plugin-version-1", ExpectedRevision: 9, AllowedFrom: []Status{StatusVerified, StatusApproved, StatusAvailable, StatusDeprecated}, To: StatusRevoked, Reason: "publisher_compromise"},
	}, repository.transitions)
}

func TestUploadOperationReservesPublicationBeforeArtifactAndRecoversFinalizeFailure(t *testing.T) {
	// Break caught: Artifact publication must always have a durable pending
	// operation that can be finalized after a catalog crash/SQL failure.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	fixture := newSignedPackageFixture(t, "publisher-1", "key-1", private, nil)
	repository := &recordingCatalogRepository{finalizeOperationErr: errors.New("catalog unavailable after artifact")}
	artifacts := &recordingArtifactWriter{}
	clock := time.Date(2026, 8, 30, 4, 0, 0, 123456789, time.UTC)
	service, err := NewService(repository, artifacts, newTestPackageVerifier(t, public, testPackageLimits()), func() time.Time { return clock })
	require.NoError(t, err)
	key := OperationKey{Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, Actor: "publisher-user", OperationID: "uploadPluginVersionPackage", IdempotencyKey: "upload-operation", Fingerprint: "sha256:" + stringsOfZeros(64), OwnerToken: "owner-" + stringsOfZeros(64)}
	builder := func(value PluginVersion) (OperationResponse, error) {
		return OperationResponse{Status: 201, ETag: value.ETag(), Body: []byte(`{"version_id":"` + value.ID + `","created_at":"` + value.CreatedAt.Format(time.RFC3339Nano) + `"}`)}, nil
	}

	_, err = service.UploadOperation(context.Background(), key.Scope, UploadMetadata{Actor: key.Actor, ContentLength: int64(len(fixture.Archive))}, key, []byte(`{"audit":"original"}`), builder, bytes.NewReader(fixture.Archive))
	require.EqualError(t, err, "catalog unavailable after artifact")
	require.Equal(t, 1, repository.beginOperationCalls)
	require.Equal(t, OperationPending, repository.operation.State)
	require.Len(t, artifacts.values, 1)
	require.Equal(t, "plugin_catalog_operation", artifacts.values[0].SourceResource.ResourceType)
	require.Equal(t, key.RecordID(), artifacts.values[0].SourceResource.ResourceID)
	originalResponse := repository.operation.Response

	repository.finalizeOperationErr = nil
	clock = clock.Add(5 * time.Minute)
	snapshot, err := service.UploadOperation(context.Background(), key.Scope, UploadMetadata{Actor: key.Actor, ContentLength: int64(len(fixture.Archive))}, key, []byte(`{"audit":"original"}`), builder, bytes.NewReader(fixture.Archive))
	require.NoError(t, err)
	require.Equal(t, OperationCommitted, snapshot.State)
	require.Equal(t, originalResponse, snapshot.Response)
	require.Equal(t, 1, repository.beginOperationCalls, "retry reuses the durable reservation")
	require.Equal(t, 2, repository.finalizeOperationCalls)
}

func TestUploadOperationRenewsExpiredPendingLeaseOnFirstRetryAfterArtifactFailure(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	fixture := newSignedPackageFixture(t, "publisher-1", "key-1", private, nil)
	clock := time.Date(2026, 8, 30, 5, 0, 0, 987654321, time.UTC)
	repository := &recordingCatalogRepository{at: clock}
	artifacts := &recordingArtifactWriter{err: errors.New("artifact publication failed")}
	service, err := NewService(repository, artifacts, newTestPackageVerifier(t, public, testPackageLimits()), func() time.Time { return clock })
	require.NoError(t, err)
	key := OperationKey{Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, Actor: "publisher-user", OperationID: "uploadPluginVersionPackage", IdempotencyKey: "expired-artifact", Fingerprint: "sha256:" + stringsOfZeros(64), OwnerToken: "owner-" + stringsOfZeros(64)}
	builder := func(value PluginVersion) (OperationResponse, error) {
		return OperationResponse{Status: 201, ETag: value.ETag(), Body: []byte(`{"created_at":"` + value.CreatedAt.Format(time.RFC3339Nano) + `"}`)}, nil
	}
	_, err = service.UploadOperation(context.Background(), key.Scope, UploadMetadata{Actor: key.Actor, ContentLength: int64(len(fixture.Archive))}, key, []byte(`{"audit":"original"}`), builder, bytes.NewReader(fixture.Archive))
	require.ErrorIs(t, err, ErrArtifactUnavailable)
	require.Equal(t, OperationPending, repository.operation.State)
	originalResponse, originalCreatedAt, originalLease := repository.operation.Response, repository.operation.Version.CreatedAt, repository.operation.LeaseExpiresAt

	clock = clock.Add(DefaultOperationLease + time.Minute)
	repository.at = clock
	artifacts.err = nil
	snapshot, err := service.UploadOperation(context.Background(), key.Scope, UploadMetadata{Actor: key.Actor, ContentLength: int64(len(fixture.Archive))}, key, []byte(`{"audit":"original"}`), builder, bytes.NewReader(fixture.Archive))
	require.NoError(t, err)
	require.Equal(t, OperationCommitted, snapshot.State)
	require.Equal(t, originalResponse, snapshot.Response)
	require.Equal(t, originalCreatedAt, snapshot.Version.CreatedAt)
	require.True(t, snapshot.LeaseExpiresAt.After(originalLease))
	require.Len(t, repository.created, 1)
}

type recordingArtifactWriter struct {
	values   []artifact.Artifact
	contents [][]byte
	order    []string
	err      error
}

func (writer *recordingArtifactWriter) PutReader(_ context.Context, value artifact.Artifact, source io.Reader) (artifact.Artifact, error) {
	contents, err := io.ReadAll(source)
	if err != nil {
		return artifact.Artifact{}, err
	}
	writer.values = append(writer.values, value)
	writer.contents = append(writer.contents, contents)
	writer.order = append(writer.order, "artifact")
	if writer.err != nil {
		return artifact.Artifact{}, writer.err
	}
	return value, nil
}

type recordingCatalogRepository struct {
	created                []PluginVersion
	order                  []string
	createErr              error
	transitionValue        PluginVersion
	transitionErr          error
	transitions            []TransitionRequest
	page                   VersionPage
	definitions            DefinitionPage
	operation              OperationSnapshot
	beginOperationCalls    int
	finalizeOperationCalls int
	finalizeOperationErr   error
	at                     time.Time
}

func (repository *recordingCatalogRepository) Create(_ context.Context, _ PluginDefinition, version PluginVersion) (PluginVersion, error) {
	repository.created = append(repository.created, version)
	repository.order = append(repository.order, "catalog")
	if repository.createErr != nil {
		return PluginVersion{}, repository.createErr
	}
	return version, nil
}

func (repository *recordingCatalogRepository) Transition(_ context.Context, request TransitionRequest) (PluginVersion, error) {
	repository.transitions = append(repository.transitions, request)
	if repository.transitionErr != nil {
		return PluginVersion{}, repository.transitionErr
	}
	value := repository.transitionValue
	value.Scope, value.ID, value.Status, value.Revision = request.Scope, request.VersionID, request.To, request.ExpectedRevision+1
	return value, nil
}

func (repository *recordingCatalogRepository) ListVersions(context.Context, platformscope.Scope, VersionFilter) (VersionPage, error) {
	return repository.page, nil
}

func (repository *recordingCatalogRepository) ListDefinitions(context.Context, platformscope.Scope, DefinitionFilter) (DefinitionPage, error) {
	return repository.definitions, nil
}

func (repository *recordingCatalogRepository) GetOperation(_ context.Context, key OperationKey) (OperationSnapshot, error) {
	if repository.operation.Key.Identity() != key.Identity() {
		return OperationSnapshot{}, ErrNotFound
	}
	return repository.operation, nil
}

func (repository *recordingCatalogRepository) BeginUploadOperation(_ context.Context, request UploadOperationRequest) (OperationSnapshot, error) {
	if repository.operation.Key.Identity() == request.Key.Identity() {
		if !operationMatchesUpload(repository.operation, request) {
			return OperationSnapshot{}, ErrConflict
		}
		if !repository.at.IsZero() && repository.operation.State == OperationPending && !repository.operation.LeaseExpiresAt.After(repository.at) {
			repository.operation.State = OperationAbandoned
			abandonedAt := repository.at
			repository.operation.AbandonedAt = &abandonedAt
		}
		if repository.operation.State == OperationAbandoned {
			if !request.LeaseExpiresAt.After(repository.operation.LeaseExpiresAt) {
				return OperationSnapshot{}, ErrConflict
			}
			repository.operation.State = OperationPending
			repository.operation.LeaseExpiresAt = request.LeaseExpiresAt
			repository.operation.AbandonedAt = nil
		}
		return repository.operation, nil
	}
	repository.beginOperationCalls++
	repository.operation = OperationSnapshot{Key: request.Key, Kind: "upload", State: OperationPending, Definition: request.Definition, Version: request.Version, ArtifactID: request.ArtifactID, ArtifactSHA256: request.ArtifactSHA256, ArtifactBytes: request.ArtifactBytes, LeaseExpiresAt: request.LeaseExpiresAt, Response: request.Response, AuditEventJSON: append([]byte(nil), request.AuditEventJSON...)}
	return repository.operation, nil
}

func (repository *recordingCatalogRepository) FinalizeUploadOperation(_ context.Context, _ OperationKey, builder OperationResponseBuilder) (OperationSnapshot, error) {
	repository.finalizeOperationCalls++
	if repository.finalizeOperationErr != nil {
		return OperationSnapshot{}, repository.finalizeOperationErr
	}
	response, err := builder(repository.operation.Version)
	if err != nil {
		return OperationSnapshot{}, err
	}
	repository.operation.State, repository.operation.Response = OperationCommitted, response
	repository.created = append(repository.created, repository.operation.Version)
	repository.order = append(repository.order, "catalog")
	return repository.operation, nil
}

func (repository *recordingCatalogRepository) TransitionOperation(_ context.Context, request TransitionOperationRequest, builder OperationResponseBuilder) (OperationSnapshot, error) {
	value, err := repository.Transition(context.Background(), request.Transition)
	if err != nil {
		return OperationSnapshot{}, err
	}
	response, err := builder(value)
	if err != nil {
		return OperationSnapshot{}, err
	}
	repository.operation = OperationSnapshot{Key: request.Key, State: OperationCommitted, Version: value, Response: response, AuditEventJSON: append([]byte(nil), request.AuditEventJSON...)}
	return repository.operation, nil
}

func (repository *recordingCatalogRepository) ReconcileExpiredUploadOperations(context.Context, time.Time, int) (OperationReconcileResult, error) {
	return OperationReconcileResult{}, nil
}

func (repository *recordingCatalogRepository) ListUnreconciledCommittedOperations(context.Context, int) ([]OperationSnapshot, error) {
	if repository.operation.State == OperationCommitted && repository.operation.CompletionReconciledAt == nil {
		return []OperationSnapshot{repository.operation}, nil
	}
	return nil, nil
}

func (repository *recordingCatalogRepository) MarkOperationCompletionReconciled(_ context.Context, _ OperationKey, at time.Time) error {
	repository.operation.CompletionReconciledAt = &at
	return nil
}

type recordingPackageVerifier struct {
	value VerifiedPackage
	err   error
}

func (verifier *recordingPackageVerifier) Verify(context.Context, io.Reader, int64) (VerifiedPackage, error) {
	return verifier.value, verifier.err
}

func validServiceVersion() PluginVersion {
	return PluginVersion{
		ID: "plugin-version-1", Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		PluginID: "mysql", Version: "1.0.0", Status: StatusVerified,
		ArtifactID: "plugin-package-a", PackageSHA256: stringsOfZeros(64), ManifestDigest: stringsOfZeros(64),
		PublisherID: "publisher-1", SigningKeyID: "key-1", ProtocolVersion: "v1",
		MinimumAgentProtocolVersion: "v1", MaximumAgentProtocolVersion: "v1",
		SupportedVariants: []string{"mysql"}, DatabaseVersionRange: ">=8 <9", Capabilities: []string{"metrics.collect"},
		MetricTemplateSchemaVersion: 1,
		Platforms:                   []Platform{{OperatingSystem: "linux", Architecture: "amd64", SHA256: stringsOfZeros(64), SizeBytes: 24}},
		Revision:                    7, CreatedAt: time.Date(2026, 8, 30, 3, 0, 0, 0, time.UTC),
	}
}
