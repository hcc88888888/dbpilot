package plugincatalog

import (
	"context"
	"io"
	"time"

	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/platformscope"
)

type ArtifactWriter interface {
	PutReader(context.Context, artifact.Artifact, io.Reader) (artifact.Artifact, error)
}

type Application struct {
	repository Repository
	artifacts  ArtifactWriter
	verifier   PackageVerifier
	now        func() time.Time
}

func NewService(repository Repository, artifacts ArtifactWriter, verifier PackageVerifier, now func() time.Time) (*Application, error) {
	if repository == nil || artifacts == nil || verifier == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Application{repository: repository, artifacts: artifacts, verifier: verifier, now: now}, nil
}

func (service *Application) Upload(ctx context.Context, scope platformscope.Scope, metadata UploadMetadata, source io.Reader) (PluginVersion, error) {
	if service == nil || ctx == nil || scope.Validate() != nil || !canonicalText(metadata.Actor, 256) || metadata.ContentLength <= 0 || source == nil {
		return PluginVersion{}, beforeSideEffect(ErrInvalid)
	}
	verified, err := service.verifier.Verify(ctx, source, metadata.ContentLength)
	if err != nil {
		return PluginVersion{}, err
	}
	defer verified.Close()
	createdAt := service.now().UTC()
	if createdAt.IsZero() || !digestPattern.MatchString(verified.PackageSHA256) || !digestPattern.MatchString(verified.ManifestDigest) {
		return PluginVersion{}, beforeSideEffect(ErrInvalid)
	}
	versionID := "plugin-version-" + verified.PackageSHA256[:32]
	artifactID := "plugin-package-" + verified.PackageSHA256
	platforms := make([]Platform, len(verified.Manifest.Binaries))
	for index, binary := range verified.Manifest.Binaries {
		platforms[index] = Platform{OperatingSystem: binary.OperatingSystem, Architecture: binary.Architecture, SHA256: binary.SHA256, SizeBytes: binary.SizeBytes}
	}
	version := PluginVersion{
		ID: versionID, Scope: scope, PluginID: verified.Manifest.PluginID, Version: verified.Manifest.Version,
		Status: StatusVerified, ArtifactID: artifactID, PackageSHA256: verified.PackageSHA256, ManifestDigest: verified.ManifestDigest,
		PublisherID: verified.Manifest.PublisherID, SigningKeyID: verified.Manifest.SigningKeyID, ProtocolVersion: verified.Manifest.ProtocolVersion,
		MinimumAgentProtocolVersion: verified.Manifest.MinimumAgentProtocolVersion, MaximumAgentProtocolVersion: verified.Manifest.MaximumAgentProtocolVersion,
		SupportedVariants: append([]string(nil), verified.Manifest.SupportedVariants...), DatabaseVersionRange: verified.Manifest.DatabaseVersionRange,
		Capabilities: append([]string(nil), verified.Manifest.Capabilities...), MetricTemplateSchemaVersion: verified.Manifest.MetricTemplateSchemaVersion,
		Platforms: platforms, Revision: 1, CreatedAt: createdAt,
	}
	if err := version.Validate(); err != nil {
		return PluginVersion{}, beforeSideEffect(ErrInvalid)
	}
	definition := PluginDefinition{
		Scope: scope, PluginID: version.PluginID, Name: version.PluginID, DatabaseFamily: verified.Manifest.DatabaseFamily,
		ProtocolVersion: version.ProtocolVersion, SupportedVariants: append([]string(nil), version.SupportedVariants...), Capabilities: append([]string(nil), version.Capabilities...),
	}
	if err := definition.Validate(); err != nil {
		return PluginVersion{}, beforeSideEffect(ErrInvalid)
	}
	reader, err := verified.Open()
	if err != nil {
		return PluginVersion{}, ErrArtifactUnavailable
	}
	storedArtifact, artifactErr := service.artifacts.PutReader(ctx, artifact.Artifact{
		ID: artifactID, Scope: scope, Kind: "plugin-package", ContentType: "application/gzip", SizeBytes: verified.SizeBytes,
		Checksum:       "sha256:" + verified.PackageSHA256,
		SourceResource: artifact.ResourceReference{ResourceType: "plugin-version", ResourceID: versionID},
		CreatedBy:      metadata.Actor, CreatedAt: createdAt,
	}, reader)
	closeErr := reader.Close()
	if artifactErr != nil || closeErr != nil {
		return PluginVersion{}, ErrArtifactUnavailable
	}
	if storedArtifact.ID != artifactID || storedArtifact.Scope != scope || storedArtifact.Checksum != "sha256:"+verified.PackageSHA256 || storedArtifact.SizeBytes != verified.SizeBytes {
		return PluginVersion{}, ErrArtifactUnavailable
	}
	created, err := service.repository.Create(ctx, definition, version)
	if err != nil {
		return PluginVersion{}, err
	}
	if created.ID != version.ID || created.Scope != scope || created.PackageSHA256 != version.PackageSHA256 || created.ManifestDigest != version.ManifestDigest || created.ArtifactID != artifactID || created.Validate() != nil {
		return PluginVersion{}, ErrConflict
	}
	return created, nil
}

func (service *Application) Approve(ctx context.Context, scope platformscope.Scope, versionID string, expectedRevision uint64) (PluginVersion, error) {
	return service.transition(ctx, TransitionRequest{Scope: scope, VersionID: versionID, ExpectedRevision: expectedRevision, AllowedFrom: []Status{StatusVerified}, To: StatusApproved})
}

func (service *Application) Publish(ctx context.Context, scope platformscope.Scope, versionID string, expectedRevision uint64) (PluginVersion, error) {
	return service.transition(ctx, TransitionRequest{Scope: scope, VersionID: versionID, ExpectedRevision: expectedRevision, AllowedFrom: []Status{StatusApproved}, To: StatusAvailable})
}

func (service *Application) Revoke(ctx context.Context, scope platformscope.Scope, versionID string, expectedRevision uint64, reason string) (PluginVersion, error) {
	if !reasonPattern.MatchString(reason) {
		return PluginVersion{}, ErrInvalid
	}
	return service.transition(ctx, TransitionRequest{Scope: scope, VersionID: versionID, ExpectedRevision: expectedRevision, AllowedFrom: []Status{StatusVerified, StatusApproved, StatusAvailable, StatusDeprecated}, To: StatusRevoked, Reason: reason})
}

func (service *Application) transition(ctx context.Context, request TransitionRequest) (PluginVersion, error) {
	if service == nil || ctx == nil || request.Scope.Validate() != nil || !catalogIDPattern.MatchString(request.VersionID) || request.ExpectedRevision == 0 || len(request.AllowedFrom) == 0 || !request.To.Valid() {
		return PluginVersion{}, ErrInvalid
	}
	value, err := service.repository.Transition(ctx, request)
	if err != nil {
		return PluginVersion{}, err
	}
	if value.Scope != request.Scope || value.ID != request.VersionID || value.Status != request.To || value.Revision != request.ExpectedRevision+1 || value.Validate() != nil {
		return PluginVersion{}, ErrConflict
	}
	return value, nil
}

func (service *Application) ListVersions(ctx context.Context, scope platformscope.Scope, filter VersionFilter) (VersionPage, error) {
	if service == nil || ctx == nil || scope.Validate() != nil || filter.Validate() != nil {
		return VersionPage{}, ErrInvalid
	}
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	page, err := service.repository.ListVersions(ctx, scope, filter)
	if err != nil {
		return VersionPage{}, err
	}
	for _, value := range page.Items {
		if value.Scope != scope || value.Validate() != nil {
			return VersionPage{}, ErrConflict
		}
	}
	return page, nil
}

func (service *Application) ListDefinitions(ctx context.Context, scope platformscope.Scope, filter DefinitionFilter) (DefinitionPage, error) {
	if service == nil || ctx == nil || scope.Validate() != nil || filter.Validate() != nil {
		return DefinitionPage{}, ErrInvalid
	}
	if filter.Limit == 0 {
		filter.Limit = 50
	}
	page, err := service.repository.ListDefinitions(ctx, scope, filter)
	if err != nil {
		return DefinitionPage{}, err
	}
	for _, value := range page.Items {
		if value.Scope != scope || value.Validate() != nil {
			return DefinitionPage{}, ErrConflict
		}
	}
	return page, nil
}

var _ CatalogService = (*Application)(nil)
