package plugincatalog

import (
	"context"
	"encoding/json"
	"errors"
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
	operations OperationRepository
	artifacts  ArtifactWriter
	verifier   PackageVerifier
	now        func() time.Time
}

func NewService(repository Repository, artifacts ArtifactWriter, verifier PackageVerifier, now func() time.Time) (*Application, error) {
	if repository == nil || artifacts == nil || verifier == nil || now == nil {
		return nil, ErrInvalid
	}
	operations, _ := repository.(OperationRepository)
	return &Application{repository: repository, operations: operations, artifacts: artifacts, verifier: verifier, now: now}, nil
}

func (service *Application) Ready(ctx context.Context) error {
	if service == nil || service.operations == nil || ctx == nil {
		return ErrInvalid
	}
	verifier, verifierOK := service.verifier.(interface{ Ready(context.Context) error })
	repository, repositoryOK := service.repository.(interface{ Ready(context.Context) error })
	if !verifierOK || !repositoryOK {
		return ErrInvalid
	}
	if err := verifier.Ready(ctx); err != nil {
		return err
	}
	return repository.Ready(ctx)
}

func (service *Application) UploadOperation(ctx context.Context, scope platformscope.Scope, metadata UploadMetadata, key OperationKey, auditJSON []byte, builder OperationResponseBuilder, source io.Reader) (OperationSnapshot, error) {
	if service == nil || service.operations == nil || key.Scope != scope || key.Validate() != nil || metadata.Actor != key.Actor || metadata.ContentLength <= 0 || source == nil || !json.Valid(auditJSON) || builder == nil {
		return OperationSnapshot{}, ErrInvalid
	}
	var authoritative *OperationSnapshot
	if existing, err := service.operations.GetOperation(ctx, key); err == nil && existing.State == OperationCommitted {
		return existing, nil
	} else if err == nil {
		if existing.Validate() != nil || existing.State != OperationPending && existing.State != OperationAbandoned {
			return OperationSnapshot{}, ErrConflict
		}
		authoritative = &existing
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return OperationSnapshot{}, err
	}
	verified, err := service.verifier.Verify(ctx, source, metadata.ContentLength)
	if err != nil {
		return OperationSnapshot{}, err
	}
	return service.publishVerifiedOperation(ctx, scope, metadata, key, auditJSON, builder, verified, authoritative)
}

func (service *Application) publishVerifiedOperation(ctx context.Context, scope platformscope.Scope, metadata UploadMetadata, key OperationKey, auditJSON []byte, builder OperationResponseBuilder, verified VerifiedPackage, authoritative *OperationSnapshot) (OperationSnapshot, error) {
	// PostgreSQL timestamptz is microsecond-precision. Canonicalize once before
	// building both the immutable version and response snapshot so transaction
	// round-trips never change replay bytes.
	retryAt := service.now().UTC().Truncate(time.Microsecond)
	createdAt := retryAt
	definition, version, artifactValue, response, finalizeBuilder, leaseExpiresAt := PluginDefinition{}, PluginVersion{}, artifact.Artifact{}, OperationResponse{}, builder, retryAt.Add(DefaultOperationLease)
	if authoritative == nil {
		var err error
		definition, version, artifactValue, err = service.valuesForVerified(scope, metadata, key.RecordID(), createdAt, verified)
		if err == nil {
			response, err = builder(version)
		}
		if err != nil || response.Validate() != nil {
			if verified.Close() != nil {
				return OperationSnapshot{}, ErrArtifactUnavailable
			}
			return OperationSnapshot{}, ErrInvalid
		}
	} else {
		if !authoritativeVerifiedPackageMatches(*authoritative, verified, auditJSON) {
			if verified.Close() != nil {
				return OperationSnapshot{}, ErrArtifactUnavailable
			}
			return OperationSnapshot{}, ErrConflict
		}
		definition, version, response, createdAt = authoritative.Definition, authoritative.Version, authoritative.Response, authoritative.Version.CreatedAt
		leaseExpiresAt = authoritative.LeaseExpiresAt
		if authoritative.State == OperationAbandoned || !authoritative.LeaseExpiresAt.After(retryAt) {
			leaseExpiresAt = retryAt.Add(DefaultOperationLease)
		}
		artifactValue = artifact.Artifact{ID: authoritative.ArtifactID, Scope: scope, Kind: "plugin-package", ContentType: "application/gzip", SizeBytes: authoritative.ArtifactBytes, Checksum: "sha256:" + authoritative.ArtifactSHA256, SourceResource: artifact.ResourceReference{ResourceType: "plugin_catalog_operation", ResourceID: key.RecordID()}, CreatedBy: metadata.Actor, CreatedAt: createdAt}
		finalizeBuilder = func(PluginVersion) (OperationResponse, error) { return response, nil }
	}
	pending, err := service.operations.BeginUploadOperation(ctx, UploadOperationRequest{
		Key: key, Definition: definition, Version: version, ArtifactID: artifactValue.ID,
		ArtifactSHA256: version.PackageSHA256, ArtifactBytes: verified.SizeBytes, CreatedBy: metadata.Actor, CreatedAt: createdAt,
		LeaseExpiresAt: leaseExpiresAt, Response: response,
		AuditEventJSON: append([]byte(nil), auditJSON...),
	})
	if err != nil {
		if verified.Close() != nil {
			return OperationSnapshot{}, ErrArtifactUnavailable
		}
		return OperationSnapshot{}, err
	}
	if pending.State == OperationCommitted {
		if verified.Close() != nil {
			return OperationSnapshot{}, ErrArtifactUnavailable
		}
		return pending, nil
	}
	reader, err := verified.Open()
	if err != nil {
		if verified.Close() != nil {
			return OperationSnapshot{}, ErrArtifactUnavailable
		}
		return OperationSnapshot{}, ErrArtifactUnavailable
	}
	storedArtifact, artifactErr := service.artifacts.PutReader(ctx, artifactValue, reader)
	closeReaderErr := reader.Close()
	cleanupErr := verified.Close()
	if artifactErr != nil || closeReaderErr != nil || cleanupErr != nil || storedArtifact.ID != artifactValue.ID || storedArtifact.Scope != scope || storedArtifact.Checksum != artifactValue.Checksum || storedArtifact.SizeBytes != artifactValue.SizeBytes {
		return OperationSnapshot{}, ErrArtifactUnavailable
	}
	return service.operations.FinalizeUploadOperation(ctx, key, finalizeBuilder)
}

func authoritativeVerifiedPackageMatches(value OperationSnapshot, verified VerifiedPackage, auditJSON []byte) bool {
	return value.Key.Scope == value.Version.Scope && value.Version.ID != "" && value.Version.PackageSHA256 == verified.PackageSHA256 && value.Version.ManifestDigest == verified.ManifestDigest && value.ArtifactID == value.Version.ArtifactID && value.ArtifactSHA256 == verified.PackageSHA256 && value.ArtifactBytes == verified.SizeBytes && value.Version.PluginID == verified.Manifest.PluginID && value.Version.Version == verified.Manifest.Version && AuditPayloadMatches(value.AuditEventJSON, auditJSON)
}

func (service *Application) valuesForVerified(scope platformscope.Scope, metadata UploadMetadata, sourceResourceID string, createdAt time.Time, verified VerifiedPackage) (PluginDefinition, PluginVersion, artifact.Artifact, error) {
	if createdAt.IsZero() || !digestPattern.MatchString(verified.PackageSHA256) || !digestPattern.MatchString(verified.ManifestDigest) {
		return PluginDefinition{}, PluginVersion{}, artifact.Artifact{}, beforeSideEffect(ErrInvalid)
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
	definition := PluginDefinition{Scope: scope, PluginID: version.PluginID, Name: version.PluginID, DatabaseFamily: verified.Manifest.DatabaseFamily, ProtocolVersion: version.ProtocolVersion, SupportedVariants: append([]string(nil), version.SupportedVariants...), Capabilities: append([]string(nil), version.Capabilities...)}
	artifactValue := artifact.Artifact{
		ID: artifactID, Scope: scope, Kind: "plugin-package", ContentType: "application/gzip", SizeBytes: verified.SizeBytes,
		Checksum:       "sha256:" + verified.PackageSHA256,
		SourceResource: artifact.ResourceReference{ResourceType: "plugin_catalog_operation", ResourceID: sourceResourceID},
		CreatedBy:      metadata.Actor, CreatedAt: createdAt,
	}
	if version.Validate() != nil || definition.Validate() != nil {
		return PluginDefinition{}, PluginVersion{}, artifact.Artifact{}, beforeSideEffect(ErrInvalid)
	}
	return definition, version, artifactValue, nil
}

func (service *Application) ApproveOperation(ctx context.Context, scope platformscope.Scope, versionID string, revision uint64, key OperationKey, auditJSON []byte, builder OperationResponseBuilder) (OperationSnapshot, error) {
	return service.transitionOperation(ctx, TransitionOperationRequest{Key: key, Transition: TransitionRequest{Scope: scope, VersionID: versionID, ExpectedRevision: revision, AllowedFrom: []Status{StatusVerified}, To: StatusApproved}, AuditEventJSON: auditJSON}, builder)
}

func (service *Application) PublishOperation(ctx context.Context, scope platformscope.Scope, versionID string, revision uint64, key OperationKey, auditJSON []byte, builder OperationResponseBuilder) (OperationSnapshot, error) {
	return service.transitionOperation(ctx, TransitionOperationRequest{Key: key, Transition: TransitionRequest{Scope: scope, VersionID: versionID, ExpectedRevision: revision, AllowedFrom: []Status{StatusApproved}, To: StatusAvailable}, AuditEventJSON: auditJSON}, builder)
}

func (service *Application) RevokeOperation(ctx context.Context, scope platformscope.Scope, versionID string, revision uint64, reason string, key OperationKey, auditJSON []byte, builder OperationResponseBuilder) (OperationSnapshot, error) {
	if !reasonPattern.MatchString(reason) {
		return OperationSnapshot{}, ErrInvalid
	}
	return service.transitionOperation(ctx, TransitionOperationRequest{Key: key, Transition: TransitionRequest{Scope: scope, VersionID: versionID, ExpectedRevision: revision, AllowedFrom: []Status{StatusVerified, StatusApproved, StatusAvailable, StatusDeprecated}, To: StatusRevoked, Reason: reason}, AuditEventJSON: auditJSON}, builder)
}

func (service *Application) transitionOperation(ctx context.Context, request TransitionOperationRequest, builder OperationResponseBuilder) (OperationSnapshot, error) {
	if service == nil || service.operations == nil || request.Key.Scope != request.Transition.Scope || request.Key.Validate() != nil || !json.Valid(request.AuditEventJSON) || builder == nil {
		return OperationSnapshot{}, ErrInvalid
	}
	return service.operations.TransitionOperation(ctx, request, builder)
}

func (service *Application) RecoverOperation(ctx context.Context, key OperationKey) (OperationSnapshot, error) {
	if service == nil || service.operations == nil || ctx == nil || key.Validate() != nil {
		return OperationSnapshot{}, ErrInvalid
	}
	value, err := service.operations.GetOperation(ctx, key)
	if err != nil {
		return OperationSnapshot{}, err
	}
	if value.State != OperationCommitted {
		return OperationSnapshot{}, ErrOperationPending
	}
	return value, nil
}

func (service *Application) ReconcileExpiredUploadOperations(ctx context.Context, at time.Time, limit int) (OperationReconcileResult, error) {
	if service == nil || service.operations == nil || ctx == nil || at.IsZero() || limit < 1 || limit > 100 {
		return OperationReconcileResult{}, ErrInvalid
	}
	return service.operations.ReconcileExpiredUploadOperations(ctx, at.UTC(), limit)
}

func (service *Application) ListUnreconciledCommittedOperations(ctx context.Context, limit int) ([]OperationSnapshot, error) {
	if service == nil || service.operations == nil || ctx == nil || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	return service.operations.ListUnreconciledCommittedOperations(ctx, limit)
}

func (service *Application) MarkOperationCompletionReconciled(ctx context.Context, key OperationKey, at time.Time) error {
	if service == nil || service.operations == nil || ctx == nil || key.Validate() != nil || at.IsZero() {
		return ErrInvalid
	}
	return service.operations.MarkOperationCompletionReconciled(ctx, key, at.UTC())
}

func (service *Application) Upload(ctx context.Context, scope platformscope.Scope, metadata UploadMetadata, source io.Reader) (PluginVersion, error) {
	if service == nil || ctx == nil || scope.Validate() != nil || !canonicalText(metadata.Actor, 256) || metadata.ContentLength <= 0 || source == nil {
		return PluginVersion{}, beforeSideEffect(ErrInvalid)
	}
	if service.operations == nil {
		return PluginVersion{}, ErrInvalid
	}
	verified, err := service.verifier.Verify(ctx, source, metadata.ContentLength)
	if err != nil {
		return PluginVersion{}, err
	}
	key := OperationKey{Scope: scope, Actor: metadata.Actor, OperationID: "uploadPluginVersionPackage", IdempotencyKey: "implicit-" + verified.PackageSHA256[:32], Fingerprint: "sha256:" + verified.PackageSHA256, OwnerToken: "owner-" + verified.PackageSHA256}
	auditJSON, _ := json.Marshal(map[string]any{"operation_id": key.OperationID, "package_sha256": verified.PackageSHA256})
	snapshot, err := service.publishVerifiedOperation(ctx, scope, metadata, key, auditJSON, func(value PluginVersion) (OperationResponse, error) {
		body, marshalErr := json.Marshal(value)
		return OperationResponse{Status: 201, ETag: value.ETag(), Body: body}, marshalErr
	}, verified, nil)
	if err != nil {
		return PluginVersion{}, err
	}
	return snapshot.Version, nil
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
