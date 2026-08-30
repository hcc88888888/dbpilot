package plugincatalog

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

const definitionColumnsSQL = "tenant_id, project_id, plugin_id, name, database_family, protocol_version, supported_variants, capabilities, latest_available_version"
const definitionListColumnsSQL = "d.tenant_id, d.project_id, d.plugin_id, d.name, d.database_family, d.protocol_version, d.supported_variants, d.capabilities, (SELECT v.semantic_version FROM plugin_versions v WHERE v.tenant_id = d.tenant_id AND v.project_id = d.project_id AND v.plugin_id = d.plugin_id AND v.status = 'available' ORDER BY v.created_at DESC, v.version_id DESC LIMIT 1) AS latest_available_version"
const versionColumnsSQL = "version_id, tenant_id, project_id, plugin_id, semantic_version, status, artifact_id, package_sha256, manifest_digest, publisher_id, signing_key_id, protocol_version, minimum_agent_protocol_version, maximum_agent_protocol_version, supported_variants, database_version_range, capabilities, metric_template_schema_version, platforms, revision, created_at, approved_at"

const insertDefinitionSQL = "INSERT INTO plugin_definitions (tenant_id, project_id, plugin_id, name, database_family, protocol_version, supported_variants, capabilities) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (tenant_id, project_id, plugin_id) DO UPDATE SET name = EXCLUDED.name, protocol_version = EXCLUDED.protocol_version, supported_variants = EXCLUDED.supported_variants, capabilities = EXCLUDED.capabilities WHERE plugin_definitions.database_family = EXCLUDED.database_family RETURNING " + definitionColumnsSQL
const insertVersionSQL = "INSERT INTO plugin_versions (version_id, tenant_id, project_id, plugin_id, semantic_version, status, artifact_id, package_sha256, manifest_digest, publisher_id, signing_key_id, protocol_version, minimum_agent_protocol_version, maximum_agent_protocol_version, supported_variants, database_version_range, capabilities, metric_template_schema_version, platforms, revision, created_at, approved_at, revocation_reason) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23) ON CONFLICT DO NOTHING RETURNING " + versionColumnsSQL
const transitionVersionSQL = "UPDATE plugin_versions SET status = $1, revision = revision + 1, approved_at = CASE WHEN $1 = 'approved' THEN $2 ELSE approved_at END, revocation_reason = CASE WHEN $1 = 'revoked' THEN $3 ELSE revocation_reason END WHERE tenant_id = $4 AND project_id = $5 AND version_id = $6 AND revision = $7 AND status = ANY($8) RETURNING " + versionColumnsSQL
const versionExistsSQL = "SELECT EXISTS (SELECT 1 FROM plugin_versions WHERE tenant_id = $1 AND project_id = $2 AND version_id = $3)"
const operationColumnsSQL = "operation_record_id, tenant_id, project_id, actor, operation_id, idempotency_key, request_fingerprint, owner_token, kind, state, version_id, plugin_id, semantic_version, artifact_id, artifact_sha256, artifact_bytes, definition_json, version_json, response_status, response_etag, response_body, audit_event_json, created_at, updated_at, lease_expires_at, abandoned_at"
const getOperationSQL = "SELECT " + operationColumnsSQL + " FROM plugin_catalog_operations WHERE tenant_id = $1 AND project_id = $2 AND actor = $3 AND operation_id = $4 AND idempotency_key = $5"
const insertOperationSQL = "INSERT INTO plugin_catalog_operations (operation_record_id, tenant_id, project_id, actor, operation_id, idempotency_key, request_fingerprint, owner_token, kind, state, version_id, plugin_id, semantic_version, artifact_id, artifact_sha256, artifact_bytes, definition_json, version_json, response_status, response_etag, response_body, audit_event_json, created_at, updated_at, lease_expires_at, abandoned_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26) ON CONFLICT DO NOTHING RETURNING " + operationColumnsSQL

type PostgresRepository struct {
	database *sql.DB
	now      func() time.Time
}

func NewPostgresRepository(database *sql.DB) *PostgresRepository {
	return NewPostgresRepositoryWithClock(database, time.Now)
}

func NewPostgresRepositoryWithClock(database *sql.DB, now func() time.Time) *PostgresRepository {
	return &PostgresRepository{database: database, now: now}
}

func (repository *PostgresRepository) Ready(ctx context.Context) error {
	if repository == nil || repository.database == nil || ctx == nil {
		return ErrInvalid
	}
	var ready bool
	if err := repository.database.QueryRowContext(ctx, "SELECT to_regclass('plugin_definitions') IS NOT NULL AND to_regclass('plugin_versions') IS NOT NULL AND to_regclass('plugin_catalog_operations') IS NOT NULL").Scan(&ready); err != nil || !ready {
		return ErrArtifactUnavailable
	}
	return nil
}

func (repository *PostgresRepository) Create(ctx context.Context, definition PluginDefinition, version PluginVersion) (PluginVersion, error) {
	if repository == nil || repository.database == nil || ctx == nil || definition.Validate() != nil || version.Validate() != nil || definition.Scope != version.Scope || definition.PluginID != version.PluginID {
		return PluginVersion{}, ErrInvalid
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return PluginVersion{}, err
	}
	rollback := func() { _ = transaction.Rollback() }
	storedDefinition, err := scanDefinition(transaction.QueryRowContext(ctx, insertDefinitionSQL,
		definition.Scope.TenantID, definition.Scope.ProjectID, definition.PluginID, definition.Name, definition.DatabaseFamily,
		definition.ProtocolVersion, jsonStrings(definition.SupportedVariants), jsonStrings(definition.Capabilities),
	))
	if errors.Is(err, sql.ErrNoRows) {
		rollback()
		return PluginVersion{}, ErrConflict
	}
	if err != nil {
		rollback()
		return PluginVersion{}, err
	}
	if storedDefinition.Scope != definition.Scope || storedDefinition.PluginID != definition.PluginID || storedDefinition.DatabaseFamily != definition.DatabaseFamily {
		rollback()
		return PluginVersion{}, ErrConflict
	}
	platforms, err := json.Marshal(version.Platforms)
	if err != nil {
		rollback()
		return PluginVersion{}, ErrInvalid
	}
	stored, err := scanVersion(transaction.QueryRowContext(ctx, insertVersionSQL,
		version.ID, version.Scope.TenantID, version.Scope.ProjectID, version.PluginID, version.Version, version.Status,
		version.ArtifactID, version.PackageSHA256, version.ManifestDigest, version.PublisherID, version.SigningKeyID, version.ProtocolVersion,
		version.MinimumAgentProtocolVersion, version.MaximumAgentProtocolVersion, jsonStrings(version.SupportedVariants), version.DatabaseVersionRange,
		jsonStrings(version.Capabilities), version.MetricTemplateSchemaVersion, string(platforms), version.Revision, version.CreatedAt.UTC(), version.ApprovedAt, "",
	))
	if errors.Is(err, sql.ErrNoRows) {
		stored, err = scanVersion(transaction.QueryRowContext(ctx, "SELECT "+versionColumnsSQL+" FROM plugin_versions WHERE tenant_id = $1 AND project_id = $2 AND version_id = $3", version.Scope.TenantID, version.Scope.ProjectID, version.ID))
		if errors.Is(err, sql.ErrNoRows) {
			rollback()
			return PluginVersion{}, ErrConflict
		}
	}
	if err != nil {
		rollback()
		return PluginVersion{}, err
	}
	if stored.Scope != version.Scope || stored.ID != version.ID || stored.PackageSHA256 != version.PackageSHA256 || stored.ManifestDigest != version.ManifestDigest || stored.ArtifactID != version.ArtifactID || stored.Validate() != nil {
		rollback()
		return PluginVersion{}, ErrConflict
	}
	if err := transaction.Commit(); err != nil {
		return PluginVersion{}, err
	}
	return stored, nil
}

func (repository *PostgresRepository) Transition(ctx context.Context, request TransitionRequest) (PluginVersion, error) {
	if repository == nil || repository.database == nil || repository.now == nil || ctx == nil || request.Scope.Validate() != nil || !catalogIDPattern.MatchString(request.VersionID) || request.ExpectedRevision == 0 || len(request.AllowedFrom) == 0 || !request.To.Valid() || request.Reason != "" && !reasonPattern.MatchString(request.Reason) {
		return PluginVersion{}, ErrInvalid
	}
	allowed := make([]string, len(request.AllowedFrom))
	for index, status := range request.AllowedFrom {
		if !status.Valid() {
			return PluginVersion{}, ErrInvalid
		}
		allowed[index] = string(status)
	}
	at := repository.now().UTC()
	stored, err := scanVersion(repository.database.QueryRowContext(ctx, transitionVersionSQL,
		request.To, at, request.Reason, request.Scope.TenantID, request.Scope.ProjectID, request.VersionID, request.ExpectedRevision, stringArrayLiteral(allowed),
	))
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if existsErr := repository.database.QueryRowContext(ctx, versionExistsSQL, request.Scope.TenantID, request.Scope.ProjectID, request.VersionID).Scan(&exists); existsErr != nil {
			return PluginVersion{}, existsErr
		}
		if !exists {
			return PluginVersion{}, ErrNotFound
		}
		return PluginVersion{}, ErrRevisionConflict
	}
	if err != nil {
		return PluginVersion{}, err
	}
	return stored, nil
}

func (repository *PostgresRepository) ListVersions(ctx context.Context, scope platformscope.Scope, filter VersionFilter) (VersionPage, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || filter.Validate() != nil {
		return VersionPage{}, ErrInvalid
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 50
	}
	query := "SELECT " + versionColumnsSQL + " FROM plugin_versions WHERE tenant_id = $1 AND project_id = $2"
	arguments := []any{scope.TenantID, scope.ProjectID}
	add := func(condition string, value any) {
		arguments = append(arguments, value)
		query += fmt.Sprintf(condition, len(arguments))
	}
	if filter.VersionID != "" {
		add(" AND version_id = $%d", filter.VersionID)
	}
	if filter.PluginID != "" {
		add(" AND plugin_id = $%d", filter.PluginID)
	}
	if filter.Status != "" {
		add(" AND status = $%d", filter.Status)
	}
	if filter.Cursor != "" {
		cursor, err := decodeVersionCursor(filter.Cursor)
		if err != nil || cursor.Scope != scope {
			return VersionPage{}, ErrInvalid
		}
		arguments = append(arguments, cursor.CreatedAt, cursor.ID)
		query += fmt.Sprintf(" AND (created_at, version_id) < ($%d, $%d)", len(arguments)-1, len(arguments))
	}
	arguments = append(arguments, limit+1)
	query += fmt.Sprintf(" ORDER BY created_at DESC, version_id DESC LIMIT $%d", len(arguments))
	rows, err := repository.database.QueryContext(ctx, query, arguments...)
	if err != nil {
		return VersionPage{}, err
	}
	defer rows.Close()
	items := make([]PluginVersion, 0, limit+1)
	for rows.Next() {
		value, scanErr := scanVersion(rows)
		if scanErr != nil {
			return VersionPage{}, scanErr
		}
		items = append(items, value)
	}
	if err := rows.Err(); err != nil {
		return VersionPage{}, err
	}
	page := VersionPage{}
	if len(items) > limit {
		page.More = true
		items = items[:limit]
		cursor, err := encodeVersionCursor(versionCursor{Scope: scope, CreatedAt: items[len(items)-1].CreatedAt, ID: items[len(items)-1].ID})
		if err != nil {
			return VersionPage{}, err
		}
		page.NextCursor = cursor
	}
	page.Items = items
	return page, nil
}

func (repository *PostgresRepository) ListDefinitions(ctx context.Context, scope platformscope.Scope, filter DefinitionFilter) (DefinitionPage, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || filter.Validate() != nil {
		return DefinitionPage{}, ErrInvalid
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 50
	}
	query := "SELECT " + definitionListColumnsSQL + " FROM plugin_definitions d WHERE d.tenant_id = $1 AND d.project_id = $2"
	arguments := []any{scope.TenantID, scope.ProjectID}
	if filter.DatabaseFamily != "" {
		arguments = append(arguments, filter.DatabaseFamily)
		query += " AND d.database_family = $3"
	}
	if filter.Cursor != "" {
		cursor, err := decodeDefinitionCursor(filter.Cursor)
		if err != nil || cursor.Scope != scope {
			return DefinitionPage{}, ErrInvalid
		}
		arguments = append(arguments, cursor.PluginID)
		query += fmt.Sprintf(" AND d.plugin_id > $%d", len(arguments))
	}
	arguments = append(arguments, limit+1)
	query += fmt.Sprintf(" ORDER BY d.plugin_id ASC LIMIT $%d", len(arguments))
	rows, err := repository.database.QueryContext(ctx, query, arguments...)
	if err != nil {
		return DefinitionPage{}, err
	}
	defer rows.Close()
	items := make([]PluginDefinition, 0, limit+1)
	for rows.Next() {
		value, scanErr := scanDefinition(rows)
		if scanErr != nil {
			return DefinitionPage{}, scanErr
		}
		items = append(items, value)
	}
	if err := rows.Err(); err != nil {
		return DefinitionPage{}, err
	}
	page := DefinitionPage{}
	if len(items) > limit {
		page.More = true
		items = items[:limit]
		cursor, err := encodeDefinitionCursor(definitionCursor{Scope: scope, PluginID: items[len(items)-1].PluginID})
		if err != nil {
			return DefinitionPage{}, err
		}
		page.NextCursor = cursor
	}
	page.Items = items
	return page, nil
}

func (repository *PostgresRepository) GetOperation(ctx context.Context, key OperationKey) (OperationSnapshot, error) {
	if repository == nil || repository.database == nil || ctx == nil || key.Validate() != nil {
		return OperationSnapshot{}, ErrInvalid
	}
	value, err := scanOperation(repository.database.QueryRowContext(ctx, getOperationSQL, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey))
	if errors.Is(err, sql.ErrNoRows) {
		return OperationSnapshot{}, ErrNotFound
	}
	if err != nil {
		return OperationSnapshot{}, err
	}
	if value.Key != key {
		return OperationSnapshot{}, ErrConflict
	}
	return value, nil
}

func (repository *PostgresRepository) BeginUploadOperation(ctx context.Context, request UploadOperationRequest) (OperationSnapshot, error) {
	if repository == nil || repository.database == nil || ctx == nil || request.Key.Validate() != nil || request.Definition.Validate() != nil || request.Version.Validate() != nil || request.Key.Scope != request.Version.Scope || request.Definition.Scope != request.Version.Scope || request.ArtifactID != request.Version.ArtifactID || request.ArtifactSHA256 != request.Version.PackageSHA256 || request.ArtifactBytes <= 0 || !canonicalText(request.CreatedBy, 256) || request.CreatedAt.IsZero() || request.LeaseExpiresAt.IsZero() || request.Response.Validate() != nil || !json.Valid(request.AuditEventJSON) {
		return OperationSnapshot{}, ErrInvalid
	}
	if existing, err := repository.GetOperation(ctx, request.Key); err == nil {
		if !operationMatchesUpload(existing, request) {
			return OperationSnapshot{}, ErrConflict
		}
		if existing.State == OperationPending && !existing.LeaseExpiresAt.After(repository.now().UTC()) {
			if _, reconcileErr := repository.ReconcileExpiredUploadOperations(ctx, repository.now().UTC(), 10); reconcileErr != nil {
				return OperationSnapshot{}, reconcileErr
			}
			existing, err = repository.GetOperation(ctx, request.Key)
			if err != nil {
				return OperationSnapshot{}, err
			}
		}
		if existing.State == OperationAbandoned {
			adopted, adoptErr := scanOperation(repository.database.QueryRowContext(ctx, "UPDATE plugin_catalog_operations SET state = 'pending', abandoned_at = NULL, lease_expires_at = $1, updated_at = $2 WHERE tenant_id = $3 AND project_id = $4 AND operation_record_id = $5 AND state = 'abandoned' RETURNING "+operationColumnsSQL, request.LeaseExpiresAt.UTC(), repository.now().UTC(), request.Key.Scope.TenantID, request.Key.Scope.ProjectID, request.Key.RecordID()))
			if errors.Is(adoptErr, sql.ErrNoRows) {
				return OperationSnapshot{}, ErrConflict
			}
			return adopted, adoptErr
		}
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return OperationSnapshot{}, err
	}
	if _, err := repository.ReconcileExpiredUploadOperations(ctx, repository.now().UTC(), 10); err != nil {
		return OperationSnapshot{}, err
	}
	var historicalDigest string
	historyErr := repository.database.QueryRowContext(ctx, "SELECT artifact_sha256 FROM plugin_catalog_operations WHERE tenant_id = $1 AND project_id = $2 AND plugin_id = $3 AND semantic_version = $4 AND kind = 'upload' ORDER BY created_at DESC, operation_record_id DESC LIMIT 1", request.Key.Scope.TenantID, request.Key.Scope.ProjectID, request.Version.PluginID, request.Version.Version).Scan(&historicalDigest)
	if historyErr != nil && !errors.Is(historyErr, sql.ErrNoRows) {
		return OperationSnapshot{}, historyErr
	}
	if historyErr == nil && historicalDigest != request.ArtifactSHA256 {
		return OperationSnapshot{}, ErrConflict
	}
	var semanticVersionExists bool
	if err := repository.database.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM plugin_versions WHERE tenant_id = $1 AND project_id = $2 AND plugin_id = $3 AND semantic_version = $4)", request.Key.Scope.TenantID, request.Key.Scope.ProjectID, request.Version.PluginID, request.Version.Version).Scan(&semanticVersionExists); err != nil {
		return OperationSnapshot{}, err
	}
	if semanticVersionExists {
		return OperationSnapshot{}, ErrConflict
	}
	definitionJSON, err := json.Marshal(request.Definition)
	if err != nil {
		return OperationSnapshot{}, ErrInvalid
	}
	versionJSON, err := json.Marshal(request.Version)
	if err != nil {
		return OperationSnapshot{}, ErrInvalid
	}
	value, err := scanOperation(repository.database.QueryRowContext(ctx, insertOperationSQL,
		request.Key.RecordID(), request.Key.Scope.TenantID, request.Key.Scope.ProjectID, request.Key.Actor, request.Key.OperationID, request.Key.IdempotencyKey,
		request.Key.Fingerprint, request.Key.OwnerToken, "upload", OperationPending, request.Version.ID, request.Version.PluginID, request.Version.Version,
		request.ArtifactID, request.ArtifactSHA256, request.ArtifactBytes, string(definitionJSON), string(versionJSON), request.Response.Status, request.Response.ETag, request.Response.Body,
		request.AuditEventJSON, request.CreatedAt.UTC(), request.CreatedAt.UTC(), request.LeaseExpiresAt.UTC(), nil,
	))
	if errors.Is(err, sql.ErrNoRows) {
		if existing, getErr := repository.GetOperation(ctx, request.Key); getErr == nil && operationMatchesUpload(existing, request) {
			return existing, nil
		}
		return OperationSnapshot{}, ErrConflict
	}
	return value, err
}

func operationMatchesUpload(value OperationSnapshot, request UploadOperationRequest) bool {
	return value.Key == request.Key && value.Kind == "upload" && value.Version.ID == request.Version.ID && value.Version.PluginID == request.Version.PluginID && value.Version.Version == request.Version.Version && value.Version.PackageSHA256 == request.Version.PackageSHA256 && value.Version.ManifestDigest == request.Version.ManifestDigest && value.ArtifactID == request.ArtifactID && value.ArtifactSHA256 == request.ArtifactSHA256 && value.ArtifactBytes == request.ArtifactBytes && value.Response.Status == request.Response.Status && value.Response.ETag == request.Response.ETag && bytes.Equal(value.Response.Body, request.Response.Body) && bytes.Equal(value.AuditEventJSON, request.AuditEventJSON)
}

func (repository *PostgresRepository) FinalizeUploadOperation(ctx context.Context, key OperationKey, builder OperationResponseBuilder) (OperationSnapshot, error) {
	if repository == nil || repository.database == nil || ctx == nil || key.Validate() != nil || builder == nil {
		return OperationSnapshot{}, ErrInvalid
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return OperationSnapshot{}, err
	}
	rollback := func() { _ = transaction.Rollback() }
	value, err := scanOperation(transaction.QueryRowContext(ctx, getOperationSQL+" FOR UPDATE", key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey))
	if errors.Is(err, sql.ErrNoRows) {
		rollback()
		return OperationSnapshot{}, ErrNotFound
	}
	if err != nil || value.Key != key {
		rollback()
		if err != nil {
			return OperationSnapshot{}, err
		}
		return OperationSnapshot{}, ErrConflict
	}
	if value.State == OperationCommitted {
		if err := transaction.Commit(); err != nil {
			return OperationSnapshot{}, err
		}
		return value, nil
	}
	var artifactExists bool
	artifactChecksum := "sha256:" + value.ArtifactSHA256
	if err := transaction.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM artifacts WHERE tenant_id = $1 AND project_id = $2 AND id = $3 AND checksum = $4 AND size_bytes = $5 AND source_resource_type = 'plugin_catalog_operation' AND source_resource_id = $6)", key.Scope.TenantID, key.Scope.ProjectID, value.ArtifactID, artifactChecksum, value.ArtifactBytes, key.RecordID()).Scan(&artifactExists); err != nil {
		rollback()
		return OperationSnapshot{}, err
	}
	if !artifactExists {
		rollback()
		return OperationSnapshot{}, ErrOperationPending
	}
	storedVersion, err := createVersionInTransaction(ctx, transaction, value.Definition, value.Version)
	if err != nil {
		rollback()
		return OperationSnapshot{}, err
	}
	response, err := builder(storedVersion)
	if err != nil || response.Validate() != nil || response.Status != value.Response.Status || response.ETag != value.Response.ETag || !bytes.Equal(response.Body, value.Response.Body) {
		rollback()
		return OperationSnapshot{}, ErrInvalid
	}
	versionJSON, err := json.Marshal(storedVersion)
	if err != nil {
		rollback()
		return OperationSnapshot{}, ErrInvalid
	}
	committed, err := scanOperation(transaction.QueryRowContext(ctx, "UPDATE plugin_catalog_operations SET state = 'committed', version_json = $1, updated_at = $2 WHERE tenant_id = $3 AND project_id = $4 AND operation_record_id = $5 AND state = 'pending' RETURNING "+operationColumnsSQL,
		string(versionJSON), repository.now().UTC(), key.Scope.TenantID, key.Scope.ProjectID, key.RecordID()))
	if err != nil {
		rollback()
		return OperationSnapshot{}, err
	}
	if err := transaction.Commit(); err != nil {
		return OperationSnapshot{}, err
	}
	return committed, nil
}

func (repository *PostgresRepository) TransitionOperation(ctx context.Context, request TransitionOperationRequest, builder OperationResponseBuilder) (OperationSnapshot, error) {
	if repository == nil || repository.database == nil || repository.now == nil || ctx == nil || request.Key.Validate() != nil || request.Transition.Scope != request.Key.Scope || !json.Valid(request.AuditEventJSON) || builder == nil {
		return OperationSnapshot{}, ErrInvalid
	}
	if existing, err := repository.GetOperation(ctx, request.Key); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return OperationSnapshot{}, err
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return OperationSnapshot{}, err
	}
	rollback := func() { _ = transaction.Rollback() }
	allowed := make([]string, len(request.Transition.AllowedFrom))
	for index, status := range request.Transition.AllowedFrom {
		allowed[index] = string(status)
	}
	at := repository.now().UTC()
	value, err := scanVersion(transaction.QueryRowContext(ctx, transitionVersionSQL, request.Transition.To, at, request.Transition.Reason, request.Key.Scope.TenantID, request.Key.Scope.ProjectID, request.Transition.VersionID, request.Transition.ExpectedRevision, stringArrayLiteral(allowed)))
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if existsErr := transaction.QueryRowContext(ctx, versionExistsSQL, request.Key.Scope.TenantID, request.Key.Scope.ProjectID, request.Transition.VersionID).Scan(&exists); existsErr != nil {
			rollback()
			return OperationSnapshot{}, existsErr
		}
		rollback()
		if !exists {
			return OperationSnapshot{}, ErrNotFound
		}
		if existing, getErr := repository.GetOperation(ctx, request.Key); getErr == nil {
			return existing, nil
		}
		return OperationSnapshot{}, ErrRevisionConflict
	}
	if err != nil {
		rollback()
		return OperationSnapshot{}, err
	}
	response, err := builder(value)
	if err != nil || response.Validate() != nil {
		rollback()
		return OperationSnapshot{}, ErrInvalid
	}
	versionJSON, _ := json.Marshal(value)
	kind := map[Status]string{StatusApproved: "approve", StatusAvailable: "publish", StatusRevoked: "revoke"}[request.Transition.To]
	committed, err := scanOperation(transaction.QueryRowContext(ctx, insertOperationSQL,
		request.Key.RecordID(), request.Key.Scope.TenantID, request.Key.Scope.ProjectID, request.Key.Actor, request.Key.OperationID, request.Key.IdempotencyKey,
		request.Key.Fingerprint, request.Key.OwnerToken, kind, OperationCommitted, value.ID, value.PluginID, value.Version, value.ArtifactID, value.PackageSHA256, int64(0), "{}", string(versionJSON), response.Status, response.ETag, response.Body, request.AuditEventJSON, at, at, at.Add(DefaultOperationLease), nil,
	))
	if errors.Is(err, sql.ErrNoRows) {
		rollback()
		if existing, getErr := repository.GetOperation(ctx, request.Key); getErr == nil {
			return existing, nil
		}
		return OperationSnapshot{}, ErrConflict
	}
	if err != nil {
		rollback()
		return OperationSnapshot{}, err
	}
	if err := transaction.Commit(); err != nil {
		return OperationSnapshot{}, err
	}
	return committed, nil
}

func (repository *PostgresRepository) ReconcileExpiredUploadOperations(ctx context.Context, at time.Time, limit int) (OperationReconcileResult, error) {
	if repository == nil || repository.database == nil || ctx == nil || at.IsZero() || limit < 1 || limit > 100 {
		return OperationReconcileResult{}, ErrInvalid
	}
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return OperationReconcileResult{}, err
	}
	rollback := func() { _ = transaction.Rollback() }
	rows, err := transaction.QueryContext(ctx, "SELECT "+operationColumnsSQL+" FROM plugin_catalog_operations WHERE kind = 'upload' AND state = 'pending' AND lease_expires_at <= $1 ORDER BY lease_expires_at ASC, tenant_id ASC, project_id ASC, operation_record_id ASC FOR UPDATE SKIP LOCKED LIMIT $2", at.UTC(), limit)
	if err != nil {
		rollback()
		return OperationReconcileResult{}, err
	}
	values := make([]OperationSnapshot, 0, limit)
	for rows.Next() {
		value, scanErr := scanOperation(rows)
		if scanErr != nil {
			_ = rows.Close()
			rollback()
			return OperationReconcileResult{}, scanErr
		}
		values = append(values, value)
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if rowsErr != nil || closeErr != nil {
		rollback()
		if rowsErr != nil {
			return OperationReconcileResult{}, rowsErr
		}
		return OperationReconcileResult{}, closeErr
	}
	result := OperationReconcileResult{}
	for _, value := range values {
		var artifactExists bool
		if err := transaction.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM artifacts WHERE tenant_id = $1 AND project_id = $2 AND id = $3 AND checksum = $4 AND size_bytes = $5 AND source_resource_type = 'plugin_catalog_operation' AND source_resource_id = $6)", value.Key.Scope.TenantID, value.Key.Scope.ProjectID, value.ArtifactID, "sha256:"+value.ArtifactSHA256, value.ArtifactBytes, value.Key.RecordID()).Scan(&artifactExists); err != nil {
			rollback()
			return OperationReconcileResult{}, err
		}
		if artifactExists {
			storedVersion, err := createVersionInTransaction(ctx, transaction, value.Definition, value.Version)
			if err != nil {
				rollback()
				return OperationReconcileResult{}, err
			}
			versionJSON, err := json.Marshal(storedVersion)
			if err != nil {
				rollback()
				return OperationReconcileResult{}, ErrInvalid
			}
			update, err := transaction.ExecContext(ctx, "UPDATE plugin_catalog_operations SET state = 'committed', version_json = $1, updated_at = $2 WHERE tenant_id = $3 AND project_id = $4 AND operation_record_id = $5 AND state = 'pending'", string(versionJSON), at.UTC(), value.Key.Scope.TenantID, value.Key.Scope.ProjectID, value.Key.RecordID())
			if err != nil {
				rollback()
				return OperationReconcileResult{}, err
			}
			affected, _ := update.RowsAffected()
			if affected != 1 {
				rollback()
				return OperationReconcileResult{}, ErrConflict
			}
			result.Finalized++
			continue
		}
		update, err := transaction.ExecContext(ctx, "UPDATE plugin_catalog_operations SET state = 'abandoned', abandoned_at = $1, updated_at = $1 WHERE tenant_id = $2 AND project_id = $3 AND operation_record_id = $4 AND state = 'pending'", at.UTC(), value.Key.Scope.TenantID, value.Key.Scope.ProjectID, value.Key.RecordID())
		if err != nil {
			rollback()
			return OperationReconcileResult{}, err
		}
		affected, _ := update.RowsAffected()
		if affected != 1 {
			rollback()
			return OperationReconcileResult{}, ErrConflict
		}
		result.Abandoned++
	}
	if err := transaction.Commit(); err != nil {
		return OperationReconcileResult{}, err
	}
	return result, nil
}

func createVersionInTransaction(ctx context.Context, transaction *sql.Tx, definition PluginDefinition, version PluginVersion) (PluginVersion, error) {
	storedDefinition, err := scanDefinition(transaction.QueryRowContext(ctx, insertDefinitionSQL,
		definition.Scope.TenantID, definition.Scope.ProjectID, definition.PluginID, definition.Name, definition.DatabaseFamily,
		definition.ProtocolVersion, jsonStrings(definition.SupportedVariants), jsonStrings(definition.Capabilities),
	))
	if err != nil || storedDefinition.Scope != definition.Scope || storedDefinition.PluginID != definition.PluginID || storedDefinition.DatabaseFamily != definition.DatabaseFamily {
		if err != nil {
			return PluginVersion{}, err
		}
		return PluginVersion{}, ErrConflict
	}
	platforms, err := json.Marshal(version.Platforms)
	if err != nil {
		return PluginVersion{}, ErrInvalid
	}
	stored, err := scanVersion(transaction.QueryRowContext(ctx, insertVersionSQL,
		version.ID, version.Scope.TenantID, version.Scope.ProjectID, version.PluginID, version.Version, version.Status,
		version.ArtifactID, version.PackageSHA256, version.ManifestDigest, version.PublisherID, version.SigningKeyID, version.ProtocolVersion,
		version.MinimumAgentProtocolVersion, version.MaximumAgentProtocolVersion, jsonStrings(version.SupportedVariants), version.DatabaseVersionRange,
		jsonStrings(version.Capabilities), version.MetricTemplateSchemaVersion, string(platforms), version.Revision, version.CreatedAt.UTC(), version.ApprovedAt, "",
	))
	if errors.Is(err, sql.ErrNoRows) {
		stored, err = scanVersion(transaction.QueryRowContext(ctx, "SELECT "+versionColumnsSQL+" FROM plugin_versions WHERE tenant_id = $1 AND project_id = $2 AND version_id = $3", version.Scope.TenantID, version.Scope.ProjectID, version.ID))
	}
	if err != nil {
		return PluginVersion{}, err
	}
	if stored.PackageSHA256 != version.PackageSHA256 || stored.ManifestDigest != version.ManifestDigest || stored.ArtifactID != version.ArtifactID {
		return PluginVersion{}, ErrConflict
	}
	return stored, nil
}

func scanOperation(scanner interface{ Scan(...any) error }) (OperationSnapshot, error) {
	var value OperationSnapshot
	var recordID, actor, operationID, idempotencyKey, fingerprint, ownerToken string
	var definitionJSON, versionJSON []byte
	var responseStatus sql.NullInt64
	var responseETag sql.NullString
	var responseBody []byte
	var createdAt, updatedAt time.Time
	var abandonedAt sql.NullTime
	if err := scanner.Scan(&recordID, &value.Key.Scope.TenantID, &value.Key.Scope.ProjectID, &actor, &operationID, &idempotencyKey, &fingerprint, &ownerToken, &value.Kind, &value.State, &value.Version.ID, &value.Version.PluginID, &value.Version.Version, &value.ArtifactID, &value.ArtifactSHA256, &value.ArtifactBytes, &definitionJSON, &versionJSON, &responseStatus, &responseETag, &responseBody, &value.AuditEventJSON, &createdAt, &updatedAt, &value.LeaseExpiresAt, &abandonedAt); err != nil {
		return OperationSnapshot{}, err
	}
	value.Key.Actor, value.Key.OperationID, value.Key.IdempotencyKey, value.Key.Fingerprint, value.Key.OwnerToken = actor, operationID, idempotencyKey, fingerprint, ownerToken
	if recordID != value.Key.RecordID() || json.Unmarshal(versionJSON, &value.Version) != nil {
		return OperationSnapshot{}, ErrConflict
	}
	if len(definitionJSON) > 0 && string(definitionJSON) != "{}" && json.Unmarshal(definitionJSON, &value.Definition) != nil {
		return OperationSnapshot{}, ErrConflict
	}
	if responseStatus.Valid {
		value.Response = OperationResponse{Status: int(responseStatus.Int64), ETag: responseETag.String, Body: append([]byte(nil), responseBody...)}
	}
	value.LeaseExpiresAt = value.LeaseExpiresAt.UTC()
	if abandonedAt.Valid {
		at := abandonedAt.Time.UTC()
		value.AbandonedAt = &at
	}
	if value.Validate() != nil {
		return OperationSnapshot{}, ErrConflict
	}
	return value, nil
}

func scanDefinition(scanner interface{ Scan(...any) error }) (PluginDefinition, error) {
	var value PluginDefinition
	var variantsJSON, capabilitiesJSON []byte
	var latest sql.NullString
	if err := scanner.Scan(&value.Scope.TenantID, &value.Scope.ProjectID, &value.PluginID, &value.Name, &value.DatabaseFamily, &value.ProtocolVersion, &variantsJSON, &capabilitiesJSON, &latest); err != nil {
		return PluginDefinition{}, err
	}
	if json.Unmarshal(variantsJSON, &value.SupportedVariants) != nil || json.Unmarshal(capabilitiesJSON, &value.Capabilities) != nil {
		return PluginDefinition{}, ErrConflict
	}
	if latest.Valid {
		value.LatestAvailableVersion = latest.String
	}
	return value, nil
}

func scanVersion(scanner interface{ Scan(...any) error }) (PluginVersion, error) {
	var value PluginVersion
	var variantsJSON, capabilitiesJSON, platformsJSON []byte
	var approved sql.NullTime
	if err := scanner.Scan(&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.PluginID, &value.Version, &value.Status, &value.ArtifactID, &value.PackageSHA256, &value.ManifestDigest, &value.PublisherID, &value.SigningKeyID, &value.ProtocolVersion, &value.MinimumAgentProtocolVersion, &value.MaximumAgentProtocolVersion, &variantsJSON, &value.DatabaseVersionRange, &capabilitiesJSON, &value.MetricTemplateSchemaVersion, &platformsJSON, &value.Revision, &value.CreatedAt, &approved); err != nil {
		return PluginVersion{}, err
	}
	if json.Unmarshal(variantsJSON, &value.SupportedVariants) != nil || json.Unmarshal(capabilitiesJSON, &value.Capabilities) != nil || json.Unmarshal(platformsJSON, &value.Platforms) != nil {
		return PluginVersion{}, ErrConflict
	}
	value.CreatedAt = value.CreatedAt.UTC()
	if approved.Valid {
		at := approved.Time.UTC()
		value.ApprovedAt = &at
	}
	return value, nil
}

func jsonStrings(values []string) string {
	encoded, _ := json.Marshal(values)
	return string(encoded)
}

// stringArrayLiteral is passed to PostgreSQL's ANY(text[]) fence. Every value
// is a closed internal status token, so quoting is deterministic.
func stringArrayLiteral(values []string) string {
	return "{" + strings.Join(values, ",") + "}"
}

func definitionColumnNames() []string { return strings.Split(definitionColumnsSQL, ", ") }
func versionColumnNames() []string    { return strings.Split(versionColumnsSQL, ", ") }

type versionCursor struct {
	Scope     platformscope.Scope `json:"scope"`
	CreatedAt time.Time           `json:"created_at"`
	ID        string              `json:"id"`
}

type definitionCursor struct {
	Scope    platformscope.Scope `json:"scope"`
	PluginID string              `json:"plugin_id"`
}

func encodeVersionCursor(value versionCursor) (string, error)       { return encodeCursor(value) }
func encodeDefinitionCursor(value definitionCursor) (string, error) { return encodeCursor(value) }

func decodeVersionCursor(encoded string) (versionCursor, error) {
	var value versionCursor
	err := decodeCursor(encoded, &value)
	return value, err
}

func decodeDefinitionCursor(encoded string) (definitionCursor, error) {
	var value definitionCursor
	err := decodeCursor(encoded, &value)
	return value, err
}

func encodeCursor(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeCursor(encoded string, target any) error {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return ErrInvalid
	}
	decoder := json.NewDecoder(strings.NewReader(string(decoded)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || ensureJSONEOF(decoder) != nil {
		return ErrInvalid
	}
	return nil
}

var _ Repository = (*PostgresRepository)(nil)
var _ OperationRepository = (*PostgresRepository)(nil)
