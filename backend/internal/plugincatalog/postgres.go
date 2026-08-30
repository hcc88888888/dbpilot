package plugincatalog

import (
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
