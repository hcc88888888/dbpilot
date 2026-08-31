package pluginassignment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
)

const assignmentColumns = `assignment_id,tenant_id,project_id,host_id,agent_id,plugin_id,database_family,desired_version_id,desired_version,artifact_id,artifact_sha256,manifest_digest,desired_state,configuration_revision,operation_revision,rollout_percentage,instance_ids,template_revision_ids,reconcile_state,blocked_reason,revision,created_at,updated_at`
const observationColumns = `assignment_id,plugin_id,database_family,installed_version,active_slot,process_state,process_id,started_at,health,restart_count,circuit_state,bound_instance_count,active_configuration_revision,observed_operation_revision,last_error_code,observation_revision,observation_digest,observed_at,received_at`

type JobStore interface {
	CreateInTx(context.Context, *sql.Tx, job.Job, []job.OutboxMessage) error
	Get(context.Context, platformscope.Scope, string) (job.Job, error)
}

type PostgresRepository struct {
	database *sql.DB
	jobs     JobStore
	commit   func(*sql.Tx) error
}

func NewPostgresRepository(database *sql.DB, jobs JobStore) *PostgresRepository {
	return &PostgresRepository{database: database, jobs: jobs, commit: func(tx *sql.Tx) error { return tx.Commit() }}
}

func (repository *PostgresRepository) Ready(ctx context.Context) error {
	if repository == nil || repository.database == nil || ctx == nil {
		return ErrInvalid
	}
	var ready bool
	if err := repository.database.QueryRowContext(ctx, `SELECT to_regclass('plugin_assignments') IS NOT NULL AND to_regclass('plugin_assignment_instances') IS NOT NULL AND to_regclass('plugin_observations') IS NOT NULL AND to_regclass('plugin_assignment_mutations') IS NOT NULL AND to_regclass('plugin_reconcile_operations') IS NOT NULL`).Scan(&ready); err != nil {
		return err
	}
	if !ready {
		return errors.New("plugin assignment schema is unavailable")
	}
	var backlog int
	if err := repository.database.QueryRowContext(ctx, `SELECT count(*) FROM plugin_assignment_repair_backlog`).Scan(&backlog); err != nil {
		return err
	}
	if backlog > 0 {
		return fmt.Errorf("plugin assignment repair backlog: %d", backlog)
	}
	return nil
}

type RepairResult struct{ Repaired, Blocked int }

func (repository *PostgresRepository) RepairUnassigned(ctx context.Context, limit int) (RepairResult, error) {
	if repository == nil || repository.database == nil || ctx == nil || limit < 1 || limit > 128 {
		return RepairResult{}, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return RepairResult{}, err
	}
	rollback := func() { _ = tx.Rollback() }
	rows, err := tx.QueryContext(ctx, `SELECT instance.instance_id,instance.tenant_id,instance.project_id,instance.host_id,instance.agent_id,instance.database_family,instance.database_variant FROM managed_database_instances instance LEFT JOIN plugin_assignment_repair_backlog backlog ON backlog.tenant_id=instance.tenant_id AND backlog.project_id=instance.project_id AND backlog.instance_id=instance.instance_id WHERE instance.management_status<>'retired' AND instance.plugin_assignment_revision=0 ORDER BY (backlog.instance_id IS NOT NULL),COALESCE(backlog.updated_at,instance.updated_at),instance.instance_id FOR UPDATE OF instance SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		rollback()
		return RepairResult{}, mapError(err)
	}
	var instances []databaseinstance.Instance
	for rows.Next() {
		var value databaseinstance.Instance
		if err := rows.Scan(&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.HostID, &value.AgentID, &value.DatabaseFamily, &value.DatabaseVariant); err != nil {
			_ = rows.Close()
			rollback()
			return RepairResult{}, err
		}
		instances = append(instances, value)
	}
	if err := rows.Close(); err != nil {
		rollback()
		return RepairResult{}, err
	}
	result := RepairResult{}
	for _, instance := range instances {
		fingerprint := "sha256:" + hex.EncodeToString(sha256Bytes(instance.Scope.Key()+"\x00repair\x00"+instance.ID))
		audit := databaseinstance.MutationAudit{Actor: "plugin-assignment-repair", OperationID: "repairPluginAssignment", IdempotencyKey: "repair:" + instance.ID, RequestFingerprint: fingerprint, RequestID: "repair-" + instance.ID}
		binding, ensureErr := repository.EnsureForInstanceTx(ctx, tx, instance, audit)
		if errors.Is(ensureErr, ErrVersionUnavailable) || errors.Is(ensureErr, ErrCapacity) {
			reason := "no_compatible_version"
			if errors.Is(ensureErr, ErrCapacity) {
				reason = "capacity_exceeded"
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO plugin_assignment_repair_backlog (tenant_id,project_id,instance_id,reason_code,attempts,updated_at) VALUES ($1,$2,$3,$4,1,CURRENT_TIMESTAMP) ON CONFLICT (tenant_id,project_id,instance_id) DO UPDATE SET reason_code=EXCLUDED.reason_code,attempts=plugin_assignment_repair_backlog.attempts+1,updated_at=CURRENT_TIMESTAMP`, instance.Scope.TenantID, instance.Scope.ProjectID, instance.ID, reason)
			if err != nil {
				rollback()
				return RepairResult{}, mapError(err)
			}
			result.Blocked++
			continue
		}
		if ensureErr != nil {
			rollback()
			return RepairResult{}, ensureErr
		}
		if _, err = tx.ExecContext(ctx, `UPDATE managed_database_instances SET plugin_id=$1,desired_plugin_version=$2,plugin_assignment_revision=$3,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$4 AND project_id=$5 AND instance_id=$6 AND plugin_assignment_revision=0`, binding.PluginID, binding.DesiredVersion, binding.ConfigurationRevision, instance.Scope.TenantID, instance.Scope.ProjectID, instance.ID); err != nil {
			rollback()
			return RepairResult{}, mapError(err)
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM plugin_assignment_repair_backlog WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3`, instance.Scope.TenantID, instance.Scope.ProjectID, instance.ID)
		if err != nil {
			rollback()
			return RepairResult{}, mapError(err)
		}
		result.Repaired++
	}
	if err := repository.commit(tx); err != nil {
		return RepairResult{}, err
	}
	return result, nil
}

type InstanceTargetAuthorizer struct{ Database *sql.DB }

func (authorizer InstanceTargetAuthorizer) AuthorizeTarget(ctx context.Context, agentID, targetID string) error {
	if authorizer.Database == nil || ctx == nil || !idPattern.MatchString(agentID) || !idPattern.MatchString(targetID) {
		return ErrInvalid
	}
	var allowed bool
	err := authorizer.Database.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM managed_database_instances WHERE agent_id=$1 AND instance_id=$2 AND management_status<>'retired')`, agentID, targetID).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrNotFound
	}
	return nil
}

func (repository *PostgresRepository) EnsureForInstance(ctx context.Context, instance databaseinstance.Instance) (Assignment, error) {
	if repository == nil || repository.database == nil || ctx == nil {
		return Assignment{}, ErrInvalid
	}
	audit := databaseinstance.MutationAudit{Actor: "plugin-assignment-service", OperationID: "ensurePluginAssignment", IdempotencyKey: "ensure:" + instance.ID, RequestFingerprint: "sha256:" + hex.EncodeToString(sha256Bytes(instance.Scope.Key()+"\x00"+instance.ID)), RequestID: "assignment-" + instance.ID}
	var last error
	for attempt := 0; attempt < 8; attempt++ {
		tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return Assignment{}, err
		}
		_, err = repository.EnsureForInstanceTx(ctx, tx, instance, audit)
		if err != nil {
			_ = tx.Rollback()
			if isRetryable(err) {
				last = err
				continue
			}
			return Assignment{}, err
		}
		if err = repository.commit(tx); err != nil {
			if isRetryable(err) {
				last = err
				continue
			}
			return Assignment{}, err
		}
		return repository.Get(ctx, instance.Scope, DeterministicID("assignment-", instance.Scope.TenantID, instance.Scope.ProjectID, instance.AgentID, instance.DatabaseFamily))
	}
	return Assignment{}, last
}

func (repository *PostgresRepository) EnsureForInstanceTx(ctx context.Context, tx *sql.Tx, instance databaseinstance.Instance, audit databaseinstance.MutationAudit) (databaseinstance.AssignmentBinding, error) {
	if repository == nil || repository.database == nil || ctx == nil || tx == nil || instance.Scope.Validate() != nil || !idPattern.MatchString(instance.ID) || !idPattern.MatchString(instance.HostID) || !idPattern.MatchString(instance.AgentID) || !familyPattern.MatchString(instance.DatabaseFamily) || !pluginIDPattern.MatchString(instance.DatabaseVariant) || audit.Validate() != nil {
		return databaseinstance.AssignmentBinding{}, ErrInvalid
	}
	// Serialize the one Agent/family process identity before testing the unique
	// row. This avoids exposing an expected concurrent first-create race as a
	// unique-key product conflict to the outer candidate transaction.
	lockIdentity := hex.EncodeToString(sha256Bytes(instance.Scope.Key() + "\x00" + instance.AgentID + "\x00" + instance.DatabaseFamily))
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockIdentity); err != nil {
		return databaseinstance.AssignmentBinding{}, mapError(err)
	}
	value, err := scanAssignment(tx.QueryRowContext(ctx, `SELECT `+assignmentColumns+` FROM plugin_assignments WHERE tenant_id=$1 AND project_id=$2 AND agent_id=$3 AND database_family=$4 FOR UPDATE`, instance.Scope.TenantID, instance.Scope.ProjectID, instance.AgentID, instance.DatabaseFamily))
	if err == nil {
		if value.HostID != instance.HostID || value.PluginID == "" {
			return databaseinstance.AssignmentBinding{}, ErrConflict
		}
		if !contains(value.InstanceIDs, instance.ID) {
			if len(value.InstanceIDs) >= MaximumAssignmentItems {
				return databaseinstance.AssignmentBinding{}, ErrCapacity
			}
			if len(value.InstanceIDs) == 0 {
				versionID, pluginID, semanticVersion, artifactID, artifactSHA, manifestDigest, selectErr := selectCompatibleVersionTx(ctx, tx, instance)
				if selectErr != nil {
					return databaseinstance.AssignmentBinding{}, selectErr
				}
				value.DesiredVersionID, value.PluginID, value.DesiredVersion, value.ArtifactID, value.ArtifactSHA256, value.ManifestDigest = versionID, pluginID, semanticVersion, artifactID, artifactSHA, manifestDigest
				value.DesiredState = DesiredRunning
			} else {
				var status string
				var variantSupported bool
				if err := tx.QueryRowContext(ctx, `SELECT status,supported_variants ? $4 FROM plugin_versions WHERE tenant_id=$1 AND project_id=$2 AND version_id=$3 FOR SHARE`, value.Scope.TenantID, value.Scope.ProjectID, value.DesiredVersionID, instance.DatabaseVariant).Scan(&status, &variantSupported); err != nil {
					return databaseinstance.AssignmentBinding{}, mapError(err)
				}
				if status == "revoked" {
					return databaseinstance.AssignmentBinding{}, ErrVersionRevoked
				}
				if !variantSupported {
					return databaseinstance.AssignmentBinding{}, ErrVersionUnavailable
				}
			}
			value.InstanceIDs = sortedUnique(append(value.InstanceIDs, instance.ID))
			value.ConfigurationRevision++
			value.OperationRevision++
			value.Revision++
			value.ReconcileState, value.BlockedReason = ReconcilePending, ""
			if err := tx.QueryRowContext(ctx, `UPDATE plugin_assignments SET instance_ids=$1,desired_version_id=$2,plugin_id=$3,desired_version=$4,artifact_id=$5,artifact_sha256=$6,manifest_digest=$7,desired_state=$8,configuration_revision=$9,operation_revision=$10,reconcile_state='pending',blocked_reason='',revision=$11,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$12 AND project_id=$13 AND assignment_id=$14 RETURNING updated_at`, jsonValue(value.InstanceIDs), value.DesiredVersionID, value.PluginID, value.DesiredVersion, value.ArtifactID, value.ArtifactSHA256, value.ManifestDigest, value.DesiredState, value.ConfigurationRevision, value.OperationRevision, value.Revision, value.Scope.TenantID, value.Scope.ProjectID, value.ID).Scan(&value.UpdatedAt); err != nil {
				return databaseinstance.AssignmentBinding{}, mapError(err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_assignment_instances (tenant_id,project_id,assignment_id,instance_id,template_revision_ids,created_at,updated_at) VALUES ($1,$2,$3,$4,'[]'::jsonb,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, value.Scope.TenantID, value.Scope.ProjectID, value.ID, instance.ID); err != nil {
				return databaseinstance.AssignmentBinding{}, mapError(err)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE managed_database_instances SET plugin_id=$1,desired_plugin_version=$2,plugin_assignment_revision=$3,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$4 AND project_id=$5 AND instance_id IN (SELECT jsonb_array_elements_text($6::jsonb))`, value.PluginID, value.DesiredVersion, value.ConfigurationRevision, value.Scope.TenantID, value.Scope.ProjectID, jsonValue(value.InstanceIDs)); err != nil {
				return databaseinstance.AssignmentBinding{}, mapError(err)
			}
			if err := insertAssignmentAudit(ctx, tx, value, audit, "plugin_assignment.configuration_changed"); err != nil {
				return databaseinstance.AssignmentBinding{}, err
			}
		}
		return binding(value), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return databaseinstance.AssignmentBinding{}, mapError(err)
	}

	versionID, pluginID, semanticVersion, artifactID, artifactSHA, manifestDigest, err := selectCompatibleVersionTx(ctx, tx, instance)
	if err != nil {
		return databaseinstance.AssignmentBinding{}, err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return databaseinstance.AssignmentBinding{}, err
	}
	value = Assignment{ID: DeterministicID("assignment-", instance.Scope.TenantID, instance.Scope.ProjectID, instance.AgentID, instance.DatabaseFamily), Scope: instance.Scope, HostID: instance.HostID, AgentID: instance.AgentID, PluginID: pluginID, DatabaseFamily: instance.DatabaseFamily, DesiredVersionID: versionID, DesiredVersion: semanticVersion, ArtifactID: artifactID, ArtifactSHA256: artifactSHA, ManifestDigest: manifestDigest, DesiredState: DesiredRunning, ConfigurationRevision: 1, OperationRevision: 1, RolloutPercentage: 100, InstanceIDs: []string{instance.ID}, TemplateRevisionIDs: []string{}, ReconcileState: ReconcilePending, Revision: 1, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	if value.Validate() != nil {
		return databaseinstance.AssignmentBinding{}, ErrInvalid
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO plugin_assignments (`+assignmentColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`, assignmentArgs(value)...)
	if err != nil {
		return databaseinstance.AssignmentBinding{}, mapError(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_assignment_instances (tenant_id,project_id,assignment_id,instance_id,template_revision_ids,created_at,updated_at) VALUES ($1,$2,$3,$4,'[]'::jsonb,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, value.Scope.TenantID, value.Scope.ProjectID, value.ID, instance.ID); err != nil {
		return databaseinstance.AssignmentBinding{}, mapError(err)
	}
	if err := insertAssignmentAudit(ctx, tx, value, audit, "plugin_assignment.created"); err != nil {
		return databaseinstance.AssignmentBinding{}, err
	}
	return binding(value), nil
}

func selectCompatibleVersionTx(ctx context.Context, tx *sql.Tx, instance databaseinstance.Instance) (string, string, string, string, string, string, error) {
	var versionID, pluginID, semanticVersion, artifactID, artifactSHA, manifestDigest string
	err := tx.QueryRowContext(ctx, `SELECT v.version_id,v.plugin_id,v.semantic_version,v.artifact_id,v.package_sha256,v.manifest_digest FROM plugin_versions v JOIN plugin_definitions d ON d.tenant_id=v.tenant_id AND d.project_id=v.project_id AND d.plugin_id=v.plugin_id JOIN managed_hosts h ON h.tenant_id=v.tenant_id AND h.project_id=v.project_id AND h.host_id=$4 WHERE v.tenant_id=$1 AND v.project_id=$2 AND d.database_family=$3 AND v.status='available' AND v.supported_variants ? $5 AND EXISTS (SELECT 1 FROM jsonb_array_elements(v.platforms) platform WHERE platform->>'operating_system'=h.operating_system AND platform->>'architecture'=h.architecture) ORDER BY v.created_at DESC,v.version_id DESC LIMIT 1 FOR SHARE OF v`, instance.Scope.TenantID, instance.Scope.ProjectID, instance.DatabaseFamily, instance.HostID, instance.DatabaseVariant).Scan(&versionID, &pluginID, &semanticVersion, &artifactID, &artifactSHA, &manifestDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", "", "", "", ErrVersionUnavailable
	}
	if err != nil {
		return "", "", "", "", "", "", mapError(err)
	}
	return versionID, pluginID, semanticVersion, artifactID, artifactSHA, manifestDigest, nil
}

func (repository *PostgresRepository) DetachInstanceTx(ctx context.Context, tx *sql.Tx, instance databaseinstance.Instance, audit databaseinstance.MutationAudit) error {
	if repository == nil || repository.database == nil || ctx == nil || tx == nil || instance.Scope.Validate() != nil || !idPattern.MatchString(instance.ID) || audit.Validate() != nil {
		return ErrInvalid
	}
	var assignmentID string
	err := tx.QueryRowContext(ctx, `SELECT assignment_id FROM plugin_assignment_instances WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3 FOR UPDATE`, instance.Scope.TenantID, instance.Scope.ProjectID, instance.ID).Scan(&assignmentID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return mapError(err)
	}
	value, err := scanAssignment(tx.QueryRowContext(ctx, `SELECT `+assignmentColumns+` FROM plugin_assignments WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 FOR UPDATE`, instance.Scope.TenantID, instance.Scope.ProjectID, assignmentID))
	if err != nil {
		return mapError(err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM plugin_assignment_instances WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 AND instance_id=$4`, instance.Scope.TenantID, instance.Scope.ProjectID, assignmentID, instance.ID); err != nil {
		return mapError(err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT instance_id,template_revision_ids FROM plugin_assignment_instances WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 ORDER BY instance_id`, instance.Scope.TenantID, instance.Scope.ProjectID, assignmentID)
	if err != nil {
		return mapError(err)
	}
	instanceIDs := make([]string, 0)
	templateSet := map[string]struct{}{}
	for rows.Next() {
		var id string
		var encoded []byte
		if err := rows.Scan(&id, &encoded); err != nil {
			_ = rows.Close()
			return err
		}
		instanceIDs = append(instanceIDs, id)
		var templates []string
		if json.Unmarshal(encoded, &templates) != nil {
			_ = rows.Close()
			return ErrInvalid
		}
		for _, template := range templates {
			templateSet[template] = struct{}{}
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	value.InstanceIDs = instanceIDs
	value.TemplateRevisionIDs = value.TemplateRevisionIDs[:0]
	for template := range templateSet {
		value.TemplateRevisionIDs = append(value.TemplateRevisionIDs, template)
	}
	sort.Strings(value.TemplateRevisionIDs)
	value.ConfigurationRevision++
	value.OperationRevision++
	value.Revision++
	value.ReconcileState, value.BlockedReason = ReconcilePending, ""
	if len(instanceIDs) == 0 {
		value.DesiredState = DesiredAbsent
	}
	if value.Validate() != nil {
		return ErrInvalid
	}
	if err := tx.QueryRowContext(ctx, `UPDATE plugin_assignments SET instance_ids=$1,template_revision_ids=$2,desired_state=$3,configuration_revision=$4,operation_revision=$5,reconcile_state='pending',blocked_reason='',revision=$6,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$7 AND project_id=$8 AND assignment_id=$9 RETURNING updated_at`, jsonValue(value.InstanceIDs), jsonValue(value.TemplateRevisionIDs), value.DesiredState, value.ConfigurationRevision, value.OperationRevision, value.Revision, value.Scope.TenantID, value.Scope.ProjectID, value.ID).Scan(&value.UpdatedAt); err != nil {
		return mapError(err)
	}
	if len(instanceIDs) > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE managed_database_instances SET plugin_assignment_revision=$1,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$2 AND project_id=$3 AND instance_id IN (SELECT jsonb_array_elements_text($4::jsonb))`, value.ConfigurationRevision, value.Scope.TenantID, value.Scope.ProjectID, jsonValue(instanceIDs)); err != nil {
			return mapError(err)
		}
	}
	return insertAssignmentAudit(ctx, tx, value, audit, "plugin_assignment.instance_detached")
}

func (repository *PostgresRepository) List(ctx context.Context, scope platformscope.Scope, filter Filter) (Page, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || filter.Validate() != nil {
		return Page{}, ErrInvalid
	}
	limit := filter.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	afterID := ""
	if filter.Cursor != "" {
		var decodeErr error
		afterID, decodeErr = decodeAssignmentCursor(scope, filter)
		if decodeErr != nil {
			return Page{}, decodeErr
		}
	}
	rows, err := repository.database.QueryContext(ctx, `SELECT `+assignmentColumns+` FROM plugin_assignments WHERE tenant_id=$1 AND project_id=$2 AND ($3='' OR assignment_id>$3) AND ($4='' OR host_id=$4) AND ($5='' OR plugin_id=$5) AND ($6='' OR agent_id=$6) AND ($7='' OR database_family=$7) ORDER BY assignment_id LIMIT $8`, scope.TenantID, scope.ProjectID, afterID, filter.HostID, filter.PluginID, filter.AgentID, filter.DatabaseFamily, limit+1)
	if err != nil {
		return Page{}, mapError(err)
	}
	defer rows.Close()
	page := Page{Items: make([]Assignment, 0, limit)}
	for rows.Next() {
		value, err := scanAssignment(rows)
		if err != nil {
			return Page{}, err
		}
		observed, err := repository.getObservation(ctx, value.Scope, value.ID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return Page{}, err
		}
		if err == nil {
			value.Observed = &observed
		}
		page.Items = append(page.Items, value)
	}
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor, err = encodeAssignmentCursor(scope, filter, page.Items[len(page.Items)-1].ID)
		if err != nil {
			return Page{}, err
		}
	}
	return page, nil
}

func (repository *PostgresRepository) Get(ctx context.Context, scope platformscope.Scope, id string) (Assignment, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !idPattern.MatchString(id) {
		return Assignment{}, ErrInvalid
	}
	value, err := scanAssignment(repository.database.QueryRowContext(ctx, `SELECT `+assignmentColumns+` FROM plugin_assignments WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Assignment{}, ErrNotFound
	}
	if err != nil {
		return Assignment{}, mapError(err)
	}
	observed, observationErr := repository.getObservation(ctx, scope, id)
	if observationErr == nil {
		value.Observed = &observed
	} else if !errors.Is(observationErr, ErrNotFound) {
		return Assignment{}, observationErr
	}
	return value, nil
}

func (repository *PostgresRepository) SetDesiredState(ctx context.Context, scope platformscope.Scope, id string, revision uint64, update DesiredUpdate) (Assignment, error) {
	return repository.mutate(ctx, scope, id, revision, update.Audit, "set_desired", func(ctx context.Context, tx *sql.Tx, value *Assignment) error {
		changedOperation, changedConfiguration := false, false
		if update.DesiredVersion != nil && *update.DesiredVersion != value.DesiredVersion {
			var versionID, artifactID, artifactSHA, manifestDigest string
			err := tx.QueryRowContext(ctx, `SELECT v.version_id,v.artifact_id,v.package_sha256,v.manifest_digest FROM plugin_versions v JOIN managed_hosts h ON h.tenant_id=v.tenant_id AND h.project_id=v.project_id AND h.host_id=$5 WHERE v.tenant_id=$1 AND v.project_id=$2 AND v.plugin_id=$3 AND v.semantic_version=$4 AND v.status='available' AND EXISTS (SELECT 1 FROM jsonb_array_elements(v.platforms) platform WHERE platform->>'operating_system'=h.operating_system AND platform->>'architecture'=h.architecture) AND NOT EXISTS (SELECT 1 FROM plugin_assignment_instances ai JOIN managed_database_instances instance ON instance.instance_id=ai.instance_id WHERE ai.tenant_id=$1 AND ai.project_id=$2 AND ai.assignment_id=$6 AND NOT (v.supported_variants ? instance.database_variant)) FOR SHARE OF v`, scope.TenantID, scope.ProjectID, value.PluginID, *update.DesiredVersion, value.HostID, value.ID).Scan(&versionID, &artifactID, &artifactSHA, &manifestDigest)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrVersionUnavailable
			}
			if err != nil {
				return mapError(err)
			}
			value.DesiredVersionID, value.DesiredVersion, value.ArtifactID, value.ArtifactSHA256, value.ManifestDigest = versionID, *update.DesiredVersion, artifactID, artifactSHA, manifestDigest
			changedConfiguration = true
			changedOperation = true
		}
		if update.DesiredState != nil && *update.DesiredState != value.DesiredState {
			value.DesiredState = *update.DesiredState
			changedOperation = true
		}
		if update.RolloutPercentage != nil && *update.RolloutPercentage != value.RolloutPercentage {
			value.RolloutPercentage = *update.RolloutPercentage
			changedOperation = true
		}
		if !changedOperation {
			return nil
		}
		if changedConfiguration {
			value.ConfigurationRevision++
		}
		value.OperationRevision++
		value.ReconcileState, value.BlockedReason = ReconcilePending, ""
		return nil
	})
}

func (repository *PostgresRepository) ForceReconcile(ctx context.Context, scope platformscope.Scope, id string, audit MutationAudit) (Assignment, error) {
	return repository.mutate(ctx, scope, id, 0, audit, "force_reconcile", func(_ context.Context, _ *sql.Tx, value *Assignment) error {
		value.OperationRevision++
		value.ReconcileState, value.BlockedReason = ReconcilePending, ""
		return nil
	})
}

func (repository *PostgresRepository) mutate(ctx context.Context, scope platformscope.Scope, id string, revision uint64, audit MutationAudit, action string, apply func(context.Context, *sql.Tx, *Assignment) error) (Assignment, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !idPattern.MatchString(id) || audit.Validate() != nil || apply == nil {
		return Assignment{}, ErrInvalid
	}
	var last error
	for attempt := 0; attempt < 8; attempt++ {
		tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return Assignment{}, err
		}
		rollback := func() { _ = tx.Rollback() }
		if replay, found, err := lookupMutation(ctx, tx, scope, audit, action, id); err != nil {
			rollback()
			if isRetryable(err) {
				last = err
				continue
			}
			return Assignment{}, err
		} else if found {
			rollback()
			return replay, nil
		}
		value, err := scanAssignment(tx.QueryRowContext(ctx, `SELECT `+assignmentColumns+` FROM plugin_assignments WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 FOR UPDATE`, scope.TenantID, scope.ProjectID, id))
		if errors.Is(err, sql.ErrNoRows) {
			rollback()
			return Assignment{}, ErrNotFound
		}
		if err != nil {
			rollback()
			if isRetryable(err) {
				last = err
				continue
			}
			return Assignment{}, mapError(err)
		}
		if revision > 0 && value.Revision != revision {
			rollback()
			return Assignment{}, ErrPrecondition
		}
		before := value
		if err := apply(ctx, tx, &value); err != nil {
			rollback()
			return Assignment{}, err
		}
		if assignmentDesiredChanged(before, value) {
			value.Revision++
			if err := tx.QueryRowContext(ctx, `UPDATE plugin_assignments SET desired_version_id=$1,desired_version=$2,artifact_id=$3,artifact_sha256=$4,manifest_digest=$5,desired_state=$6,configuration_revision=$7,operation_revision=$8,rollout_percentage=$9,reconcile_state=$10,blocked_reason=$11,revision=$12,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$13 AND project_id=$14 AND assignment_id=$15 RETURNING updated_at`, value.DesiredVersionID, value.DesiredVersion, value.ArtifactID, value.ArtifactSHA256, value.ManifestDigest, value.DesiredState, value.ConfigurationRevision, value.OperationRevision, value.RolloutPercentage, value.ReconcileState, value.BlockedReason, value.Revision, scope.TenantID, scope.ProjectID, id).Scan(&value.UpdatedAt); err != nil {
				rollback()
				if isRetryable(err) {
					last = err
					continue
				}
				return Assignment{}, mapError(err)
			}
		}
		if value.Validate() != nil {
			rollback()
			return Assignment{}, ErrInvalid
		}
		if err := persistMutation(ctx, tx, value, audit, action); err != nil {
			rollback()
			if isRetryable(err) {
				last = err
				continue
			}
			return Assignment{}, err
		}
		if err := insertAssignmentAudit(ctx, tx, value, databaseinstance.MutationAudit(audit), "plugin_assignment."+action); err != nil {
			rollback()
			if isRetryable(err) {
				last = err
				continue
			}
			return Assignment{}, err
		}
		if err := repository.commit(tx); err != nil {
			if isRetryable(err) {
				last = err
				continue
			}
			return Assignment{}, err
		}
		return value, nil
	}
	return Assignment{}, last
}

func (repository *PostgresRepository) RecordObservation(ctx context.Context, report ObservationReport) error {
	if repository == nil || repository.database == nil || ctx == nil || report.Validate() != nil {
		return ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	rollback := func() { _ = tx.Rollback() }
	var receivedAt time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&receivedAt); err != nil {
		rollback()
		return err
	}
	receivedAt = receivedAt.UTC()
	for _, observed := range report.Assignments {
		value, err := scanAssignment(tx.QueryRowContext(ctx, `SELECT `+assignmentColumns+` FROM plugin_assignments WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 FOR UPDATE`, report.Scope.TenantID, report.Scope.ProjectID, observed.AssignmentID))
		if errors.Is(err, sql.ErrNoRows) {
			rollback()
			return ErrNotFound
		}
		if err != nil {
			rollback()
			return mapError(err)
		}
		if value.HostID != report.HostID || value.AgentID != report.AgentID || observed.PluginID != value.PluginID || observed.DatabaseFamily != value.DatabaseFamily {
			rollback()
			return ErrConflict
		}
		observed.Digest = observationDigest(observed)
		observed.ReceivedAt = receivedAt
		var previousRevision uint64
		var previousDigest string
		err = tx.QueryRowContext(ctx, `SELECT observation_revision,observation_digest FROM plugin_observations WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 FOR UPDATE`, report.Scope.TenantID, report.Scope.ProjectID, value.ID).Scan(&previousRevision, &previousDigest)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			rollback()
			return mapError(err)
		}
		if err == nil && observed.ObservationRevision < previousRevision {
			rollback()
			return ErrStaleObservation
		}
		if err == nil && observed.ObservationRevision == previousRevision {
			if observed.Digest != previousDigest {
				rollback()
				return ErrConflict
			}
			if _, updateErr := tx.ExecContext(ctx, `UPDATE plugin_observations SET received_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND assignment_id=$4 AND observation_revision=$5 AND observation_digest=$6`, receivedAt, report.Scope.TenantID, report.Scope.ProjectID, value.ID, previousRevision, previousDigest); updateErr != nil {
				rollback()
				return mapError(updateErr)
			}
			continue
		}
		observationValues := append([]any{report.Scope.TenantID, report.Scope.ProjectID, report.HostID, report.AgentID}, observationArgs(observed)...)
		_, err = tx.ExecContext(ctx, `INSERT INTO plugin_observations (tenant_id,project_id,host_id,agent_id,`+observationColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23) ON CONFLICT (tenant_id,project_id,assignment_id) DO UPDATE SET installed_version=EXCLUDED.installed_version,active_slot=EXCLUDED.active_slot,process_state=EXCLUDED.process_state,process_id=EXCLUDED.process_id,started_at=EXCLUDED.started_at,health=EXCLUDED.health,restart_count=EXCLUDED.restart_count,circuit_state=EXCLUDED.circuit_state,bound_instance_count=EXCLUDED.bound_instance_count,active_configuration_revision=EXCLUDED.active_configuration_revision,observed_operation_revision=EXCLUDED.observed_operation_revision,last_error_code=EXCLUDED.last_error_code,observation_revision=EXCLUDED.observation_revision,observation_digest=EXCLUDED.observation_digest,observed_at=EXCLUDED.observed_at,received_at=EXCLUDED.received_at`, observationValues...)
		if err != nil {
			rollback()
			return mapError(err)
		}
		value.Observed = &observed
		state := ReconcilePending
		if value.HasObservedRevisionConflict() {
			state = ReconcileConflict
		} else if !value.NeedsReconcile() {
			state = ReconcileConverged
		}
		if _, err := tx.ExecContext(ctx, `UPDATE plugin_assignments SET reconcile_state=$1,blocked_reason='',revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$2 AND project_id=$3 AND assignment_id=$4`, state, report.Scope.TenantID, report.Scope.ProjectID, value.ID); err != nil {
			rollback()
			return mapError(err)
		}
	}
	return repository.commit(tx)
}

func (repository *PostgresRepository) getObservation(ctx context.Context, scope platformscope.Scope, id string) (ObservedState, error) {
	value, err := scanObservation(repository.database.QueryRowContext(ctx, `SELECT `+observationColumns+` FROM plugin_observations WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ObservedState{}, ErrNotFound
	}
	return value, mapError(err)
}

func (repository *PostgresRepository) ClaimDue(ctx context.Context, at time.Time, limit int, lease time.Duration) ([]ReconcileClaim, error) {
	if repository == nil || repository.database == nil || ctx == nil || at.IsZero() || limit < 1 || limit > 100 || lease < time.Second || lease > 10*time.Minute {
		return nil, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	rollback := func() { _ = tx.Rollback() }
	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&databaseNow); err != nil {
		rollback()
		return nil, err
	}
	databaseNow = databaseNow.UTC()
	leasedUntil := databaseNow.Add(lease)
	if _, err := tx.ExecContext(ctx, `WITH candidates AS (SELECT a.tenant_id,a.project_id,a.assignment_id FROM plugin_assignments a JOIN plugin_versions v ON v.tenant_id=a.tenant_id AND v.project_id=a.project_id AND v.version_id=a.desired_version_id WHERE v.status='revoked' AND a.desired_state IN ('running','installed') AND (a.reconcile_state<>'blocked' OR a.blocked_reason<>'version_revoked') ORDER BY a.updated_at,a.assignment_id FOR UPDATE OF a SKIP LOCKED LIMIT $1) UPDATE plugin_assignments a SET reconcile_state='blocked',blocked_reason='version_revoked',reconcile_claim_token=NULL,reconcile_lease_expires_at=NULL,revision=a.revision+1,updated_at=CURRENT_TIMESTAMP FROM candidates c WHERE a.tenant_id=c.tenant_id AND a.project_id=c.project_id AND a.assignment_id=c.assignment_id`, limit); err != nil {
		rollback()
		return nil, mapError(err)
	}
	if _, err := tx.ExecContext(ctx, `WITH candidates AS (SELECT a.tenant_id,a.project_id,a.assignment_id,CASE WHEN h.status<>'online' OR COALESCE(h.last_heartbeat_at,h.updated_at)<CURRENT_TIMESTAMP-INTERVAL '2 minutes' THEN 'agent_offline' ELSE 'observation_stale' END reason FROM plugin_assignments a JOIN managed_hosts h ON h.tenant_id=a.tenant_id AND h.project_id=a.project_id AND h.host_id=a.host_id LEFT JOIN plugin_observations o ON o.tenant_id=a.tenant_id AND o.project_id=a.project_id AND o.assignment_id=a.assignment_id WHERE a.reconcile_state='pending' AND (h.status<>'online' OR COALESCE(h.last_heartbeat_at,h.updated_at)<CURRENT_TIMESTAMP-INTERVAL '2 minutes' OR (o.assignment_id IS NOT NULL AND o.received_at<CURRENT_TIMESTAMP-INTERVAL '2 minutes')) ORDER BY a.updated_at,a.assignment_id FOR UPDATE OF a SKIP LOCKED LIMIT $1) UPDATE plugin_assignments a SET reconcile_state='waiting',blocked_reason=c.reason,reconcile_claim_token=NULL,reconcile_lease_expires_at=NULL,revision=a.revision+1,updated_at=CURRENT_TIMESTAMP FROM candidates c WHERE a.tenant_id=c.tenant_id AND a.project_id=c.project_id AND a.assignment_id=c.assignment_id`, limit); err != nil {
		rollback()
		return nil, mapError(err)
	}
	if _, err := tx.ExecContext(ctx, `WITH candidates AS (SELECT a.tenant_id,a.project_id,a.assignment_id FROM plugin_assignments a JOIN managed_hosts h ON h.tenant_id=a.tenant_id AND h.project_id=a.project_id AND h.host_id=a.host_id LEFT JOIN plugin_observations o ON o.tenant_id=a.tenant_id AND o.project_id=a.project_id AND o.assignment_id=a.assignment_id WHERE a.reconcile_state='waiting' AND a.blocked_reason IN ('agent_offline','observation_stale') AND h.status='online' AND COALESCE(h.last_heartbeat_at,h.updated_at)>=CURRENT_TIMESTAMP-INTERVAL '2 minutes' AND (o.assignment_id IS NULL OR o.received_at>=CURRENT_TIMESTAMP-INTERVAL '2 minutes') ORDER BY a.updated_at,a.assignment_id FOR UPDATE OF a SKIP LOCKED LIMIT $1) UPDATE plugin_assignments a SET reconcile_state='pending',blocked_reason='',revision=a.revision+1,updated_at=CURRENT_TIMESTAMP FROM candidates c WHERE a.tenant_id=c.tenant_id AND a.project_id=c.project_id AND a.assignment_id=c.assignment_id`, limit); err != nil {
		rollback()
		return nil, mapError(err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.tenant_id,a.project_id,a.assignment_id FROM plugin_assignments a JOIN managed_hosts h ON h.tenant_id=a.tenant_id AND h.project_id=a.project_id AND h.host_id=a.host_id LEFT JOIN plugin_observations o ON o.tenant_id=a.tenant_id AND o.project_id=a.project_id AND o.assignment_id=a.assignment_id WHERE a.reconcile_state='pending' AND h.status='online' AND COALESCE(h.last_heartbeat_at,h.updated_at)>=CURRENT_TIMESTAMP-INTERVAL '2 minutes' AND (o.assignment_id IS NULL OR o.received_at>=CURRENT_TIMESTAMP-INTERVAL '2 minutes') AND (a.reconcile_lease_expires_at IS NULL OR a.reconcile_lease_expires_at<=CURRENT_TIMESTAMP) ORDER BY a.updated_at,a.assignment_id FOR UPDATE OF a SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		rollback()
		return nil, mapError(err)
	}
	type claimKey struct{ tenant, project, id string }
	var ids []claimKey
	for rows.Next() {
		var key claimKey
		if err := rows.Scan(&key.tenant, &key.project, &key.id); err != nil {
			_ = rows.Close()
			rollback()
			return nil, err
		}
		ids = append(ids, key)
	}
	if err := rows.Close(); err != nil {
		rollback()
		return nil, err
	}
	claims := make([]ReconcileClaim, 0, len(ids))
	for _, key := range ids {
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			rollback()
			return nil, err
		}
		token := "claim-" + hex.EncodeToString(random)
		value, err := scanAssignment(tx.QueryRowContext(ctx, `UPDATE plugin_assignments SET reconcile_claim_token=$1,reconcile_lease_expires_at=$2 WHERE tenant_id=$3 AND project_id=$4 AND assignment_id=$5 AND reconcile_state='pending' RETURNING `+assignmentColumns, token, leasedUntil, key.tenant, key.project, key.id))
		if err != nil {
			rollback()
			return nil, mapError(err)
		}
		observed, observationErr := getObservationTx(ctx, tx, value.Scope, value.ID)
		if observationErr == nil {
			value.Observed = &observed
		} else if !errors.Is(observationErr, ErrNotFound) {
			rollback()
			return nil, observationErr
		}
		claim := ReconcileClaim{Assignment: value, Token: token, LeasedUntil: leasedUntil}
		if claim.Validate() != nil {
			rollback()
			return nil, ErrInvalid
		}
		claims = append(claims, claim)
	}
	if err := repository.commit(tx); err != nil {
		return nil, err
	}
	return claims, nil
}

func (repository *PostgresRepository) ClaimOne(ctx context.Context, assignment Assignment, at time.Time, lease time.Duration) (ReconcileClaim, error) {
	if repository == nil || repository.database == nil || ctx == nil || assignment.Validate() != nil || at.IsZero() || lease < time.Second || lease > 10*time.Minute {
		return ReconcileClaim{}, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return ReconcileClaim{}, err
	}
	rollback := func() { _ = tx.Rollback() }
	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&databaseNow); err != nil {
		rollback()
		return ReconcileClaim{}, err
	}
	var hostFresh, observationFresh bool
	err = tx.QueryRowContext(ctx, `SELECT h.status='online' AND COALESCE(h.last_heartbeat_at,h.updated_at)>=CURRENT_TIMESTAMP-INTERVAL '2 minutes',COALESCE(o.received_at>=CURRENT_TIMESTAMP-INTERVAL '2 minutes',TRUE) FROM managed_hosts h LEFT JOIN plugin_observations o ON o.tenant_id=$1 AND o.project_id=$2 AND o.assignment_id=$3 WHERE h.tenant_id=$1 AND h.project_id=$2 AND h.host_id=$4`, assignment.Scope.TenantID, assignment.Scope.ProjectID, assignment.ID, assignment.HostID).Scan(&hostFresh, &observationFresh)
	if errors.Is(err, sql.ErrNoRows) {
		rollback()
		return ReconcileClaim{}, ErrNotFound
	}
	if err != nil {
		rollback()
		return ReconcileClaim{}, mapError(err)
	}
	if !hostFresh || !observationFresh {
		reason := "agent_offline"
		if hostFresh {
			reason = "observation_stale"
		}
		_, err = tx.ExecContext(ctx, `UPDATE plugin_assignments SET reconcile_state='waiting',blocked_reason=$1,reconcile_claim_token=NULL,reconcile_lease_expires_at=NULL,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$2 AND project_id=$3 AND assignment_id=$4 AND revision=$5`, reason, assignment.Scope.TenantID, assignment.Scope.ProjectID, assignment.ID, assignment.Revision)
		if err != nil {
			rollback()
			return ReconcileClaim{}, mapError(err)
		}
		if err := repository.commit(tx); err != nil {
			return ReconcileClaim{}, err
		}
		return ReconcileClaim{}, ErrConflict
	}
	leasedUntil := databaseNow.UTC().Add(lease)
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		rollback()
		return ReconcileClaim{}, err
	}
	token := "claim-" + hex.EncodeToString(random)
	value, err := scanAssignment(tx.QueryRowContext(ctx, `UPDATE plugin_assignments SET reconcile_claim_token=$1,reconcile_lease_expires_at=$2 WHERE tenant_id=$3 AND project_id=$4 AND assignment_id=$5 AND revision=$6 AND reconcile_state='pending' AND (reconcile_lease_expires_at IS NULL OR reconcile_lease_expires_at<=CURRENT_TIMESTAMP) RETURNING `+assignmentColumns, token, leasedUntil, assignment.Scope.TenantID, assignment.Scope.ProjectID, assignment.ID, assignment.Revision))
	if errors.Is(err, sql.ErrNoRows) {
		rollback()
		return ReconcileClaim{}, ErrClaimLost
	}
	if err != nil {
		rollback()
		return ReconcileClaim{}, mapError(err)
	}
	observed, observationErr := getObservationTx(ctx, tx, value.Scope, value.ID)
	if observationErr == nil {
		value.Observed = &observed
	} else if !errors.Is(observationErr, ErrNotFound) {
		rollback()
		return ReconcileClaim{}, observationErr
	}
	claim := ReconcileClaim{Assignment: value, Token: token, LeasedUntil: leasedUntil}
	if claim.Validate() != nil {
		rollback()
		return ReconcileClaim{}, ErrInvalid
	}
	if err := repository.commit(tx); err != nil {
		return ReconcileClaim{}, err
	}
	return claim, nil
}

func (repository *PostgresRepository) MarkConverged(ctx context.Context, claim ReconcileClaim) error {
	if repository == nil || repository.database == nil || ctx == nil || claim.Validate() != nil {
		return ErrInvalid
	}
	result, err := repository.database.ExecContext(ctx, `UPDATE plugin_assignments SET reconcile_state='converged',blocked_reason='',reconcile_claim_token=NULL,reconcile_lease_expires_at=NULL,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 AND revision=$4 AND reconcile_claim_token=$5 AND reconcile_lease_expires_at>CURRENT_TIMESTAMP`, claim.Assignment.Scope.TenantID, claim.Assignment.Scope.ProjectID, claim.Assignment.ID, claim.Assignment.Revision, claim.Token)
	if err != nil {
		return mapError(err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ErrClaimLost
	}
	return nil
}

func (repository *PostgresRepository) MarkConflict(ctx context.Context, claim ReconcileClaim) error {
	if repository == nil || repository.database == nil || ctx == nil || claim.Validate() != nil || !claim.Assignment.HasObservedRevisionConflict() {
		return ErrInvalid
	}
	result, err := repository.database.ExecContext(ctx, `UPDATE plugin_assignments SET reconcile_state='state_conflict',blocked_reason='',reconcile_claim_token=NULL,reconcile_lease_expires_at=NULL,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 AND revision=$4 AND reconcile_claim_token=$5 AND reconcile_lease_expires_at>CURRENT_TIMESTAMP`, claim.Assignment.Scope.TenantID, claim.Assignment.Scope.ProjectID, claim.Assignment.ID, claim.Assignment.Revision, claim.Token)
	if err != nil {
		return mapError(err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ErrClaimLost
	}
	return nil
}

func (repository *PostgresRepository) MarkWaiting(ctx context.Context, claim ReconcileClaim, reason string) error {
	if repository == nil || repository.database == nil || ctx == nil || claim.Validate() != nil || !pluginIDPattern.MatchString(reason) {
		return ErrInvalid
	}
	result, err := repository.database.ExecContext(ctx, `UPDATE plugin_assignments SET reconcile_state='waiting',blocked_reason=$1,reconcile_claim_token=NULL,reconcile_lease_expires_at=NULL,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$2 AND project_id=$3 AND assignment_id=$4 AND revision=$5 AND reconcile_claim_token=$6 AND reconcile_lease_expires_at>CURRENT_TIMESTAMP`, reason, claim.Assignment.Scope.TenantID, claim.Assignment.Scope.ProjectID, claim.Assignment.ID, claim.Assignment.Revision, claim.Token)
	if err != nil {
		return mapError(err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ErrClaimLost
	}
	return nil
}

func (repository *PostgresRepository) Schedule(ctx context.Context, claim ReconcileClaim, value job.Job, message job.OutboxMessage) (job.Job, bool, error) {
	if repository == nil || repository.database == nil || repository.jobs == nil || ctx == nil || claim.Validate() != nil {
		return job.Job{}, false, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return job.Job{}, false, err
	}
	rollback := func() { _ = tx.Rollback() }
	current, err := scanAssignment(tx.QueryRowContext(ctx, `SELECT `+assignmentColumns+` FROM plugin_assignments WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 AND revision=$4 AND reconcile_claim_token=$5 AND reconcile_lease_expires_at>CURRENT_TIMESTAMP FOR UPDATE`, claim.Assignment.Scope.TenantID, claim.Assignment.Scope.ProjectID, claim.Assignment.ID, claim.Assignment.Revision, claim.Token))
	if errors.Is(err, sql.ErrNoRows) {
		rollback()
		return job.Job{}, false, ErrClaimLost
	}
	if err != nil {
		rollback()
		return job.Job{}, false, mapError(err)
	}
	observed, observationErr := getObservationTx(ctx, tx, current.Scope, current.ID)
	if observationErr == nil {
		current.Observed = &observed
	} else if !errors.Is(observationErr, ErrNotFound) {
		rollback()
		return job.Job{}, false, observationErr
	}
	var versionStatus string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM plugin_versions WHERE tenant_id=$1 AND project_id=$2 AND version_id=$3 FOR SHARE`, current.Scope.TenantID, current.Scope.ProjectID, current.DesiredVersionID).Scan(&versionStatus); err != nil {
		rollback()
		return job.Job{}, false, mapError(err)
	}
	if versionStatus == "revoked" && current.DesiredState != DesiredStopped && current.DesiredState != DesiredAbsent {
		if _, err := tx.ExecContext(ctx, `UPDATE plugin_assignments SET reconcile_state='blocked',blocked_reason='version_revoked',reconcile_claim_token=NULL,reconcile_lease_expires_at=NULL,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, current.Scope.TenantID, current.Scope.ProjectID, current.ID); err != nil {
			rollback()
			return job.Job{}, false, mapError(err)
		}
		if err := repository.commit(tx); err != nil {
			return job.Job{}, false, err
		}
		return job.Job{}, false, ErrVersionRevoked
	}
	if versionStatus != "available" && versionStatus != "deprecated" && !(versionStatus == "revoked" && (current.DesiredState == DesiredStopped || current.DesiredState == DesiredAbsent)) {
		rollback()
		return job.Job{}, false, ErrVersionUnavailable
	}
	if !current.NeedsReconcile() {
		if _, err := tx.ExecContext(ctx, `UPDATE plugin_assignments SET reconcile_state='converged',reconcile_claim_token=NULL,reconcile_lease_expires_at=NULL,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, current.Scope.TenantID, current.Scope.ProjectID, current.ID); err != nil {
			rollback()
			return job.Job{}, false, mapError(err)
		}
		return job.Job{}, false, repository.commit(tx)
	}
	var existingJob string
	err = tx.QueryRowContext(ctx, `SELECT job_id FROM plugin_reconcile_operations WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 AND configuration_revision=$4 AND operation_revision=$5`, current.Scope.TenantID, current.Scope.ProjectID, current.ID, current.ConfigurationRevision, current.OperationRevision).Scan(&existingJob)
	if err == nil {
		if _, err := tx.ExecContext(ctx, `UPDATE plugin_assignments SET reconcile_state='waiting',blocked_reason='operation_in_flight',reconcile_claim_token=NULL,reconcile_lease_expires_at=NULL,last_scheduled_job_id=$1,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$2 AND project_id=$3 AND assignment_id=$4`, existingJob, current.Scope.TenantID, current.Scope.ProjectID, current.ID); err != nil {
			rollback()
			return job.Job{}, false, mapError(err)
		}
		if err := repository.commit(tx); err != nil {
			return job.Job{}, false, err
		}
		stored, err := repository.jobs.Get(ctx, current.Scope, existingJob)
		return stored, false, err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		rollback()
		return job.Job{}, false, mapError(err)
	}
	if value.Scope != current.Scope || value.SourceResource.ResourceType != "plugin_assignment" || value.SourceResource.ResourceID != current.ID || message.JobID != value.ID || message.TargetID != current.AgentID {
		rollback()
		return job.Job{}, false, ErrInvalid
	}
	if err := repository.jobs.CreateInTx(ctx, tx, value, []job.OutboxMessage{message}); err != nil {
		rollback()
		return job.Job{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO plugin_reconcile_operations (tenant_id,project_id,assignment_id,configuration_revision,operation_revision,job_id,command_id,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP)`, current.Scope.TenantID, current.Scope.ProjectID, current.ID, current.ConfigurationRevision, current.OperationRevision, value.ID, message.ID); err != nil {
		rollback()
		return job.Job{}, false, mapError(err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE plugin_assignments SET reconcile_state='waiting',blocked_reason='operation_in_flight',last_scheduled_configuration_revision=$1,last_scheduled_operation_revision=$2,last_scheduled_job_id=$3,reconcile_claim_token=NULL,reconcile_lease_expires_at=NULL,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$4 AND project_id=$5 AND assignment_id=$6 AND reconcile_claim_token=$7`, current.ConfigurationRevision, current.OperationRevision, value.ID, current.Scope.TenantID, current.Scope.ProjectID, current.ID, claim.Token)
	if err != nil {
		rollback()
		return job.Job{}, false, mapError(err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected != 1 {
		rollback()
		return job.Job{}, false, ErrClaimLost
	}
	if err := repository.commit(tx); err != nil {
		if stored, getErr := repository.jobs.Get(ctx, current.Scope, value.ID); getErr == nil {
			return stored, true, nil
		}
		return job.Job{}, false, err
	}
	stored, err := repository.jobs.Get(ctx, current.Scope, value.ID)
	return stored, true, err
}

func (repository *PostgresRepository) FindScheduledJob(ctx context.Context, assignment Assignment) (job.Job, bool, error) {
	if repository == nil || repository.database == nil || repository.jobs == nil || ctx == nil || assignment.Validate() != nil {
		return job.Job{}, false, ErrInvalid
	}
	var jobID string
	err := repository.database.QueryRowContext(ctx, `SELECT job_id FROM plugin_reconcile_operations WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 AND configuration_revision=$4 AND operation_revision=$5`, assignment.Scope.TenantID, assignment.Scope.ProjectID, assignment.ID, assignment.ConfigurationRevision, assignment.OperationRevision).Scan(&jobID)
	if errors.Is(err, sql.ErrNoRows) {
		return job.Job{}, false, nil
	}
	if err != nil {
		return job.Job{}, false, mapError(err)
	}
	value, err := repository.jobs.Get(ctx, assignment.Scope, jobID)
	if err != nil {
		return job.Job{}, false, err
	}
	if value.SourceResource.ResourceType != "plugin_assignment" || value.SourceResource.ResourceID != assignment.ID {
		return job.Job{}, false, ErrConflict
	}
	return value, true, nil
}

func getObservationTx(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, id string) (ObservedState, error) {
	value, err := scanObservation(tx.QueryRowContext(ctx, `SELECT `+observationColumns+` FROM plugin_observations WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, scope.TenantID, scope.ProjectID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ObservedState{}, ErrNotFound
	}
	return value, mapError(err)
}

type rowScanner interface{ Scan(...any) error }

func scanAssignment(scanner rowScanner) (Assignment, error) {
	var value Assignment
	var instances, templates []byte
	var config, operation, revision int64
	err := scanner.Scan(&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.HostID, &value.AgentID, &value.PluginID, &value.DatabaseFamily, &value.DesiredVersionID, &value.DesiredVersion, &value.ArtifactID, &value.ArtifactSHA256, &value.ManifestDigest, &value.DesiredState, &config, &operation, &value.RolloutPercentage, &instances, &templates, &value.ReconcileState, &value.BlockedReason, &revision, &value.CreatedAt, &value.UpdatedAt)
	if err != nil {
		return Assignment{}, err
	}
	if config < 1 || operation < 1 || revision < 1 || json.Unmarshal(instances, &value.InstanceIDs) != nil || json.Unmarshal(templates, &value.TemplateRevisionIDs) != nil {
		return Assignment{}, ErrInvalid
	}
	value.ConfigurationRevision, value.OperationRevision, value.Revision = uint64(config), uint64(operation), uint64(revision)
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
	if value.Validate() != nil {
		return Assignment{}, ErrInvalid
	}
	return value, nil
}
func scanObservation(scanner rowScanner) (ObservedState, error) {
	var value ObservedState
	var pid, restarts, bound, config, operation, revision int64
	var started sql.NullTime
	err := scanner.Scan(&value.AssignmentID, &value.PluginID, &value.DatabaseFamily, &value.InstalledVersion, &value.ActiveSlot, &value.ProcessState, &pid, &started, &value.Health, &restarts, &value.CircuitState, &bound, &config, &operation, &value.LastErrorCode, &revision, &value.Digest, &value.ObservedAt, &value.ReceivedAt)
	if err != nil {
		return ObservedState{}, err
	}
	if pid < 0 || restarts < 0 || bound < 0 || config < 0 || operation < 0 || revision < 1 {
		return ObservedState{}, ErrInvalid
	}
	value.PID = uint32(pid)
	value.RestartCount = uint32(restarts)
	value.BoundInstanceCount = uint32(bound)
	value.ActiveConfigurationRevision = uint64(config)
	value.ObservedOperationRevision = uint64(operation)
	value.ObservationRevision = uint64(revision)
	value.ObservedAt = value.ObservedAt.UTC()
	value.ReceivedAt = value.ReceivedAt.UTC()
	if started.Valid {
		at := started.Time.UTC()
		value.StartedAt = &at
	}
	if value.Validate() != nil {
		return ObservedState{}, ErrInvalid
	}
	return value, nil
}
func assignmentArgs(v Assignment) []any {
	return []any{v.ID, v.Scope.TenantID, v.Scope.ProjectID, v.HostID, v.AgentID, v.PluginID, v.DatabaseFamily, v.DesiredVersionID, v.DesiredVersion, v.ArtifactID, v.ArtifactSHA256, v.ManifestDigest, v.DesiredState, v.ConfigurationRevision, v.OperationRevision, v.RolloutPercentage, jsonValue(v.InstanceIDs), jsonValue(v.TemplateRevisionIDs), v.ReconcileState, v.BlockedReason, v.Revision, v.CreatedAt, v.UpdatedAt}
}
func observationArgs(v ObservedState) []any {
	return []any{v.AssignmentID, v.PluginID, v.DatabaseFamily, v.InstalledVersion, v.ActiveSlot, v.ProcessState, v.PID, v.StartedAt, v.Health, v.RestartCount, v.CircuitState, v.BoundInstanceCount, v.ActiveConfigurationRevision, v.ObservedOperationRevision, v.LastErrorCode, v.ObservationRevision, v.Digest, v.ObservedAt, v.ReceivedAt}
}
func jsonValue(value any) []byte { encoded, _ := json.Marshal(value); return encoded }
func binding(value Assignment) databaseinstance.AssignmentBinding {
	return databaseinstance.AssignmentBinding{AssignmentID: value.ID, PluginID: value.PluginID, DesiredVersion: value.DesiredVersion, ConfigurationRevision: value.ConfigurationRevision}
}
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func assignmentDesiredChanged(left, right Assignment) bool {
	return left.DesiredVersionID != right.DesiredVersionID || left.DesiredVersion != right.DesiredVersion || left.ArtifactID != right.ArtifactID || left.ArtifactSHA256 != right.ArtifactSHA256 || left.ManifestDigest != right.ManifestDigest || left.DesiredState != right.DesiredState || left.ConfigurationRevision != right.ConfigurationRevision || left.OperationRevision != right.OperationRevision || left.RolloutPercentage != right.RolloutPercentage || left.ReconcileState != right.ReconcileState || left.BlockedReason != right.BlockedReason
}
func sha256Bytes(value string) []byte { digest := sha256.Sum256([]byte(value)); return digest[:] }
func observationDigest(value ObservedState) string {
	copy := value
	copy.Digest = ""
	copy.ReceivedAt = time.Time{}
	encoded, _ := json.Marshal(copy)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func mapError(err error) error {
	if err == nil {
		return nil
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23505", "23503":
			return ErrConflict
		case "23502", "23514", "22P02", "22001":
			return ErrInvalid
		}
	}
	return err
}
func isRetryable(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && (pqErr.Code == "40001" || pqErr.Code == "40P01")
}

func insertAssignmentAudit(ctx context.Context, tx *sql.Tx, value Assignment, audit databaseinstance.MutationAudit, action string) error {
	detail, _ := json.Marshal(map[string]any{"assignment_id": value.ID, "agent_id": value.AgentID, "database_family": value.DatabaseFamily, "configuration_revision": value.ConfigurationRevision, "operation_revision": value.OperationRevision, "instance_count": len(value.InstanceIDs)})
	dedupe := DeterministicID("plugin-assignment-audit-", value.Scope.Key(), action, audit.Actor, audit.OperationID, audit.IdempotencyKey, value.ID, fmt.Sprint(value.ConfigurationRevision), fmt.Sprint(value.OperationRevision))
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events (id,tenant_id,project_id,occurred_at,action,actor_type,actor_id,resource_type,resource_id,result,request_id,trace_id,job_id,command_id,dedupe_key,detail,created_at) VALUES ($1,$2,$3,CURRENT_TIMESTAMP,$4,'user',$5,'plugin_assignment',$6,'success',$7,$8,'','',$9,$10,CURRENT_TIMESTAMP) ON CONFLICT (tenant_id,project_id,dedupe_key) WHERE dedupe_key<>'' DO NOTHING`, "audit-"+dedupe, value.Scope.TenantID, value.Scope.ProjectID, action, audit.Actor, value.ID, audit.RequestID, audit.TraceID, dedupe, detail)
	return mapError(err)
}
func persistMutation(ctx context.Context, tx *sql.Tx, value Assignment, audit MutationAudit, action string) error {
	snapshot, err := json.Marshal(value)
	if err != nil {
		return ErrInvalid
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO plugin_assignment_mutations (tenant_id,project_id,actor_id,operation_id,idempotency_key,request_fingerprint,action,assignment_id,response_snapshot,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP)`, value.Scope.TenantID, value.Scope.ProjectID, audit.Actor, audit.OperationID, audit.IdempotencyKey, audit.RequestFingerprint, action, value.ID, snapshot)
	return mapError(err)
}
func lookupMutation(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, audit MutationAudit, action, id string) (Assignment, bool, error) {
	var fingerprint, storedAction, storedID string
	var snapshot []byte
	err := tx.QueryRowContext(ctx, `SELECT request_fingerprint,action,assignment_id,response_snapshot FROM plugin_assignment_mutations WHERE tenant_id=$1 AND project_id=$2 AND actor_id=$3 AND operation_id=$4 AND idempotency_key=$5`, scope.TenantID, scope.ProjectID, audit.Actor, audit.OperationID, audit.IdempotencyKey).Scan(&fingerprint, &storedAction, &storedID, &snapshot)
	if errors.Is(err, sql.ErrNoRows) {
		return Assignment{}, false, nil
	}
	if err != nil {
		return Assignment{}, false, mapError(err)
	}
	if fingerprint != audit.RequestFingerprint || storedAction != action || storedID != id {
		return Assignment{}, false, ErrConflict
	}
	var value Assignment
	if json.Unmarshal(snapshot, &value) != nil || value.Validate() != nil {
		return Assignment{}, false, ErrInvalid
	}
	return value, true, nil
}

type assignmentCursor struct {
	Version     int    `json:"v"`
	AfterID     string `json:"after_id"`
	QueryDigest string `json:"query_sha256"`
}

func encodeAssignmentCursor(scope platformscope.Scope, filter Filter, afterID string) (string, error) {
	if scope.Validate() != nil || !idPattern.MatchString(afterID) {
		return "", ErrInvalid
	}
	payload := assignmentCursor{Version: 1, AfterID: afterID, QueryDigest: assignmentCursorDigest(scope, filter)}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", ErrInvalid
	}
	result := base64.RawURLEncoding.EncodeToString(encoded)
	if !cursorPattern.MatchString(result) {
		return "", ErrInvalid
	}
	return result, nil
}
func decodeAssignmentCursor(scope platformscope.Scope, filter Filter) (string, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(filter.Cursor)
	if err != nil || len(encoded) > 384 {
		return "", ErrInvalid
	}
	var payload assignmentCursor
	if json.Unmarshal(encoded, &payload) != nil || payload.Version != 1 || !idPattern.MatchString(payload.AfterID) || payload.QueryDigest != assignmentCursorDigest(scope, filter) {
		return "", ErrInvalid
	}
	return payload.AfterID, nil
}
func assignmentCursorDigest(scope platformscope.Scope, filter Filter) string {
	filter.Cursor = ""
	encoded, _ := json.Marshal(struct {
		Scope          platformscope.Scope `json:"scope"`
		HostID         string              `json:"host_id"`
		PluginID       string              `json:"plugin_id"`
		AgentID        string              `json:"agent_id"`
		DatabaseFamily string              `json:"database_family"`
		Limit          int                 `json:"limit"`
		Sort           string              `json:"sort"`
	}{scope, filter.HostID, filter.PluginID, filter.AgentID, filter.DatabaseFamily, filter.Limit, "assignment_id:asc"})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

var _ databaseinstance.AcceptanceProvisioner = (*PostgresRepository)(nil)
