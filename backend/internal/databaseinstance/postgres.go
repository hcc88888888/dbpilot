package databaseinstance

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
)

const instanceColumns = `instance_id,tenant_id,project_id,host_id,agent_id,candidate_id,discovery_source,source_fingerprint,source_identity,database_family,database_variant,display_name,endpoint,unix_socket,version_hint,edition,discovered_role,topology,credential_ref,tls_ref,plugin_id,desired_plugin_version,template_profile_id,labels,capabilities,capability_state,connection_test_status,connection_test_error_code,connection_test_at,plugin_assignment_revision,management_status,revision,created_at,updated_at,retired_at`

type PostgresRepository struct {
	database    *sql.DB
	commit      func(*sql.Tx) error
	provisioner AcceptanceProvisioner
	jobs        ValidationJobStore
}

func NewPostgresRepository(database *sql.DB) *PostgresRepository {
	return &PostgresRepository{database: database, commit: func(transaction *sql.Tx) error { return transaction.Commit() }}
}

func NewPostgresRepositoryWithProvisioner(database *sql.DB, provisioner AcceptanceProvisioner) *PostgresRepository {
	return &PostgresRepository{database: database, provisioner: provisioner, commit: func(transaction *sql.Tx) error { return transaction.Commit() }}
}

func NewPostgresRepositoryWithRuntime(database *sql.DB, provisioner AcceptanceProvisioner, jobs ValidationJobStore) *PostgresRepository {
	return &PostgresRepository{database: database, provisioner: provisioner, jobs: jobs, commit: func(transaction *sql.Tx) error { return transaction.Commit() }}
}

func (repository *PostgresRepository) AcceptCandidate(ctx context.Context, scope platformscope.Scope, candidateID string, request AcceptCandidateRequest) (Instance, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(candidateID) || request.Validate() != nil {
		return Instance{}, ErrInvalid
	}
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		value, err := repository.acceptCandidateOnce(ctx, scope, candidateID, request)
		if !isSerializationFailure(err) {
			return value, err
		}
		last = err
	}
	return Instance{}, last
}

func (repository *PostgresRepository) acceptCandidateOnce(ctx context.Context, scope platformscope.Scope, candidateID string, request AcceptCandidateRequest) (Instance, error) {
	transaction, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Instance{}, err
	}
	rollback := func() { _ = transaction.Rollback() }
	if replay, found, err := lookupMutation(ctx, transaction, scope, request.Audit, "accept", candidateID); err != nil {
		rollback()
		return Instance{}, mapPostgresError(err)
	} else if found {
		rollback()
		return replay, nil
	}
	var now time.Time
	if err := transaction.QueryRowContext(ctx, "SELECT CURRENT_TIMESTAMP").Scan(&now); err != nil {
		rollback()
		return Instance{}, mapPostgresError(err)
	}
	now = now.UTC()
	var candidate candidateState
	var fingerprint []byte
	err = transaction.QueryRowContext(ctx, `SELECT c.host_id,c.agent_id,c.discovery_source,c.database_family,c.database_variant,c.version_hint,c.normalized_endpoint,c.unix_socket,c.process_identity,c.service_name,c.container_identity,c.container_image,c.discovered_role,c.fingerprint,c.observation_revision,c.last_seen_at,c.status,c.accepted_instance_id,s.result_status,s.reason_code,s.observation_revision,h.status FROM discovery_candidates c JOIN discovery_scan_sources s ON s.tenant_id=c.tenant_id AND s.project_id=c.project_id AND s.host_id=c.host_id AND s.discovery_source=c.discovery_source JOIN managed_hosts h ON h.tenant_id=c.tenant_id AND h.project_id=c.project_id AND h.host_id=c.host_id AND h.agent_id=c.agent_id WHERE c.tenant_id=$1 AND c.project_id=$2 AND c.candidate_id=$3 FOR UPDATE OF c`, scope.TenantID, scope.ProjectID, candidateID).Scan(
		&candidate.hostID, &candidate.agentID, &candidate.source, &candidate.family, &candidate.variant, &candidate.version,
		&candidate.endpoint, &candidate.socket, &candidate.processIdentity, &candidate.serviceName, &candidate.containerIdentity,
		&candidate.containerImage, &candidate.role, &fingerprint, &candidate.revision, &candidate.lastSeenAt, &candidate.status,
		&candidate.acceptedInstanceID, &candidate.sourceStatus, &candidate.sourceReason, &candidate.sourceRevision, &candidate.hostStatus,
	)
	if errors.Is(err, sql.ErrNoRows) {
		rollback()
		return Instance{}, ErrNotFound
	}
	if err != nil {
		rollback()
		return Instance{}, mapPostgresError(err)
	}
	candidate.fingerprint = hex.EncodeToString(fingerprint)
	if candidate.revision != request.ExpectedCandidateRevision || candidate.fingerprint != request.CandidateFingerprint {
		rollback()
		return Instance{}, ErrPrecondition
	}
	if candidate.family != request.DatabaseFamily || candidate.variant != request.DatabaseVariant || candidate.endpoint != request.Endpoint || candidate.socket != request.UnixSocket {
		rollback()
		return Instance{}, ErrConflict
	}
	if candidate.hostStatus == "decommissioned" || candidate.sourceStatus != "completed" || candidate.sourceReason != "healthy" || candidate.sourceRevision != candidate.revision || candidate.lastSeenAt.IsZero() {
		rollback()
		return Instance{}, ErrConflict
	}
	if candidate.status == string(discovery.StatusAccepted) {
		value, getErr := getInstanceTx(ctx, transaction, scope, candidate.acceptedInstanceID)
		if getErr != nil || value.ManagementStatus == StatusRetired || !acceptMatches(value, candidateID, request) {
			rollback()
			if getErr != nil {
				return Instance{}, getErr
			}
			return Instance{}, ErrConflict
		}
		if err := repository.ensureAssignmentProjection(ctx, transaction, &value, request.Audit, now); err != nil {
			rollback()
			return Instance{}, err
		}
		if err := persistMutationAndAudit(ctx, transaction, scope, request.Audit, "accept", candidateID, request.ExpectedCandidateRevision, value, "database_instance.accepted", candidateID); err != nil {
			rollback()
			return Instance{}, err
		}
		if err := repository.commitTransaction(ctx, transaction, scope, request.Audit, "accept", candidateID, &value); err != nil {
			return Instance{}, err
		}
		return value, nil
	}
	if candidate.status != string(discovery.StatusAwaitingConfirmation) && candidate.status != string(discovery.StatusDiscovered) {
		rollback()
		return Instance{}, ErrConflict
	}
	identity := sourceIdentity(candidate)
	if identity == "" {
		rollback()
		return Instance{}, ErrConflict
	}
	if existing, found, lookupErr := findActiveInstanceBySourceIdentity(ctx, transaction, scope, candidate.hostID, candidate.family, identity); lookupErr != nil {
		rollback()
		return Instance{}, lookupErr
	} else if found {
		if existing.AgentID != candidate.agentID || existing.DatabaseVariant != request.DatabaseVariant || existing.DisplayName != request.DisplayName || existing.CredentialRef != request.CredentialRef || existing.TLSRef != request.TLSRef || !equalLabels(existing.Labels, request.Labels) {
			rollback()
			return Instance{}, ErrConflict
		}
		if existing.Endpoint != candidate.endpoint || existing.UnixSocket != candidate.socket || existing.SourceFingerprint != candidate.fingerprint {
			existing.Endpoint, existing.UnixSocket, existing.SourceFingerprint = candidate.endpoint, candidate.socket, candidate.fingerprint
			existing.Revision++
			existing.UpdatedAt = now
			result, updateErr := transaction.ExecContext(ctx, `UPDATE managed_database_instances SET endpoint=$4,unix_socket=$5,source_fingerprint=$6,canonical_connection=$7,revision=$8,updated_at=$9 WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3 AND management_status<>'retired'`, scope.TenantID, scope.ProjectID, existing.ID, existing.Endpoint, existing.UnixSocket, existing.SourceFingerprint, canonicalConnection(existing.Endpoint, existing.UnixSocket), existing.Revision, existing.UpdatedAt)
			if updateErr != nil {
				rollback()
				return Instance{}, mapPostgresError(updateErr)
			}
			if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
				rollback()
				return Instance{}, ErrConflict
			}
		}
		if err := repository.ensureAssignmentProjection(ctx, transaction, &existing, request.Audit, now); err != nil {
			rollback()
			return Instance{}, err
		}
		result, updateErr := transaction.ExecContext(ctx, `UPDATE discovery_candidates SET status='accepted',accepted_instance_id=$4,updated_at=$5 WHERE tenant_id=$1 AND project_id=$2 AND candidate_id=$3 AND observation_revision=$6 AND fingerprint=$7 AND status IN ('discovered','awaiting_confirmation')`, scope.TenantID, scope.ProjectID, candidateID, existing.ID, now, request.ExpectedCandidateRevision, fingerprint)
		if updateErr != nil {
			rollback()
			return Instance{}, mapPostgresError(updateErr)
		}
		if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
			rollback()
			return Instance{}, ErrPrecondition
		}
		if err := persistMutationAndAudit(ctx, transaction, scope, request.Audit, "accept", candidateID, request.ExpectedCandidateRevision, existing, "database_instance.accepted", candidateID); err != nil {
			rollback()
			return Instance{}, err
		}
		if err := repository.commitTransaction(ctx, transaction, scope, request.Audit, "accept", candidateID, &existing); err != nil {
			return Instance{}, err
		}
		return existing, nil
	}
	value := Instance{
		ID: deterministicInstanceID(scope, candidateID), Scope: scope, HostID: candidate.hostID, AgentID: candidate.agentID,
		CandidateID: candidateID, DiscoverySource: discovery.Source(candidate.source), SourceFingerprint: candidate.fingerprint, SourceIdentity: identity,
		DatabaseFamily: candidate.family, DatabaseVariant: candidate.variant, DisplayName: request.DisplayName, Endpoint: candidate.endpoint, UnixSocket: candidate.socket,
		Version: candidate.version, Role: candidate.role, CredentialRef: request.CredentialRef, TLSRef: request.TLSRef, Labels: cloneLabels(request.Labels),
		Capabilities: []string{}, CapabilityState: CapabilityPluginNotInstalled, ConnectionTestStatus: ConnectionNotTested,
		ManagementStatus: StatusAccepted, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if value.Validate() != nil {
		rollback()
		return Instance{}, ErrInvalid
	}
	labels, _ := json.Marshal(value.Labels)
	capabilities := []byte("[]")
	_, err = transaction.ExecContext(ctx, `INSERT INTO managed_database_instances (`+instanceColumns+`,canonical_connection) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36)`, instanceArgs(value, labels, capabilities, canonicalConnection(value.Endpoint, value.UnixSocket))...)
	if err != nil {
		rollback()
		return Instance{}, mapPostgresError(err)
	}
	if err := repository.ensureAssignmentProjection(ctx, transaction, &value, request.Audit, now); err != nil {
		rollback()
		return Instance{}, err
	}
	result, err := transaction.ExecContext(ctx, `UPDATE discovery_candidates SET status='accepted',accepted_instance_id=$4,updated_at=$5 WHERE tenant_id=$1 AND project_id=$2 AND candidate_id=$3 AND observation_revision=$6 AND fingerprint=$7 AND status IN ('discovered','awaiting_confirmation')`, scope.TenantID, scope.ProjectID, candidateID, value.ID, now, request.ExpectedCandidateRevision, fingerprint)
	if err != nil {
		rollback()
		return Instance{}, mapPostgresError(err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		rollback()
		return Instance{}, ErrPrecondition
	}
	if err := persistMutationAndAudit(ctx, transaction, scope, request.Audit, "accept", candidateID, request.ExpectedCandidateRevision, value, "database_instance.accepted", candidateID); err != nil {
		rollback()
		return Instance{}, err
	}
	if err := repository.commitTransaction(ctx, transaction, scope, request.Audit, "accept", candidateID, &value); err != nil {
		return Instance{}, err
	}
	return value, nil
}

func (repository *PostgresRepository) ensureAssignmentProjection(ctx context.Context, transaction *sql.Tx, value *Instance, audit MutationAudit, now time.Time) error {
	if repository.provisioner == nil {
		return nil
	}
	binding, err := repository.provisioner.EnsureForInstanceTx(ctx, transaction, *value, audit)
	if err != nil {
		return err
	}
	if !identifierPattern.MatchString(binding.AssignmentID) || !identifierPattern.MatchString(binding.PluginID) || !bounded(binding.DesiredVersion, 64, true) || binding.ConfigurationRevision == 0 {
		return ErrInvalid
	}
	if value.PluginID == binding.PluginID && value.DesiredPluginVersion == binding.DesiredVersion && value.PluginAssignmentRevision == binding.ConfigurationRevision {
		return nil
	}
	value.PluginID = binding.PluginID
	value.DesiredPluginVersion = binding.DesiredVersion
	value.PluginAssignmentRevision = binding.ConfigurationRevision
	value.Revision++
	value.UpdatedAt = now.UTC()
	result, err := transaction.ExecContext(ctx, `UPDATE managed_database_instances SET plugin_id=$4,desired_plugin_version=$5,plugin_assignment_revision=$6,revision=$7,updated_at=$8 WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3 AND management_status<>'retired'`, value.Scope.TenantID, value.Scope.ProjectID, value.ID, value.PluginID, value.DesiredPluginVersion, value.PluginAssignmentRevision, value.Revision, value.UpdatedAt)
	if err != nil {
		return mapPostgresError(err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return ErrConflict
	}
	return nil
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
		afterID, decodeErr = decodeInstanceCursor(scope, filter)
		if decodeErr != nil {
			return Page{}, decodeErr
		}
	}
	rows, err := repository.database.QueryContext(ctx, `SELECT `+instanceColumns+` FROM managed_database_instances WHERE tenant_id=$1 AND project_id=$2 AND ($3='' OR instance_id>$3) AND ($4='' OR host_id=$4) AND ($5='' OR database_family=$5) AND ($6='' OR management_status=$6) ORDER BY instance_id LIMIT $7`, scope.TenantID, scope.ProjectID, afterID, filter.HostID, filter.DatabaseFamily, string(filter.Status), limit+1)
	if err != nil {
		return Page{}, mapPostgresError(err)
	}
	defer rows.Close()
	page := Page{Items: make([]Instance, 0, limit)}
	for rows.Next() {
		value, err := scanInstance(rows)
		if err != nil {
			return Page{}, err
		}
		page.Items = append(page.Items, value)
	}
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor, err = encodeInstanceCursor(scope, filter, page.Items[len(page.Items)-1].ID)
		if err != nil {
			return Page{}, err
		}
	}
	return page, nil
}

type instanceCursor struct {
	Version     int    `json:"v"`
	AfterID     string `json:"after_id"`
	QueryDigest string `json:"query_sha256"`
}

func encodeInstanceCursor(scope platformscope.Scope, filter Filter, afterID string) (string, error) {
	if scope.Validate() != nil || !identifierPattern.MatchString(afterID) {
		return "", ErrInvalid
	}
	payload := instanceCursor{Version: 1, AfterID: afterID, QueryDigest: instanceCursorQueryDigest(scope, filter)}
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

func decodeInstanceCursor(scope platformscope.Scope, filter Filter) (string, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(filter.Cursor)
	if err != nil || len(encoded) > 384 {
		return "", ErrInvalid
	}
	var payload instanceCursor
	if json.Unmarshal(encoded, &payload) != nil || payload.Version != 1 || !identifierPattern.MatchString(payload.AfterID) || payload.QueryDigest != instanceCursorQueryDigest(scope, filter) {
		return "", ErrInvalid
	}
	return payload.AfterID, nil
}

func instanceCursorQueryDigest(scope platformscope.Scope, filter Filter) string {
	encoded, _ := json.Marshal(struct {
		Scope          platformscope.Scope `json:"scope"`
		HostID         string              `json:"host_id"`
		DatabaseFamily string              `json:"database_family"`
		Status         ManagementStatus    `json:"status"`
		Sort           string              `json:"sort"`
	}{scope, filter.HostID, filter.DatabaseFamily, filter.Status, "instance_id:asc"})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (repository *PostgresRepository) Get(ctx context.Context, scope platformscope.Scope, instanceID string) (Instance, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(instanceID) {
		return Instance{}, ErrInvalid
	}
	return getInstanceRow(repository.database.QueryRowContext(ctx, `SELECT `+instanceColumns+` FROM managed_database_instances WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3`, scope.TenantID, scope.ProjectID, instanceID))
}

func (repository *PostgresRepository) Update(ctx context.Context, scope platformscope.Scope, instanceID string, revision uint64, update Update) (Instance, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(instanceID) || revision == 0 || update.Validate() != nil || update.Audit.Validate() != nil {
		return Instance{}, ErrInvalid
	}
	return repository.mutate(ctx, scope, instanceID, revision, update.Audit, "update", "database_instance.updated", func(value *Instance) error {
		if value.ManagementStatus == StatusRetired {
			return ErrConflict
		}
		if update.DisplayName != nil {
			value.DisplayName = *update.DisplayName
		}
		connectionChanged := update.CredentialRef != nil && *update.CredentialRef != value.CredentialRef || update.TLSRef != nil && *update.TLSRef != value.TLSRef || update.DesiredPluginVersion != nil && *update.DesiredPluginVersion != value.DesiredPluginVersion
		if update.CredentialRef != nil {
			value.CredentialRef = *update.CredentialRef
		}
		if update.TLSRef != nil {
			value.TLSRef = *update.TLSRef
		}
		if update.DesiredPluginVersion != nil {
			value.DesiredPluginVersion = *update.DesiredPluginVersion
		}
		if update.TemplateProfileID != nil {
			value.TemplateProfileID = *update.TemplateProfileID
		}
		if update.Labels != nil {
			value.Labels = cloneLabels(*update.Labels)
		}
		if connectionChanged {
			value.ConnectionTestStatus = ConnectionNotTested
			value.ConnectionTestErrorCode = ""
			value.ConnectionTestAt = nil
			value.ManagementStatus = StatusProvisioning
		}
		return nil
	})
}

func (repository *PostgresRepository) Retire(ctx context.Context, scope platformscope.Scope, instanceID string, revision uint64, audit MutationAudit) (Instance, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(instanceID) || revision == 0 || audit.Validate() != nil {
		return Instance{}, ErrInvalid
	}
	return repository.mutate(ctx, scope, instanceID, revision, audit, "retire", "database_instance.retired", func(value *Instance) error {
		if value.ManagementStatus == StatusRetired {
			return ErrConflict
		}
		value.ManagementStatus = StatusRetired
		if value.ConnectionTestStatus == ConnectionQueued || value.ConnectionTestStatus == ConnectionRunning {
			value.ConnectionTestStatus = ConnectionPluginFailed
			value.ConnectionTestErrorCode = ConnectionErrorPlugin
		}
		return nil
	})
}

func (repository *PostgresRepository) mutate(ctx context.Context, scope platformscope.Scope, instanceID string, revision uint64, audit MutationAudit, action, auditAction string, apply func(*Instance) error) (Instance, error) {
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		value, err := repository.mutateOnce(ctx, scope, instanceID, revision, audit, action, auditAction, apply)
		if !isSerializationFailure(err) {
			return value, err
		}
		last = err
	}
	return Instance{}, last
}

func (repository *PostgresRepository) mutateOnce(ctx context.Context, scope platformscope.Scope, instanceID string, revision uint64, audit MutationAudit, action, auditAction string, apply func(*Instance) error) (Instance, error) {
	transaction, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Instance{}, err
	}
	rollback := func() { _ = transaction.Rollback() }
	if replay, found, err := lookupMutation(ctx, transaction, scope, audit, action, instanceID); err != nil {
		rollback()
		return Instance{}, mapPostgresError(err)
	} else if found {
		rollback()
		return replay, nil
	}
	value, err := getInstanceTxForUpdate(ctx, transaction, scope, instanceID)
	if err != nil {
		rollback()
		return Instance{}, err
	}
	if value.Revision != revision {
		rollback()
		return Instance{}, ErrPrecondition
	}
	if err := apply(&value); err != nil {
		rollback()
		return Instance{}, err
	}
	var now time.Time
	if err := transaction.QueryRowContext(ctx, "SELECT CURRENT_TIMESTAMP").Scan(&now); err != nil {
		rollback()
		return Instance{}, err
	}
	now = now.UTC()
	value.Revision++
	value.UpdatedAt = now
	if action == "retire" {
		retired := now
		value.RetiredAt = &retired
		if err := repository.retireActiveValidationTx(ctx, transaction, scope, instanceID, &value, now); err != nil {
			rollback()
			return Instance{}, err
		}
	}
	if value.Validate() != nil {
		rollback()
		return Instance{}, ErrInvalid
	}
	labels, _ := json.Marshal(value.Labels)
	result, err := transaction.ExecContext(ctx, `UPDATE managed_database_instances SET display_name=$4,credential_ref=$5,tls_ref=$6,desired_plugin_version=$7,template_profile_id=$8,labels=$9,capability_state=$10,connection_test_status=$11,connection_test_error_code=$12,connection_test_at=$13,management_status=$14,revision=$15,updated_at=$16,retired_at=$17,connection_validation_job_id=CASE WHEN $11 IN ('queued','running') AND $14<>'retired' THEN connection_validation_job_id ELSE '' END,connection_validation_command_id=CASE WHEN $11 IN ('queued','running') AND $14<>'retired' THEN connection_validation_command_id ELSE '' END WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3 AND revision=$18`, scope.TenantID, scope.ProjectID, instanceID, value.DisplayName, value.CredentialRef, value.TLSRef, value.DesiredPluginVersion, value.TemplateProfileID, labels, value.CapabilityState, value.ConnectionTestStatus, value.ConnectionTestErrorCode, value.ConnectionTestAt, value.ManagementStatus, value.Revision, now, value.RetiredAt, revision)
	if err != nil {
		rollback()
		return Instance{}, mapPostgresError(err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		rollback()
		return Instance{}, ErrPrecondition
	}
	if action == "retire" {
		if provisioner, ok := repository.provisioner.(RetirementProvisioner); ok {
			if err := provisioner.DetachInstanceTx(ctx, transaction, value, audit); err != nil {
				rollback()
				return Instance{}, err
			}
		}
	}
	if err := persistMutationAndAudit(ctx, transaction, scope, audit, action, instanceID, revision, value, auditAction, instanceID); err != nil {
		rollback()
		return Instance{}, err
	}
	if err := repository.commitTransaction(ctx, transaction, scope, audit, action, instanceID, &value); err != nil {
		return Instance{}, err
	}
	return value, nil
}

func (repository *PostgresRepository) retireActiveValidationTx(ctx context.Context, transaction *sql.Tx, scope platformscope.Scope, instanceID string, value *Instance, at time.Time) error {
	var jobID, commandID string
	if err := transaction.QueryRowContext(ctx, `SELECT connection_validation_job_id,connection_validation_command_id FROM managed_database_instances WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3 FOR UPDATE`, scope.TenantID, scope.ProjectID, instanceID).Scan(&jobID, &commandID); err != nil {
		return mapPostgresError(err)
	}
	if jobID == "" && commandID == "" {
		return nil
	}
	if !identifierPattern.MatchString(jobID) || !identifierPattern.MatchString(commandID) || value == nil {
		return ErrInvalid
	}
	state, err := loadValidationState(ctx, transaction, scope, jobID, commandID)
	if err != nil {
		return err
	}
	if state.InstanceID != instanceID || state.Status != ConnectionQueued && state.Status != ConnectionRunning {
		return ErrConflict
	}
	var agentID string
	if err := transaction.QueryRowContext(ctx, `SELECT agent_id FROM managed_database_instances WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3`, scope.TenantID, scope.ProjectID, instanceID).Scan(&agentID); err != nil {
		return mapPostgresError(err)
	}
	if err := job.CancelValidationInTx(ctx, transaction, scope, jobID, commandID, agentID, at); err != nil {
		return err
	}
	result, err := transaction.ExecContext(ctx, `UPDATE database_instance_validations SET status='plugin_failed',error_code='plugin_failed',started_at=COALESCE(started_at,$1),completed_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND job_id=$4 AND command_id=$5 AND status IN ('queued','running')`, at, scope.TenantID, scope.ProjectID, jobID, commandID)
	if err != nil {
		return mapPostgresError(err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		return ErrConflict
	}
	target := ValidationTarget{AssignmentID: state.AssignmentID, ConfigurationRevision: state.ConfigurationRevision, OperationRevision: state.OperationRevision}
	return insertValidationAudit(ctx, transaction, *value, state.Audit, jobID, commandID, target, "database_instance.connection_test_failed", "failure", ConnectionErrorPlugin, at)
}

func (repository *PostgresRepository) commitTransaction(ctx context.Context, transaction *sql.Tx, scope platformscope.Scope, audit MutationAudit, action, resourceID string, expected *Instance) error {
	commitErr := repository.commit(transaction)
	if commitErr == nil {
		return nil
	}
	recovered, found, lookupErr := repository.lookupCommittedMutation(ctx, scope, audit, action, resourceID)
	if lookupErr != nil {
		return errors.Join(commitErr, lookupErr)
	}
	if found && recovered.ID == expected.ID && recovered.Revision == expected.Revision {
		*expected = recovered
		return nil
	}
	if isSerializationFailure(commitErr) {
		return commitErr
	}
	if !found || recovered.ID != expected.ID || recovered.Revision != expected.Revision {
		return errors.New("database instance commit outcome is unknown")
	}
	return commitErr
}

func (repository *PostgresRepository) lookupCommittedMutation(ctx context.Context, scope platformscope.Scope, audit MutationAudit, action, resourceID string) (Instance, bool, error) {
	var fingerprint, storedAction, storedResource string
	var snapshot []byte
	err := repository.database.QueryRowContext(ctx, `SELECT request_fingerprint,action,resource_id,response_snapshot FROM database_instance_mutations WHERE tenant_id=$1 AND project_id=$2 AND actor_id=$3 AND operation_id=$4 AND idempotency_key=$5`, scope.TenantID, scope.ProjectID, audit.Actor, audit.OperationID, audit.IdempotencyKey).Scan(&fingerprint, &storedAction, &storedResource, &snapshot)
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, false, nil
	}
	if err != nil {
		return Instance{}, false, mapPostgresError(err)
	}
	if fingerprint != audit.RequestFingerprint || storedAction != action || storedResource != resourceID {
		return Instance{}, false, ErrConflict
	}
	value, err := decodeSnapshot(snapshot)
	return value, err == nil, err
}

type candidateState struct {
	hostID, agentID, source, family, variant, version, endpoint, socket   string
	processIdentity, serviceName, containerIdentity, containerImage, role string
	fingerprint                                                           string
	revision, sourceRevision                                              uint64
	lastSeenAt                                                            time.Time
	status, acceptedInstanceID, sourceStatus, sourceReason, hostStatus    string
}

func sourceIdentity(value candidateState) string {
	switch discovery.Source(value.source) {
	case discovery.SourceDocker:
		if value.containerIdentity != "" {
			return "docker:" + value.containerIdentity
		}
	case discovery.SourceNative:
		if value.serviceName != "" {
			return "native-service:" + value.serviceName
		}
		return "native-fingerprint:" + value.fingerprint
	}
	return "fingerprint:" + value.fingerprint
}

func canonicalConnection(endpoint, socket string) string {
	if endpoint != "" {
		return "tcp:" + strings.ToLower(endpoint)
	}
	return "unix:" + socket
}

func acceptMatches(value Instance, candidateID string, request AcceptCandidateRequest) bool {
	return candidateID != "" && value.DatabaseFamily == request.DatabaseFamily && value.DatabaseVariant == request.DatabaseVariant && value.DisplayName == request.DisplayName && value.Endpoint == request.Endpoint && value.UnixSocket == request.UnixSocket && value.CredentialRef == request.CredentialRef && value.TLSRef == request.TLSRef && equalLabels(value.Labels, request.Labels)
}

func equalLabels(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func deterministicInstanceID(scope platformscope.Scope, candidateID string) string {
	digest := sha256.Sum256([]byte(scope.Key() + "\x00" + candidateID))
	return "dbi-" + hex.EncodeToString(digest[:16])
}

func persistMutationAndAudit(ctx context.Context, transaction *sql.Tx, scope platformscope.Scope, audit MutationAudit, action, resourceID string, expectedRevision uint64, value Instance, auditAction, auditSourceID string) error {
	snapshot, err := json.Marshal(value)
	if err != nil {
		return ErrInvalid
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO database_instance_mutations (tenant_id,project_id,actor_id,operation_id,idempotency_key,request_fingerprint,action,resource_id,instance_id,expected_revision,resulting_revision,response_snapshot,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, scope.TenantID, scope.ProjectID, audit.Actor, audit.OperationID, audit.IdempotencyKey, audit.RequestFingerprint, action, resourceID, value.ID, expectedRevision, value.Revision, snapshot, value.UpdatedAt)
	if err != nil {
		return mapPostgresError(err)
	}
	auditIdentity, marshalErr := json.Marshal(struct {
		Scope              platformscope.Scope `json:"scope"`
		Action             string              `json:"action"`
		AuditAction        string              `json:"audit_action"`
		Actor              string              `json:"actor"`
		OperationID        string              `json:"operation_id"`
		IdempotencyKey     string              `json:"idempotency_key"`
		RequestFingerprint string              `json:"request_fingerprint"`
		ResourceID         string              `json:"resource_id"`
		InstanceID         string              `json:"instance_id"`
		ExpectedRevision   uint64              `json:"expected_revision"`
		ResultingRevision  uint64              `json:"resulting_revision"`
	}{scope, action, auditAction, audit.Actor, audit.OperationID, audit.IdempotencyKey, audit.RequestFingerprint, resourceID, value.ID, expectedRevision, value.Revision})
	if marshalErr != nil {
		return ErrInvalid
	}
	digest := sha256.Sum256(auditIdentity)
	candidateID := value.CandidateID
	if action == "accept" {
		candidateID = auditSourceID
	}
	detail, _ := json.Marshal(map[string]any{"operation_id": audit.OperationID, "mutation_action": action, "candidate_id": candidateID, "database_family": value.DatabaseFamily, "expected_revision": expectedRevision, "resulting_revision": value.Revision, "change_digest": audit.RequestFingerprint})
	_, err = transaction.ExecContext(ctx, `INSERT INTO audit_events (id,tenant_id,project_id,occurred_at,action,actor_type,actor_id,resource_type,resource_id,result,request_id,trace_id,job_id,command_id,dedupe_key,detail,created_at) VALUES ($1,$2,$3,$4,$5,'user',$6,'database_instance',$7,'success',$8,$9,'','',$10,$11,$4) ON CONFLICT (tenant_id,project_id,dedupe_key) WHERE dedupe_key<>'' DO NOTHING`, "audit-dbi-"+hex.EncodeToString(digest[:]), scope.TenantID, scope.ProjectID, value.UpdatedAt, auditAction, audit.Actor, value.ID, audit.RequestID, audit.TraceID, "database-instance:"+hex.EncodeToString(digest[:]), detail)
	return mapPostgresError(err)
}

func lookupMutation(ctx context.Context, transaction *sql.Tx, scope platformscope.Scope, audit MutationAudit, action, resourceID string) (Instance, bool, error) {
	var fingerprint, storedAction, storedResource string
	var snapshot []byte
	err := transaction.QueryRowContext(ctx, `SELECT request_fingerprint,action,resource_id,response_snapshot FROM database_instance_mutations WHERE tenant_id=$1 AND project_id=$2 AND actor_id=$3 AND operation_id=$4 AND idempotency_key=$5`, scope.TenantID, scope.ProjectID, audit.Actor, audit.OperationID, audit.IdempotencyKey).Scan(&fingerprint, &storedAction, &storedResource, &snapshot)
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, false, nil
	}
	if err != nil {
		return Instance{}, false, err
	}
	if fingerprint != audit.RequestFingerprint || storedAction != action || storedResource != resourceID {
		return Instance{}, false, ErrConflict
	}
	value, err := decodeSnapshot(snapshot)
	return value, err == nil, err
}

func decodeSnapshot(snapshot []byte) (Instance, error) {
	var value Instance
	if json.Unmarshal(snapshot, &value) != nil || value.Validate() != nil {
		return Instance{}, ErrInvalid
	}
	return value, nil
}

func getInstanceTx(ctx context.Context, transaction *sql.Tx, scope platformscope.Scope, instanceID string) (Instance, error) {
	return getInstanceRow(transaction.QueryRowContext(ctx, `SELECT `+instanceColumns+` FROM managed_database_instances WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3`, scope.TenantID, scope.ProjectID, instanceID))
}

func getInstanceTxForUpdate(ctx context.Context, transaction *sql.Tx, scope platformscope.Scope, instanceID string) (Instance, error) {
	return getInstanceRow(transaction.QueryRowContext(ctx, `SELECT `+instanceColumns+` FROM managed_database_instances WHERE tenant_id=$1 AND project_id=$2 AND instance_id=$3 FOR UPDATE`, scope.TenantID, scope.ProjectID, instanceID))
}

func findActiveInstanceBySourceIdentity(ctx context.Context, transaction *sql.Tx, scope platformscope.Scope, hostID, family, identity string) (Instance, bool, error) {
	value, err := scanInstance(transaction.QueryRowContext(ctx, `SELECT `+instanceColumns+` FROM managed_database_instances WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3 AND database_family=$4 AND source_identity=$5 AND management_status<>'retired' FOR UPDATE`, scope.TenantID, scope.ProjectID, hostID, family, identity))
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, false, nil
	}
	if err != nil {
		return Instance{}, false, mapPostgresError(err)
	}
	return value, true, nil
}

type rowScanner interface{ Scan(...any) error }

func getInstanceRow(scanner rowScanner) (Instance, error) {
	value, err := scanInstance(scanner)
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, ErrNotFound
	}
	return value, err
}

func scanInstance(scanner rowScanner) (Instance, error) {
	var value Instance
	var source string
	var labels, capabilities []byte
	var connectionAt, retiredAt sql.NullTime
	var assignmentRevision, revision int64
	err := scanner.Scan(&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.HostID, &value.AgentID, &value.CandidateID, &source, &value.SourceFingerprint, &value.SourceIdentity, &value.DatabaseFamily, &value.DatabaseVariant, &value.DisplayName, &value.Endpoint, &value.UnixSocket, &value.Version, &value.Edition, &value.Role, &value.Topology, &value.CredentialRef, &value.TLSRef, &value.PluginID, &value.DesiredPluginVersion, &value.TemplateProfileID, &labels, &capabilities, &value.CapabilityState, &value.ConnectionTestStatus, &value.ConnectionTestErrorCode, &connectionAt, &assignmentRevision, &value.ManagementStatus, &revision, &value.CreatedAt, &value.UpdatedAt, &retiredAt)
	if err != nil {
		return Instance{}, err
	}
	if assignmentRevision < 0 || revision < 1 || json.Unmarshal(labels, &value.Labels) != nil || json.Unmarshal(capabilities, &value.Capabilities) != nil {
		return Instance{}, ErrInvalid
	}
	value.DiscoverySource = discovery.Source(source)
	value.PluginAssignmentRevision = uint64(assignmentRevision)
	value.Revision = uint64(revision)
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
	if connectionAt.Valid {
		at := connectionAt.Time.UTC()
		value.ConnectionTestAt = &at
	}
	if retiredAt.Valid {
		at := retiredAt.Time.UTC()
		value.RetiredAt = &at
	}
	if value.Validate() != nil {
		return Instance{}, ErrInvalid
	}
	return value, nil
}

func instanceArgs(value Instance, labels, capabilities []byte, canonical string) []any {
	return []any{value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.HostID, value.AgentID, value.CandidateID, value.DiscoverySource, value.SourceFingerprint, value.SourceIdentity, value.DatabaseFamily, value.DatabaseVariant, value.DisplayName, value.Endpoint, value.UnixSocket, value.Version, value.Edition, value.Role, value.Topology, value.CredentialRef, value.TLSRef, value.PluginID, value.DesiredPluginVersion, value.TemplateProfileID, labels, capabilities, value.CapabilityState, value.ConnectionTestStatus, value.ConnectionTestErrorCode, value.ConnectionTestAt, value.PluginAssignmentRevision, value.ManagementStatus, value.Revision, value.CreatedAt, value.UpdatedAt, value.RetiredAt, canonical}
}

func mapPostgresError(err error) error {
	var postgresError *pq.Error
	if !errors.As(err, &postgresError) {
		return err
	}
	switch postgresError.Code {
	case "40001", "40P01":
		return postgresError
	case "23505", "23503":
		return ErrConflict
	case "23502", "23514", "22P02", "22001":
		return ErrInvalid
	default:
		return err
	}
}

func isSerializationFailure(err error) bool {
	var postgresError *pq.Error
	return errors.As(err, &postgresError) && (postgresError.Code == "40001" || postgresError.Code == "40P01")
}

var _ Repository = (*PostgresRepository)(nil)
