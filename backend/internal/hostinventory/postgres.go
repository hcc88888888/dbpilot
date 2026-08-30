package hostinventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
)

const hostColumnsSQL = "tenant_id, project_id, host_id, agent_id, display_name, hostname, operating_system, operating_system_version, kernel_version, architecture, logical_cpu_count, memory_capacity_bytes, filesystems, network_addresses, labels, container_runtime, capabilities, agent_version, enrollment_revision, observation_revision, enrolled_at, last_hello_at, last_heartbeat_at, status, version, decommission_actor, decommission_operation, decommission_idempotency_key, decommission_fingerprint, decommission_owner_token"

const getHostSQL = "SELECT " + hostColumnsSQL + " FROM managed_hosts WHERE tenant_id = $1 AND project_id = $2 AND host_id = $3"
const getHostByAgentSQL = "SELECT " + hostColumnsSQL + " FROM managed_hosts WHERE tenant_id = $1 AND project_id = $2 AND agent_id = $3"

const recordObservationSQL = `WITH upserted AS (
    INSERT INTO managed_hosts (
        tenant_id, project_id, host_id, agent_id, display_name, hostname,
        operating_system, operating_system_version, kernel_version, architecture,
        logical_cpu_count, memory_capacity_bytes, filesystems, network_addresses,
        capabilities, agent_version, enrollment_revision, observation_revision,
        enrolled_at, status, version, updated_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 1, $17, $19, 'enrolling', 1, $19)
    ON CONFLICT (host_id) DO UPDATE SET
        hostname = EXCLUDED.hostname,
        operating_system = EXCLUDED.operating_system,
        operating_system_version = EXCLUDED.operating_system_version,
        kernel_version = EXCLUDED.kernel_version,
        architecture = EXCLUDED.architecture,
        logical_cpu_count = EXCLUDED.logical_cpu_count,
        memory_capacity_bytes = EXCLUDED.memory_capacity_bytes,
        filesystems = EXCLUDED.filesystems,
        network_addresses = EXCLUDED.network_addresses,
        capabilities = EXCLUDED.capabilities,
        agent_version = EXCLUDED.agent_version,
        observation_revision = EXCLUDED.observation_revision,
        version = managed_hosts.version + 1,
        updated_at = EXCLUDED.updated_at
    WHERE managed_hosts.tenant_id = EXCLUDED.tenant_id
      AND managed_hosts.project_id = EXCLUDED.project_id
      AND managed_hosts.agent_id = EXCLUDED.agent_id
      AND managed_hosts.observation_revision < EXCLUDED.observation_revision
      AND managed_hosts.status <> 'decommissioned'
    RETURNING ` + hostColumnsSQL + `
), inserted_observation AS (
    INSERT INTO host_observations (
        tenant_id, project_id, host_id, agent_id, observation_revision,
        snapshot, observed_at, received_at
    )
    SELECT tenant_id, project_id, host_id, agent_id, observation_revision, $20, $18, $19
    FROM upserted
    RETURNING host_id
)
SELECT ` + hostColumnsSQL + ` FROM upserted`

const recordHeartbeatSQL = `UPDATE managed_hosts SET
    last_heartbeat_at = $1,
    status = 'online',
    version = version + 1,
    updated_at = $1
WHERE tenant_id = $2 AND project_id = $3 AND agent_id = $4
  AND status <> 'decommissioned'
  AND (last_heartbeat_at IS NULL OR last_heartbeat_at < $1)
RETURNING ` + hostColumnsSQL

const decommissionHostSQL = `UPDATE managed_hosts SET
    status = 'decommissioned',
    decommission_actor = $6,
    decommission_operation = $7,
    decommission_idempotency_key = $8,
    decommission_fingerprint = $9,
    decommission_owner_token = $10,
    version = version + 1,
    updated_at = $5
WHERE tenant_id = $1 AND project_id = $2 AND host_id = $3 AND version = $4 AND status <> 'decommissioned'
RETURNING ` + hostColumnsSQL

type postgresQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type PostgresRepository struct{ database postgresQuerier }

func NewPostgresRepository(database postgresQuerier) *PostgresRepository {
	return &PostgresRepository{database: database}
}

func (repository *PostgresRepository) RecordObservation(ctx context.Context, scope platformscope.Scope, observation Observation, receivedAt time.Time) (Host, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || observation.Validate() != nil || !validUTC(receivedAt) {
		return Host{}, ErrInvalid
	}
	filesystems, err := json.Marshal(observation.Filesystems)
	if err != nil {
		return Host{}, ErrInvalid
	}
	addresses, err := json.Marshal(observation.NetworkAddresses)
	if err != nil {
		return Host{}, ErrInvalid
	}
	capabilities := make([]Capability, len(observation.Capabilities))
	for index, name := range observation.Capabilities {
		capabilities[index] = Capability{Name: name, Available: true}
	}
	capabilityJSON, err := json.Marshal(capabilities)
	if err != nil {
		return Host{}, ErrInvalid
	}
	snapshot, err := json.Marshal(observation)
	if err != nil {
		return Host{}, ErrInvalid
	}
	host, err := scanHost(repository.database.QueryRowContext(ctx, recordObservationSQL,
		scope.TenantID, scope.ProjectID, observation.HostID, observation.AgentID, observation.Hostname, observation.Hostname,
		observation.OS, observation.OSVersion, observation.Kernel, observation.Architecture, observation.LogicalCPUCount,
		observation.MemoryCapacityBytes, filesystems, addresses, capabilityJSON, observation.AgentVersion,
		observation.Revision, observation.ObservedAt, receivedAt, snapshot,
	))
	if errors.Is(err, sql.ErrNoRows) {
		host, err = repository.Get(ctx, scope, observation.HostID)
		if err == nil && host.AgentID != observation.AgentID {
			return Host{}, ErrConflict
		}
		if err != nil {
			return Host{}, err
		}
		switch {
		case host.ObservationRevision > observation.Revision:
			return Host{}, ErrStaleRevision
		case host.ObservationRevision == observation.Revision:
			return host, nil
		default:
			return Host{}, ErrConflict
		}
	}
	if err != nil {
		return Host{}, mapPostgresError(err)
	}
	return host, nil
}

func (repository *PostgresRepository) RecordHeartbeat(ctx context.Context, scope platformscope.Scope, agentID string, at time.Time) (Host, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(agentID) || !validUTC(at) {
		return Host{}, ErrInvalid
	}
	host, err := scanHost(repository.database.QueryRowContext(ctx, recordHeartbeatSQL, at, scope.TenantID, scope.ProjectID, agentID))
	if errors.Is(err, sql.ErrNoRows) {
		return repository.getByAgent(ctx, scope, agentID)
	}
	if err != nil {
		return Host{}, mapPostgresError(err)
	}
	return host, nil
}

func (repository *PostgresRepository) List(ctx context.Context, scope platformscope.Scope, filter Filter) (Page, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || filter.Validate() != nil || !validUTC(filter.now) || filter.staleAfter <= 0 || filter.offlineAfter <= filter.staleAfter {
		return Page{}, ErrInvalid
	}
	limit := filter.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	classification := `CASE
        WHEN status = 'decommissioned' THEN 'decommissioned'
        WHEN status IN ('pending', 'enrolling') THEN status
        WHEN last_heartbeat_at IS NULL THEN 'offline'
        WHEN last_heartbeat_at >= $4::timestamptz - ($5 * INTERVAL '1 microsecond') THEN 'online'
        WHEN last_heartbeat_at >= $4::timestamptz - ($6 * INTERVAL '1 microsecond') THEN 'stale'
        ELSE 'offline'
    END`
	query := `WITH classified AS (
    SELECT tenant_id, project_id, host_id, agent_id, display_name, hostname,
        operating_system, operating_system_version, kernel_version, architecture,
        logical_cpu_count, memory_capacity_bytes, filesystems, network_addresses,
        labels, container_runtime, capabilities, agent_version, enrollment_revision,
		observation_revision, enrolled_at, last_hello_at, last_heartbeat_at,
		` + classification + ` AS status, version, decommission_actor, decommission_operation,
		decommission_idempotency_key, decommission_fingerprint, decommission_owner_token
    FROM managed_hosts WHERE tenant_id = $1 AND project_id = $2 AND ($3 = '' OR host_id > $3)
)
SELECT ` + hostColumnsSQL + ` FROM classified
WHERE ($7 = '' OR status = $7)
ORDER BY host_id
LIMIT $8`
	rows, err := repository.database.QueryContext(ctx, query, scope.TenantID, scope.ProjectID, filter.Cursor, filter.now, filter.staleAfter.Microseconds(), filter.offlineAfter.Microseconds(), string(filter.Status), limit+1)
	if err != nil {
		return Page{}, mapPostgresError(err)
	}
	defer rows.Close()
	page := Page{Items: make([]Host, 0, limit)}
	for rows.Next() {
		host, err := scanHost(rows)
		if err != nil {
			return Page{}, err
		}
		page.Items = append(page.Items, host)
	}
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = page.Items[len(page.Items)-1].ID
	}
	return page, nil
}

func (repository *PostgresRepository) Get(ctx context.Context, scope platformscope.Scope, hostID string) (Host, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(hostID) {
		return Host{}, ErrInvalid
	}
	host, err := scanHost(repository.database.QueryRowContext(ctx, getHostSQL, scope.TenantID, scope.ProjectID, hostID))
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if err != nil {
		return Host{}, mapPostgresError(err)
	}
	return host, nil
}

func (repository *PostgresRepository) Decommission(ctx context.Context, scope platformscope.Scope, hostID string, expectedVersion uint64, at time.Time, transition DecommissionTransition) (Host, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !identifierPattern.MatchString(hostID) || !validPostgresRevision(expectedVersion, false) || !validUTC(at) || transition.Validate() != nil {
		return Host{}, ErrInvalid
	}
	host, err := scanHost(repository.database.QueryRowContext(ctx, decommissionHostSQL, scope.TenantID, scope.ProjectID, hostID, expectedVersion, at, transition.Actor, transition.OperationID, transition.IdempotencyKey, transition.Fingerprint, transition.OwnerToken))
	if err == nil {
		return host, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Host{}, mapPostgresError(err)
	}
	var version uint64
	err = repository.database.QueryRowContext(ctx, "SELECT version FROM managed_hosts WHERE tenant_id = $1 AND project_id = $2 AND host_id = $3", scope.TenantID, scope.ProjectID, hostID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if err != nil {
		return Host{}, mapPostgresError(err)
	}
	return Host{}, ErrConflict
}

func (repository *PostgresRepository) getByAgent(ctx context.Context, scope platformscope.Scope, agentID string) (Host, error) {
	host, err := scanHost(repository.database.QueryRowContext(ctx, getHostByAgentSQL, scope.TenantID, scope.ProjectID, agentID))
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if err != nil {
		return Host{}, mapPostgresError(err)
	}
	return host, nil
}

type rowScanner interface{ Scan(...any) error }

func scanHost(scanner rowScanner) (Host, error) {
	var host Host
	var logicalCPUCount, memoryCapacityBytes, enrollmentRevision, observationRevision, version int64
	var filesystems, addresses, labels, capabilities []byte
	var helloAt, heartbeatAt sql.NullTime
	var decommissionActor, decommissionOperation, decommissionKey, decommissionFingerprint, decommissionOwner sql.NullString
	err := scanner.Scan(
		&host.Scope.TenantID, &host.Scope.ProjectID, &host.ID, &host.AgentID, &host.DisplayName, &host.Hostname,
		&host.OperatingSystem, &host.OperatingSystemVersion, &host.KernelVersion, &host.Architecture,
		&logicalCPUCount, &memoryCapacityBytes, &filesystems, &addresses, &labels, &host.ContainerRuntime,
		&capabilities, &host.AgentVersion, &enrollmentRevision, &observationRevision, &host.EnrolledAt,
		&helloAt, &heartbeatAt, &host.Status, &version,
		&decommissionActor, &decommissionOperation, &decommissionKey, &decommissionFingerprint, &decommissionOwner,
	)
	if err != nil {
		return Host{}, err
	}
	if logicalCPUCount < 0 || memoryCapacityBytes < 0 || enrollmentRevision < 1 || observationRevision < 0 || version < 1 {
		return Host{}, ErrInvalid
	}
	host.CPU = ResourceSummary{Capacity: uint64(logicalCPUCount)}
	host.Memory = ResourceSummary{Capacity: uint64(memoryCapacityBytes)}
	host.EnrollmentRevision, host.ObservationRevision, host.Version = uint64(enrollmentRevision), uint64(observationRevision), uint64(version)
	if err := json.Unmarshal(filesystems, &host.Filesystems); err != nil {
		return Host{}, fmt.Errorf("decode host filesystems: %w", err)
	}
	if err := json.Unmarshal(addresses, &host.NetworkAddresses); err != nil {
		return Host{}, fmt.Errorf("decode host network addresses: %w", err)
	}
	if err := json.Unmarshal(labels, &host.Labels); err != nil {
		return Host{}, fmt.Errorf("decode host labels: %w", err)
	}
	if err := json.Unmarshal(capabilities, &host.Capabilities); err != nil {
		return Host{}, fmt.Errorf("decode host capabilities: %w", err)
	}
	host.EnrolledAt = host.EnrolledAt.UTC()
	if helloAt.Valid {
		host.LastHelloAt = helloAt.Time.UTC()
	}
	if heartbeatAt.Valid {
		host.LastHeartbeatAt = heartbeatAt.Time.UTC()
	}
	if decommissionActor.Valid || decommissionOperation.Valid || decommissionKey.Valid || decommissionFingerprint.Valid || decommissionOwner.Valid {
		if !decommissionActor.Valid || !decommissionOperation.Valid || !decommissionKey.Valid || !decommissionFingerprint.Valid || !decommissionOwner.Valid {
			return Host{}, ErrInvalid
		}
		host.DecommissionTransition = &DecommissionTransition{
			Actor: decommissionActor.String, OperationID: decommissionOperation.String,
			IdempotencyKey: decommissionKey.String, Fingerprint: decommissionFingerprint.String, OwnerToken: decommissionOwner.String,
		}
	}
	if host.Validate() != nil {
		return Host{}, ErrInvalid
	}
	return host, nil
}

func hostColumnNames() []string {
	return []string{
		"tenant_id", "project_id", "host_id", "agent_id", "display_name", "hostname", "operating_system", "operating_system_version", "kernel_version", "architecture",
		"logical_cpu_count", "memory_capacity_bytes", "filesystems", "network_addresses", "labels", "container_runtime", "capabilities", "agent_version",
		"enrollment_revision", "observation_revision", "enrolled_at", "last_hello_at", "last_heartbeat_at", "status", "version",
		"decommission_actor", "decommission_operation", "decommission_idempotency_key", "decommission_fingerprint", "decommission_owner_token",
	}
}

func mapPostgresError(err error) error {
	var postgresError *pq.Error
	if !errors.As(err, &postgresError) {
		return err
	}
	switch postgresError.Code {
	case "23505", "23503":
		return ErrConflict
	case "23502", "23514", "22P02", "22001":
		return ErrInvalid
	default:
		return err
	}
}

var _ Repository = (*PostgresRepository)(nil)
