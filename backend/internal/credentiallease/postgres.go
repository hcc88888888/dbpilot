package credentiallease

import (
	"context"
	"database/sql"
	"time"
)

type ExecutionFence interface {
	ExecutionLeaseActive(string, string, time.Time) bool
}

type PostgresAuthorizer struct {
	Database *sql.DB
	Fences   ExecutionFence
}

func (authorizer PostgresAuthorizer) Authorize(ctx context.Context, agent AuthenticatedAgent, request LeaseRequest) (Authorization, error) {
	if ctx == nil || ctx.Err() != nil || authorizer.Database == nil || authorizer.Fences == nil || !validAgent(agent) || !validLeaseRequest(request) {
		return Authorization{}, ErrLeaseRejected
	}
	const query = `SELECT pa.tenant_id,pa.project_id,pa.host_id,pa.agent_id,pa.assignment_id,pa.database_family,
pa.configuration_revision,pa.operation_revision,di.instance_id,di.revision,di.credential_ref,di.tls_ref,di.management_status,
op.command_id,CURRENT_TIMESTAMP
FROM plugin_assignments pa
JOIN plugin_assignment_instances pai ON pai.tenant_id=pa.tenant_id AND pai.project_id=pa.project_id AND pai.assignment_id=pa.assignment_id
JOIN managed_database_instances di ON di.tenant_id=pa.tenant_id AND di.project_id=pa.project_id AND di.instance_id=pai.instance_id AND di.host_id=pa.host_id AND di.agent_id=pa.agent_id AND di.database_family=pa.database_family
JOIN plugin_reconcile_operations op ON op.tenant_id=pa.tenant_id AND op.project_id=pa.project_id AND op.assignment_id=pa.assignment_id AND op.configuration_revision=pa.configuration_revision AND op.operation_revision=pa.operation_revision
WHERE pa.agent_id=$1 AND pa.assignment_id=$2 AND di.instance_id=$3 AND pa.configuration_revision=$4
AND pa.desired_state='running' AND di.management_status<>'retired'`
	var value Authorization
	var commandID string
	err := authorizer.Database.QueryRowContext(ctx, query, agent.AgentID, request.AssignmentID, request.InstanceID, request.ConfigurationRevision).Scan(&value.Scope.TenantID, &value.Scope.ProjectID, &value.HostID, &value.AgentID, &value.AssignmentID, &value.DatabaseFamily, &value.ConfigurationRevision, &value.OperationRevision, &value.InstanceID, &value.InstanceRevision, &value.CredentialRef, &value.TLSRef, &value.ManagementStatus, &commandID, &value.AuthorizedAt)
	if err != nil || !validAuthorization(value, agent, request) {
		return Authorization{}, ErrLeaseRejected
	}
	value.AuthorizedAt = value.AuthorizedAt.UTC()
	if !authorizer.Fences.ExecutionLeaseActive(agent.AgentID, commandID, value.AuthorizedAt) {
		return authorizer.AuthorizeRenewal(ctx, agent, request)
	}
	return value, nil
}

func (authorizer PostgresAuthorizer) AuthorizeRenewal(ctx context.Context, agent AuthenticatedAgent, request LeaseRequest) (Authorization, error) {
	if ctx == nil || ctx.Err() != nil || authorizer.Database == nil || !validAgent(agent) || !validLeaseRequest(request) {
		return Authorization{}, ErrLeaseRejected
	}
	const query = `SELECT pa.tenant_id,pa.project_id,pa.host_id,pa.agent_id,pa.assignment_id,pa.database_family,
pa.configuration_revision,pa.operation_revision,di.instance_id,di.revision,di.credential_ref,di.tls_ref,di.management_status,
CURRENT_TIMESTAMP
FROM plugin_assignments pa
JOIN plugin_assignment_instances pai ON pai.tenant_id=pa.tenant_id AND pai.project_id=pa.project_id AND pai.assignment_id=pa.assignment_id
JOIN managed_database_instances di ON di.tenant_id=pa.tenant_id AND di.project_id=pa.project_id AND di.instance_id=pai.instance_id AND di.host_id=pa.host_id AND di.agent_id=pa.agent_id AND di.database_family=pa.database_family
JOIN plugin_reconcile_operations op ON op.tenant_id=pa.tenant_id AND op.project_id=pa.project_id AND op.assignment_id=pa.assignment_id AND op.configuration_revision=pa.configuration_revision AND op.operation_revision=pa.operation_revision
JOIN jobs j ON j.tenant_id=op.tenant_id AND j.project_id=op.project_id AND j.id=op.job_id AND j.status='succeeded'
JOIN command_outbox co ON co.tenant_id=op.tenant_id AND co.project_id=op.project_id AND co.job_id=op.job_id AND co.id=op.command_id AND co.command_status='succeeded'
JOIN plugin_versions pv ON pv.tenant_id=pa.tenant_id AND pv.project_id=pa.project_id AND pv.version_id=pa.desired_version_id AND pv.status='available'
JOIN plugin_observations po ON po.tenant_id=pa.tenant_id AND po.project_id=pa.project_id AND po.assignment_id=pa.assignment_id AND po.process_state='running' AND po.health='healthy' AND po.active_configuration_revision=pa.configuration_revision AND po.observed_operation_revision=pa.operation_revision
WHERE pa.agent_id=$1 AND pa.assignment_id=$2 AND di.instance_id=$3 AND pa.configuration_revision=$4
AND pa.desired_state='running' AND di.management_status<>'retired'
AND EXISTS (
SELECT 1 FROM credential_lease_audits cla
WHERE cla.tenant_id=pa.tenant_id AND cla.project_id=pa.project_id AND cla.agent_id=pa.agent_id AND cla.host_id=pa.host_id
AND cla.assignment_id=pa.assignment_id AND cla.instance_id=di.instance_id
AND cla.configuration_revision=pa.configuration_revision AND cla.operation_revision=pa.operation_revision
AND cla.instance_revision=di.revision
AND cla.credential_ref_hash='sha256:' || encode(sha256(convert_to('dbpilot-credential-reference-audit-v1','UTF8') || decode('00','hex') || convert_to(di.credential_ref,'UTF8')),'hex')
AND cla.result='issued')`
	var value Authorization
	err := authorizer.Database.QueryRowContext(ctx, query, agent.AgentID, request.AssignmentID, request.InstanceID, request.ConfigurationRevision).Scan(&value.Scope.TenantID, &value.Scope.ProjectID, &value.HostID, &value.AgentID, &value.AssignmentID, &value.DatabaseFamily, &value.ConfigurationRevision, &value.OperationRevision, &value.InstanceID, &value.InstanceRevision, &value.CredentialRef, &value.TLSRef, &value.ManagementStatus, &value.AuthorizedAt)
	if err != nil || !validAuthorization(value, agent, request) || !strictSecretReference(value.CredentialRef) {
		return Authorization{}, ErrLeaseRejected
	}
	value.AuthorizedAt = value.AuthorizedAt.UTC()
	return value, nil
}

type PostgresClock struct{ Database *sql.DB }

func (clock PostgresClock) Now(ctx context.Context) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil || clock.Database == nil {
		return time.Time{}, ErrLeaseRejected
	}
	var now time.Time
	if err := clock.Database.QueryRowContext(ctx, "SELECT CURRENT_TIMESTAMP").Scan(&now); err != nil {
		return time.Time{}, ErrLeaseRejected
	}
	return now.UTC(), nil
}

type PostgresAuditRecorder struct{ Database *sql.DB }

func (recorder PostgresAuditRecorder) Record(ctx context.Context, record AuditRecord) error {
	if ctx == nil || ctx.Err() != nil || recorder.Database == nil || record.Validate() != nil {
		return ErrLeaseRejected
	}
	const statement = `INSERT INTO credential_lease_audits
(tenant_id,project_id,agent_id,host_id,assignment_id,instance_id,configuration_revision,operation_revision,instance_revision,credential_ref_hash,credential_revision,lease_id_hash,result,expiry_class,occurred_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
	_, err := recorder.Database.ExecContext(ctx, statement, record.TenantID, record.ProjectID, record.AgentID, record.HostID, record.AssignmentID, record.InstanceID, record.ConfigurationRevision, record.OperationRevision, record.InstanceRevision, record.CredentialRefHash, record.CredentialRevision, record.LeaseIDHash, record.Result, record.ExpiryClass, record.OccurredAt)
	if err != nil {
		return ErrLeaseRejected
	}
	return nil
}

var _ Authorizer = PostgresAuthorizer{}
var _ RenewalAuthorizer = PostgresAuthorizer{}
var _ DatabaseClock = PostgresClock{}
var _ AuditRecorder = PostgresAuditRecorder{}
