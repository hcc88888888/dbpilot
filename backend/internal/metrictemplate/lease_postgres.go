package metrictemplate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type ExecutionFence interface {
	ExecutionLeaseActive(string, string, time.Time) bool
}

type PostgresLeaseAuthorizer struct {
	Database *sql.DB
	Fences   ExecutionFence
	Now      func() time.Time
}

func (authorizer PostgresLeaseAuthorizer) AuthorizeMetricTemplateLease(ctx context.Context, agent AuthenticatedAgent, request LeaseRequest) (LeaseAuthorization, error) {
	if authorizer.Database == nil || authorizer.Fences == nil || ctx == nil || ctx.Err() != nil || !validLeaseAgent(agent) || !validTemplateLeaseRequest(request) {
		return LeaseAuthorization{}, ErrLeaseRejected
	}
	now := time.Now().UTC()
	if authorizer.Now != nil {
		now = authorizer.Now().UTC()
	}
	liveFence := authorizer.Fences.ExecutionLeaseActive(agent.AgentID, request.CommandID, now)
	if liveFence {
		value, err := authorizer.loadTrial(ctx, agent, request, now)
		if err == nil {
			return value, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return LeaseAuthorization{}, ErrLeaseRejected
		}
	}
	value, err := authorizer.loadPublished(ctx, agent, request, now, liveFence)
	if err != nil {
		return LeaseAuthorization{}, ErrLeaseRejected
	}
	return value, nil
}

func (authorizer PostgresLeaseAuthorizer) loadTrial(ctx context.Context, agent AuthenticatedAgent, request LeaseRequest, now time.Time) (LeaseAuthorization, error) {
	return scanLeaseAuthorization(authorizer.Database.QueryRowContext(ctx, `SELECT revision.tenant_id,revision.project_id,instance.host_id,instance.agent_id,trial.assignment_id,trial.instance_id,trial.configuration_revision,trial.operation_revision,revision.revision_id,revision.query_digest,revision.template_id,revision.revision,revision.read_only_statement,revision.collection_interval_seconds,revision.timeout_seconds,revision.max_rows,revision.max_columns,revision.cardinality_limit,revision.value_mappings,revision.label_mappings,TRUE FROM metric_template_trials trial JOIN metric_template_revisions revision ON revision.tenant_id=trial.tenant_id AND revision.project_id=trial.project_id AND revision.revision_id=trial.revision_id JOIN managed_database_instances instance ON instance.tenant_id=trial.tenant_id AND instance.project_id=trial.project_id AND instance.instance_id=trial.instance_id JOIN plugin_assignments assignment ON assignment.tenant_id=trial.tenant_id AND assignment.project_id=trial.project_id AND assignment.assignment_id=trial.assignment_id JOIN plugin_versions version ON version.tenant_id=trial.tenant_id AND version.project_id=trial.project_id AND version.version_id=trial.plugin_version_id JOIN jobs job ON job.tenant_id=trial.tenant_id AND job.project_id=trial.project_id AND job.id=trial.job_id WHERE trial.command_id=$1 AND trial.assignment_id=$2 AND trial.instance_id=$3 AND trial.configuration_revision=$4 AND trial.operation_revision=$5 AND trial.revision_id=$6 AND trial.query_digest=$7 AND trial.status='running' AND revision.status='trial_running' AND revision.template_id=$10 AND instance.agent_id=$8 AND instance.management_status IN ('managed','monitoring') AND assignment.configuration_revision=trial.configuration_revision AND assignment.operation_revision=trial.operation_revision AND assignment.desired_version_id=trial.plugin_version_id AND assignment.desired_state='running' AND version.status='available' AND version.metric_template_schema_version=$9 AND job.status IN ('dispatched','running')`, request.CommandID, request.AssignmentID, request.InstanceID, request.ConfigurationRevision, request.OperationRevision, request.RevisionID, request.QueryDigest, agent.AgentID, MetricTemplateSchemaVersion, request.TemplateID), now)
}

func (authorizer PostgresLeaseAuthorizer) loadPublished(ctx context.Context, agent AuthenticatedAgent, request LeaseRequest, now time.Time, liveFence bool) (LeaseAuthorization, error) {
	return scanLeaseAuthorization(authorizer.Database.QueryRowContext(ctx, `SELECT revision.tenant_id,revision.project_id,instance.host_id,instance.agent_id,assignment.assignment_id,instance.instance_id,assignment.configuration_revision,assignment.operation_revision,revision.revision_id,revision.query_digest,revision.template_id,revision.revision,revision.read_only_statement,revision.collection_interval_seconds,revision.timeout_seconds,revision.max_rows,revision.max_columns,revision.cardinality_limit,revision.value_mappings,revision.label_mappings,FALSE FROM plugin_assignment_instances binding JOIN plugin_assignments assignment ON assignment.tenant_id=binding.tenant_id AND assignment.project_id=binding.project_id AND assignment.assignment_id=binding.assignment_id JOIN managed_database_instances instance ON instance.tenant_id=binding.tenant_id AND instance.project_id=binding.project_id AND instance.instance_id=binding.instance_id JOIN plugin_versions version ON version.tenant_id=assignment.tenant_id AND version.project_id=assignment.project_id AND version.version_id=assignment.desired_version_id JOIN metric_template_revisions revision ON revision.tenant_id=binding.tenant_id AND revision.project_id=binding.project_id AND revision.revision_id=$6 JOIN plugin_reconcile_operations operation ON operation.tenant_id=assignment.tenant_id AND operation.project_id=assignment.project_id AND operation.assignment_id=assignment.assignment_id AND operation.configuration_revision=assignment.configuration_revision AND operation.operation_revision=assignment.operation_revision JOIN jobs job ON job.tenant_id=operation.tenant_id AND job.project_id=operation.project_id AND job.id=operation.job_id JOIN command_outbox outbox ON outbox.tenant_id=operation.tenant_id AND outbox.project_id=operation.project_id AND outbox.id=operation.command_id AND outbox.id=$1 WHERE binding.assignment_id=$2 AND binding.instance_id=$3 AND assignment.configuration_revision=$4 AND assignment.operation_revision=$5 AND revision.query_digest=$7 AND revision.template_id=$10 AND binding.template_revision_ids ? revision.revision_id AND revision.status IN ('published','superseded') AND EXISTS (SELECT 1 FROM metric_template_publications publication WHERE publication.tenant_id=revision.tenant_id AND publication.project_id=revision.project_id AND publication.selected_revision_id=revision.revision_id) AND instance.agent_id=$8 AND instance.management_status<>'retired' AND assignment.desired_state='running' AND version.status='available' AND version.metric_template_schema_version=$9 AND ((job.status='succeeded' AND outbox.command_phase='succeeded') OR ($11 AND job.status IN ('dispatched','running') AND outbox.command_phase IN ('start_authorized','running')))`, request.CommandID, request.AssignmentID, request.InstanceID, request.ConfigurationRevision, request.OperationRevision, request.RevisionID, request.QueryDigest, agent.AgentID, MetricTemplateSchemaVersion, request.TemplateID, liveFence), now)
}

func scanLeaseAuthorization(row scanner, now time.Time) (LeaseAuthorization, error) {
	var value LeaseAuthorization
	var mappings, labels []byte
	err := row.Scan(&value.Scope.TenantID, &value.Scope.ProjectID, &value.HostID, &value.AgentID, &value.AssignmentID, &value.InstanceID, &value.ConfigurationRevision, &value.OperationRevision, &value.RevisionID, &value.QueryDigest, &value.TemplateID, &value.Definition.Revision, &value.Definition.StatementBytes, &value.Definition.CollectionIntervalSeconds, &value.Definition.TimeoutSeconds, &value.Definition.MaxRows, &value.Definition.MaxColumns, &value.Definition.CardinalityLimit, &mappings, &labels, &value.Trial)
	if err != nil {
		return LeaseAuthorization{}, err
	}
	if json.Unmarshal(mappings, &value.Definition.ValueMappings) != nil || json.Unmarshal(labels, &value.Definition.LabelMappings) != nil {
		return LeaseAuthorization{}, ErrLeaseRejected
	}
	value.AuthorizedAt = now
	return value, nil
}

type PostgresLeaseAuditRecorder struct{ Database *sql.DB }

func (recorder PostgresLeaseAuditRecorder) Record(ctx context.Context, value LeaseAudit) error {
	if recorder.Database == nil || ctx == nil || value.Validate() != nil {
		return ErrLeaseRejected
	}
	detail, _ := json.Marshal(map[string]any{"assignment_id": value.AssignmentID, "instance_id": value.InstanceID, "command_id": value.CommandID, "template_id": value.TemplateID, "revision_id": value.RevisionID, "query_digest": value.QueryDigest, "configuration_revision": value.ConfigurationRevision, "operation_revision": value.OperationRevision, "trial": value.Trial, "result": value.Result})
	dedupe := deterministicID("metric-lease-audit-", value.Scope.Key()+"\x00"+value.AgentID+"\x00"+value.CommandID+"\x00"+value.RevisionID+"\x00"+string(value.Result))
	_, err := recorder.Database.ExecContext(ctx, `INSERT INTO audit_events (id,tenant_id,project_id,occurred_at,action,actor_type,actor_id,resource_type,resource_id,result,request_id,trace_id,job_id,command_id,dedupe_key,detail,created_at) VALUES ($1,$2,$3,$4,'metric_template.lease','agent',$5,'metric_template_revision',$6,$7,'','','',$8,$9,$10,$4) ON CONFLICT (tenant_id,project_id,dedupe_key) WHERE dedupe_key<>'' DO NOTHING`, "audit-"+dedupe, value.Scope.TenantID, value.Scope.ProjectID, value.OccurredAt, value.AgentID, value.RevisionID, string(value.Result), value.CommandID, dedupe, detail)
	return mapPostgresError(err)
}

var _ MetricTemplateLeaseAuthorizer = PostgresLeaseAuthorizer{}
var _ LeaseAuditRecorder = PostgresLeaseAuditRecorder{}
