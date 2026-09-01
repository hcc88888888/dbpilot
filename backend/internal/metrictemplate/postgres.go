package metrictemplate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/pluginassignment"
	"github.com/Masterminds/semver/v3"
	"github.com/lib/pq"
	"google.golang.org/protobuf/proto"
)

const revisionColumns = `revision_id,tenant_id,project_id,template_id,revision,database_family,variants,name,description,query_kind,read_only_statement,collection_interval_seconds,timeout_seconds,max_rows,max_columns,value_mappings,label_mappings,database_version_range,plugin_version_range,cardinality_limit,query_digest,status,created_by,approved_by,resource_revision,created_at,updated_at`

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
	err := repository.database.QueryRowContext(ctx, `SELECT to_regclass('metric_templates') IS NOT NULL AND to_regclass('metric_template_revisions') IS NOT NULL AND to_regclass('metric_template_trials') IS NOT NULL AND to_regclass('metric_template_publications') IS NOT NULL AND to_regclass('metric_template_mutations') IS NOT NULL`).Scan(&ready)
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("metric template schema is unavailable")
	}
	return nil
}

// LoadPluginTemplateReferences returns only published immutable identities,
// digests and execution bounds. Query text remains in the protected revision
// row and is available solely through the MetricTemplateLease flow.
func (repository *PostgresRepository) LoadPluginTemplateReferences(ctx context.Context, assignment pluginassignment.Assignment) ([]*agentv1.MetricTemplateCommandReference, []*agentv1.PluginInstanceTemplateReferences, error) {
	if repository == nil || repository.database == nil || ctx == nil || assignment.Validate() != nil || len(assignment.TemplateRevisionIDs) > MaximumAssignments {
		return nil, nil, ErrInvalid
	}
	byInstance := make(map[string][]*agentv1.MetricTemplateCommandReference, len(assignment.InstanceIDs))
	for _, instanceID := range assignment.InstanceIDs {
		byInstance[instanceID] = []*agentv1.MetricTemplateCommandReference{}
	}
	if len(assignment.TemplateRevisionIDs) == 0 {
		instances := make([]*agentv1.PluginInstanceTemplateReferences, 0, len(assignment.InstanceIDs))
		for _, instanceID := range assignment.InstanceIDs {
			instances = append(instances, &agentv1.PluginInstanceTemplateReferences{InstanceId: instanceID, Templates: []*agentv1.MetricTemplateCommandReference{}})
		}
		return []*agentv1.MetricTemplateCommandReference{}, instances, nil
	}
	rows, err := repository.database.QueryContext(ctx, `SELECT binding.instance_id,revision.template_id,revision.revision_id,revision.query_digest,revision.timeout_seconds,revision.max_rows,revision.max_columns,revision.cardinality_limit FROM plugin_assignment_instances binding CROSS JOIN LATERAL jsonb_array_elements_text(binding.template_revision_ids) item(revision_id) JOIN metric_template_revisions revision ON revision.tenant_id=binding.tenant_id AND revision.project_id=binding.project_id AND revision.revision_id=item.revision_id WHERE binding.tenant_id=$1 AND binding.project_id=$2 AND binding.assignment_id=$3 AND binding.instance_id=ANY($4) AND revision.status IN ('published','superseded') AND EXISTS (SELECT 1 FROM metric_template_publications publication WHERE publication.tenant_id=revision.tenant_id AND publication.project_id=revision.project_id AND publication.selected_revision_id=revision.revision_id) ORDER BY binding.instance_id,revision.template_id,revision.revision_id`, assignment.Scope.TenantID, assignment.Scope.ProjectID, assignment.ID, pq.Array(assignment.InstanceIDs))
	if err != nil {
		return nil, nil, mapPostgresError(err)
	}
	defer rows.Close()
	byRevision := make(map[string]*agentv1.MetricTemplateCommandReference, len(assignment.TemplateRevisionIDs))
	for rows.Next() {
		var instanceID, templateID, revisionID, digestHex string
		var timeout, maxRows, maxColumns, cardinality uint32
		if err := rows.Scan(&instanceID, &templateID, &revisionID, &digestHex, &timeout, &maxRows, &maxColumns, &cardinality); err != nil {
			return nil, nil, err
		}
		if _, ok := byInstance[instanceID]; !ok || !contains(assignment.TemplateRevisionIDs, revisionID) {
			return nil, nil, ErrConflict
		}
		digest, decodeErr := hex.DecodeString(digestHex)
		if decodeErr != nil || len(digest) != 32 {
			return nil, nil, ErrInvalid
		}
		reference := &agentv1.MetricTemplateCommandReference{TemplateId: templateID, RevisionId: revisionID, QueryDigest: digest, TimeoutSeconds: timeout, MaxRows: maxRows, MaxColumns: maxColumns, CardinalityLimit: cardinality}
		if existing := byRevision[revisionID]; existing != nil && !proto.Equal(existing, reference) {
			return nil, nil, ErrConflict
		}
		byRevision[revisionID] = reference
		byInstance[instanceID] = append(byInstance[instanceID], reference)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(byRevision) != len(assignment.TemplateRevisionIDs) {
		return nil, nil, ErrNotApproved
	}
	references := make([]*agentv1.MetricTemplateCommandReference, 0, len(byRevision))
	for _, revisionID := range assignment.TemplateRevisionIDs {
		references = append(references, proto.Clone(byRevision[revisionID]).(*agentv1.MetricTemplateCommandReference))
	}
	sort.Slice(references, func(i, j int) bool {
		if references[i].GetTemplateId() == references[j].GetTemplateId() {
			return references[i].GetRevisionId() < references[j].GetRevisionId()
		}
		return references[i].GetTemplateId() < references[j].GetTemplateId()
	})
	instances := make([]*agentv1.PluginInstanceTemplateReferences, 0, len(assignment.InstanceIDs))
	for _, instanceID := range assignment.InstanceIDs {
		values := byInstance[instanceID]
		sort.Slice(values, func(i, j int) bool { return values[i].GetTemplateId() < values[j].GetTemplateId() })
		instances = append(instances, &agentv1.PluginInstanceTemplateReferences{InstanceId: instanceID, Templates: cloneAgentTemplateReferences(values)})
	}
	return references, instances, nil
}

func cloneAgentTemplateReferences(values []*agentv1.MetricTemplateCommandReference) []*agentv1.MetricTemplateCommandReference {
	result := make([]*agentv1.MetricTemplateCommandReference, len(values))
	for index, value := range values {
		result[index] = proto.Clone(value).(*agentv1.MetricTemplateCommandReference)
	}
	return result
}

func (repository *PostgresRepository) CreateTemplate(ctx context.Context, scope platformscope.Scope, draft TemplateDraft, actor Actor) (Template, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || draft.Validate() != nil || actor.Validate() != nil {
		return Template{}, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Template{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if snapshot, found, err := lookupTemplateMutation(ctx, tx, scope, actor, "create_template", draft.ID); err != nil {
		return Template{}, err
	} else if found {
		return snapshot, nil
	}
	var created time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO metric_templates (tenant_id,project_id,template_id,database_family,name,description,builtin,latest_revision,published_revision,created_at) VALUES ($1,$2,$3,$4,$5,$6,FALSE,0,NULL,CURRENT_TIMESTAMP) RETURNING created_at`, scope.TenantID, scope.ProjectID, draft.ID, draft.DatabaseFamily, draft.Name, draft.Description).Scan(&created)
	if err != nil {
		return Template{}, mapPostgresError(err)
	}
	value := Template{ID: draft.ID, Scope: scope, DatabaseFamily: draft.DatabaseFamily, Name: draft.Name, Description: draft.Description, CreatedAt: created.UTC()}
	if value.Validate() != nil {
		return Template{}, ErrInvalid
	}
	if err := insertAudit(ctx, tx, scope, actor, "metric_template.created", "metric_template", value.ID, map[string]any{"template_id": value.ID, "database_family": value.DatabaseFamily}); err != nil {
		return Template{}, err
	}
	if err := persistMutation(ctx, tx, scope, actor, "create_template", value.ID, "template", value); err != nil {
		return Template{}, err
	}
	if err := repository.commit(tx); err != nil {
		return Template{}, err
	}
	return value, nil
}

func (repository *PostgresRepository) GetTemplate(ctx context.Context, scope platformscope.Scope, templateID string) (Template, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !templateIDPattern.MatchString(templateID) {
		return Template{}, ErrInvalid
	}
	var value Template
	var published sql.NullInt64
	err := repository.database.QueryRowContext(ctx, `SELECT template_id,database_family,name,description,builtin,latest_revision,published_revision,created_at FROM metric_templates WHERE tenant_id=$1 AND project_id=$2 AND template_id=$3`, scope.TenantID, scope.ProjectID, templateID).Scan(&value.ID, &value.DatabaseFamily, &value.Name, &value.Description, &value.Builtin, &value.LatestRevision, &published, &value.CreatedAt)
	if err != nil {
		return Template{}, mapPostgresError(err)
	}
	value.Scope = scope
	value.CreatedAt = value.CreatedAt.UTC()
	if published.Valid {
		x := uint64(published.Int64)
		value.PublishedRevision = &x
	}
	if value.Validate() != nil {
		return Template{}, ErrInvalid
	}
	return value, nil
}

func (repository *PostgresRepository) CreateDraft(ctx context.Context, scope platformscope.Scope, templateID string, draft Draft, actor Actor) (Revision, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !templateIDPattern.MatchString(templateID) || actor.Validate() != nil || draft.CreatedBy != actor.Subject || !validDefinitionShape(draft.TemplateDefinition) {
		return Revision{}, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Revision{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if snapshot, found, err := lookupRevisionMutation(ctx, tx, scope, actor, "create_revision", templateID); err != nil {
		return Revision{}, err
	} else if found {
		return snapshot, nil
	}
	var family string
	var latest uint64
	var builtin bool
	if err := tx.QueryRowContext(ctx, `SELECT database_family,latest_revision,builtin FROM metric_templates WHERE tenant_id=$1 AND project_id=$2 AND template_id=$3 FOR UPDATE`, scope.TenantID, scope.ProjectID, templateID).Scan(&family, &latest, &builtin); err != nil {
		return Revision{}, mapPostgresError(err)
	}
	if builtin || family != draft.DatabaseFamily {
		return Revision{}, ErrConflict
	}
	next := latest + 1
	revisionID := deterministicID("metric-revision-", scope.Key()+"\x00"+templateID+"\x00"+fmt.Sprint(next))
	digest := DefinitionDigest(draft.ReadOnlyStatement)
	valuesJSON, _ := json.Marshal(draft.ValueMappings)
	labelsJSON, _ := json.Marshal(draft.LabelMappings)
	variantsJSON, _ := json.Marshal(draft.Variants)
	var created time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO metric_template_revisions (`+revisionColumns+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,'draft',$22,'',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) RETURNING created_at`, revisionID, scope.TenantID, scope.ProjectID, templateID, next, family, variantsJSON, draft.Name, draft.Description, draft.QueryKind, draft.ReadOnlyStatement, draft.CollectionIntervalSeconds, draft.TimeoutSeconds, draft.MaxRows, draft.MaxColumns, valuesJSON, labelsJSON, draft.DatabaseVersionRange, draft.PluginVersionRange, draft.CardinalityLimit, digest, draft.CreatedBy).Scan(&created)
	if err != nil {
		return Revision{}, mapPostgresError(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE metric_templates SET latest_revision=$1,name=$2,description=$3 WHERE tenant_id=$4 AND project_id=$5 AND template_id=$6`, next, draft.Name, draft.Description, scope.TenantID, scope.ProjectID, templateID); err != nil {
		return Revision{}, mapPostgresError(err)
	}
	value := revisionFromDraft(scope, templateID, revisionID, next, draft, digest, created.UTC())
	if err := insertAudit(ctx, tx, scope, actor, "metric_template.revision_created", "metric_template_revision", revisionID, map[string]any{"template_id": templateID, "revision_id": revisionID, "revision": next, "query_digest": digest}); err != nil {
		return Revision{}, err
	}
	if err := persistMutation(ctx, tx, scope, actor, "create_revision", templateID, "revision", publicRevisionSnapshot(value)); err != nil {
		return Revision{}, err
	}
	if err := repository.commit(tx); err != nil {
		return Revision{}, err
	}
	return value, nil
}

func (repository *PostgresRepository) ListTemplates(ctx context.Context, scope platformscope.Scope, filter Filter) (TemplatePage, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || filter.Validate() != nil {
		return TemplatePage{}, ErrInvalid
	}
	limit := filter.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	after, err := decodeCursor(scope, filter.DatabaseFamily, filter.Cursor)
	if err != nil {
		return TemplatePage{}, err
	}
	rows, err := repository.database.QueryContext(ctx, `SELECT template_id,database_family,name,description,builtin,latest_revision,published_revision,created_at FROM metric_templates WHERE tenant_id=$1 AND project_id=$2 AND ($3='' OR database_family=$3) AND template_id>$4 ORDER BY template_id LIMIT $5`, scope.TenantID, scope.ProjectID, filter.DatabaseFamily, after, limit+1)
	if err != nil {
		return TemplatePage{}, mapPostgresError(err)
	}
	defer rows.Close()
	var values []Template
	for rows.Next() {
		var value Template
		var published sql.NullInt64
		if err := rows.Scan(&value.ID, &value.DatabaseFamily, &value.Name, &value.Description, &value.Builtin, &value.LatestRevision, &published, &value.CreatedAt); err != nil {
			return TemplatePage{}, err
		}
		value.Scope = scope
		value.CreatedAt = value.CreatedAt.UTC()
		if published.Valid {
			x := uint64(published.Int64)
			value.PublishedRevision = &x
		}
		if value.Validate() != nil {
			return TemplatePage{}, ErrInvalid
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return TemplatePage{}, err
	}
	page := TemplatePage{Items: values}
	if len(values) > limit {
		page.Items = values[:limit]
		page.NextCursor, err = encodeCursor(scope, filter.DatabaseFamily, page.Items[limit-1].ID)
	}
	return page, err
}

func (repository *PostgresRepository) ListRevisions(ctx context.Context, scope platformscope.Scope, templateID string, filter RevisionFilter) (RevisionPage, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !templateIDPattern.MatchString(templateID) || filter.Validate() != nil {
		return RevisionPage{}, ErrInvalid
	}
	limit := filter.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	afterRevision, afterID := uint64(1<<63-1), "~"
	if filter.Cursor != "" {
		var err error
		afterRevision, afterID, err = decodeRevisionCursor(scope, templateID, filter.Cursor)
		if err != nil {
			return RevisionPage{}, err
		}
	}
	rows, err := repository.database.QueryContext(ctx, `SELECT `+revisionColumns+` FROM metric_template_revisions WHERE tenant_id=$1 AND project_id=$2 AND template_id=$3 AND (revision<$4 OR (revision=$4 AND revision_id<$5)) ORDER BY revision DESC,revision_id DESC LIMIT $6`, scope.TenantID, scope.ProjectID, templateID, int64(afterRevision), afterID, limit+1)
	if err != nil {
		return RevisionPage{}, mapPostgresError(err)
	}
	defer rows.Close()
	values := []Revision{}
	for rows.Next() {
		value, err := scanRevision(rows)
		if err != nil {
			return RevisionPage{}, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return RevisionPage{}, err
	}
	page := RevisionPage{Items: values}
	if len(values) > limit {
		page.Items = values[:limit]
		last := page.Items[limit-1]
		page.NextCursor, err = encodeRevisionCursor(scope, templateID, last.Revision, last.ID)
	}
	return page, err
}

func (repository *PostgresRepository) GetRevision(ctx context.Context, scope platformscope.Scope, revisionID string) (Revision, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !idPattern.MatchString(revisionID) {
		return Revision{}, ErrInvalid
	}
	value, err := scanRevision(repository.database.QueryRowContext(ctx, `SELECT `+revisionColumns+` FROM metric_template_revisions WHERE tenant_id=$1 AND project_id=$2 AND revision_id=$3`, scope.TenantID, scope.ProjectID, revisionID))
	if err != nil {
		return Revision{}, mapPostgresError(err)
	}
	return value, nil
}

func (repository *PostgresRepository) ReplayRevisionMutation(ctx context.Context, scope platformscope.Scope, actor Actor, action, resourceID string) (Revision, bool, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || actor.Validate() != nil || !idPattern.MatchString(resourceID) {
		return Revision{}, false, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Revision{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	return lookupRevisionMutation(ctx, tx, scope, actor, action, resourceID)
}

func (repository *PostgresRepository) ReplayTrialMutation(ctx context.Context, scope platformscope.Scope, actor Actor, revisionID string) (job.Job, bool, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || actor.Validate() != nil || !idPattern.MatchString(revisionID) {
		return job.Job{}, false, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return job.Job{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	return lookupJobMutation(ctx, tx, scope, actor, "trial_revision", revisionID)
}

func (repository *PostgresRepository) FinishValidation(ctx context.Context, scope platformscope.Scope, revisionID string, expected uint64, validated ValidatedDefinition, succeeded bool, actor Actor) (Revision, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !idPattern.MatchString(revisionID) || expected == 0 || actor.Validate() != nil || !digestPattern.MatchString(validated.QueryDigest) || validated.ReadOnlyStatement != "" {
		return Revision{}, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Revision{}, err
	}
	defer func() { _ = tx.Rollback() }()
	action := "validate_revision"
	if snapshot, found, err := lookupRevisionMutation(ctx, tx, scope, actor, action, revisionID); err != nil {
		return Revision{}, err
	} else if found {
		return snapshot, nil
	}
	current, err := scanRevision(tx.QueryRowContext(ctx, `SELECT `+revisionColumns+` FROM metric_template_revisions WHERE tenant_id=$1 AND project_id=$2 AND revision_id=$3 FOR UPDATE`, scope.TenantID, scope.ProjectID, revisionID))
	if err != nil {
		return Revision{}, mapPostgresError(err)
	}
	if current.ResourceRevision != expected {
		return Revision{}, ErrPrecondition
	}
	if current.Status != StatusDraft && current.Status != StatusValidating {
		return Revision{}, ErrInvalidTransition
	}
	if current.QueryDigest != validated.QueryDigest {
		return Revision{}, ErrConflict
	}
	status := StatusValidationFailed
	if succeeded {
		status = StatusValidated
	}
	now := time.Now().UTC()
	next, err := current.Transition(status, actor.Subject, now)
	if err != nil {
		return Revision{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE metric_template_revisions SET status=$1,resource_revision=$2,updated_at=$3 WHERE tenant_id=$4 AND project_id=$5 AND revision_id=$6 AND resource_revision=$7`, status, next.ResourceRevision, now, scope.TenantID, scope.ProjectID, revisionID, expected); err != nil {
		return Revision{}, mapPostgresError(err)
	}
	result := "failure"
	if succeeded {
		result = "success"
	}
	if err := insertAuditResult(ctx, tx, scope, actor, "metric_template.validated", "metric_template_revision", revisionID, result, map[string]any{"revision_id": revisionID, "query_digest": current.QueryDigest, "status": status}); err != nil {
		return Revision{}, err
	}
	if err := persistMutation(ctx, tx, scope, actor, action, revisionID, "revision", publicRevisionSnapshot(next)); err != nil {
		return Revision{}, err
	}
	if err := repository.commit(tx); err != nil {
		return Revision{}, err
	}
	return next, nil
}

func (repository *PostgresRepository) ResolveTrialTarget(ctx context.Context, scope platformscope.Scope, instanceID string) (TrialTarget, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !idPattern.MatchString(instanceID) {
		return TrialTarget{}, ErrInvalid
	}
	var value TrialTarget
	value.Scope = scope
	err := repository.database.QueryRowContext(ctx, `SELECT instance.instance_id,instance.agent_id,binding.assignment_id,assignment.configuration_revision,assignment.operation_revision,assignment.desired_version_id,instance.database_family,instance.database_variant,(version.status='available'),version.metric_template_schema_version FROM managed_database_instances instance JOIN plugin_assignment_instances binding ON binding.tenant_id=instance.tenant_id AND binding.project_id=instance.project_id AND binding.instance_id=instance.instance_id JOIN plugin_assignments assignment ON assignment.tenant_id=binding.tenant_id AND assignment.project_id=binding.project_id AND assignment.assignment_id=binding.assignment_id JOIN plugin_versions version ON version.tenant_id=assignment.tenant_id AND version.project_id=assignment.project_id AND version.version_id=assignment.desired_version_id JOIN plugin_observations observation ON observation.tenant_id=assignment.tenant_id AND observation.project_id=assignment.project_id AND observation.assignment_id=assignment.assignment_id WHERE instance.tenant_id=$1 AND instance.project_id=$2 AND instance.instance_id=$3 AND instance.management_status IN ('managed','monitoring') AND assignment.desired_state='running' AND instance.plugin_assignment_revision=assignment.configuration_revision AND observation.active_configuration_revision=assignment.configuration_revision AND observation.observed_operation_revision=assignment.operation_revision AND observation.installed_version=assignment.desired_version AND observation.process_state IN ('running','degraded')`, scope.TenantID, scope.ProjectID, instanceID).Scan(&value.InstanceID, &value.AgentID, &value.AssignmentID, &value.ConfigurationRevision, &value.OperationRevision, &value.PluginVersionID, &value.DatabaseFamily, &value.DatabaseVariant, &value.PluginAvailable, &value.PluginSchemaVersion)
	if err != nil {
		return TrialTarget{}, mapPostgresError(err)
	}
	if value.Validate() != nil {
		return TrialTarget{}, ErrInvalid
	}
	return value, nil
}

func (repository *PostgresRepository) CreateTrial(ctx context.Context, revision Revision, request TrialRequest, value job.Job, messages []job.OutboxMessage) (job.Job, error) {
	if repository == nil || repository.database == nil || repository.jobs == nil || ctx == nil || revision.Validate() != nil || request.Validate() != nil || len(messages) != 1 || value.SourceResource.ResourceID != revision.ID || value.ID != messages[0].JobID {
		return job.Job{}, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return job.Job{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if stored, found, err := lookupJobMutation(ctx, tx, revision.Scope, request.Actor, "trial_revision", revision.ID); err != nil {
		return job.Job{}, err
	} else if found {
		return stored, nil
	}
	current, err := scanRevision(tx.QueryRowContext(ctx, `SELECT `+revisionColumns+` FROM metric_template_revisions WHERE tenant_id=$1 AND project_id=$2 AND revision_id=$3 FOR UPDATE`, revision.Scope.TenantID, revision.Scope.ProjectID, revision.ID))
	if err != nil {
		return job.Job{}, mapPostgresError(err)
	}
	if current.QueryDigest != revision.QueryDigest || current.Status != StatusValidated {
		return job.Job{}, ErrInvalidTransition
	}
	envelope := new(agentv1.CommandEnvelope)
	if proto.Unmarshal(messages[0].Payload, envelope) != nil {
		return job.Job{}, ErrInvalid
	}
	command := envelope.GetCollectDatabaseMetrics()
	digestBytes, _ := hex.DecodeString(revision.QueryDigest)
	if command == nil || !command.GetTrial() || len(command.GetInstanceIds()) != 1 || command.GetInstanceIds()[0] != request.InstanceID || len(command.GetTemplateIds()) != 1 || command.GetTemplateIds()[0] != revision.TemplateID || len(command.GetTemplateRevisions()) != 1 {
		return job.Job{}, ErrInvalid
	}
	reference := command.GetTemplateRevisions()[0]
	if reference == nil || reference.GetTemplateId() != revision.TemplateID || reference.GetRevisionId() != revision.ID || !bytes.Equal(reference.GetQueryDigest(), digestBytes) || reference.GetTimeoutSeconds() != uint32(revision.TimeoutSeconds) || reference.GetMaxRows() != uint32(revision.MaxRows) || reference.GetMaxColumns() != uint32(revision.MaxColumns) || reference.GetCardinalityLimit() != uint32(revision.CardinalityLimit) {
		return job.Job{}, ErrInvalid
	}
	target, err := resolveTrialTargetTx(ctx, tx, revision.Scope, request.InstanceID)
	if err != nil {
		return job.Job{}, err
	}
	if target.AssignmentID != command.GetAssignmentId() || target.ConfigurationRevision != command.GetConfigurationRevision() || target.OperationRevision != command.GetOperationRevision() || target.PluginVersionID != request.PluginVersionID || target.DatabaseFamily != revision.DatabaseFamily || !contains(revision.Variants, target.DatabaseVariant) || !target.PluginAvailable || target.PluginSchemaVersion != MetricTemplateSchemaVersion {
		return job.Job{}, ErrIncompatible
	}
	if err := repository.jobs.CreateInTx(ctx, tx, value, messages); err != nil {
		return job.Job{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO metric_template_trials (tenant_id,project_id,job_id,command_id,revision_id,query_digest,instance_id,assignment_id,plugin_version_id,configuration_revision,operation_revision,timeout_seconds,max_rows,max_columns,cardinality_limit,status,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'running',$16)`, revision.Scope.TenantID, revision.Scope.ProjectID, value.ID, messages[0].ID, revision.ID, revision.QueryDigest, request.InstanceID, target.AssignmentID, target.PluginVersionID, target.ConfigurationRevision, target.OperationRevision, revision.TimeoutSeconds, revision.MaxRows, revision.MaxColumns, revision.CardinalityLimit, value.CreatedAt); err != nil {
		return job.Job{}, mapPostgresError(err)
	}
	if current.Status == StatusValidated {
		if _, err := tx.ExecContext(ctx, `UPDATE metric_template_revisions SET status='trial_running',resource_revision=resource_revision+1,updated_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND revision_id=$4 AND status='validated'`, value.CreatedAt, revision.Scope.TenantID, revision.Scope.ProjectID, revision.ID); err != nil {
			return job.Job{}, mapPostgresError(err)
		}
	}
	if err := insertAudit(ctx, tx, revision.Scope, request.Actor, "metric_template.trial_started", "metric_template_revision", revision.ID, map[string]any{"revision_id": revision.ID, "query_digest": revision.QueryDigest, "instance_id": request.InstanceID, "job_id": value.ID, "timeout_seconds": revision.TimeoutSeconds, "max_rows": revision.MaxRows, "max_columns": revision.MaxColumns}); err != nil {
		return job.Job{}, err
	}
	snapshot := map[string]any{"job_id": value.ID, "revision_id": revision.ID, "query_digest": revision.QueryDigest, "timeout_seconds": revision.TimeoutSeconds, "max_rows": revision.MaxRows, "max_columns": revision.MaxColumns, "cardinality_limit": revision.CardinalityLimit}
	snapshot["job"] = value
	if err := persistMutation(ctx, tx, revision.Scope, request.Actor, "trial_revision", revision.ID, "job", snapshot); err != nil {
		return job.Job{}, err
	}
	if err := repository.commit(tx); err != nil {
		if stored, getErr := repository.jobs.Get(ctx, revision.Scope, value.ID); getErr == nil {
			return stored, nil
		}
		return job.Job{}, err
	}
	return repository.jobs.Get(ctx, revision.Scope, value.ID)
}

func (repository *PostgresRepository) RecordTrialResult(ctx context.Context, scope platformscope.Scope, jobID string, result TrialResult, at time.Time) (Revision, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !idPattern.MatchString(jobID) || result.Validate() != nil || !validUTC(at) {
		return Revision{}, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Revision{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var revisionID, digest, status string
	var cardinalityLimit, maxRows, maxColumns int
	var valueMappingsJSON, labelMappingsJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT trial.revision_id,trial.query_digest,trial.status,trial.cardinality_limit,trial.max_rows,trial.max_columns,revision.value_mappings,revision.label_mappings FROM metric_template_trials trial JOIN metric_template_revisions revision ON revision.tenant_id=trial.tenant_id AND revision.project_id=trial.project_id AND revision.revision_id=trial.revision_id WHERE trial.tenant_id=$1 AND trial.project_id=$2 AND trial.job_id=$3 FOR UPDATE OF trial`, scope.TenantID, scope.ProjectID, jobID).Scan(&revisionID, &digest, &status, &cardinalityLimit, &maxRows, &maxColumns, &valueMappingsJSON, &labelMappingsJSON)
	if err != nil {
		return Revision{}, mapPostgresError(err)
	}
	if revisionID != result.RevisionID || digest != result.QueryDigest {
		return Revision{}, ErrConflict
	}
	if status != "running" {
		value, err := scanRevision(tx.QueryRowContext(ctx, `SELECT `+revisionColumns+` FROM metric_template_revisions WHERE tenant_id=$1 AND project_id=$2 AND revision_id=$3`, scope.TenantID, scope.ProjectID, revisionID))
		return value, mapPostgresError(err)
	}
	metrics, _ := json.Marshal(result.Metrics)
	var valueMappings []ValueMapping
	var labelMappings []LabelMapping
	if json.Unmarshal(valueMappingsJSON, &valueMappings) != nil || json.Unmarshal(labelMappingsJSON, &labelMappings) != nil {
		return Revision{}, ErrInvalid
	}
	trialStatus := "failed"
	revisionStatus := StatusTrialFailed
	if failure := trialLimitFailure(result, cardinalityLimit, maxRows, maxColumns, valueMappings, labelMappings); failure != "" {
		result.StatusCode = failure
	} else if result.StatusCode == "succeeded" {
		trialStatus = "succeeded"
		revisionStatus = StatusTrialPassed
	}
	if _, err := tx.ExecContext(ctx, `UPDATE metric_template_trials SET status=$1,status_code=$2,candidate_metrics=$3,row_count=$4,column_count=$5,metric_count=$6,duration_millis=$7,completed_at=$8 WHERE tenant_id=$9 AND project_id=$10 AND job_id=$11 AND status='running'`, trialStatus, result.StatusCode, metrics, result.RowCount, result.ColumnCount, result.MetricCount, result.DurationMillis, at, scope.TenantID, scope.ProjectID, jobID); err != nil {
		return Revision{}, mapPostgresError(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE metric_template_revisions SET status=$1,resource_revision=resource_revision+1,updated_at=$2 WHERE tenant_id=$3 AND project_id=$4 AND revision_id=$5 AND status='trial_running'`, revisionStatus, at, scope.TenantID, scope.ProjectID, revisionID); err != nil {
		return Revision{}, mapPostgresError(err)
	}
	value, err := scanRevision(tx.QueryRowContext(ctx, `SELECT `+revisionColumns+` FROM metric_template_revisions WHERE tenant_id=$1 AND project_id=$2 AND revision_id=$3`, scope.TenantID, scope.ProjectID, revisionID))
	if err != nil {
		return Revision{}, mapPostgresError(err)
	}
	if err := repository.commit(tx); err != nil {
		return Revision{}, err
	}
	return value, nil
}

func (repository *PostgresRepository) ClassifyTrialResult(ctx context.Context, scope platformscope.Scope, jobID string, result TrialResult) (TrialResult, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !idPattern.MatchString(jobID) || result.Validate() != nil {
		return TrialResult{}, ErrInvalid
	}
	var revisionID, digest string
	var cardinalityLimit, maxRows, maxColumns int
	var valueMappingsJSON, labelMappingsJSON []byte
	err := repository.database.QueryRowContext(ctx, `SELECT trial.revision_id,trial.query_digest,trial.cardinality_limit,trial.max_rows,trial.max_columns,revision.value_mappings,revision.label_mappings FROM metric_template_trials trial JOIN metric_template_revisions revision ON revision.tenant_id=trial.tenant_id AND revision.project_id=trial.project_id AND revision.revision_id=trial.revision_id WHERE trial.tenant_id=$1 AND trial.project_id=$2 AND trial.job_id=$3`, scope.TenantID, scope.ProjectID, jobID).Scan(&revisionID, &digest, &cardinalityLimit, &maxRows, &maxColumns, &valueMappingsJSON, &labelMappingsJSON)
	if err != nil {
		return TrialResult{}, mapPostgresError(err)
	}
	if revisionID != result.RevisionID || digest != result.QueryDigest {
		return TrialResult{}, ErrConflict
	}
	var valueMappings []ValueMapping
	var labelMappings []LabelMapping
	if json.Unmarshal(valueMappingsJSON, &valueMappings) != nil || json.Unmarshal(labelMappingsJSON, &labelMappings) != nil {
		return TrialResult{}, ErrInvalid
	}
	if failure := trialLimitFailure(result, cardinalityLimit, maxRows, maxColumns, valueMappings, labelMappings); failure != "" {
		result = TrialResult{RevisionID: result.RevisionID, QueryDigest: result.QueryDigest, StatusCode: failure}
	}
	return result, nil
}

func (repository *PostgresRepository) FailTerminalTrials(ctx context.Context, limit int, at time.Time) (int, error) {
	if repository == nil || repository.database == nil || ctx == nil || limit < 1 || limit > 128 || !validUTC(at) {
		return 0, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT trial.tenant_id,trial.project_id,trial.job_id,trial.revision_id,job.status FROM metric_template_trials trial JOIN jobs job ON job.tenant_id=trial.tenant_id AND job.project_id=trial.project_id AND job.id=trial.job_id WHERE trial.status='running' AND job.status IN ('failed','cancelled','timed_out') ORDER BY trial.created_at,trial.job_id FOR UPDATE OF trial SKIP LOCKED LIMIT $1`, limit)
	if err != nil {
		return 0, mapPostgresError(err)
	}
	type terminal struct{ tenant, project, job, revision, status string }
	var values []terminal
	for rows.Next() {
		var value terminal
		if err := rows.Scan(&value.tenant, &value.project, &value.job, &value.revision, &value.status); err != nil {
			_ = rows.Close()
			return 0, err
		}
		values = append(values, value)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for _, value := range values {
		code := "command_failed"
		if value.status == "cancelled" {
			code = "job_cancelled"
		} else if value.status == "timed_out" {
			code = "job_timed_out"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE metric_template_trials SET status='failed',status_code=$1,candidate_metrics='[]'::jsonb,row_count=0,column_count=0,metric_count=0,duration_millis=0,completed_at=$2 WHERE tenant_id=$3 AND project_id=$4 AND job_id=$5 AND status='running'`, code, at, value.tenant, value.project, value.job); err != nil {
			return 0, mapPostgresError(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE metric_template_revisions SET status='trial_failed',resource_revision=resource_revision+1,updated_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND revision_id=$4 AND status='trial_running'`, at, value.tenant, value.project, value.revision); err != nil {
			return 0, mapPostgresError(err)
		}
	}
	if err := repository.commit(tx); err != nil {
		return 0, err
	}
	return len(values), nil
}

func (repository *PostgresRepository) Approve(ctx context.Context, scope platformscope.Scope, revisionID string, expected uint64, actor Actor) (Revision, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !idPattern.MatchString(revisionID) || expected == 0 || actor.Validate() != nil {
		return Revision{}, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Revision{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if snapshot, found, err := lookupRevisionMutation(ctx, tx, scope, actor, "approve_revision", revisionID); err != nil {
		return Revision{}, err
	} else if found {
		return snapshot, nil
	}
	current, err := scanRevision(tx.QueryRowContext(ctx, `SELECT `+revisionColumns+` FROM metric_template_revisions WHERE tenant_id=$1 AND project_id=$2 AND revision_id=$3 FOR UPDATE`, scope.TenantID, scope.ProjectID, revisionID))
	if err != nil {
		return Revision{}, mapPostgresError(err)
	}
	if current.ResourceRevision != expected {
		return Revision{}, ErrPrecondition
	}
	if current.CreatedBy == actor.Subject {
		return Revision{}, ErrSelfApproval
	}
	if current.Status != StatusTrialPassed && current.Status != StatusApprovalPending {
		return Revision{}, ErrInvalidTransition
	}
	now := time.Now().UTC()
	next, err := current.Transition(StatusApproved, actor.Subject, now)
	if err != nil {
		return Revision{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE metric_template_revisions SET status='approved',approved_by=$1,resource_revision=$2,updated_at=$3 WHERE tenant_id=$4 AND project_id=$5 AND revision_id=$6 AND resource_revision=$7`, actor.Subject, next.ResourceRevision, now, scope.TenantID, scope.ProjectID, revisionID, expected); err != nil {
		return Revision{}, mapPostgresError(err)
	}
	if err := insertAudit(ctx, tx, scope, actor, "metric_template.approved", "metric_template_revision", revisionID, map[string]any{"revision_id": revisionID, "query_digest": current.QueryDigest, "revision": current.Revision}); err != nil {
		return Revision{}, err
	}
	if err := persistMutation(ctx, tx, scope, actor, "approve_revision", revisionID, "revision", publicRevisionSnapshot(next)); err != nil {
		return Revision{}, err
	}
	if err := repository.commit(tx); err != nil {
		return Revision{}, err
	}
	return next, nil
}

func (repository *PostgresRepository) Publish(ctx context.Context, scope platformscope.Scope, revisionID string, expected uint64, publish PublishScope, validated ValidatedDefinition) (Revision, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || !idPattern.MatchString(revisionID) || expected == 0 || publish.Validate() != nil || validated.ReadOnlyStatement != "" || !digestPattern.MatchString(validated.QueryDigest) {
		return Revision{}, ErrInvalid
	}
	tx, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Revision{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if snapshot, found, err := lookupRevisionMutation(ctx, tx, scope, publish.Actor, "publish_revision", revisionID); err != nil {
		return Revision{}, err
	} else if found {
		return snapshot, nil
	}
	current, err := scanRevision(tx.QueryRowContext(ctx, `SELECT `+revisionColumns+` FROM metric_template_revisions WHERE tenant_id=$1 AND project_id=$2 AND revision_id=$3 FOR UPDATE`, scope.TenantID, scope.ProjectID, revisionID))
	if err != nil {
		return Revision{}, mapPostgresError(err)
	}
	if current.ResourceRevision != expected {
		return Revision{}, ErrPrecondition
	}
	if current.QueryDigest != validated.QueryDigest || current.Status != StatusApproved && !(publish.Rollback && current.Status == StatusSuperseded) {
		return Revision{}, ErrNotApproved
	}
	targets, err := loadPublicationTargets(ctx, tx, current, publish.InstanceIDs)
	if err != nil {
		return Revision{}, err
	}
	if len(targets) > MaximumAssignments {
		return Revision{}, ErrCapacity
	}
	if len(targets) == 0 {
		return Revision{}, ErrNotFound
	}
	assignmentInstances := map[string][]string{}
	for _, target := range targets {
		if !compatiblePublicationTarget(current, target) {
			return Revision{}, ErrIncompatible
		}
		assignmentInstances[target.AssignmentID] = append(assignmentInstances[target.AssignmentID], target.InstanceID)
	}
	if len(assignmentInstances) > MaximumAssignments {
		return Revision{}, ErrCapacity
	}
	var publicationRevision uint64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(publication_revision),0)+1 FROM metric_template_publications WHERE tenant_id=$1 AND project_id=$2 AND template_id=$3`, scope.TenantID, scope.ProjectID, current.TemplateID).Scan(&publicationRevision); err != nil {
		return Revision{}, err
	}
	now := time.Now().UTC()
	var next Revision
	if publish.Rollback && current.Status == StatusSuperseded {
		next = current
		next.Status = StatusPublished
		next.ResourceRevision++
		next.UpdatedAt = now
	} else {
		next, err = current.Transition(StatusPublished, publish.Actor.Subject, now)
		if err != nil {
			return Revision{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE metric_template_revisions SET status='published',resource_revision=$1,updated_at=$2 WHERE tenant_id=$3 AND project_id=$4 AND revision_id=$5 AND resource_revision=$6`, next.ResourceRevision, now, scope.TenantID, scope.ProjectID, revisionID, expected); err != nil {
		return Revision{}, mapPostgresError(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE metric_template_revisions SET status='superseded',resource_revision=resource_revision+1,updated_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND template_id=$4 AND revision_id<>$5 AND status='published'`, now, scope.TenantID, scope.ProjectID, current.TemplateID, revisionID); err != nil {
		return Revision{}, mapPostgresError(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE metric_templates SET published_revision=$1 WHERE tenant_id=$2 AND project_id=$3 AND template_id=$4`, current.Revision, scope.TenantID, scope.ProjectID, current.TemplateID); err != nil {
		return Revision{}, mapPostgresError(err)
	}
	for assignmentID, instances := range assignmentInstances {
		var configuration, operation, resource uint64
		if err := tx.QueryRowContext(ctx, `SELECT configuration_revision,operation_revision,revision FROM plugin_assignments WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 FOR UPDATE`, scope.TenantID, scope.ProjectID, assignmentID).Scan(&configuration, &operation, &resource); err != nil {
			return Revision{}, mapPostgresError(err)
		}
		for _, instanceID := range instances {
			var encoded []byte
			if err := tx.QueryRowContext(ctx, `SELECT template_revision_ids FROM plugin_assignment_instances WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3 AND instance_id=$4 FOR UPDATE`, scope.TenantID, scope.ProjectID, assignmentID, instanceID).Scan(&encoded); err != nil {
				return Revision{}, mapPostgresError(err)
			}
			var values []string
			if json.Unmarshal(encoded, &values) != nil {
				return Revision{}, ErrInvalid
			}
			values, err = replaceTemplateRevisionTx(ctx, tx, scope, current.TemplateID, values, revisionID)
			if err != nil {
				return Revision{}, err
			}
			if len(values) > MaximumAssignments {
				return Revision{}, ErrCapacity
			}
			if _, err := tx.ExecContext(ctx, `UPDATE plugin_assignment_instances SET template_revision_ids=$1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$2 AND project_id=$3 AND assignment_id=$4 AND instance_id=$5`, jsonValue(values), scope.TenantID, scope.ProjectID, assignmentID, instanceID); err != nil {
				return Revision{}, mapPostgresError(err)
			}
		}
		aggregate, aggregateErr := assignmentTemplateRevisionUnionTx(ctx, tx, scope, assignmentID)
		if aggregateErr != nil {
			return Revision{}, aggregateErr
		}
		if len(aggregate) > MaximumAssignments {
			return Revision{}, ErrCapacity
		}
		configuration++
		operation++
		resource++
		if _, err := tx.ExecContext(ctx, `UPDATE plugin_assignments SET template_revision_ids=$1,configuration_revision=$2,operation_revision=$3,reconcile_state='pending',blocked_reason='',revision=$4,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$5 AND project_id=$6 AND assignment_id=$7`, jsonValue(aggregate), configuration, operation, resource, scope.TenantID, scope.ProjectID, assignmentID); err != nil {
			return Revision{}, mapPostgresError(err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE managed_database_instances instance SET plugin_assignment_revision=$1,revision=revision+1,updated_at=CURRENT_TIMESTAMP FROM plugin_assignment_instances binding WHERE binding.tenant_id=$2 AND binding.project_id=$3 AND binding.assignment_id=$4 AND instance.tenant_id=binding.tenant_id AND instance.project_id=binding.project_id AND instance.instance_id=binding.instance_id`, configuration, scope.TenantID, scope.ProjectID, assignmentID); err != nil {
			return Revision{}, mapPostgresError(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO metric_template_publications (tenant_id,project_id,template_id,publication_revision,selected_revision_id,query_digest,rollback,instance_count,assignment_count,published_by,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, scope.TenantID, scope.ProjectID, current.TemplateID, publicationRevision, revisionID, current.QueryDigest, publish.Rollback, len(targets), len(assignmentInstances), publish.Actor.Subject, now); err != nil {
		return Revision{}, mapPostgresError(err)
	}
	if err := insertAudit(ctx, tx, scope, publish.Actor, "metric_template.published", "metric_template_revision", revisionID, map[string]any{"revision_id": revisionID, "query_digest": current.QueryDigest, "publication_revision": publicationRevision, "instance_count": len(targets), "assignment_count": len(assignmentInstances), "rollback": publish.Rollback}); err != nil {
		return Revision{}, err
	}
	if err := persistMutation(ctx, tx, scope, publish.Actor, "publish_revision", revisionID, "revision", publicRevisionSnapshot(next)); err != nil {
		return Revision{}, err
	}
	if err := repository.commit(tx); err != nil {
		return Revision{}, err
	}
	return next, nil
}

func assignmentTemplateRevisionUnionTx(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, assignmentID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT item.revision_id FROM plugin_assignment_instances binding CROSS JOIN LATERAL jsonb_array_elements_text(binding.template_revision_ids) item(revision_id) WHERE binding.tenant_id=$1 AND binding.project_id=$2 AND binding.assignment_id=$3 ORDER BY item.revision_id`, scope.TenantID, scope.ProjectID, assignmentID)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

type publicationTarget struct {
	InstanceID, AssignmentID, SemanticVersion, DatabaseVariant, DatabaseVersion, Status string
	SchemaVersion                                                                       uint32
}

func loadPublicationTargets(ctx context.Context, tx *sql.Tx, revision Revision, ids []string) ([]publicationTarget, error) {
	selectedIDs := ids
	if selectedIDs == nil {
		selectedIDs = []string{}
	}
	rows, err := tx.QueryContext(ctx, `SELECT instance.instance_id,binding.assignment_id,version.semantic_version,instance.database_variant,instance.version_hint,version.status,version.metric_template_schema_version FROM managed_database_instances instance JOIN plugin_assignment_instances binding ON binding.tenant_id=instance.tenant_id AND binding.project_id=instance.project_id AND binding.instance_id=instance.instance_id JOIN plugin_assignments assignment ON assignment.tenant_id=binding.tenant_id AND assignment.project_id=binding.project_id AND assignment.assignment_id=binding.assignment_id JOIN plugin_versions version ON version.tenant_id=assignment.tenant_id AND version.project_id=assignment.project_id AND version.version_id=assignment.desired_version_id WHERE instance.tenant_id=$1 AND instance.project_id=$2 AND instance.database_family=$3 AND instance.management_status<>'retired' AND (cardinality($4::text[])=0 OR instance.instance_id=ANY($4)) ORDER BY instance.instance_id FOR UPDATE OF instance,binding,assignment`, revision.Scope.TenantID, revision.Scope.ProjectID, revision.DatabaseFamily, pq.Array(selectedIDs))
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()
	var values []publicationTarget
	for rows.Next() {
		var value publicationTarget
		if err := rows.Scan(&value.InstanceID, &value.AssignmentID, &value.SemanticVersion, &value.DatabaseVariant, &value.DatabaseVersion, &value.Status, &value.SchemaVersion); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) > 0 && len(values) != len(ids) {
		return nil, ErrNotFound
	}
	return values, nil
}
func compatiblePublicationTarget(revision Revision, target publicationTarget) bool {
	return target.Status == "available" && target.SchemaVersion == MetricTemplateSchemaVersion && contains(revision.Variants, target.DatabaseVariant) && versionMatches(revision.PluginVersionRange, target.SemanticVersion) && versionMatches(revision.DatabaseVersionRange, target.DatabaseVersion)
}
func versionMatches(constraint, value string) bool {
	if strings.TrimSpace(constraint) == "" {
		return true
	}
	parsed, err := semver.NewConstraint(constraint)
	if err != nil {
		return false
	}
	version, err := semver.NewVersion(value)
	return err == nil && parsed.Check(version)
}

func resolveTrialTargetTx(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, instanceID string) (TrialTarget, error) {
	var value TrialTarget
	value.Scope = scope
	err := tx.QueryRowContext(ctx, `SELECT instance.instance_id,instance.agent_id,binding.assignment_id,assignment.configuration_revision,assignment.operation_revision,assignment.desired_version_id,instance.database_family,instance.database_variant,(version.status='available'),version.metric_template_schema_version FROM managed_database_instances instance JOIN plugin_assignment_instances binding ON binding.tenant_id=instance.tenant_id AND binding.project_id=instance.project_id AND binding.instance_id=instance.instance_id JOIN plugin_assignments assignment ON assignment.tenant_id=binding.tenant_id AND assignment.project_id=binding.project_id AND assignment.assignment_id=binding.assignment_id JOIN plugin_versions version ON version.tenant_id=assignment.tenant_id AND version.project_id=assignment.project_id AND version.version_id=assignment.desired_version_id JOIN plugin_observations observation ON observation.tenant_id=assignment.tenant_id AND observation.project_id=assignment.project_id AND observation.assignment_id=assignment.assignment_id WHERE instance.tenant_id=$1 AND instance.project_id=$2 AND instance.instance_id=$3 AND instance.management_status IN ('managed','monitoring') AND assignment.desired_state='running' AND instance.plugin_assignment_revision=assignment.configuration_revision AND observation.active_configuration_revision=assignment.configuration_revision AND observation.observed_operation_revision=assignment.operation_revision AND observation.installed_version=assignment.desired_version AND observation.process_state IN ('running','degraded') FOR UPDATE OF instance,binding,assignment`, scope.TenantID, scope.ProjectID, instanceID).Scan(&value.InstanceID, &value.AgentID, &value.AssignmentID, &value.ConfigurationRevision, &value.OperationRevision, &value.PluginVersionID, &value.DatabaseFamily, &value.DatabaseVariant, &value.PluginAvailable, &value.PluginSchemaVersion)
	if err != nil {
		return TrialTarget{}, mapPostgresError(err)
	}
	return value, nil
}

func revisionFromDraft(scope platformscope.Scope, templateID, revisionID string, revision uint64, draft Draft, digest string, at time.Time) Revision {
	return Revision{ID: revisionID, Scope: scope, TemplateID: templateID, Revision: revision, DatabaseFamily: draft.DatabaseFamily, Variants: append([]string(nil), draft.Variants...), Name: draft.Name, Description: draft.Description, QueryKind: draft.QueryKind, ReadOnlyStatement: draft.ReadOnlyStatement, CollectionIntervalSeconds: draft.CollectionIntervalSeconds, TimeoutSeconds: draft.TimeoutSeconds, MaxRows: draft.MaxRows, MaxColumns: draft.MaxColumns, ValueMappings: append([]ValueMapping(nil), draft.ValueMappings...), LabelMappings: append([]LabelMapping(nil), draft.LabelMappings...), DatabaseVersionRange: draft.DatabaseVersionRange, PluginVersionRange: draft.PluginVersionRange, CardinalityLimit: draft.CardinalityLimit, QueryDigest: digest, Status: StatusDraft, CreatedBy: draft.CreatedBy, ResourceRevision: 1, CreatedAt: at, UpdatedAt: at}
}

type scanner interface{ Scan(...any) error }

func scanRevision(row scanner) (Revision, error) {
	var value Revision
	var variants, values, labels []byte
	err := row.Scan(&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.TemplateID, &value.Revision, &value.DatabaseFamily, &variants, &value.Name, &value.Description, &value.QueryKind, &value.ReadOnlyStatement, &value.CollectionIntervalSeconds, &value.TimeoutSeconds, &value.MaxRows, &value.MaxColumns, &values, &labels, &value.DatabaseVersionRange, &value.PluginVersionRange, &value.CardinalityLimit, &value.QueryDigest, &value.Status, &value.CreatedBy, &value.ApprovedBy, &value.ResourceRevision, &value.CreatedAt, &value.UpdatedAt)
	if err != nil {
		return Revision{}, err
	}
	if json.Unmarshal(variants, &value.Variants) != nil || json.Unmarshal(values, &value.ValueMappings) != nil || json.Unmarshal(labels, &value.LabelMappings) != nil {
		return Revision{}, ErrInvalid
	}
	value.CreatedAt = value.CreatedAt.UTC()
	value.UpdatedAt = value.UpdatedAt.UTC()
	if value.Validate() != nil {
		return Revision{}, ErrInvalid
	}
	return value, nil
}

func publicRevisionSnapshot(value Revision) map[string]any {
	return map[string]any{"revision_id": value.ID, "template_id": value.TemplateID, "revision": value.Revision, "database_family": value.DatabaseFamily, "variants": value.Variants, "name": value.Name, "description": value.Description, "query_kind": value.QueryKind, "collection_interval_seconds": value.CollectionIntervalSeconds, "timeout_seconds": value.TimeoutSeconds, "max_rows": value.MaxRows, "max_columns": value.MaxColumns, "value_mappings": value.ValueMappings, "label_mappings": value.LabelMappings, "database_version_range": value.DatabaseVersionRange, "plugin_version_range": value.PluginVersionRange, "cardinality_limit": value.CardinalityLimit, "query_digest": value.QueryDigest, "status": value.Status, "created_by": value.CreatedBy, "approved_by": value.ApprovedBy, "resource_revision": value.ResourceRevision, "created_at": value.CreatedAt, "updated_at": value.UpdatedAt}
}

func persistMutation(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, actor Actor, action, resourceID, kind string, snapshot any) error {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return ErrInvalid
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO metric_template_mutations (tenant_id,project_id,actor_id,operation_id,idempotency_key,request_fingerprint,action,resource_id,response_kind,response_snapshot,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,CURRENT_TIMESTAMP)`, scope.TenantID, scope.ProjectID, actor.Subject, actor.OperationID, actor.IdempotencyKey, actor.RequestFingerprint, action, resourceID, kind, encoded)
	return mapPostgresError(err)
}
func lookupMutation(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, actor Actor, action, resourceID, kind string) ([]byte, bool, error) {
	var fingerprint, storedAction, storedID, storedKind string
	var snapshot []byte
	err := tx.QueryRowContext(ctx, `SELECT request_fingerprint,action,resource_id,response_kind,response_snapshot FROM metric_template_mutations WHERE tenant_id=$1 AND project_id=$2 AND actor_id=$3 AND operation_id=$4 AND idempotency_key=$5`, scope.TenantID, scope.ProjectID, actor.Subject, actor.OperationID, actor.IdempotencyKey).Scan(&fingerprint, &storedAction, &storedID, &storedKind, &snapshot)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, mapPostgresError(err)
	}
	if fingerprint != actor.RequestFingerprint || storedAction != action || storedID != resourceID || storedKind != kind {
		return nil, false, ErrConflict
	}
	return snapshot, true, nil
}
func lookupTemplateMutation(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, actor Actor, action, id string) (Template, bool, error) {
	snapshot, found, err := lookupMutation(ctx, tx, scope, actor, action, id, "template")
	if err != nil || !found {
		return Template{}, found, err
	}
	var value Template
	if json.Unmarshal(snapshot, &value) != nil || value.Validate() != nil {
		return Template{}, false, ErrInvalid
	}
	return value, true, nil
}
func lookupRevisionMutation(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, actor Actor, action, id string) (Revision, bool, error) {
	snapshot, found, err := lookupMutation(ctx, tx, scope, actor, action, id, "revision")
	if err != nil || !found {
		return Revision{}, found, err
	}
	var stored struct {
		RevisionID       string    `json:"revision_id"`
		Status           Status    `json:"status"`
		ApprovedBy       string    `json:"approved_by"`
		ResourceRevision uint64    `json:"resource_revision"`
		CreatedAt        time.Time `json:"created_at"`
		UpdatedAt        time.Time `json:"updated_at"`
	}
	if json.Unmarshal(snapshot, &stored) != nil || !idPattern.MatchString(stored.RevisionID) || !stored.Status.Valid() || stored.ResourceRevision == 0 {
		return Revision{}, false, ErrInvalid
	}
	value, err := scanRevision(tx.QueryRowContext(ctx, `SELECT `+revisionColumns+` FROM metric_template_revisions WHERE tenant_id=$1 AND project_id=$2 AND revision_id=$3`, scope.TenantID, scope.ProjectID, stored.RevisionID))
	if err != nil {
		return Revision{}, false, mapPostgresError(err)
	}
	value.Status, value.ApprovedBy, value.ResourceRevision = stored.Status, stored.ApprovedBy, stored.ResourceRevision
	value.CreatedAt, value.UpdatedAt = stored.CreatedAt.UTC(), stored.UpdatedAt.UTC()
	if value.Validate() != nil {
		return Revision{}, false, ErrInvalid
	}
	return value, true, nil
}
func lookupJobMutation(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, actor Actor, action, id string) (job.Job, bool, error) {
	snapshot, found, err := lookupMutation(ctx, tx, scope, actor, action, id, "job")
	if err != nil || !found {
		return job.Job{}, found, err
	}
	var value struct {
		Job job.Job `json:"job"`
	}
	if json.Unmarshal(snapshot, &value) != nil || value.Job.Scope != scope || value.Job.SourceResource.ResourceID != id || job.ValidateTargets(value.Job) != nil {
		return job.Job{}, false, ErrInvalid
	}
	return value.Job, true, nil
}

func insertAudit(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, actor Actor, action, resourceType, resourceID string, detail map[string]any) error {
	return insertAuditResult(ctx, tx, scope, actor, action, resourceType, resourceID, "success", detail)
}
func insertAuditResult(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, actor Actor, action, resourceType, resourceID, result string, detail map[string]any) error {
	encoded, _ := json.Marshal(detail)
	dedupe := deterministicID("metric-audit-", scope.Key()+"\x00"+action+"\x00"+actor.Subject+"\x00"+actor.OperationID+"\x00"+actor.IdempotencyKey+"\x00"+resourceID)
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events (id,tenant_id,project_id,occurred_at,action,actor_type,actor_id,resource_type,resource_id,result,request_id,trace_id,job_id,command_id,dedupe_key,detail,created_at) VALUES ($1,$2,$3,CURRENT_TIMESTAMP,$4,'user',$5,$6,$7,$8,$9,$10,'','',$11,$12,CURRENT_TIMESTAMP) ON CONFLICT (tenant_id,project_id,dedupe_key) WHERE dedupe_key<>'' DO NOTHING`, "audit-"+dedupe, scope.TenantID, scope.ProjectID, action, actor.Subject, resourceType, resourceID, result, actor.RequestID, actor.TraceID, dedupe, encoded)
	return mapPostgresError(err)
}

func replaceTemplateRevisionTx(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, templateID string, values []string, replacement string) ([]string, error) {
	result := make([]string, 0, len(values)+1)
	for _, id := range values {
		var existingTemplate string
		err := tx.QueryRowContext(ctx, `SELECT template_id FROM metric_template_revisions WHERE tenant_id=$1 AND project_id=$2 AND revision_id=$3`, scope.TenantID, scope.ProjectID, id).Scan(&existingTemplate)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotApproved
		}
		if err != nil {
			return nil, mapPostgresError(err)
		}
		if existingTemplate != templateID {
			result = append(result, id)
		}
	}
	result = append(result, replacement)
	sort.Strings(result)
	return unique(result), nil
}
func unique(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if values[read] != values[write-1] {
			values[write] = values[read]
			write++
		}
	}
	return values[:write]
}
func jsonValue(value any) []byte { encoded, _ := json.Marshal(value); return encoded }

type cursor struct {
	Version int    `json:"v"`
	After   string `json:"after"`
	Digest  string `json:"digest"`
}

type revisionCursor struct {
	Version       int    `json:"v"`
	AfterRevision uint64 `json:"after_revision"`
	AfterID       string `json:"after_id"`
	Digest        string `json:"digest"`
}

func encodeRevisionCursor(scope platformscope.Scope, templateID string, revision uint64, afterID string) (string, error) {
	if scope.Validate() != nil || !templateIDPattern.MatchString(templateID) || revision == 0 || revision > uint64(1<<63-1) || !idPattern.MatchString(afterID) {
		return "", ErrInvalid
	}
	value := revisionCursor{Version: 1, AfterRevision: revision, AfterID: afterID, Digest: DefinitionDigest(scope.Key() + "\x00" + templateID)}
	encoded, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeRevisionCursor(scope platformscope.Scope, templateID, encoded string) (uint64, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) > 384 {
		return 0, "", ErrInvalid
	}
	var value revisionCursor
	if json.Unmarshal(raw, &value) != nil || value.Version != 1 || value.AfterRevision == 0 || value.AfterRevision > uint64(1<<63-1) || !idPattern.MatchString(value.AfterID) || value.Digest != DefinitionDigest(scope.Key()+"\x00"+templateID) {
		return 0, "", ErrInvalid
	}
	return value.AfterRevision, value.AfterID, nil
}

func encodeCursor(scope platformscope.Scope, filter, after string) (string, error) {
	if scope.Validate() != nil || !idPattern.MatchString(after) {
		return "", ErrInvalid
	}
	value := cursor{Version: 1, After: after, Digest: DefinitionDigest(scope.Key() + "\x00" + filter)}
	encoded, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}
func decodeCursor(scope platformscope.Scope, filter, encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) > 384 {
		return "", ErrInvalid
	}
	var value cursor
	if json.Unmarshal(raw, &value) != nil || value.Version != 1 || !idPattern.MatchString(value.After) || value.Digest != DefinitionDigest(scope.Key()+"\x00"+filter) {
		return "", ErrInvalid
	}
	return value.After, nil
}

func mapPostgresError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code {
		case "23505", "23503":
			return ErrConflict
		case "23502", "23514", "22P02", "22001":
			return ErrInvalid
		case "40001", "40P01":
			return ErrConflict
		}
	}
	return err
}

var _ Repository = (*PostgresRepository)(nil)
var _ TrialTargetResolver = (*PostgresRepository)(nil)
