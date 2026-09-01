package metrictemplate

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"google.golang.org/protobuf/proto"
)

const MetricTemplateSchemaVersion uint32 = 1

type Repository interface {
	CreateTemplate(context.Context, platformscope.Scope, TemplateDraft, Actor) (Template, error)
	GetTemplate(context.Context, platformscope.Scope, string) (Template, error)
	CreateDraft(context.Context, platformscope.Scope, string, Draft, Actor) (Revision, error)
	ListTemplates(context.Context, platformscope.Scope, Filter) (TemplatePage, error)
	ListRevisions(context.Context, platformscope.Scope, string, RevisionFilter) (RevisionPage, error)
	GetRevision(context.Context, platformscope.Scope, string) (Revision, error)
	ReplayRevisionMutation(context.Context, platformscope.Scope, Actor, string, string) (Revision, bool, error)
	ReplayTrialMutation(context.Context, platformscope.Scope, Actor, string) (job.Job, bool, error)
	FinishValidation(context.Context, platformscope.Scope, string, uint64, ValidatedDefinition, bool, Actor) (Revision, error)
	CreateTrial(context.Context, Revision, TrialRequest, job.Job, []job.OutboxMessage) (job.Job, error)
	Approve(context.Context, platformscope.Scope, string, uint64, Actor) (Revision, error)
	Publish(context.Context, platformscope.Scope, string, uint64, PublishScope, ValidatedDefinition) (Revision, error)
}

type TrialTarget struct {
	Scope                 platformscope.Scope
	InstanceID            string
	AgentID               string
	AssignmentID          string
	ConfigurationRevision uint64
	OperationRevision     uint64
	PluginVersionID       string
	DatabaseFamily        string
	DatabaseVariant       string
	PluginAvailable       bool
	PluginSchemaVersion   uint32
}

func (value TrialTarget) Validate() error {
	if value.Scope.Validate() != nil || !idPattern.MatchString(value.InstanceID) || !idPattern.MatchString(value.AgentID) || !idPattern.MatchString(value.AssignmentID) || value.ConfigurationRevision == 0 || value.OperationRevision == 0 || !idPattern.MatchString(value.PluginVersionID) || !familyPattern.MatchString(value.DatabaseFamily) || !variantPattern.MatchString(value.DatabaseVariant) || value.PluginSchemaVersion == 0 {
		return ErrInvalid
	}
	return nil
}

type TrialTargetResolver interface {
	ResolveTrialTarget(context.Context, platformscope.Scope, string) (TrialTarget, error)
}

type Service interface {
	CreateTemplate(context.Context, platformscope.Scope, TemplateDraft, Actor) (Template, error)
	CreateDraft(context.Context, platformscope.Scope, string, Draft, Actor) (Revision, error)
	ListTemplates(context.Context, platformscope.Scope, Filter) (TemplatePage, error)
	ListRevisions(context.Context, platformscope.Scope, string, RevisionFilter) (RevisionPage, error)
	Validate(context.Context, platformscope.Scope, string, uint64, Actor) (Revision, error)
	StartTrial(context.Context, platformscope.Scope, string, TrialRequest) (job.Job, error)
	Approve(context.Context, platformscope.Scope, string, uint64, Actor) (Revision, error)
	Publish(context.Context, platformscope.Scope, string, uint64, PublishScope) (Revision, error)
}

type ApplicationService struct {
	repository Repository
	dialect    DialectValidator
	targets    TrialTargetResolver
	now        func() time.Time
}

func NewService(repository Repository, dialect DialectValidator, targets TrialTargetResolver, now func() time.Time) *ApplicationService {
	if now == nil {
		now = time.Now
	}
	return &ApplicationService{repository: repository, dialect: dialect, targets: targets, now: now}
}

func (service *ApplicationService) CreateTemplate(ctx context.Context, scope platformscope.Scope, draft TemplateDraft, actor Actor) (Template, error) {
	if ctx == nil || service == nil || service.repository == nil || scope.Validate() != nil || draft.Validate() != nil || actor.Validate() != nil {
		return Template{}, ErrInvalid
	}
	value, err := service.repository.CreateTemplate(ctx, scope, draft, actor)
	if err != nil {
		return Template{}, err
	}
	if value.Scope != scope || value.ID != draft.ID || value.Validate() != nil {
		return Template{}, ErrConflict
	}
	return value, nil
}

func (service *ApplicationService) CreateDraft(ctx context.Context, scope platformscope.Scope, templateID string, draft Draft, actor Actor) (Revision, error) {
	if ctx == nil || service == nil || service.repository == nil || scope.Validate() != nil || !templateIDPattern.MatchString(templateID) || actor.Validate() != nil || !idPattern.MatchString(draft.CreatedBy) || draft.CreatedBy != actor.Subject {
		return Revision{}, ErrInvalid
	}
	// Persisting a draft requires only bounded shape. Semantic SQL safety is a
	// state transition and is recorded as validated/validation_failed later.
	normalized := draft.TemplateDefinition
	if normalized.DatabaseFamily == "" {
		template, err := service.repository.GetTemplate(ctx, scope, templateID)
		if err != nil {
			return Revision{}, err
		}
		normalized.DatabaseFamily = template.DatabaseFamily
	}
	if normalized.TimeoutSeconds == 0 {
		normalized.TimeoutSeconds = 5
	}
	if normalized.MaxRows == 0 {
		normalized.MaxRows = 1
	}
	normalized.Variants = normalizedStrings(normalized.Variants)
	if !validDefinitionShape(normalized) {
		return Revision{}, ErrValidationFailed
	}
	draft.TemplateDefinition = normalized
	value, err := service.repository.CreateDraft(ctx, scope, templateID, draft, actor)
	if err != nil {
		return Revision{}, err
	}
	checked := checkedRevision(value, scope, "")
	if checked.ID == "" {
		return Revision{}, ErrConflict
	}
	return checked, nil
}

func (service *ApplicationService) ListTemplates(ctx context.Context, scope platformscope.Scope, filter Filter) (TemplatePage, error) {
	if ctx == nil || service == nil || service.repository == nil || scope.Validate() != nil || filter.Validate() != nil {
		return TemplatePage{}, ErrInvalid
	}
	page, err := service.repository.ListTemplates(ctx, scope, filter)
	if err != nil {
		return TemplatePage{}, err
	}
	if page.Items == nil {
		page.Items = []Template{}
	}
	for _, value := range page.Items {
		if value.Scope != scope || value.Validate() != nil {
			return TemplatePage{}, ErrConflict
		}
	}
	return page, nil
}

func (service *ApplicationService) ListRevisions(ctx context.Context, scope platformscope.Scope, templateID string, filter RevisionFilter) (RevisionPage, error) {
	if ctx == nil || service == nil || service.repository == nil || scope.Validate() != nil || !templateIDPattern.MatchString(templateID) || filter.Validate() != nil {
		return RevisionPage{}, ErrInvalid
	}
	page, err := service.repository.ListRevisions(ctx, scope, templateID, filter)
	if err != nil {
		return RevisionPage{}, err
	}
	if page.Items == nil {
		page.Items = []Revision{}
	}
	for _, value := range page.Items {
		if value.Scope != scope || value.TemplateID != templateID || value.Validate() != nil {
			return RevisionPage{}, ErrConflict
		}
	}
	return page, nil
}

func (service *ApplicationService) Validate(ctx context.Context, scope platformscope.Scope, revisionID string, expected uint64, actor Actor) (Revision, error) {
	if ctx == nil || service == nil || service.repository == nil || service.dialect == nil || scope.Validate() != nil || !idPattern.MatchString(revisionID) || expected == 0 || actor.Validate() != nil {
		return Revision{}, ErrInvalid
	}
	if replay, found, err := service.repository.ReplayRevisionMutation(ctx, scope, actor, "validate_revision", revisionID); err != nil {
		return Revision{}, err
	} else if found {
		return replay, nil
	}
	revision, err := service.repository.GetRevision(ctx, scope, revisionID)
	if err != nil {
		return Revision{}, err
	}
	if revision.ResourceRevision != expected {
		return Revision{}, ErrPrecondition
	}
	if revision.Status != StatusDraft && revision.Status != StatusValidating && revision.Status != StatusValidated && revision.Status != StatusValidationFailed {
		return Revision{}, ErrInvalidTransition
	}
	serverValidated, err := ValidateDefinition(revision.Definition())
	if err != nil {
		_, persistErr := service.repository.FinishValidation(ctx, scope, revisionID, expected, ValidatedDefinition{QueryDigest: revision.QueryDigest}, false, actor)
		if persistErr != nil {
			return Revision{}, persistErr
		}
		return Revision{}, ErrValidationFailed
	}
	authoritative, err := service.dialect.ValidateReadOnly(ctx, revision.Definition())
	if err != nil || authoritative.QueryDigest != serverValidated.QueryDigest || authoritative.ReadOnlyStatement != "" {
		_, persistErr := service.repository.FinishValidation(ctx, scope, revisionID, expected, serverValidated, false, actor)
		if persistErr != nil {
			return Revision{}, persistErr
		}
		return Revision{}, ErrDialectRejected
	}
	return service.repository.FinishValidation(ctx, scope, revisionID, expected, serverValidated, true, actor)
}

func (service *ApplicationService) StartTrial(ctx context.Context, scope platformscope.Scope, revisionID string, request TrialRequest) (job.Job, error) {
	if ctx == nil || service == nil || service.repository == nil || service.dialect == nil || service.targets == nil || scope.Validate() != nil || !idPattern.MatchString(revisionID) || request.Validate() != nil {
		return job.Job{}, ErrInvalid
	}
	if replay, found, err := service.repository.ReplayTrialMutation(ctx, scope, request.Actor, revisionID); err != nil {
		return job.Job{}, err
	} else if found {
		return replay, nil
	}
	revision, err := service.repository.GetRevision(ctx, scope, revisionID)
	if err != nil {
		return job.Job{}, err
	}
	if revision.Status != StatusValidated {
		if revision.Status == StatusTrialRunning {
			return job.Job{}, ErrConflict
		}
		return job.Job{}, ErrInvalidTransition
	}
	validated, err := service.dialect.ValidateReadOnly(ctx, revision.Definition())
	if err != nil || validated.QueryDigest != revision.QueryDigest || validated.ReadOnlyStatement != "" {
		return job.Job{}, ErrDialectRejected
	}
	target, err := service.targets.ResolveTrialTarget(ctx, scope, request.InstanceID)
	if err != nil {
		return job.Job{}, err
	}
	if target.Validate() != nil || target.Scope != scope || target.InstanceID != request.InstanceID || target.PluginVersionID != request.PluginVersionID || target.DatabaseFamily != revision.DatabaseFamily || !contains(revision.Variants, target.DatabaseVariant) || !target.PluginAvailable || target.PluginSchemaVersion != MetricTemplateSchemaVersion {
		return job.Job{}, ErrIncompatible
	}
	value, message, err := BuildTrialJob(revision, target, request, service.now().UTC())
	if err != nil {
		return job.Job{}, err
	}
	return service.repository.CreateTrial(ctx, revision, request, value, []job.OutboxMessage{message})
}

func (service *ApplicationService) Approve(ctx context.Context, scope platformscope.Scope, revisionID string, expected uint64, actor Actor) (Revision, error) {
	if ctx == nil || service == nil || service.repository == nil || scope.Validate() != nil || !idPattern.MatchString(revisionID) || expected == 0 || actor.Validate() != nil {
		return Revision{}, ErrInvalid
	}
	if replay, found, err := service.repository.ReplayRevisionMutation(ctx, scope, actor, "approve_revision", revisionID); err != nil {
		return Revision{}, err
	} else if found {
		return replay, nil
	}
	revision, err := service.repository.GetRevision(ctx, scope, revisionID)
	if err != nil {
		return Revision{}, err
	}
	if revision.ResourceRevision != expected {
		return Revision{}, ErrPrecondition
	}
	if actor.Subject == revision.CreatedBy {
		return Revision{}, ErrSelfApproval
	}
	if revision.Status != StatusTrialPassed && revision.Status != StatusApprovalPending && revision.Status != StatusApproved {
		return Revision{}, ErrInvalidTransition
	}
	return service.repository.Approve(ctx, scope, revisionID, expected, actor)
}

func (service *ApplicationService) Publish(ctx context.Context, scope platformscope.Scope, revisionID string, expected uint64, publish PublishScope) (Revision, error) {
	if ctx == nil || service == nil || service.repository == nil || service.dialect == nil || scope.Validate() != nil || !idPattern.MatchString(revisionID) || expected == 0 || publish.Validate() != nil {
		return Revision{}, ErrInvalid
	}
	if replay, found, err := service.repository.ReplayRevisionMutation(ctx, scope, publish.Actor, "publish_revision", revisionID); err != nil {
		return Revision{}, err
	} else if found {
		return replay, nil
	}
	revision, err := service.repository.GetRevision(ctx, scope, revisionID)
	if err != nil {
		return Revision{}, err
	}
	if revision.ResourceRevision != expected {
		return Revision{}, ErrPrecondition
	}
	if revision.Status == StatusSuperseded {
		publish.Rollback = true
	} else if revision.Status != StatusApproved && revision.Status != StatusPublished {
		return Revision{}, ErrNotApproved
	}
	validated, err := service.dialect.ValidateReadOnly(ctx, revision.Definition())
	if err != nil || validated.QueryDigest != revision.QueryDigest || validated.ReadOnlyStatement != "" {
		return Revision{}, ErrDialectRejected
	}
	return service.repository.Publish(ctx, scope, revisionID, expected, publish, validated)
}

func BuildTrialJob(revision Revision, target TrialTarget, request TrialRequest, at time.Time) (job.Job, job.OutboxMessage, error) {
	if revision.Validate() != nil || target.Validate() != nil || request.Validate() != nil || at.IsZero() || at.Location() != time.UTC || revision.Scope != target.Scope || revision.Status != StatusValidated {
		return job.Job{}, job.OutboxMessage{}, ErrInvalid
	}
	digest, err := hex.DecodeString(revision.QueryDigest)
	if err != nil || len(digest) != 32 {
		return job.Job{}, job.OutboxMessage{}, ErrInvalid
	}
	reference := &agentv1.MetricTemplateCommandReference{TemplateId: revision.TemplateID, RevisionId: revision.ID, QueryDigest: digest, TimeoutSeconds: uint32(revision.TimeoutSeconds), MaxRows: uint32(revision.MaxRows), MaxColumns: uint32(revision.MaxColumns), CardinalityLimit: uint32(revision.CardinalityLimit)}
	command := &agentv1.CommandEnvelope{AgentId: target.AgentID, LeaseSeconds: uint32(revision.TimeoutSeconds), Command: &agentv1.CommandEnvelope_CollectDatabaseMetrics{CollectDatabaseMetrics: &agentv1.CollectDatabaseMetrics{AssignmentId: target.AssignmentID, ConfigurationRevision: target.ConfigurationRevision, OperationRevision: target.OperationRevision, InstanceIds: []string{target.InstanceID}, TemplateIds: []string{revision.TemplateID}, TemplateRevisions: []*agentv1.MetricTemplateCommandReference{reference}, Trial: true}}}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return job.Job{}, job.OutboxMessage{}, fmt.Errorf("marshal CollectDatabaseMetrics: %w", err)
	}
	identity := revision.Scope.Key() + "\x00" + revision.ID + "\x00" + request.InstanceID + "\x00" + request.PluginVersionID + "\x00" + request.Actor.Subject + "\x00" + request.Actor.IdempotencyKey
	jobID := deterministicID("job-metric-trial-", identity)
	commandID := deterministicID("command-metric-trial-", identity)
	timeout := at.Add(time.Duration(revision.TimeoutSeconds+30) * time.Second)
	value := job.Job{ID: jobID, Type: "metric_template.trial", Scope: revision.Scope, Status: job.StatusQueued, Outcome: job.OutcomeNone, InstanceID: request.InstanceID, TargetResourceIDs: []string{target.AgentID}, InitiatedBy: request.Actor.Subject, SourceResource: job.ResourceReference{ResourceType: "metric_template_revision", ResourceID: revision.ID}, IdempotencyKey: request.Actor.IdempotencyKey, Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: at, TimeoutAt: &timeout, MaxConcurrency: 1, TargetTimeout: time.Duration(revision.TimeoutSeconds) * time.Second, RequestID: request.Actor.RequestID, TraceID: request.Actor.TraceID}
	message := job.OutboxMessage{ID: commandID, Scope: revision.Scope, JobID: jobID, TargetID: target.AgentID, Type: "agent.command", Payload: payload, AvailableAt: at, CreatedAt: at}
	return value, message, nil
}

func checkedRevision(value Revision, scope platformscope.Scope, expectedID string) Revision {
	if value.Scope != scope || expectedID != "" && value.ID != expectedID || value.Validate() != nil {
		return Revision{}
	}
	return value
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func deterministicID(prefix, identity string) string {
	return prefix + DefinitionDigest(identity)[:32]
}

var _ Service = (*ApplicationService)(nil)
