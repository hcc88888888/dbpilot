package metrictemplate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestServiceValidatesWithAuthoritativeDialectAndPersistsOnlyDigestMetadata(t *testing.T) {
	repository := newMetricRepositoryFixture()
	validatorCalls := 0
	service := NewService(repository, DeterministicDialectValidator{Validate: func(_ context.Context, definition TemplateDefinition) error {
		validatorCalls++
		require.Equal(t, "SELECT value FROM metrics", definition.ReadOnlyStatement)
		return nil
	}}, nil, time.Now)

	value, err := service.Validate(context.Background(), repository.revision.Scope, repository.revision.ID, repository.revision.ResourceRevision, testActor("creator", "validateMetricTemplateRevision"))
	require.NoError(t, err)
	require.Equal(t, StatusValidated, value.Status)
	require.Equal(t, 1, validatorCalls)
	require.Empty(t, repository.lastValidated.ReadOnlyStatement)
	require.Equal(t, repository.revision.QueryDigest, repository.lastValidated.QueryDigest)
}

func TestServiceTrialCreatesOneBoundedTypedJobWithoutSQL(t *testing.T) {
	repository := newMetricRepositoryFixture()
	repository.revision.Status = StatusValidated
	repository.revision.ResourceRevision = 2
	targets := trialTargetFixture{target: TrialTarget{Scope: repository.revision.Scope, InstanceID: "instance-a", AgentID: "agent-a", AssignmentID: "assignment-a", ConfigurationRevision: 7, OperationRevision: 9, PluginVersionID: "version-a", DatabaseFamily: "mysql", DatabaseVariant: "mysql", PluginAvailable: true, PluginSchemaVersion: 1}}
	service := NewService(repository, DeterministicDialectValidator{Validate: func(context.Context, TemplateDefinition) error { return nil }}, targets, func() time.Time { return time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC) })

	created, err := service.StartTrial(context.Background(), repository.revision.Scope, repository.revision.ID, TrialRequest{InstanceID: "instance-a", PluginVersionID: "version-a", Actor: testActor("creator", "trialMetricTemplateRevision")})
	require.NoError(t, err)
	require.Equal(t, "metric_template.trial", created.Type)
	require.Equal(t, []string{"agent-a"}, created.TargetResourceIDs)
	require.Equal(t, 1, repository.trialCreates)
	require.Len(t, repository.messages, 1)
	require.NotContains(t, string(repository.messages[0].Payload), "SELECT")

	envelope := new(agentv1.CommandEnvelope)
	require.NoError(t, proto.Unmarshal(repository.messages[0].Payload, envelope))
	command := envelope.GetCollectDatabaseMetrics()
	require.NotNil(t, command)
	require.Equal(t, "assignment-a", command.GetAssignmentId())
	require.Equal(t, uint64(7), command.GetConfigurationRevision())
	require.Equal(t, uint64(9), command.GetOperationRevision())
	require.Equal(t, []string{"instance-a"}, command.GetInstanceIds())
	require.Equal(t, []string{repository.revision.TemplateID}, command.GetTemplateIds())
	require.True(t, command.GetTrial())
	require.Len(t, command.GetTemplateRevisions(), 1)
	require.Equal(t, repository.revision.TemplateID, command.GetTemplateRevisions()[0].GetTemplateId())
	require.Equal(t, repository.revision.QueryDigest, fmt.Sprintf("%x", command.GetTemplateRevisions()[0].GetQueryDigest()))
	require.Equal(t, uint32(repository.revision.TimeoutSeconds), command.GetTemplateRevisions()[0].GetTimeoutSeconds())
	require.False(t, bytes.Contains(repository.messages[0].Payload, []byte(repository.revision.ReadOnlyStatement)))
}

func TestServiceTrialRejectsCrossScopeUnavailableAndIncompatibleTargetsBeforeCreatingJob(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*TrialTarget)
	}{
		{"cross scope", func(value *TrialTarget) { value.Scope.ProjectID = "project-b" }},
		{"wrong family", func(value *TrialTarget) { value.DatabaseFamily = "postgres" }},
		{"wrong variant", func(value *TrialTarget) { value.DatabaseVariant = "mariadb" }},
		{"wrong version", func(value *TrialTarget) { value.PluginVersionID = "version-b" }},
		{"unavailable", func(value *TrialTarget) { value.PluginAvailable = false }},
		{"wrong schema", func(value *TrialTarget) { value.PluginSchemaVersion = 2 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := newMetricRepositoryFixture()
			repository.revision.Status = StatusValidated
			target := TrialTarget{Scope: repository.revision.Scope, InstanceID: "instance-a", AgentID: "agent-a", AssignmentID: "assignment-a", ConfigurationRevision: 7, OperationRevision: 9, PluginVersionID: "version-a", DatabaseFamily: "mysql", DatabaseVariant: "mysql", PluginAvailable: true, PluginSchemaVersion: 1}
			test.mutate(&target)
			service := NewService(repository, DeterministicDialectValidator{Validate: func(context.Context, TemplateDefinition) error { return nil }}, trialTargetFixture{target: target}, time.Now)
			_, err := service.StartTrial(context.Background(), repository.revision.Scope, repository.revision.ID, TrialRequest{InstanceID: "instance-a", PluginVersionID: "version-a", Actor: testActor("creator", "trialMetricTemplateRevision")})
			require.ErrorIs(t, err, ErrIncompatible)
			require.Zero(t, repository.trialCreates)
		})
	}
}

func TestServiceRejectsSecondDifferentTrialWhileRevisionRunning(t *testing.T) {
	repository := newMetricRepositoryFixture()
	repository.revision.Status = StatusValidated
	target := TrialTarget{Scope: repository.revision.Scope, InstanceID: "instance-a", AgentID: "agent-a", AssignmentID: "assignment-a", ConfigurationRevision: 7, OperationRevision: 9, PluginVersionID: "version-a", DatabaseFamily: "mysql", DatabaseVariant: "mysql", PluginAvailable: true, PluginSchemaVersion: 1}
	service := NewService(repository, DeterministicDialectValidator{Validate: func(context.Context, TemplateDefinition) error { return nil }}, trialTargetFixture{target: target}, time.Now)
	_, err := service.StartTrial(context.Background(), repository.revision.Scope, repository.revision.ID, TrialRequest{InstanceID: "instance-a", PluginVersionID: "version-a", Actor: testActor("creator", "trialMetricTemplateRevision")})
	require.NoError(t, err)
	second := testActor("creator", "trialMetricTemplateRevision")
	second.IdempotencyKey = "different-key"
	second.RequestFingerprint = "sha256:" + strings64("b")
	_, err = service.StartTrial(context.Background(), repository.revision.Scope, repository.revision.ID, TrialRequest{InstanceID: "instance-a", PluginVersionID: "version-a", Actor: second})
	require.ErrorIs(t, err, ErrConflict)
	require.Equal(t, 1, repository.trialCreates)
}

func TestServiceApproveRejectsCreatorAndPublishRequiresApprovedRevision(t *testing.T) {
	repository := newMetricRepositoryFixture()
	repository.revision.Status = StatusTrialPassed
	repository.revision.ResourceRevision = 4
	service := NewService(repository, DeterministicDialectValidator{Validate: func(context.Context, TemplateDefinition) error { return nil }}, nil, time.Now)

	_, err := service.Approve(context.Background(), repository.revision.Scope, repository.revision.ID, 4, testActor("creator", "approveMetricTemplateRevision"))
	require.ErrorIs(t, err, ErrSelfApproval)
	_, err = service.Publish(context.Background(), repository.revision.Scope, repository.revision.ID, 4, PublishScope{Actor: testActor("approver", "publishMetricTemplateRevision")})
	require.ErrorIs(t, err, ErrNotApproved)

	repository.revision.Status = StatusApproved
	repository.revision.ApprovedBy = "approver"
	repository.revision.ResourceRevision = 5
	published, err := service.Publish(context.Background(), repository.revision.Scope, repository.revision.ID, 5, PublishScope{Actor: testActor("approver", "publishMetricTemplateRevision")})
	require.NoError(t, err)
	require.Equal(t, StatusPublished, published.Status)
	require.Equal(t, 1, repository.publishCalls)
}

type metricRepositoryFixture struct {
	revision      Revision
	lastValidated ValidatedDefinition
	trialCreates  int
	publishCalls  int
	messages      []job.OutboxMessage
}

func newMetricRepositoryFixture() *metricRepositoryFixture {
	now := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)
	revision := validRevision(now)
	revision.QueryDigest = DefinitionDigest(revision.ReadOnlyStatement)
	return &metricRepositoryFixture{revision: revision}
}

func (repository *metricRepositoryFixture) CreateTemplate(context.Context, platformscope.Scope, TemplateDraft, Actor) (Template, error) {
	return Template{}, errors.New("not used")
}
func (repository *metricRepositoryFixture) GetTemplate(_ context.Context, scope platformscope.Scope, id string) (Template, error) {
	return Template{ID: id, Scope: scope, DatabaseFamily: "mysql", Name: "Custom", LatestRevision: 1, CreatedAt: repository.revision.CreatedAt}, nil
}
func (repository *metricRepositoryFixture) CreateDraft(context.Context, platformscope.Scope, string, Draft, Actor) (Revision, error) {
	return Revision{}, errors.New("not used")
}
func (repository *metricRepositoryFixture) ListTemplates(context.Context, platformscope.Scope, Filter) (TemplatePage, error) {
	return TemplatePage{}, errors.New("not used")
}
func (repository *metricRepositoryFixture) ListRevisions(context.Context, platformscope.Scope, string, RevisionFilter) (RevisionPage, error) {
	return RevisionPage{}, errors.New("not used")
}
func (repository *metricRepositoryFixture) GetRevision(_ context.Context, scope platformscope.Scope, id string) (Revision, error) {
	if repository.revision.Scope != scope || repository.revision.ID != id {
		return Revision{}, ErrNotFound
	}
	return repository.revision, nil
}
func (repository *metricRepositoryFixture) ReplayRevisionMutation(context.Context, platformscope.Scope, Actor, string, string) (Revision, bool, error) {
	return Revision{}, false, nil
}
func (repository *metricRepositoryFixture) ReplayTrialMutation(context.Context, platformscope.Scope, Actor, string) (job.Job, bool, error) {
	return job.Job{}, false, nil
}
func (repository *metricRepositoryFixture) FinishValidation(_ context.Context, scope platformscope.Scope, id string, expected uint64, validated ValidatedDefinition, succeeded bool, actor Actor) (Revision, error) {
	if scope != repository.revision.Scope || id != repository.revision.ID || expected != repository.revision.ResourceRevision || actor.Validate() != nil {
		return Revision{}, ErrPrecondition
	}
	repository.lastValidated = validated
	status := StatusValidationFailed
	if succeeded {
		status = StatusValidated
	}
	next, err := repository.revision.Transition(status, actor.Subject, repository.revision.UpdatedAt.Add(time.Minute))
	if err != nil {
		return Revision{}, err
	}
	repository.revision = next
	return next, nil
}
func (repository *metricRepositoryFixture) CreateTrial(_ context.Context, revision Revision, request TrialRequest, value job.Job, messages []job.OutboxMessage) (job.Job, error) {
	repository.trialCreates++
	repository.messages = append([]job.OutboxMessage(nil), messages...)
	repository.revision.Status = StatusTrialRunning
	repository.revision.ResourceRevision++
	return value, nil
}
func (repository *metricRepositoryFixture) Approve(_ context.Context, scope platformscope.Scope, id string, expected uint64, actor Actor) (Revision, error) {
	if scope != repository.revision.Scope || id != repository.revision.ID || expected != repository.revision.ResourceRevision {
		return Revision{}, ErrPrecondition
	}
	next, err := repository.revision.Transition(StatusApproved, actor.Subject, repository.revision.UpdatedAt.Add(time.Minute))
	if err == nil {
		repository.revision = next
	}
	return next, err
}
func (repository *metricRepositoryFixture) Publish(_ context.Context, scope platformscope.Scope, id string, expected uint64, publish PublishScope, _ ValidatedDefinition) (Revision, error) {
	repository.publishCalls++
	if scope != repository.revision.Scope || id != repository.revision.ID || expected != repository.revision.ResourceRevision {
		return Revision{}, ErrPrecondition
	}
	next, err := repository.revision.Transition(StatusPublished, publish.Actor.Subject, repository.revision.UpdatedAt.Add(time.Minute))
	if err == nil {
		repository.revision = next
	}
	return next, err
}

type trialTargetFixture struct {
	target TrialTarget
	err    error
}

func (fixture trialTargetFixture) ResolveTrialTarget(context.Context, platformscope.Scope, string) (TrialTarget, error) {
	return fixture.target, fixture.err
}

func testActor(subject, operation string) Actor {
	return Actor{Subject: subject, OperationID: operation, IdempotencyKey: "idempotency-a", RequestFingerprint: "sha256:" + strings64("a"), RequestID: "request-a", TraceID: "trace-a"}
}

func strings64(value string) string { return string(bytes.Repeat([]byte(value), 64)) }
