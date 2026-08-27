package job

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCreateWithOutboxCommitsJobTargetsAndEveryMessage(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	job, messages := persistenceFixture()

	mock.ExpectBegin()
	expectJobInsert(mock, job)
	expectTargetInsert(mock, job, "db-1")
	expectTargetInsert(mock, job, "db-2")
	expectOutboxInsert(mock, messages[0], nil)
	expectOutboxInsert(mock, messages[1], nil)
	mock.ExpectCommit()

	require.NoError(t, repository.CreateWithOutbox(context.Background(), job, messages))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateWithOutboxAcceptsUnsignedProtobufCommandPayload(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	value, messages := persistenceFixture()
	payload, err := proto.Marshal(&agentv1.CommandEnvelope{AgentId: "db-1", LeaseSeconds: 30, Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{}}})
	require.NoError(t, err)
	messages = []OutboxMessage{{ID: "command-protobuf", Scope: value.Scope, JobID: value.ID, TargetID: "db-1", Type: commandOutboxType, Payload: payload, AvailableAt: value.CreatedAt, CreatedAt: value.CreatedAt}}

	mock.ExpectBegin()
	expectJobInsert(mock, value)
	for _, targetID := range value.TargetResourceIDs {
		expectTargetInsert(mock, value, targetID)
	}
	expectOutboxInsert(mock, messages[0], nil)
	mock.ExpectCommit()

	require.NoError(t, repository.CreateWithOutbox(context.Background(), value, messages))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateWithOutboxRollsBackWhenAnOutboxInsertFails(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	job, messages := persistenceFixture()

	mock.ExpectBegin()
	expectJobInsert(mock, job)
	expectTargetInsert(mock, job, "db-1")
	expectTargetInsert(mock, job, "db-2")
	expectOutboxInsert(mock, messages[0], nil)
	expectOutboxInsert(mock, messages[1], errors.New("disk full"))
	mock.ExpectRollback()

	err = repository.CreateWithOutbox(context.Background(), job, messages)
	require.ErrorContains(t, err, "insert outbox message")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestCreateInTxParticipatesInModuleOwnedTransaction(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	job, messages := persistenceFixture()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO inspection_runs").WithArgs("inspection-1").WillReturnResult(sqlmock.NewResult(0, 1))
	expectJobInsert(mock, job)
	expectTargetInsert(mock, job, "db-1")
	expectTargetInsert(mock, job, "db-2")
	expectOutboxInsert(mock, messages[0], nil)
	expectOutboxInsert(mock, messages[1], nil)
	mock.ExpectCommit()

	tx, err := database.BeginTx(context.Background(), nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(context.Background(), "INSERT INTO inspection_runs (id) VALUES ($1)", "inspection-1")
	require.NoError(t, err)
	require.NoError(t, repository.CreateInTx(context.Background(), tx, job, messages))
	require.NoError(t, tx.Commit())
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestClaimOutboxLeasesRowsWithSkipLockedInCreationOrder(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	createdOne := at.Add(-2 * time.Minute)
	createdTwo := at.Add(-time.Minute)
	columns := []string{"id", "tenant_id", "project_id", "job_id", "target_id", "message_type", "payload", "prepared_envelope", "available_at", "created_at", "lease_expires_at", "published_at", "attempts"}
	rows := sqlmock.NewRows(columns).
		AddRow("msg-1", "tenant-1", "project-1", "job-1", "db-1", "agent.command", []byte(`{"command_id":"command-1"}`), nil, createdOne, createdOne, at.Add(DefaultOutboxLease), nil, 1).
		AddRow("msg-2", "tenant-1", "project-1", "job-1", "db-2", "agent.command", []byte(`{"command_id":"command-2"}`), nil, createdTwo, createdTwo, at.Add(DefaultOutboxLease), nil, 1)
	mock.ExpectQuery("(?s)FOR UPDATE SKIP LOCKED.*SET lease_expires_at.*ORDER BY created_at, id").
		WithArgs(at.UTC(), 2, at.UTC().Add(DefaultOutboxLease)).
		WillReturnRows(rows)

	messages, err := repository.ClaimOutbox(context.Background(), 2, at)
	require.NoError(t, err)
	require.Equal(t, []string{"msg-1", "msg-2"}, []string{messages[0].ID, messages[1].ID})
	require.Equal(t, at.UTC().Add(DefaultOutboxLease), *messages[0].LeasedUntil)
	require.Equal(t, time.UTC, messages[0].CreatedAt.Location())
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetReadsJobAndTargetsInOneSnapshotTransaction(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	value, _ := persistenceFixture()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .* FROM jobs").WithArgs("tenant-1", "project-1", "job-1").WillReturnRows(jobRows(value))
	mock.ExpectQuery("SELECT target_id.*FROM job_targets").WithArgs("tenant-1", "project-1", "job-1").WillReturnRows(
		sqlmock.NewRows([]string{"target_id", "status", "error_summary", "result_summary", "artifacts", "finished_at"}).
			AddRow("db-1", string(TargetQueued), "", "", []byte("[]"), nil).
			AddRow("db-2", string(TargetQueued), "", "", []byte("[]"), nil),
	)
	mock.ExpectCommit()

	got, err := repository.Get(context.Background(), value.Scope, value.ID)
	require.NoError(t, err)
	require.Equal(t, []string{"db-1", "db-2"}, got.TargetResourceIDs)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetRollsBackSnapshotWhenTargetReadFails(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	value, _ := persistenceFixture()

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .* FROM jobs").WithArgs("tenant-1", "project-1", "job-1").WillReturnRows(jobRows(value))
	mock.ExpectQuery("SELECT target_id.*FROM job_targets").WithArgs("tenant-1", "project-1", "job-1").WillReturnError(errors.New("connection reset"))
	mock.ExpectRollback()

	_, err = repository.Get(context.Background(), value.Scope, value.ID)
	require.ErrorContains(t, err, "get job targets")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTransitionReturnsConflictWhenVersionWasAlreadyAdvanced(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	job := runningJob()
	transitionAt := job.StartedAt.Add(time.Minute)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .* FROM jobs").WithArgs("tenant-1", "project-1", "job-1").WillReturnRows(jobRows(job))
	mock.ExpectQuery("SELECT target_id.*FROM job_targets").WithArgs("tenant-1", "project-1", "job-1").WillReturnRows(
		sqlmock.NewRows([]string{"target_id", "status", "error_summary", "result_summary", "artifacts", "finished_at"}).
			AddRow("db-1", string(TargetRunning), "", "", []byte("[]"), nil),
	)
	mock.ExpectExec("UPDATE jobs SET .* WHERE tenant_id = \\$[0-9]+ AND project_id = \\$[0-9]+ AND id = \\$[0-9]+ AND version = \\$[0-9]+").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	completed := Progress{TotalTargets: 1, CompletedTargets: 1}
	_, err = repository.Transition(context.Background(), Transition{
		Scope: job.Scope, JobID: job.ID, CurrentVersion: job.Version, To: StatusSucceeded, At: transitionAt,
		Progress: &completed, TargetResults: []TargetResult{{TargetID: "db-1", Status: TargetSucceeded}},
	})
	require.ErrorIs(t, err, ErrConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTransitionMergesPersistedTargetResultsBeforeUpdating(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	current := runningJob()
	current.Progress = Progress{TotalTargets: 2, CompletedTargets: 1}
	at := current.StartedAt.Add(time.Minute)
	progress := Progress{TotalTargets: 2, CompletedTargets: 1, FailedTargets: 1}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .* FROM jobs").WithArgs("tenant-1", "project-1", "job-1").WillReturnRows(jobRows(current))
	mock.ExpectQuery("SELECT target_id.*FROM job_targets").WithArgs("tenant-1", "project-1", "job-1").WillReturnRows(
		sqlmock.NewRows([]string{"target_id", "status", "error_summary", "result_summary", "artifacts", "finished_at"}).
			AddRow("db-1", string(TargetSucceeded), "", "ok", []byte("[]"), at.Add(-time.Second)).
			AddRow("db-2", string(TargetRunning), "", "", []byte("[]"), nil),
	)
	mock.ExpectExec("UPDATE jobs SET").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO job_targets").WithArgs("tenant-1", "project-1", "job-1", "db-2", string(TargetFailed), "query failed", "", []byte("[]"), at.UTC()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	got, err := repository.Transition(context.Background(), Transition{
		Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, At: at,
		Progress: &progress, TargetResults: []TargetResult{{TargetID: "db-2", Status: TargetFailed, ErrorSummary: "query failed", FinishedAt: &at}},
	})
	require.NoError(t, err)
	require.Len(t, got.TargetResults, 2)
	require.Equal(t, TargetSucceeded, got.TargetResults[0].Status)
	require.Equal(t, TargetFailed, got.TargetResults[1].Status)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestTransitionWrapsCommitFailureAsAmbiguous(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	current := runningJob()
	at := current.StartedAt.Add(time.Minute)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT .* FROM jobs").WithArgs("tenant-1", "project-1", "job-1").WillReturnRows(jobRows(current))
	mock.ExpectQuery("SELECT target_id.*FROM job_targets").WithArgs("tenant-1", "project-1", "job-1").WillReturnRows(
		sqlmock.NewRows([]string{"target_id", "status", "error_summary", "result_summary", "artifacts", "finished_at"}).
			AddRow("db-1", string(TargetRunning), "", "", []byte("[]"), nil),
	)
	mock.ExpectExec("UPDATE jobs SET").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit().WillReturnError(errors.New("connection lost after commit request"))

	_, err = repository.Transition(context.Background(), Transition{
		Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version,
		To: StatusCancelling, Actor: "operator-1", At: at,
	})
	require.ErrorIs(t, err, ErrAmbiguousCommit)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMarkOutboxPublishedReturnsNotFoundForUnknownMessage(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	mock.ExpectExec("UPDATE command_outbox SET published_at").WithArgs(at.UTC(), scope.TenantID, scope.ProjectID, "missing").WillReturnResult(sqlmock.NewResult(0, 0))

	err = repository.MarkOutboxPublished(context.Background(), scope, "missing", at)
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMarkOutboxPublishedCannotUpdateAnotherScope(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	at := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	wrongScope := platformscope.Scope{TenantID: "tenant-other", ProjectID: "project-other"}

	mock.ExpectExec("UPDATE command_outbox SET published_at").
		WithArgs(at, wrongScope.TenantID, wrongScope.ProjectID, "msg-1").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = repository.MarkOutboxPublished(context.Background(), wrongScope, "msg-1", at)
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, mock.ExpectationsWereMet())
}

func persistenceFixture() (Job, []OutboxMessage) {
	created := time.Date(2026, 8, 28, 16, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	job := Job{
		ID: "job-1", Type: "inspection.run", Scope: scope, Status: StatusQueued, Outcome: OutcomeNone,
		TargetResourceIDs: []string{"db-1", "db-2"}, InitiatedBy: "operator-1",
		SourceResource: ResourceReference{ResourceType: "inspection_run", ResourceID: "inspection-1"},
		IdempotencyKey: "request-1", Version: 1, Progress: Progress{TotalTargets: 2},
		Artifacts: []ArtifactReference{}, CreatedAt: created, TimeoutAt: timePointer(created.Add(time.Hour)),
		RequestID: "req-1", TraceID: "trace-1",
	}
	messages := []OutboxMessage{
		{ID: "msg-1", Scope: scope, JobID: job.ID, TargetID: "db-1", Type: "agent.command", Payload: []byte(`{"command_id":"command-1"}`), AvailableAt: created, CreatedAt: created},
		{ID: "msg-2", Scope: scope, JobID: job.ID, TargetID: "db-2", Type: "agent.command", Payload: []byte(`{"command_id":"command-2"}`), AvailableAt: created, CreatedAt: created.Add(time.Second)},
	}
	return job, messages
}

func expectJobInsert(mock sqlmock.Sqlmock, job Job) {
	mock.ExpectExec("INSERT INTO jobs").WithArgs(
		job.ID, job.Scope.TenantID, job.Scope.ProjectID, job.Type, string(job.Status), string(job.Outcome), job.InstanceID,
		job.InitiatedBy, job.SourceResource.ResourceType, job.SourceResource.ResourceID, job.IdempotencyKey, job.Version,
		job.Progress.TotalTargets, job.Progress.CompletedTargets, job.Progress.FailedTargets, job.Progress.SkippedTargets,
		job.ErrorSummary, job.ResultSummary, []byte("[]"), job.CreatedAt.UTC(), nil, nil, nil, job.TimeoutAt.UTC(), "", nil,
		job.RequestID, job.TraceID,
	).WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectTargetInsert(mock sqlmock.Sqlmock, job Job, targetID string) {
	mock.ExpectExec("INSERT INTO job_targets").WithArgs(job.Scope.TenantID, job.Scope.ProjectID, job.ID, targetID, string(TargetQueued), "", "", []byte("[]"), nil).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectOutboxInsert(mock sqlmock.Sqlmock, message OutboxMessage, insertErr error) {
	expectation := mock.ExpectExec("INSERT INTO command_outbox").WithArgs(
		message.ID, message.Scope.TenantID, message.Scope.ProjectID, message.JobID, message.TargetID, message.Type, message.Payload,
		nil, message.AvailableAt.UTC(), message.CreatedAt.UTC(), nil, nil, 0,
	)
	if insertErr != nil {
		expectation.WillReturnError(insertErr)
	} else {
		expectation.WillReturnResult(sqlmock.NewResult(0, 1))
	}
}

func jobRows(job Job) *sqlmock.Rows {
	return sqlmock.NewRows(jobColumnNames()).AddRow(
		job.ID, job.Scope.TenantID, job.Scope.ProjectID, job.Type, string(job.Status), string(job.Outcome), job.InstanceID,
		job.InitiatedBy, job.SourceResource.ResourceType, job.SourceResource.ResourceID, job.IdempotencyKey, job.Version,
		job.Progress.TotalTargets, job.Progress.CompletedTargets, job.Progress.FailedTargets, job.Progress.SkippedTargets,
		job.ErrorSummary, job.ResultSummary, []byte("[]"), job.CreatedAt, job.DispatchedAt, job.StartedAt, job.FinishedAt, job.TimeoutAt,
		job.CancelRequestedBy, job.CancelRequestedAt, job.RequestID, job.TraceID,
	)
}

func TestLookupCommandReturnsDurableScopeAndCorrelationByGlobalCommandID(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	value, messages := persistenceFixture()
	message := messages[0]

	columns := []string{"id", "tenant_id", "project_id", "job_id", "target_id", "message_type", "payload", "prepared_envelope", "available_at", "created_at", "lease_expires_at", "published_at", "attempts"}
	published := message.CreatedAt.Add(time.Minute)
	mock.ExpectQuery("SELECT .* FROM command_outbox WHERE id = \\$1").WithArgs(message.ID).WillReturnRows(
		sqlmock.NewRows(columns).AddRow(message.ID, value.Scope.TenantID, value.Scope.ProjectID, value.ID, message.TargetID, message.Type, message.Payload, nil, message.AvailableAt, message.CreatedAt, nil, published, 2),
	)

	got, err := repository.LookupCommand(context.Background(), message.ID)
	require.NoError(t, err)
	require.Equal(t, value.Scope, got.Scope)
	require.Equal(t, value.ID, got.JobID)
	require.Equal(t, message.TargetID, got.TargetID)
	require.Equal(t, message.Payload, got.Payload)
	require.NotNil(t, got.PublishedAt)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPrepareCommandEnvelopeStoresOnceAndReturnsPersistedBytes(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := NewPostgresRepository(database)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	proposed := []byte("signed-envelope-proposal")
	stored := []byte("signed-envelope-already-stored")
	mock.ExpectQuery("UPDATE command_outbox.*prepared_envelope.*COALESCE.*RETURNING prepared_envelope").
		WithArgs(scope.TenantID, scope.ProjectID, "command-1", proposed).
		WillReturnRows(sqlmock.NewRows([]string{"prepared_envelope"}).AddRow(stored))

	got, err := repository.PrepareCommandEnvelope(context.Background(), scope, "command-1", proposed)
	require.NoError(t, err)
	require.Equal(t, stored, got)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRepositoryImplementsRepository(t *testing.T) {
	var _ Repository = (*PostgresRepository)(nil)
	var _ DispatchRepository = (*PostgresRepository)(nil)
}
