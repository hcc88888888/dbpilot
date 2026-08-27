package idempotency

import (
	"context"
	"database/sql"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestPostgresStoreAtomicallyClaimsNewOrExpiredCompletedKeys(t *testing.T) {
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	expires := now.Add(DefaultTTL)
	key := validKey()
	fingerprint := "sha256:0a9896a42ff3a8f7c9edfe3c97cc1e9d2b6bc06122f89876a49ea3bc4cc51b59"
	owner := "owner-1111111111111111111111111111111111111111111111111111111111111111"

	t.Run("new", func(t *testing.T) {
		database, mock := newIdempotencySQLMock(t)
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(insertClaimSQL)).
			WithArgs(key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey, fingerprint, owner, expires, now).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		claim, err := NewPostgresStore(database).Claim(context.Background(), key, fingerprint, owner, now, expires)
		require.NoError(t, err)
		require.True(t, claim.Claimed)
		require.Equal(t, owner, claim.OwnerToken)
		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("expired", func(t *testing.T) {
		database, mock := newIdempotencySQLMock(t)
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta(insertClaimSQL)).WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(regexp.QuoteMeta(reclaimExpiredCompletedSQL)).
			WithArgs(fingerprint, owner, expires, now, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		claim, err := NewPostgresStore(database).Claim(context.Background(), key, fingerprint, owner, now, expires)
		require.NoError(t, err)
		require.True(t, claim.Claimed)
		require.Equal(t, owner, claim.OwnerToken)
		require.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestPostgresStoreReplaysCompletedAndClassifiesDuplicateClaims(t *testing.T) {
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	expires := now.Add(DefaultTTL)
	key := validKey()
	fingerprint := "sha256:0a9896a42ff3a8f7c9edfe3c97cc1e9d2b6bc06122f89876a49ea3bc4cc51b59"
	owner := "owner-1111111111111111111111111111111111111111111111111111111111111111"
	responseHeaders := []byte(`{"Content-Type":["application/json"],"ETag":["\"8\""]}`)
	responseBody := []byte(`{"id":"job-1","version":8}`)

	for _, test := range []struct {
		name              string
		storedFingerprint string
		state             State
		wantErr           error
		wantReplay        bool
	}{
		{name: "completed replay", storedFingerprint: fingerprint, state: StateCompleted, wantReplay: true},
		{name: "different fingerprint", storedFingerprint: "sha256:70b9d78842924a3f00599c8298f0e6786ea68aa7b6ea5f5f74335c7d26d0579d", state: StateCompleted, wantErr: ErrKeyConflict},
		{name: "processing duplicate", storedFingerprint: fingerprint, state: StateProcessing, wantErr: ErrInProgress},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, mock := newIdempotencySQLMock(t)
			mock.ExpectBegin()
			mock.ExpectExec(regexp.QuoteMeta(insertClaimSQL)).WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectExec(regexp.QuoteMeta(reclaimExpiredCompletedSQL)).WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery(regexp.QuoteMeta(selectRecordSQL)).
				WithArgs(key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey).
				WillReturnRows(sqlmock.NewRows([]string{"request_fingerprint", "state", "response_status", "response_headers", "response_json"}).
					AddRow(test.storedFingerprint, test.state, http.StatusAccepted, responseHeaders, responseBody))
			mock.ExpectCommit()

			claim, err := NewPostgresStore(database).Claim(context.Background(), key, fingerprint, owner, now, expires)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
			} else {
				require.NoError(t, err)
			}
			if test.wantReplay {
				require.NotNil(t, claim.Response)
				require.Empty(t, claim.OwnerToken)
				require.Equal(t, http.StatusAccepted, claim.Response.Status)
				require.Equal(t, `"8"`, claim.Response.Header.Get("ETag"))
				require.Equal(t, responseBody, claim.Response.Body)
			}
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestPostgresStoreNeverReclaimsExpiredProcessingClaim(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	expires := now.Add(DefaultTTL)
	key := validKey()
	fingerprint := "sha256:0a9896a42ff3a8f7c9edfe3c97cc1e9d2b6bc06122f89876a49ea3bc4cc51b59"
	owner := "owner-2222222222222222222222222222222222222222222222222222222222222222"

	database, mock := newIdempotencySQLMock(t)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(insertClaimSQL)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(reclaimExpiredCompletedSQL)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(selectRecordSQL)).
		WillReturnRows(sqlmock.NewRows([]string{"request_fingerprint", "state", "response_status", "response_headers", "response_json"}).
			AddRow(fingerprint, StateProcessing, 0, []byte(`{}`), nil))
	mock.ExpectCommit()

	claim, err := NewPostgresStore(database).Claim(context.Background(), key, fingerprint, owner, now, expires)
	require.ErrorIs(t, err, ErrInProgress)
	require.False(t, claim.Claimed)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreCompletesAndAbortsOnlyMatchingProcessingClaim(t *testing.T) {
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	key := validKey()
	fingerprint := "sha256:0a9896a42ff3a8f7c9edfe3c97cc1e9d2b6bc06122f89876a49ea3bc4cc51b59"
	owner := "owner-1111111111111111111111111111111111111111111111111111111111111111"
	response := Response{Status: http.StatusAccepted, Header: http.Header{"ETag": {`"8"`}}, Body: []byte(`{"id":"job-1"}`)}

	database, mock := newIdempotencySQLMock(t)
	mock.ExpectExec(regexp.QuoteMeta(completeClaimSQL)).
		WithArgs(response.Status, `{"ETag":["\"8\""]}`, response.Body, now, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey, fingerprint, owner).
		WillReturnResult(sqlmock.NewResult(0, 1))

	completed, err := NewPostgresStore(database).Complete(context.Background(), key, fingerprint, owner, response, now)
	require.NoError(t, err)
	require.Equal(t, response, completed)

	mock.ExpectExec(regexp.QuoteMeta(abortClaimSQL)).
		WithArgs(key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey, fingerprint, owner).
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, NewPostgresStore(database).Abort(context.Background(), key, fingerprint, owner))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreRejectsStaleOwnerCompleteAndAbort(t *testing.T) {
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	key := validKey()
	fingerprint := "sha256:0a9896a42ff3a8f7c9edfe3c97cc1e9d2b6bc06122f89876a49ea3bc4cc51b59"
	staleOwner := "owner-1111111111111111111111111111111111111111111111111111111111111111"
	response := Response{Status: http.StatusAccepted, Header: http.Header{"ETag": {`"8"`}}, Body: []byte(`{"id":"job-1"}`)}

	database, mock := newIdempotencySQLMock(t)
	mock.ExpectExec(regexp.QuoteMeta(completeClaimSQL)).WillReturnResult(sqlmock.NewResult(0, 0))
	_, err := NewPostgresStore(database).Complete(context.Background(), key, fingerprint, staleOwner, response, now)
	require.ErrorIs(t, err, ErrOwnershipConflict)

	mock.ExpectExec(regexp.QuoteMeta(abortClaimSQL)).WillReturnResult(sqlmock.NewResult(0, 0))
	err = NewPostgresStore(database).Abort(context.Background(), key, fingerprint, staleOwner)
	require.ErrorIs(t, err, ErrOwnershipConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func newIdempotencySQLMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	return database, mock
}
