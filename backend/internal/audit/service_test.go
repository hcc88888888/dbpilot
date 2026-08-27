package audit

import (
	"context"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestRecordRejectsMissingRequiredIdentityFields(t *testing.T) {
	valid := Event{
		Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		Actor: Actor{Type: "user", ID: "operator-1"}, Action: "inspection.started",
		Resource: Resource{Type: "inspection", ID: "inspection-1"}, Result: "accepted", RequestID: "request-1",
	}
	for name, mutate := range map[string]func(*Event){
		"actor":    func(value *Event) { value.Actor = Actor{} },
		"action":   func(value *Event) { value.Action = "" },
		"resource": func(value *Event) { value.Resource = Resource{} },
		"result":   func(value *Event) { value.Result = "" },
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			_, err := NewService(&memoryStore{}).Record(context.Background(), value)
			require.ErrorIs(t, err, ErrInvalidEvent)
		})
	}
}

func TestRecordRedactsSQLRecursivelyAndRejectsCredentialKeys(t *testing.T) {
	store := &memoryStore{}
	now := time.Date(2026, 8, 28, 20, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	service := NewService(store)
	service.now = func() time.Time { return now }
	service.newID = func() (string, error) { return "audit-fixed", nil }
	input := validEvent()
	input.Detail = map[string]any{"operation": map[string]any{"sql_text": "select password from users where id = 7"}}

	got, err := service.Record(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, "audit-fixed", got.ID)
	require.Equal(t, time.UTC, got.OccurredAt.Location())
	require.Equal(t, now.UTC(), got.OccurredAt)
	nested := got.Detail["operation"].(map[string]any)
	require.Equal(t, "SELECT statement", nested["sql_summary"])
	require.Regexp(t, `^sha256:[0-9a-f]{64}$`, nested["sql_digest"])
	require.NotContains(t, nested, "sql_text")
	require.Equal(t, got, store.appended[0])

	for _, detail := range []map[string]any{
		{"password": "secret"},
		{"nested": map[string]any{"access_token": "secret"}},
		{"items": []any{map[string]any{"credential_ref": "secret://db/prod"}}},
	} {
		input := validEvent()
		input.Detail = detail
		_, err := service.Record(context.Background(), input)
		require.ErrorIs(t, err, ErrSensitiveDetail)
	}
}

func TestRecordRejectsCallerSuppliedImmutableID(t *testing.T) {
	value := validEvent()
	value.ID = "caller-controlled"
	_, err := NewService(&memoryStore{}).Record(context.Background(), value)
	require.ErrorIs(t, err, ErrImmutableID)
}

func TestRecordRejectsDetailThatCannotBePersistedAsJSON(t *testing.T) {
	value := validEvent()
	value.Detail = map[string]any{"callback": func() {}}

	_, err := NewService(&memoryStore{}).Record(context.Background(), value)
	require.ErrorIs(t, err, ErrInvalidEvent)
}

func TestListCursorCannotCrossTenantOrProjectScope(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	created := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	store := &memoryStore{listed: []Event{{ID: "audit-1", Scope: scope, OccurredAt: created, CreatedAt: created}, {ID: "audit-2", Scope: scope, OccurredAt: created.Add(time.Second), CreatedAt: created.Add(time.Second)}}}
	service := NewService(store)
	page, err := service.List(context.Background(), scope, ListQuery{Limit: 1})
	require.NoError(t, err)
	require.NotEmpty(t, page.NextCursor)

	_, err = service.List(context.Background(), platformscope.Scope{TenantID: scope.TenantID, ProjectID: "project-2"}, ListQuery{Cursor: page.NextCursor, Limit: 1})
	require.ErrorIs(t, err, ErrInvalidCursor)
}

func validEvent() Event {
	return Event{
		Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		Actor: Actor{Type: "user", ID: "operator-1"}, Action: "inspection.started",
		Resource: Resource{Type: "inspection", ID: "inspection-1"}, Result: "accepted", RequestID: "request-1",
	}
}

type memoryStore struct {
	appended []Event
	listed   []Event
}

func (store *memoryStore) Append(_ context.Context, value Event) error {
	store.appended = append(store.appended, value)
	return nil
}

func (store *memoryStore) List(_ context.Context, _ platformscope.Scope, _ StoreListQuery) ([]Event, error) {
	return append([]Event(nil), store.listed...), nil
}
