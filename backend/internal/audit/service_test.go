package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
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

func TestRecordOnceReturnsExistingEquivalentEventWithoutSecondAppend(t *testing.T) {
	store := &memoryStore{once: make(map[string]Event)}
	service := NewService(store)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	nextID := 0
	service.newID = func() (string, error) { nextID++; return fmt.Sprintf("audit-%d", nextID), nil }
	input := validEvent()
	input.DedupeKey = "command.delivery_timed_out:command-1"
	input.CommandID = "command-1"
	input.JobID = "job-1"

	first, err := service.RecordOnce(context.Background(), input)
	require.NoError(t, err)
	second, err := service.RecordOnce(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, first.ID, second.ID)
	require.Len(t, store.appended, 1)
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
	nested := requireDetailMap(t, got.Detail["operation"])
	evidence := requireDetailSlice(t, nested["sql_evidence"])
	require.Len(t, evidence, 1)
	item := requireDetailMap(t, evidence[0])
	require.Equal(t, "sql_text", item["source_field"])
	require.Equal(t, "SELECT statement", item["summary"])
	require.Regexp(t, `^sha256:[0-9a-f]{64}$`, item["digest"])
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

func TestRecordNormalizesEveryJSONSerializableShapeBeforeRedaction(t *testing.T) {
	type secretStruct struct {
		Credential string `json:"credential"`
	}
	tests := map[string]any{
		"typed map":     map[string]string{"password": "hunter2"},
		"typed slice":   []secretStruct{{Credential: "secret://db/prod"}},
		"struct":        secretStruct{Credential: "secret://db/prod"},
		"pointer":       &secretStruct{Credential: "secret://db/prod"},
		"raw message":   json.RawMessage(`{"nested":{"access_token":"hunter2"}}`),
		"nested shapes": map[string][]*secretStruct{"items": {{Credential: "secret://db/prod"}}},
	}
	for name, shape := range tests {
		t.Run(name, func(t *testing.T) {
			value := validEvent()
			value.Detail = map[string]any{"payload": shape}
			_, err := NewService(&memoryStore{}).Record(context.Background(), value)
			require.ErrorIs(t, err, ErrSensitiveDetail)
		})
	}
}

func TestRecordRejectsPrivateKeysDSNsPEMAndCredentialConnectionURIsAtAnyDepth(t *testing.T) {
	tests := map[string]map[string]any{
		"private_key key": {"nested": map[string]any{"private_key": "opaque"}},
		"privatekey key":  {"items": []any{map[string]any{"privatekey": "opaque"}}},
		"dsn key":         {"config": map[string]any{"dsn": "opaque"}},
		"PEM block":       {"nested": map[string]any{"value": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"}},
		"MongoDB URI":     {"value": "mongodb://dbuser:dbpass@mongo.example/app"},
		"MongoDB SRV URI": {"value": "mongodb+srv://dbuser:dbpass@mongo.example/app"},
		"Neo4j URI":       {"value": "neo4j://graph:secret@graph.example"},
		"Redis URI":       {"value": "redis://default:secret@cache.example/0"},
		"generic URI":     {"value": "https://user:secret@database.example/connect"},
	}
	for name, detail := range tests {
		t.Run(name, func(t *testing.T) {
			value := validEvent()
			value.Detail = detail
			_, err := NewService(&memoryStore{}).Record(context.Background(), value)
			require.ErrorIs(t, err, ErrSensitiveDetail)
			require.NotContains(t, err.Error(), "secret")
			require.NotContains(t, err.Error(), "dbpass")
		})
	}
}

func TestRecordRedactsSQLInsideTypedAndRawJSONShapes(t *testing.T) {
	type queryStruct struct {
		SQL string `json:"sql_text"`
	}
	value := validEvent()
	value.Detail = map[string]any{
		"typed": []queryStruct{{SQL: "select * from accounts"}},
		"raw":   json.RawMessage(`{"statement":"delete from sessions"}`),
	}

	got, err := NewService(&memoryStore{}).Record(context.Background(), value)
	require.NoError(t, err)
	typedItems := requireDetailSlice(t, got.Detail["typed"])
	typedEvidence := requireDetailSlice(t, requireDetailMap(t, typedItems[0])["sql_evidence"])
	rawEvidence := requireDetailSlice(t, requireDetailMap(t, got.Detail["raw"])["sql_evidence"])
	require.Equal(t, "SELECT statement", requireDetailMap(t, typedEvidence[0])["summary"])
	require.Equal(t, "DELETE statement", requireDetailMap(t, rawEvidence[0])["summary"])
	require.NotContains(t, got.Detail, "select * from accounts")
}

func TestRecordDeepCopiesNormalizedTypedValuesAcrossAllBoundaries(t *testing.T) {
	type payload struct {
		Items []map[string]string `json:"items"`
	}
	original := &payload{Items: []map[string]string{{"status": "before"}}}
	value := validEvent()
	value.Detail = map[string]any{"payload": original}
	store := &memoryStore{}

	got, err := NewService(store).Record(context.Background(), value)
	require.NoError(t, err)
	original.Items[0]["status"] = "mutated-input"
	returnedPayload := requireDetailMap(t, got.Detail["payload"])
	returnedItems := requireDetailSlice(t, returnedPayload["items"])
	requireDetailMap(t, returnedItems[0])["status"] = "mutated-return"

	storedPayload := requireDetailMap(t, store.appended[0].Detail["payload"])
	storedItems := requireDetailSlice(t, storedPayload["items"])
	stored := requireDetailMap(t, storedItems[0])
	require.Equal(t, "before", stored["status"])
}

func TestRecordProducesDeterministicEvidenceForEverySQLField(t *testing.T) {
	first := validEvent()
	first.Detail = map[string]any{"statement": "delete from sessions", "safe": "value", "sql_text": "select * from accounts"}
	second := validEvent()
	second.Detail = map[string]any{"sql_text": "select * from accounts", "safe": "value", "statement": "delete from sessions"}

	firstGot, err := NewService(&memoryStore{}).Record(context.Background(), first)
	require.NoError(t, err)
	secondGot, err := NewService(&memoryStore{}).Record(context.Background(), second)
	require.NoError(t, err)
	require.Equal(t, firstGot.Detail, secondGot.Detail)
	evidence := requireDetailSlice(t, firstGot.Detail["sql_evidence"])
	require.Len(t, evidence, 2)
	require.Equal(t, "sql_text", requireDetailMap(t, evidence[0])["source_field"])
	require.Equal(t, "statement", requireDetailMap(t, evidence[1])["source_field"])
	encoded, err := json.Marshal(firstGot.Detail)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "select * from accounts")
	require.NotContains(t, string(encoded), "delete from sessions")
}

func TestRecordRejectsCallerSuppliedSQLDerivedFields(t *testing.T) {
	for _, key := range []string{"sql_evidence", "sql_digest", "sql_summary"} {
		value := validEvent()
		value.Detail = map[string]any{key: "caller-controlled", "sql_text": "select 1"}
		_, err := NewService(&memoryStore{}).Record(context.Background(), value)
		require.ErrorIs(t, err, ErrInvalidEvent)
	}
}

func TestRecordRejectsEveryNonStringSQLFieldAtRootAndNestedDepth(t *testing.T) {
	values := map[string]struct {
		key   string
		value any
	}{
		"typed slice": {key: "query", value: []string{"select password from users"}},
		"object":      {key: "sql", value: map[string]any{"text": "select password from users"}},
		"number":      {key: "statement", value: 7},
		"boolean":     {key: "sql_text", value: true},
		"null":        {key: "query", value: nil},
	}
	for name, fixture := range values {
		for _, nested := range []bool{false, true} {
			depth := "root"
			detail := map[string]any{fixture.key: fixture.value}
			if nested {
				depth = "nested"
				detail = map[string]any{"operation": detail}
			}
			t.Run(name+"/"+depth, func(t *testing.T) {
				value := validEvent()
				value.Detail = detail
				_, err := NewService(&memoryStore{}).Record(context.Background(), value)
				require.ErrorIs(t, err, ErrInvalidEvent)
			})
		}
	}
}

func TestRecordAcceptsStringForEverySQLFieldName(t *testing.T) {
	for _, key := range []string{"sql", "query", "statement", "sql_text"} {
		value := validEvent()
		value.Detail = map[string]any{key: "select 1"}

		got, err := NewService(&memoryStore{}).Record(context.Background(), value)
		require.NoError(t, err)
		evidence := requireDetailSlice(t, got.Detail["sql_evidence"])
		require.Equal(t, key, requireDetailMap(t, evidence[0])["source_field"])
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

func TestListNormalizesAndCopiesTypedStoredDetail(t *testing.T) {
	type payload struct {
		Labels map[string]string `json:"labels"`
	}
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	created := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	original := &payload{Labels: map[string]string{"status": "before"}}
	store := &memoryStore{listed: []Event{{ID: "audit-1", Scope: scope, OccurredAt: created, CreatedAt: created, Detail: map[string]any{"payload": original}}}}

	page, err := NewService(store).List(context.Background(), scope, ListQuery{Limit: 10})
	require.NoError(t, err)
	returned := requireDetailMap(t, page.Items[0].Detail["payload"])
	requireDetailMap(t, returned["labels"])["status"] = "mutated-return"

	require.Equal(t, "before", original.Labels["status"])
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
	once     map[string]Event
}

func (store *memoryStore) AppendOnce(_ context.Context, value Event) (Event, error) {
	if existing, ok := store.once[value.DedupeKey]; ok {
		if existing.Action != value.Action || existing.Resource != value.Resource || existing.CommandID != value.CommandID || existing.JobID != value.JobID || !reflect.DeepEqual(existing.Detail, value.Detail) {
			return Event{}, ErrDedupeConflict
		}
		return existing, nil
	}
	store.once[value.DedupeKey] = value
	store.appended = append(store.appended, value)
	return value, nil
}

func (store *memoryStore) Append(_ context.Context, value Event) error {
	store.appended = append(store.appended, value)
	return nil
}

func (store *memoryStore) List(_ context.Context, _ platformscope.Scope, _ StoreListQuery) ([]Event, error) {
	return append([]Event(nil), store.listed...), nil
}

func requireDetailMap(t *testing.T, value any) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	require.True(t, ok, "expected canonical JSON object, got %T", value)
	return result
}

func requireDetailSlice(t *testing.T, value any) []any {
	t.Helper()
	result, ok := value.([]any)
	require.True(t, ok, "expected canonical JSON array, got %T", value)
	return result
}
