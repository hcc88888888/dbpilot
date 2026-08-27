package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"

	"dbpilot.local/platform/internal/platformscope"
)

const (
	DefaultListLimit = 50
	MaximumListLimit = 100
)

type Store interface {
	Append(context.Context, Event) error
	List(context.Context, platformscope.Scope, StoreListQuery) ([]Event, error)
}

type Service struct {
	store Store
	now   func() time.Time
	newID func() (string, error)
}

func NewService(store Store) *Service {
	return &Service{store: store, now: time.Now, newID: newAuditID}
}

func (service *Service) Record(ctx context.Context, input Event) (Event, error) {
	if service == nil || service.store == nil || ctx == nil {
		return Event{}, ErrInvalidEvent
	}
	if input.ID != "" {
		return Event{}, ErrImmutableID
	}
	if err := validateDraft(input); err != nil {
		return Event{}, err
	}
	detail, err := sanitizeDetailMap(input.Detail)
	if err != nil {
		return Event{}, err
	}
	id, err := service.newID()
	if err != nil {
		return Event{}, fmt.Errorf("generate audit event ID: %w", err)
	}
	now := service.currentTime()
	input.ID = id
	if input.OccurredAt.IsZero() {
		input.OccurredAt = now
	} else {
		input.OccurredAt = input.OccurredAt.UTC()
	}
	input.CreatedAt = now
	input.Detail = detail
	if err := service.store.Append(ctx, cloneEvent(input)); err != nil {
		return Event{}, err
	}
	return cloneEvent(input), nil
}

func (service *Service) List(ctx context.Context, scope platformscope.Scope, query ListQuery) (Page, error) {
	if service == nil || service.store == nil || ctx == nil || scope.Validate() != nil || query.Limit < 0 || query.Limit > MaximumListLimit {
		return Page{}, ErrInvalidEvent
	}
	limit := query.Limit
	if limit == 0 {
		limit = DefaultListLimit
	}
	storeQuery := StoreListQuery{Limit: limit + 1}
	if query.Cursor != "" {
		cursor, err := decodeCursor(query.Cursor)
		if err != nil || cursor.Scope != scope || cursor.CreatedAt.IsZero() || strings.TrimSpace(cursor.ID) == "" {
			return Page{}, ErrInvalidCursor
		}
		storeQuery.After = cursor.CreatedAt.UTC()
		storeQuery.AfterID = cursor.ID
	}
	items, err := service.store.List(ctx, scope, storeQuery)
	if err != nil {
		return Page{}, err
	}
	for index := range items {
		if items[index].Scope != scope {
			return Page{}, ErrInvalidCursor
		}
		detail, err := normalizeSanitizedDetailMap(items[index].Detail)
		if err != nil {
			return Page{}, err
		}
		items[index].Detail = detail
		items[index] = cloneEvent(items[index])
		items[index].OccurredAt = items[index].OccurredAt.UTC()
		items[index].CreatedAt = items[index].CreatedAt.UTC()
	}
	page := Page{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor, err = encodeCursor(cursorValue{Scope: scope, CreatedAt: last.CreatedAt, ID: last.ID})
		if err != nil {
			return Page{}, err
		}
	}
	if page.Items == nil {
		page.Items = []Event{}
	}
	return page, nil
}

func validateDraft(value Event) error {
	if value.Scope.Validate() != nil || !canonical(value.Actor.Type) || !canonical(value.Actor.ID) || !canonical(value.Action) || !canonical(value.Resource.Type) || !canonical(value.Resource.ID) || !canonical(value.Result) || !canonical(value.RequestID) {
		return ErrInvalidEvent
	}
	return nil
}

func validateStored(value Event) error {
	if !canonical(value.ID) || value.OccurredAt.IsZero() || value.CreatedAt.IsZero() {
		return ErrInvalidEvent
	}
	copy := value
	copy.ID = ""
	return validateDraft(copy)
}

func canonical(value string) bool {
	return value != "" && value == strings.TrimSpace(value)
}

func sanitizeDetailMap(detail map[string]any) (map[string]any, error) {
	normalized, err := normalizeDetailMap(detail)
	if err != nil {
		return nil, err
	}
	return sanitizeMap(normalized)
}

func sanitizeMap(input map[string]any) (map[string]any, error) {
	result := make(map[string]any, len(input))
	evidence := make([]any, 0)
	keys := sortedMapKeys(input)
	for _, key := range keys {
		value := input[key]
		if reservedSQLDerivedKey(key) {
			return nil, ErrInvalidEvent
		}
		if sensitiveKey(key) {
			return nil, ErrSensitiveDetail
		}
		if sqlKey(key) {
			statement, ok := value.(string)
			if !ok || strings.TrimSpace(statement) == "" {
				return nil, ErrInvalidEvent
			}
			digest := sha256.Sum256([]byte(statement))
			evidence = append(evidence, map[string]any{
				"source_field": key,
				"digest":       "sha256:" + hex.EncodeToString(digest[:]),
				"summary":      sqlSummary(statement),
			})
			continue
		}
		sanitized, err := sanitizeValue(value)
		if err != nil {
			return nil, err
		}
		result[key] = sanitized
	}
	if len(evidence) > 0 {
		result["sql_evidence"] = evidence
	}
	return result, nil
}

func sanitizeValue(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		return sanitizeMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index := range typed {
			value, err := sanitizeValue(typed[index])
			if err != nil {
				return nil, err
			}
			result[index] = value
		}
		return result, nil
	case string:
		if containsCredentialMaterial(typed) {
			return nil, ErrSensitiveDetail
		}
		return typed, nil
	default:
		return typed, nil
	}
}

func sensitiveKey(key string) bool {
	normalized := normalizeKey(key)
	for _, marker := range []string{"password", "passwd", "token", "credential", "secret", "authorization", "api_key"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func sqlKey(key string) bool {
	switch normalizeKey(key) {
	case "sql", "sql_text", "query", "statement":
		return true
	default:
		return false
	}
}

func reservedSQLDerivedKey(key string) bool {
	switch normalizeKey(key) {
	case "sql_evidence", "sql_digest", "sql_summary":
		return true
	default:
		return false
	}
}

func normalizeKey(key string) string {
	return strings.ToLower(strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			return character
		}
		return '_'
	}, key))
}

func containsCredentialMaterial(value string) bool {
	normalized := strings.ToLower(value)
	for _, marker := range []string{"password=", "passwd=", "token=", "credential=", "secret=", "authorization:", "bearer ", "secret://", "postgres://", "postgresql://", "mysql://"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func sqlSummary(statement string) string {
	fields := strings.Fields(statement)
	if len(fields) == 0 {
		return "SQL statement"
	}
	verb := strings.ToUpper(strings.Trim(fields[0], "();"))
	switch verb {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP", "EXPLAIN", "WITH", "CALL":
		return verb + " statement"
	default:
		return "SQL statement"
	}
}

func cloneEvent(value Event) Event {
	if value.Detail == nil {
		value.Detail = map[string]any{}
		return value
	}
	value.Detail = cloneDetailMap(value.Detail)
	return value
}

func cloneDetailMap(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = cloneDetailValue(value)
	}
	return result
}

func cloneDetailValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneDetailMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index := range typed {
			result[index] = cloneDetailValue(typed[index])
		}
		return result
	default:
		return typed
	}
}

func normalizeDetailMap(detail map[string]any) (map[string]any, error) {
	if detail == nil {
		return map[string]any{}, nil
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return nil, ErrInvalidEvent
	}
	return decodeCanonicalDetail(encoded)
}

func decodeCanonicalDetail(encoded []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var normalized map[string]any
	if err := decoder.Decode(&normalized); err != nil || normalized == nil {
		return nil, ErrInvalidEvent
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, ErrInvalidEvent
	}
	return normalized, nil
}

func normalizeSanitizedDetailMap(detail map[string]any) (map[string]any, error) {
	normalized, err := normalizeDetailMap(detail)
	if err != nil {
		return nil, err
	}
	if err := validateSanitizedMap(normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func validateSanitizedMap(input map[string]any) error {
	for _, key := range sortedMapKeys(input) {
		value := input[key]
		if sensitiveKey(key) {
			return ErrSensitiveDetail
		}
		switch normalizeKey(key) {
		case "sql_digest", "sql_summary":
			return ErrInvalidEvent
		case "sql_evidence":
			if err := validateSQLEvidence(value); err != nil {
				return err
			}
			continue
		}
		if sqlKey(key) {
			return ErrInvalidEvent
		}
		if err := validateSanitizedValue(value); err != nil {
			return err
		}
	}
	return nil
}

func validateSanitizedValue(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		return validateSanitizedMap(typed)
	case []any:
		for _, item := range typed {
			if err := validateSanitizedValue(item); err != nil {
				return err
			}
		}
	case string:
		if containsCredentialMaterial(typed) {
			return ErrSensitiveDetail
		}
	}
	return nil
}

func validateSQLEvidence(value any) error {
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return ErrInvalidEvent
	}
	previous := ""
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok || len(entry) != 3 {
			return ErrInvalidEvent
		}
		source, sourceOK := entry["source_field"].(string)
		digest, digestOK := entry["digest"].(string)
		summary, summaryOK := entry["summary"].(string)
		if !sourceOK || !digestOK || !summaryOK || !sqlKey(source) || source <= previous || !validSQLDigest(digest) || !validSQLSummary(summary) {
			return ErrInvalidEvent
		}
		previous = source
	}
	return nil
}

func validSQLDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validSQLSummary(value string) bool {
	switch value {
	case "SELECT statement", "INSERT statement", "UPDATE statement", "DELETE statement", "CREATE statement", "ALTER statement", "DROP statement", "EXPLAIN statement", "WITH statement", "CALL statement", "SQL statement":
		return true
	default:
		return false
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrInvalidEvent
	}
	return nil
}

func sortedMapKeys(input map[string]any) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func newAuditID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return "audit-" + hex.EncodeToString(bytes), nil
}

func (service *Service) currentTime() time.Time {
	if service.now == nil {
		return time.Now().UTC()
	}
	return service.now().UTC()
}

type cursorValue struct {
	Scope     platformscope.Scope `json:"scope"`
	CreatedAt time.Time           `json:"created_at"`
	ID        string              `json:"id"`
}

func encodeCursor(value cursorValue) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeCursor(value string) (cursorValue, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return cursorValue{}, err
	}
	var cursor cursorValue
	if err := json.Unmarshal(encoded, &cursor); err != nil {
		return cursorValue{}, err
	}
	return cursor, nil
}
