package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"github.com/stretchr/testify/require"
)

func TestRuleCreateRejectsPrincipalOutsideProjectBeforeServiceCall(t *testing.T) {
	fixture := newHTTPFixture()
	response := fixture.request(http.MethodPost, "/api/v1/tenants/t1/projects/p2/rules", memberFor("t1", "p1"), validRuleBody())
	require.Equal(t, http.StatusForbidden, response.Code)
	require.Zero(t, fixture.repository.calls)
}

func TestRuleResponsesSerializeLongDurationsAsLosslessStrings(t *testing.T) {
	fixture := newHTTPFixture()
	rule := fixture.repository.rules["rule-1"]
	rule.EvaluationEvery = time.Duration(9_072_000_000_000_000)
	rule.LookbackWindow = time.Duration(9_223_372_036_854_775_807)
	rule.For = time.Duration(9_223_372_036_854_775_807)
	fixture.repository.rules[rule.ID] = rule

	response := fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/rules/rule-1", memberFor("t1", "p1"), nil)
	require.Equal(t, http.StatusOK, response.Code)

	var output struct {
		EvaluationEvery string `json:"evaluation_every"`
		LookbackWindow  string `json:"lookback_window"`
		For             string `json:"for"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &output))
	require.Equal(t, "2520h0m0s", output.EvaluationEvery)
	require.Equal(t, "2562047h47m16.854775807s", output.LookbackWindow)
	require.Equal(t, "2562047h47m16.854775807s", output.For)

	var input ruleInput
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &input))
	roundTripped := input.value(fixture.scope, rule.ID)
	require.Equal(t, rule.EvaluationEvery, roundTripped.EvaluationEvery)
	require.Equal(t, rule.LookbackWindow, roundTripped.LookbackWindow)
	require.Equal(t, rule.For, roundTripped.For)
}

func TestEventAcknowledgeWritesActorAndReturnsScopedEvent(t *testing.T) {
	fixture := newHTTPFixture()
	response := fixture.request(http.MethodPost, "/api/v1/tenants/t1/projects/p1/alerts/event-1/acknowledge", memberFor("t1", "p1"), []byte(`{"category":"investigating","reason":"operator accepted the incident"}`))
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "actor-1", fixture.repository.lastAudit.Actor)
	require.Equal(t, "event.acknowledged", fixture.repository.lastAudit.Action)
	require.Equal(t, alert.DispositionAcknowledgement, fixture.repository.lastDisposition.Kind)
	require.Equal(t, "operator accepted the incident", fixture.repository.lastDisposition.Reason)
	var event alert.AlertEvent
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &event))
	require.Equal(t, alert.EventAcknowledged, event.State)
	require.Equal(t, fixture.scope, event.Scope)
}

func TestEventRootCauseCluesAreAppendOnlyScopedAndPaginated(t *testing.T) {
	fixture := newHTTPFixture()
	response := fixture.request(http.MethodPost, "/api/v1/tenants/t1/projects/p1/alerts/event-1/root-cause", memberFor("t1", "p1"), []byte(`{"category":"database_capacity","reason":"connection pool exhausted"}`))
	require.Equal(t, http.StatusCreated, response.Code)
	require.Equal(t, alert.DispositionRootCause, fixture.repository.lastDisposition.Kind)
	require.Equal(t, "event.root_cause", fixture.repository.lastAudit.Action)

	response = fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/alerts/event-1/dispositions?limit=1&offset=0", memberFor("t1", "p1"), nil)
	require.Equal(t, http.StatusOK, response.Code)
	var values []alert.EventDisposition
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &values))
	require.Len(t, values, 1)
	require.Equal(t, "actor-1", values[0].Actor)
}

func TestAlertOverviewContainsEventCountsAndEvaluatorHealth(t *testing.T) {
	fixture := newHTTPFixture()
	response := fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/overview", memberFor("t1", "p1"), nil)
	require.Equal(t, http.StatusOK, response.Code)
	require.JSONEq(t, `{"events":{"firing":1},"evaluator":{"healthy":true}}`, response.Body.String())
}

func TestAlertOverviewUsesOnlyRequestedScopeEvaluatorHealth(t *testing.T) {
	fixture := newHTTPFixture()
	handler := NewHTTPHandler(Services{Repository: fixture.repository, Evaluator: scopedEvaluator{
		global:  alert.EvaluatorHealth{FailedRules: 1, LastError: "one or more alert rules failed"},
		byScope: map[string]alert.EvaluatorHealth{fixture.scope.Key(): {}},
	}, Now: func() time.Time { return fixture.repository.now }}, memberFor("t1", "p1"))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/projects/p1/overview", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"healthy":true`)
}

func TestAlertOverviewCountsMoreThanOnePageOfEvents(t *testing.T) {
	fixture := newHTTPFixture()
	fixture.repository.events = make(map[string]alert.AlertEvent, 501)
	for index := 0; index < 501; index++ {
		id := fmt.Sprintf("event-%04d", index)
		fixture.repository.events[id] = alert.AlertEvent{ID: id, Scope: fixture.scope, State: alert.EventFiring}
	}
	response := fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/overview", memberFor("t1", "p1"), nil)
	require.Equal(t, http.StatusOK, response.Code)
	require.JSONEq(t, `{"events":{"firing":501},"evaluator":{"healthy":true}}`, response.Body.String())
}

func TestHTTPHandlerCoversScopedAlertConfigurationRoutes(t *testing.T) {
	tests := []struct {
		method string
		path   string
		body   []byte
		status int
	}{
		{http.MethodGet, "/api/v1/tenants/t1/projects/p1/alerts", nil, http.StatusOK},
		{http.MethodGet, "/api/v1/tenants/t1/projects/p1/alerts/event-1", nil, http.StatusOK},
		{http.MethodGet, "/api/v1/tenants/t1/projects/p1/alerts/event-1/deliveries", nil, http.StatusOK},
		{http.MethodGet, "/api/v1/tenants/t1/projects/p1/rules", nil, http.StatusOK},
		{http.MethodPost, "/api/v1/tenants/t1/projects/p1/rules", validRuleBody(), http.StatusCreated},
		{http.MethodGet, "/api/v1/tenants/t1/projects/p1/rules/rule-1", nil, http.StatusOK},
		{http.MethodPut, "/api/v1/tenants/t1/projects/p1/rules/rule-1", validRuleBody(), http.StatusOK},
		{http.MethodPost, "/api/v1/tenants/t1/projects/p1/rules/rule-1/enable", []byte(`{"enabled":false}`), http.StatusOK},
		{http.MethodDelete, "/api/v1/tenants/t1/projects/p1/rules/rule-1", nil, http.StatusNoContent},
		{http.MethodGet, "/api/v1/tenants/t1/projects/p1/policies", nil, http.StatusOK},
		{http.MethodPost, "/api/v1/tenants/t1/projects/p1/policies", validPolicyBody(), http.StatusCreated},
		{http.MethodGet, "/api/v1/tenants/t1/projects/p1/policies/policy-1", nil, http.StatusOK},
		{http.MethodPut, "/api/v1/tenants/t1/projects/p1/policies/policy-1", validPolicyBody(), http.StatusOK},
		{http.MethodDelete, "/api/v1/tenants/t1/projects/p1/policies/policy-1", nil, http.StatusNoContent},
		{http.MethodGet, "/api/v1/tenants/t1/projects/p1/templates", nil, http.StatusOK},
		{http.MethodPost, "/api/v1/tenants/t1/projects/p1/templates", validTemplateBody(), http.StatusCreated},
		{http.MethodGet, "/api/v1/tenants/t1/projects/p1/templates/template-1", nil, http.StatusOK},
		{http.MethodPut, "/api/v1/tenants/t1/projects/p1/templates/template-1", validTemplateBody(), http.StatusOK},
		{http.MethodDelete, "/api/v1/tenants/t1/projects/p1/templates/template-1", nil, http.StatusNoContent},
		{http.MethodGet, "/api/v1/tenants/t1/projects/p1/silences", nil, http.StatusOK},
		{http.MethodPost, "/api/v1/tenants/t1/projects/p1/silences", validSilenceBody(), http.StatusCreated},
		{http.MethodGet, "/api/v1/tenants/t1/projects/p1/silences/silence-1", nil, http.StatusOK},
		{http.MethodPut, "/api/v1/tenants/t1/projects/p1/silences/silence-1", validSilenceBody(), http.StatusOK},
		{http.MethodDelete, "/api/v1/tenants/t1/projects/p1/silences/silence-1", nil, http.StatusNoContent},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			fixture := newHTTPFixture()
			response := fixture.request(test.method, test.path, memberFor("t1", "p1"), test.body)
			require.Equal(t, test.status, response.Code, response.Body.String())
		})
	}
}

func TestHTTPHandlerRejectsAuthenticationScopeAndMalformedJSONConsistently(t *testing.T) {
	fixture := newHTTPFixture()
	tests := []struct {
		name      string
		resolver  PrincipalResolver
		path      string
		body      []byte
		wantCode  int
		wantError string
	}{
		{"unauthenticated", errorPrincipalResolver{ErrUnauthenticated}, "/api/v1/tenants/t1/projects/p1/rules", nil, http.StatusUnauthorized, "unauthenticated"},
		{"forbidden", memberFor("t1", "p2"), "/api/v1/tenants/t1/projects/p1/rules", nil, http.StatusForbidden, "forbidden"},
		{"unknown field", memberFor("t1", "p1"), "/api/v1/tenants/t1/projects/p1/rules", []byte(`{"unknown":true}`), http.StatusBadRequest, "invalid_request"},
		{"body scope", memberFor("t1", "p1"), "/api/v1/tenants/t1/projects/p1/rules", []byte(`{"scope":{"tenant_id":"other","project_id":"other"}}`), http.StatusBadRequest, "invalid_request"},
		{"trailing JSON", memberFor("t1", "p1"), "/api/v1/tenants/t1/projects/p1/rules", append(validRuleBody(), []byte(` {}`)...), http.StatusBadRequest, "invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := NewHTTPHandler(Services{Repository: fixture.repository, Evaluator: healthyEvaluator{}}, test.resolver)
			request := httptest.NewRequest(http.MethodPost, test.path, bytes.NewReader(test.body))
			if test.body != nil {
				request.Header.Set("Content-Type", "application/json")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			require.Equal(t, test.wantCode, response.Code)
			require.Contains(t, response.Body.String(), `"code":"`+test.wantError+`"`)
		})
	}
}

func TestHTTPHandlerNormalizesRouterErrorsAsJSON(t *testing.T) {
	fixture := newHTTPFixture()
	for name, test := range rangeRouterErrorCases() {
		t.Run(name, func(t *testing.T) {
			response := fixture.request(test.method, test.path, memberFor("t1", "p1"), nil)
			require.Equal(t, test.wantStatus, response.Code)
			require.Equal(t, "application/json", response.Header().Get("Content-Type"))
			require.Contains(t, response.Body.String(), `"code":"`+test.wantCode+`"`)
		})
	}
}

func rangeRouterErrorCases() map[string]struct {
	method, path string
	wantStatus   int
	wantCode     string
} {
	return map[string]struct {
		method, path string
		wantStatus   int
		wantCode     string
	}{
		"wrong method":   {http.MethodPatch, "/api/v1/tenants/t1/projects/p1/rules", http.StatusMethodNotAllowed, "method_not_allowed"},
		"unknown path":   {http.MethodGet, "/api/v1/does-not-exist", http.StatusNotFound, "not_found"},
		"abnormal slash": {http.MethodGet, "/api/v1/tenants/t1/projects//rules", http.StatusNotFound, "not_found"},
	}
}

func TestJSONEndpointsRequireMediaTypeAndClassifyOversize(t *testing.T) {
	fixture := newHTTPFixture()
	path := "/api/v1/tenants/t1/projects/p1/rules"
	handler := NewHTTPHandler(Services{Repository: fixture.repository, Evaluator: healthyEvaluator{}}, memberFor("t1", "p1"))

	for _, mediaType := range []string{"", "text/plain"} {
		request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(validRuleBody()))
		request.Header.Set("Content-Type", mediaType)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		require.Equal(t, http.StatusUnsupportedMediaType, response.Code)
		require.Contains(t, response.Body.String(), `"code":"unsupported_media_type"`)
	}

	oversize := []byte(`{"name":"` + strings.Repeat("a", int(maxJSONBodyBytes)) + `"}`)
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(oversize))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusRequestEntityTooLarge, response.Code)
	require.Contains(t, response.Body.String(), `"code":"payload_too_large"`)
}

func TestHTTPHandlerReturnsScopedNotFoundAndRedactsSecrets(t *testing.T) {
	fixture := newHTTPFixture()
	missing := fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/alerts/missing", memberFor("t1", "p1"), nil)
	require.Equal(t, http.StatusNotFound, missing.Code)

	policy := fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/policies/policy-1", memberFor("t1", "p1"), nil)
	require.Equal(t, http.StatusOK, policy.Code)
	require.NotContains(t, policy.Body.String(), "env://DBPILOT_WEBHOOK_TOKEN")
	require.Contains(t, policy.Body.String(), `"has_secret":true`)

	deliveries := fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/alerts/event-1/deliveries", memberFor("t1", "p1"), nil)
	require.Equal(t, http.StatusOK, deliveries.Code)
	require.Contains(t, deliveries.Body.String(), `"event_state":"firing"`)
	require.NotContains(t, deliveries.Body.String(), "env://DBPILOT_WEBHOOK_TOKEN")
	require.NotContains(t, deliveries.Body.String(), "request_body")
}

func TestHealthAndReadySeparateLivenessFromDependencyReadiness(t *testing.T) {
	fixture := newHTTPFixture()
	handler := NewHTTPHandler(Services{Repository: fixture.repository, Evaluator: healthyEvaluator{}, Ready: func(context.Context) error { return errors.New("database unavailable") }}, memberFor("t1", "p1"))
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusOK, health.Code)
	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, ready.Code)
	require.Contains(t, ready.Body.String(), `"code":"not_ready"`)
}

func TestHTTPHandlerNeverSerializesRepositoryRecordsFromAnotherScope(t *testing.T) {
	fixture := newHTTPFixture()
	event := fixture.repository.events["event-1"]
	event.Scope = alert.Scope{TenantID: "other", ProjectID: "project"}
	fixture.repository.events[event.ID] = event
	response := fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/alerts/event-1", memberFor("t1", "p1"), nil)
	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.NotContains(t, response.Body.String(), "other")
}

type httpFixture struct {
	scope      alert.Scope
	repository *memoryControlPlaneRepository
	handler    http.Handler
}

func newHTTPFixture() *httpFixture {
	scope := alert.Scope{TenantID: "t1", ProjectID: "p1"}
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	rule := alert.AlertRule{ID: "rule-1", Scope: scope, Name: "CPU", Metric: "host.cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", Enabled: true, CreatedAt: now, UpdatedAt: now}
	event := alert.AlertEvent{ID: "event-1", Scope: scope, RuleID: rule.ID, Fingerprint: "fingerprint-1", State: alert.EventFiring, FirstSeen: now.Add(-time.Minute), LastSeen: now, FiringAt: now, LastActor: "system:evaluator"}
	policy := alert.NotificationPolicy{ID: "policy-1", Scope: scope, Name: "Webhook", Channel: "webhook", Target: "https://allowed.example/hook", SecretRef: "env://DBPILOT_WEBHOOK_TOKEN", TemplateID: "template-1", Enabled: true, CreatedAt: now, UpdatedAt: now}
	template := alert.NotificationTemplate{ID: "template-1", Scope: scope, Name: "Default", Subject: "Alert", Body: "{{event.id}}", Revision: 1, CreatedAt: now, UpdatedAt: now}
	silence := alert.Silence{ID: "silence-1", Scope: scope, Matchers: map[string]string{"label.host": "db-1"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(time.Hour), CreatedBy: "actor-1", Reason: "maintenance", CreatedAt: now, UpdatedAt: now}
	delivery := alert.NotificationDelivery{ID: "delivery-1", Scope: scope, EventID: event.ID, PolicyID: policy.ID, EventState: event.State, IdempotencyKey: "delivery-1", Status: alert.DeliveryDelivered, Attempts: 1, AttemptedAt: now, DeliveredAt: now, Request: alert.DeliveryRequest{DeliveryID: "delivery-1", Scope: scope, EventID: event.ID, State: event.State, Channel: "webhook", PolicyID: policy.ID, TemplateID: template.ID, TemplateVersion: "1", SecretRef: "env://DBPILOT_WEBHOOK_TOKEN", Body: "sensitive request body"}}
	repository := &memoryControlPlaneRepository{now: now, rules: map[string]alert.AlertRule{rule.ID: rule}, events: map[string]alert.AlertEvent{event.ID: event}, policies: map[string]alert.NotificationPolicy{policy.ID: policy}, templates: map[string]alert.NotificationTemplate{template.ID: template}, silences: map[string]alert.Silence{silence.ID: silence}, deliveries: []alert.NotificationDelivery{delivery}}
	services := Services{Repository: repository, Evaluator: healthyEvaluator{}, Now: func() time.Time { return now }}
	return &httpFixture{scope: scope, repository: repository, handler: NewHTTPHandler(services, memberFor("t1", "p1"))}
}

func (fixture *httpFixture) request(method, path string, resolver PrincipalResolver, body []byte) *httptest.ResponseRecorder {
	handler := NewHTTPHandler(Services{Repository: fixture.repository, Evaluator: healthyEvaluator{}, Now: func() time.Time { return fixture.repository.now }}, resolver)
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type staticPrincipalResolver struct{ principal alert.Principal }

func memberFor(tenant, project string) staticPrincipalResolver {
	scope := alert.Scope{TenantID: tenant, ProjectID: project}
	return staticPrincipalResolver{principal: alert.Principal{Subject: "actor-1", Projects: map[string]struct{}{scope.Key(): {}}}}
}

func (resolver staticPrincipalResolver) ResolvePrincipal(*http.Request) (alert.Principal, error) {
	return resolver.principal, nil
}

type errorPrincipalResolver struct{ err error }

func (resolver errorPrincipalResolver) ResolvePrincipal(*http.Request) (alert.Principal, error) {
	return alert.Principal{}, resolver.err
}

type healthyEvaluator struct{}

func (healthyEvaluator) Health() alert.EvaluatorHealth { return alert.EvaluatorHealth{} }

type scopedEvaluator struct {
	global  alert.EvaluatorHealth
	byScope map[string]alert.EvaluatorHealth
}

func (e scopedEvaluator) Health() alert.EvaluatorHealth { return e.global }
func (e scopedEvaluator) HealthForScope(scope alert.Scope) alert.EvaluatorHealth {
	return e.byScope[scope.Key()]
}

func validRuleBody() []byte {
	return []byte(`{"name":"CPU","metric":"host.cpu","aggregation":"avg","operator":">","threshold":80,"evaluation_every":"1m","for":"1m","missing_data":"ignore","severity":"critical","enabled":true}`)
}

func validPolicyBody() []byte {
	return []byte(`{"name":"Webhook","channel":"webhook","target":"https://allowed.example/hook","secret_ref":"env://DBPILOT_WEBHOOK_TOKEN","template_id":"template-1","enabled":true}`)
}

func validTemplateBody() []byte {
	return []byte(`{"name":"Default","subject":"Alert","body":"{{event.id}}"}`)
}

func validSilenceBody() []byte {
	return []byte(`{"matchers":{"label.host":"db-1"},"starts_at":"2026-08-27T09:00:00Z","ends_at":"2026-08-27T11:00:00Z","reason":"maintenance"}`)
}

type memoryControlPlaneRepository struct {
	now             time.Time
	calls           int
	nextID          int
	lastAudit       alert.AuditRecord
	rules           map[string]alert.AlertRule
	events          map[string]alert.AlertEvent
	policies        map[string]alert.NotificationPolicy
	templates       map[string]alert.NotificationTemplate
	silences        map[string]alert.Silence
	deliveries      []alert.NotificationDelivery
	dispositions    []alert.EventDisposition
	lastDisposition alert.EventDisposition
}

func (repository *memoryControlPlaneRepository) NewID(prefix string) (string, error) {
	repository.nextID++
	return prefix + "-new", nil
}
func (repository *memoryControlPlaneRepository) CreateRule(_ context.Context, value alert.AlertRule) (alert.AlertRule, error) {
	repository.calls++
	repository.rules[value.ID] = value
	return value, nil
}
func (repository *memoryControlPlaneRepository) UpdateRule(_ context.Context, value alert.AlertRule) (alert.AlertRule, error) {
	repository.calls++
	if _, ok := repository.rules[value.ID]; !ok {
		return alert.AlertRule{}, alert.ErrNotFound
	}
	repository.rules[value.ID] = value
	return value, nil
}
func (repository *memoryControlPlaneRepository) DeleteRule(_ context.Context, _ alert.Scope, id string) error {
	repository.calls++
	if _, ok := repository.rules[id]; !ok {
		return alert.ErrNotFound
	}
	delete(repository.rules, id)
	return nil
}
func (repository *memoryControlPlaneRepository) ListRules(context.Context, alert.Scope) ([]alert.AlertRule, error) {
	repository.calls++
	return mapValues(repository.rules), nil
}
func (repository *memoryControlPlaneRepository) GetRule(_ context.Context, _ alert.Scope, id string) (alert.AlertRule, error) {
	repository.calls++
	value, ok := repository.rules[id]
	if !ok {
		return alert.AlertRule{}, alert.ErrNotFound
	}
	return value, nil
}
func (repository *memoryControlPlaneRepository) PutEvent(_ context.Context, value alert.AlertEvent) (alert.AlertEvent, error) {
	repository.events[value.ID] = value
	return value, nil
}
func (repository *memoryControlPlaneRepository) PutEventAndAudit(_ context.Context, value alert.AlertEvent, audit alert.AuditRecord) (alert.AlertEvent, error) {
	repository.calls++
	repository.events[value.ID] = value
	repository.lastAudit = audit
	return value, nil
}
func (repository *memoryControlPlaneRepository) PutEventAndDisposition(_ context.Context, value alert.AlertEvent, audit alert.AuditRecord, disposition alert.EventDisposition) (alert.AlertEvent, error) {
	repository.calls++
	repository.events[value.ID] = value
	repository.lastAudit = audit
	repository.lastDisposition = disposition
	repository.dispositions = append(repository.dispositions, disposition)
	return value, nil
}
func (repository *memoryControlPlaneRepository) AppendEventDisposition(_ context.Context, disposition alert.EventDisposition, audit alert.AuditRecord) error {
	if event, ok := repository.events[disposition.EventID]; !ok || event.Scope != disposition.Scope {
		return alert.ErrNotFound
	}
	repository.lastAudit = audit
	repository.lastDisposition = disposition
	repository.dispositions = append(repository.dispositions, disposition)
	return nil
}
func (repository *memoryControlPlaneRepository) ListEventDispositions(_ context.Context, scope alert.Scope, eventID string, limit, offset int) ([]alert.EventDisposition, error) {
	values := make([]alert.EventDisposition, 0)
	for _, disposition := range repository.dispositions {
		if disposition.Scope == scope && disposition.EventID == eventID {
			values = append(values, disposition)
		}
	}
	if offset >= len(values) {
		return []alert.EventDisposition{}, nil
	}
	end := offset + limit
	if end > len(values) {
		end = len(values)
	}
	return values[offset:end], nil
}
func (repository *memoryControlPlaneRepository) FindEventByFingerprint(context.Context, alert.Scope, string) (alert.AlertEvent, bool, error) {
	return alert.AlertEvent{}, false, nil
}
func (repository *memoryControlPlaneRepository) ListEvents(_ context.Context, _ alert.Scope, filter alert.EventFilter) ([]alert.AlertEvent, error) {
	repository.calls++
	values := mapValues(repository.events)
	if filter.Limit > 0 && len(values) > filter.Limit {
		values = values[:filter.Limit]
	}
	return values, nil
}
func (repository *memoryControlPlaneRepository) CountEventsByState(context.Context, alert.Scope) (map[alert.EventState]int, error) {
	repository.calls++
	counts := make(map[alert.EventState]int)
	for _, event := range repository.events {
		counts[event.State]++
	}
	return counts, nil
}
func (repository *memoryControlPlaneRepository) ListRuleEvents(context.Context, alert.Scope, string, alert.EventFilter) ([]alert.AlertEvent, error) {
	return nil, nil
}
func (repository *memoryControlPlaneRepository) GetEvent(_ context.Context, _ alert.Scope, id string) (alert.AlertEvent, error) {
	repository.calls++
	value, ok := repository.events[id]
	if !ok {
		return alert.AlertEvent{}, alert.ErrNotFound
	}
	return value, nil
}
func (repository *memoryControlPlaneRepository) AppendAudit(_ context.Context, value alert.AuditRecord) error {
	repository.lastAudit = value
	return nil
}
func (repository *memoryControlPlaneRepository) CreateNotificationPolicy(_ context.Context, value alert.NotificationPolicy) (alert.NotificationPolicy, error) {
	repository.calls++
	repository.policies[value.ID] = value
	return value, nil
}
func (repository *memoryControlPlaneRepository) UpdateNotificationPolicy(_ context.Context, value alert.NotificationPolicy) (alert.NotificationPolicy, error) {
	repository.calls++
	if _, ok := repository.policies[value.ID]; !ok {
		return alert.NotificationPolicy{}, alert.ErrNotFound
	}
	repository.policies[value.ID] = value
	return value, nil
}
func (repository *memoryControlPlaneRepository) DeleteNotificationPolicy(_ context.Context, _ alert.Scope, id string) error {
	repository.calls++
	if _, ok := repository.policies[id]; !ok {
		return alert.ErrNotFound
	}
	delete(repository.policies, id)
	return nil
}
func (repository *memoryControlPlaneRepository) ListNotificationPolicies(context.Context, alert.Scope) ([]alert.NotificationPolicy, error) {
	repository.calls++
	return mapValues(repository.policies), nil
}
func (repository *memoryControlPlaneRepository) GetNotificationPolicy(_ context.Context, _ alert.Scope, id string) (alert.NotificationPolicy, error) {
	repository.calls++
	value, ok := repository.policies[id]
	if !ok {
		return alert.NotificationPolicy{}, alert.ErrNotFound
	}
	return value, nil
}
func (repository *memoryControlPlaneRepository) CreateNotificationTemplate(_ context.Context, value alert.NotificationTemplate) (alert.NotificationTemplate, error) {
	repository.calls++
	repository.templates[value.ID] = value
	return value, nil
}
func (repository *memoryControlPlaneRepository) UpdateNotificationTemplate(_ context.Context, value alert.NotificationTemplate) (alert.NotificationTemplate, error) {
	repository.calls++
	if _, ok := repository.templates[value.ID]; !ok {
		return alert.NotificationTemplate{}, alert.ErrNotFound
	}
	repository.templates[value.ID] = value
	return value, nil
}
func (repository *memoryControlPlaneRepository) DeleteNotificationTemplate(_ context.Context, _ alert.Scope, id string) error {
	repository.calls++
	if _, ok := repository.templates[id]; !ok {
		return alert.ErrNotFound
	}
	delete(repository.templates, id)
	return nil
}
func (repository *memoryControlPlaneRepository) ListNotificationTemplates(context.Context, alert.Scope) ([]alert.NotificationTemplate, error) {
	repository.calls++
	return mapValues(repository.templates), nil
}
func (repository *memoryControlPlaneRepository) GetNotificationTemplate(_ context.Context, _ alert.Scope, id string) (alert.NotificationTemplate, error) {
	repository.calls++
	value, ok := repository.templates[id]
	if !ok {
		return alert.NotificationTemplate{}, alert.ErrNotFound
	}
	return value, nil
}
func (repository *memoryControlPlaneRepository) CreateSilence(_ context.Context, value alert.Silence) (alert.Silence, error) {
	repository.calls++
	repository.silences[value.ID] = value
	return value, nil
}
func (repository *memoryControlPlaneRepository) UpdateSilence(_ context.Context, value alert.Silence) (alert.Silence, error) {
	repository.calls++
	if _, ok := repository.silences[value.ID]; !ok {
		return alert.Silence{}, alert.ErrNotFound
	}
	repository.silences[value.ID] = value
	return value, nil
}
func (repository *memoryControlPlaneRepository) DeleteSilence(_ context.Context, _ alert.Scope, id string) error {
	repository.calls++
	if _, ok := repository.silences[id]; !ok {
		return alert.ErrNotFound
	}
	delete(repository.silences, id)
	return nil
}
func (repository *memoryControlPlaneRepository) ListSilences(context.Context, alert.Scope) ([]alert.Silence, error) {
	repository.calls++
	return mapValues(repository.silences), nil
}
func (repository *memoryControlPlaneRepository) GetSilence(_ context.Context, _ alert.Scope, id string) (alert.Silence, error) {
	repository.calls++
	value, ok := repository.silences[id]
	if !ok {
		return alert.Silence{}, alert.ErrNotFound
	}
	return value, nil
}
func (repository *memoryControlPlaneRepository) ListNotificationDeliveries(context.Context, alert.Scope, string) ([]alert.NotificationDelivery, error) {
	repository.calls++
	return repository.deliveries, nil
}

func mapValues[T any](values map[string]T) []T {
	result := make([]T, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
