package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dbpilot.local/platform/internal/alert"
)

const maxJSONBodyBytes int64 = 1 << 20

type EvaluatorHealthReader interface {
	Health() alert.EvaluatorHealth
}

type Services struct {
	Repository alert.ControlPlaneRepository
	Evaluator  EvaluatorHealthReader
	Now        func() time.Time
	Ready      func(context.Context) error
}

type ScopedHandler func(http.ResponseWriter, *http.Request, alert.Scope, alert.Principal)

type principalContextKey struct{}

func RequireScope(next ScopedHandler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := request.Context().Value(principalContextKey{}).(alert.Principal)
		if !ok || strings.TrimSpace(principal.Subject) == "" {
			writeAPIError(writer, http.StatusUnauthorized, "unauthenticated", "authentication is required")
			return
		}
		scope := alert.Scope{TenantID: request.PathValue("tenantID"), ProjectID: request.PathValue("projectID")}
		if scope.Validate() != nil || !headerIdentifier.MatchString(scope.TenantID) || !headerIdentifier.MatchString(scope.ProjectID) {
			writeAPIError(writer, http.StatusBadRequest, "invalid_scope", "tenant and project are invalid")
			return
		}
		if !principal.Allows(scope) {
			writeAPIError(writer, http.StatusForbidden, "forbidden", "project access is forbidden")
			return
		}
		next(writer, request, scope, principal)
	})
}

func authenticate(resolver PrincipalResolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if resolver == nil {
			writeAPIError(writer, http.StatusUnauthorized, "unauthenticated", "authentication is required")
			return
		}
		principal, err := resolver.ResolvePrincipal(request)
		if err != nil || strings.TrimSpace(principal.Subject) == "" {
			writeAPIError(writer, http.StatusUnauthorized, "unauthenticated", "authentication is required")
			return
		}
		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal)))
	})
}

func NewHTTPHandler(services Services, resolver PrincipalResolver) http.Handler {
	if services.Now == nil {
		services.Now = time.Now
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, request *http.Request) {
		if services.Repository == nil || services.Evaluator == nil || (services.Ready != nil && services.Ready(request.Context()) != nil) || !evaluatorHealthy(services.Evaluator.Health()) {
			writeAPIError(writer, http.StatusServiceUnavailable, "not_ready", "control plane is not ready")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
	})

	api := httpAPI{services: services}
	register := func(pattern string, handler ScopedHandler) {
		available := ScopedHandler(func(writer http.ResponseWriter, request *http.Request, scope alert.Scope, principal alert.Principal) {
			if services.Repository == nil {
				writeAPIError(writer, http.StatusServiceUnavailable, "unavailable", "control plane is unavailable")
				return
			}
			handler(writer, request, scope, principal)
		})
		mux.Handle(pattern, authenticate(resolver, RequireScope(available)))
	}
	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/overview", api.overview)
	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/alerts", api.listAlerts)
	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/alerts/{id}", api.getAlert)
	register("POST /api/v1/tenants/{tenantID}/projects/{projectID}/alerts/{id}/acknowledge", api.acknowledgeAlert)
	register("POST /api/v1/tenants/{tenantID}/projects/{projectID}/alerts/{id}/resolve", api.resolveAlert)
	register("POST /api/v1/tenants/{tenantID}/projects/{projectID}/alerts/{id}/recover", api.resolveAlert)
	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/alerts/{id}/deliveries", api.listDeliveries)

	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/rules", api.listRules)
	register("POST /api/v1/tenants/{tenantID}/projects/{projectID}/rules", api.createRule)
	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/rules/{id}", api.getRule)
	register("PUT /api/v1/tenants/{tenantID}/projects/{projectID}/rules/{id}", api.updateRule)
	register("DELETE /api/v1/tenants/{tenantID}/projects/{projectID}/rules/{id}", api.deleteRule)
	register("POST /api/v1/tenants/{tenantID}/projects/{projectID}/rules/{id}/enable", api.enableRule)

	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/policies", api.listPolicies)
	register("POST /api/v1/tenants/{tenantID}/projects/{projectID}/policies", api.createPolicy)
	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/policies/{id}", api.getPolicy)
	register("PUT /api/v1/tenants/{tenantID}/projects/{projectID}/policies/{id}", api.updatePolicy)
	register("DELETE /api/v1/tenants/{tenantID}/projects/{projectID}/policies/{id}", api.deletePolicy)
	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/notification-policies", api.listPolicies)
	register("POST /api/v1/tenants/{tenantID}/projects/{projectID}/notification-policies", api.createPolicy)
	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/notification-policies/{id}", api.getPolicy)
	register("PUT /api/v1/tenants/{tenantID}/projects/{projectID}/notification-policies/{id}", api.updatePolicy)
	register("DELETE /api/v1/tenants/{tenantID}/projects/{projectID}/notification-policies/{id}", api.deletePolicy)

	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/templates", api.listTemplates)
	register("POST /api/v1/tenants/{tenantID}/projects/{projectID}/templates", api.createTemplate)
	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/templates/{id}", api.getTemplate)
	register("PUT /api/v1/tenants/{tenantID}/projects/{projectID}/templates/{id}", api.updateTemplate)
	register("DELETE /api/v1/tenants/{tenantID}/projects/{projectID}/templates/{id}", api.deleteTemplate)
	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/notification-templates", api.listTemplates)
	register("POST /api/v1/tenants/{tenantID}/projects/{projectID}/notification-templates", api.createTemplate)
	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/notification-templates/{id}", api.getTemplate)
	register("PUT /api/v1/tenants/{tenantID}/projects/{projectID}/notification-templates/{id}", api.updateTemplate)
	register("DELETE /api/v1/tenants/{tenantID}/projects/{projectID}/notification-templates/{id}", api.deleteTemplate)

	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/silences", api.listSilences)
	register("POST /api/v1/tenants/{tenantID}/projects/{projectID}/silences", api.createSilence)
	register("GET /api/v1/tenants/{tenantID}/projects/{projectID}/silences/{id}", api.getSilence)
	register("PUT /api/v1/tenants/{tenantID}/projects/{projectID}/silences/{id}", api.updateSilence)
	register("DELETE /api/v1/tenants/{tenantID}/projects/{projectID}/silences/{id}", api.deleteSilence)
	mux.HandleFunc("/api/v1/", func(writer http.ResponseWriter, _ *http.Request) {
		writeAPIError(writer, http.StatusNotFound, "not_found", "resource was not found")
	})
	return mux
}

type httpAPI struct{ services Services }

func (api httpAPI) overview(writer http.ResponseWriter, request *http.Request, scope alert.Scope, _ alert.Principal) {
	events, err := api.services.Repository.ListEvents(request.Context(), scope, alert.EventFilter{Limit: 500})
	if err != nil {
		apiError(writer, err)
		return
	}
	counts := make(map[string]int)
	for _, event := range events {
		if event.Scope != scope {
			writeAPIError(writer, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		counts[string(event.State)]++
	}
	healthy := api.services.Evaluator != nil && evaluatorHealthy(api.services.Evaluator.Health())
	writeJSON(writer, http.StatusOK, map[string]any{"events": counts, "evaluator": map[string]bool{"healthy": healthy}})
}

func evaluatorHealthy(health alert.EvaluatorHealth) bool {
	return health.LastError == "" && health.FailedRules == 0 && health.QueueDepth == 0
}

func (api httpAPI) listAlerts(writer http.ResponseWriter, request *http.Request, scope alert.Scope, _ alert.Principal) {
	filter, err := eventFilter(request)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "query is invalid")
		return
	}
	values, err := api.services.Repository.ListEvents(request.Context(), scope, filter)
	respondScoped(writer, scope, values, err, http.StatusOK)
}

func (api httpAPI) getAlert(writer http.ResponseWriter, request *http.Request, scope alert.Scope, _ alert.Principal) {
	value, err := api.services.Repository.GetEvent(request.Context(), scope, request.PathValue("id"))
	respondScoped(writer, scope, value, err, http.StatusOK)
}

func (api httpAPI) acknowledgeAlert(writer http.ResponseWriter, request *http.Request, scope alert.Scope, principal alert.Principal) {
	api.transitionAlert(writer, request, scope, principal, alert.EventAcknowledged)
}

func (api httpAPI) resolveAlert(writer http.ResponseWriter, request *http.Request, scope alert.Scope, principal alert.Principal) {
	api.transitionAlert(writer, request, scope, principal, alert.EventResolved)
}

func (api httpAPI) transitionAlert(writer http.ResponseWriter, request *http.Request, scope alert.Scope, principal alert.Principal, state alert.EventState) {
	event, err := api.services.Repository.GetEvent(request.Context(), scope, request.PathValue("id"))
	if err != nil {
		apiError(writer, err)
		return
	}
	if event.Scope != scope {
		writeAPIError(writer, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	at := api.services.Now().UTC()
	event, err = event.Transition(state, at, principal.Subject)
	if err != nil {
		apiError(writer, err)
		return
	}
	auditID, err := api.services.Repository.NewID("audit")
	if err != nil {
		apiError(writer, err)
		return
	}
	audit := alert.AuditRecord{ID: auditID, Scope: scope, Actor: principal.Subject, Action: "event." + string(state), TargetID: event.ID, OccurredAt: at, Details: map[string]string{"state": string(state)}}
	event, err = api.services.Repository.PutEventAndAudit(request.Context(), event, audit)
	respondScoped(writer, scope, event, err, http.StatusOK)
}

func (api httpAPI) listDeliveries(writer http.ResponseWriter, request *http.Request, scope alert.Scope, _ alert.Principal) {
	event, err := api.services.Repository.GetEvent(request.Context(), scope, request.PathValue("id"))
	if err != nil {
		apiError(writer, err)
		return
	}
	if event.Scope != scope {
		writeAPIError(writer, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	values, err := api.services.Repository.ListNotificationDeliveries(request.Context(), scope, request.PathValue("id"))
	respondScoped(writer, scope, values, err, http.StatusOK)
}

type durationValue time.Duration

func (value *durationValue) UnmarshalJSON(data []byte) error {
	var text string
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
		duration, err := time.ParseDuration(text)
		*value = durationValue(duration)
		return err
	}
	var nanoseconds int64
	if err := json.Unmarshal(data, &nanoseconds); err != nil {
		return err
	}
	*value = durationValue(time.Duration(nanoseconds))
	return nil
}

type ruleInput struct {
	Name                  string            `json:"name"`
	Metric                string            `json:"metric"`
	Aggregation           string            `json:"aggregation"`
	Operator              string            `json:"operator"`
	Threshold             float64           `json:"threshold"`
	EvaluationEvery       durationValue     `json:"evaluation_every"`
	For                   durationValue     `json:"for"`
	MissingData           string            `json:"missing_data"`
	Severity              string            `json:"severity"`
	NotificationPolicyIDs []string          `json:"notification_policy_ids,omitempty"`
	Labels                map[string]string `json:"labels,omitempty"`
	Enabled               bool              `json:"enabled"`
}

func (input ruleInput) value(scope alert.Scope, id string) alert.AlertRule {
	return alert.AlertRule{ID: id, Scope: scope, Name: input.Name, Metric: input.Metric, Aggregation: input.Aggregation, Operator: input.Operator, Threshold: input.Threshold, EvaluationEvery: time.Duration(input.EvaluationEvery), For: time.Duration(input.For), MissingData: input.MissingData, Severity: input.Severity, NotificationPolicyIDs: input.NotificationPolicyIDs, Labels: input.Labels, Enabled: input.Enabled}
}

func (api httpAPI) listRules(writer http.ResponseWriter, request *http.Request, scope alert.Scope, _ alert.Principal) {
	values, err := api.services.Repository.ListRules(request.Context(), scope)
	respondScoped(writer, scope, values, err, http.StatusOK)
}
func (api httpAPI) getRule(writer http.ResponseWriter, request *http.Request, scope alert.Scope, _ alert.Principal) {
	value, err := api.services.Repository.GetRule(request.Context(), scope, request.PathValue("id"))
	respondScoped(writer, scope, value, err, http.StatusOK)
}
func (api httpAPI) createRule(writer http.ResponseWriter, request *http.Request, scope alert.Scope, principal alert.Principal) {
	var input ruleInput
	if !decodeJSON(writer, request, &input) {
		return
	}
	id, err := api.services.Repository.NewID("rule")
	if err != nil {
		apiError(writer, err)
		return
	}
	value, err := api.services.Repository.CreateRule(alert.ContextWithAuditActor(request.Context(), principal.Subject), input.value(scope, id))
	respondScoped(writer, scope, value, err, http.StatusCreated)
}
func (api httpAPI) updateRule(writer http.ResponseWriter, request *http.Request, scope alert.Scope, principal alert.Principal) {
	var input ruleInput
	if !decodeJSON(writer, request, &input) {
		return
	}
	value, err := api.services.Repository.UpdateRule(alert.ContextWithAuditActor(request.Context(), principal.Subject), input.value(scope, request.PathValue("id")))
	respondScoped(writer, scope, value, err, http.StatusOK)
}
func (api httpAPI) enableRule(writer http.ResponseWriter, request *http.Request, scope alert.Scope, principal alert.Principal) {
	input := struct {
		Enabled bool `json:"enabled"`
	}{Enabled: true}
	if request.Body != http.NoBody && request.ContentLength != 0 {
		if !decodeJSON(writer, request, &input) {
			return
		}
	}
	value, err := api.services.Repository.GetRule(request.Context(), scope, request.PathValue("id"))
	if err == nil {
		if value.Scope != scope {
			writeAPIError(writer, http.StatusInternalServerError, "internal", "internal server error")
			return
		}
		value.Enabled = input.Enabled
		value, err = api.services.Repository.UpdateRule(alert.ContextWithAuditActor(request.Context(), principal.Subject), value)
	}
	respondScoped(writer, scope, value, err, http.StatusOK)
}
func (api httpAPI) deleteRule(writer http.ResponseWriter, request *http.Request, scope alert.Scope, principal alert.Principal) {
	api.delete(writer, api.services.Repository.DeleteRule(alert.ContextWithAuditActor(request.Context(), principal.Subject), scope, request.PathValue("id")))
}

type policyInput struct {
	Name           string            `json:"name"`
	Channel        string            `json:"channel"`
	Target         string            `json:"target"`
	SecretRef      string            `json:"secret_ref"`
	TemplateID     string            `json:"template_id"`
	Severities     []string          `json:"severities,omitempty"`
	MatchLabels    map[string]string `json:"match_labels,omitempty"`
	WindowStartUTC string            `json:"window_start_utc,omitempty"`
	WindowEndUTC   string            `json:"window_end_utc,omitempty"`
	Enabled        bool              `json:"enabled"`
}

func (input policyInput) value(scope alert.Scope, id string) alert.NotificationPolicy {
	return alert.NotificationPolicy{ID: id, Scope: scope, Name: input.Name, Channel: input.Channel, Target: input.Target, SecretRef: input.SecretRef, TemplateID: input.TemplateID, Severities: input.Severities, MatchLabels: input.MatchLabels, WindowStartUTC: input.WindowStartUTC, WindowEndUTC: input.WindowEndUTC, Enabled: input.Enabled}
}
func (api httpAPI) listPolicies(w http.ResponseWriter, r *http.Request, s alert.Scope, _ alert.Principal) {
	v, e := api.services.Repository.ListNotificationPolicies(r.Context(), s)
	respondScoped(w, s, v, e, http.StatusOK)
}
func (api httpAPI) getPolicy(w http.ResponseWriter, r *http.Request, s alert.Scope, _ alert.Principal) {
	v, e := api.services.Repository.GetNotificationPolicy(r.Context(), s, r.PathValue("id"))
	respondScoped(w, s, v, e, http.StatusOK)
}
func (api httpAPI) createPolicy(w http.ResponseWriter, r *http.Request, s alert.Scope, p alert.Principal) {
	var in policyInput
	if !decodeJSON(w, r, &in) {
		return
	}
	id, e := api.services.Repository.NewID("policy")
	if e != nil {
		apiError(w, e)
		return
	}
	v, e := api.services.Repository.CreateNotificationPolicy(alert.ContextWithAuditActor(r.Context(), p.Subject), in.value(s, id))
	respondScoped(w, s, v, e, http.StatusCreated)
}
func (api httpAPI) updatePolicy(w http.ResponseWriter, r *http.Request, s alert.Scope, p alert.Principal) {
	var in policyInput
	if !decodeJSON(w, r, &in) {
		return
	}
	v, e := api.services.Repository.UpdateNotificationPolicy(alert.ContextWithAuditActor(r.Context(), p.Subject), in.value(s, r.PathValue("id")))
	respondScoped(w, s, v, e, http.StatusOK)
}
func (api httpAPI) deletePolicy(w http.ResponseWriter, r *http.Request, s alert.Scope, p alert.Principal) {
	api.delete(w, api.services.Repository.DeleteNotificationPolicy(alert.ContextWithAuditActor(r.Context(), p.Subject), s, r.PathValue("id")))
}

type templateInput struct {
	Name    string `json:"name"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

func (api httpAPI) listTemplates(w http.ResponseWriter, r *http.Request, s alert.Scope, _ alert.Principal) {
	v, e := api.services.Repository.ListNotificationTemplates(r.Context(), s)
	respondScoped(w, s, v, e, http.StatusOK)
}
func (api httpAPI) getTemplate(w http.ResponseWriter, r *http.Request, s alert.Scope, _ alert.Principal) {
	v, e := api.services.Repository.GetNotificationTemplate(r.Context(), s, r.PathValue("id"))
	respondScoped(w, s, v, e, http.StatusOK)
}
func (api httpAPI) createTemplate(w http.ResponseWriter, r *http.Request, s alert.Scope, p alert.Principal) {
	var in templateInput
	if !decodeJSON(w, r, &in) {
		return
	}
	id, e := api.services.Repository.NewID("template")
	if e != nil {
		apiError(w, e)
		return
	}
	v, e := api.services.Repository.CreateNotificationTemplate(alert.ContextWithAuditActor(r.Context(), p.Subject), alert.NotificationTemplate{ID: id, Scope: s, Name: in.Name, Subject: in.Subject, Body: in.Body, Revision: 1})
	respondScoped(w, s, v, e, http.StatusCreated)
}
func (api httpAPI) updateTemplate(w http.ResponseWriter, r *http.Request, s alert.Scope, p alert.Principal) {
	var in templateInput
	if !decodeJSON(w, r, &in) {
		return
	}
	existing, e := api.services.Repository.GetNotificationTemplate(r.Context(), s, r.PathValue("id"))
	if e != nil {
		apiError(w, e)
		return
	}
	if existing.Scope != s {
		writeAPIError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	existing.Name, existing.Subject, existing.Body, existing.Revision = in.Name, in.Subject, in.Body, existing.Revision+1
	v, e := api.services.Repository.UpdateNotificationTemplate(alert.ContextWithAuditActor(r.Context(), p.Subject), existing)
	respondScoped(w, s, v, e, http.StatusOK)
}
func (api httpAPI) deleteTemplate(w http.ResponseWriter, r *http.Request, s alert.Scope, p alert.Principal) {
	api.delete(w, api.services.Repository.DeleteNotificationTemplate(alert.ContextWithAuditActor(r.Context(), p.Subject), s, r.PathValue("id")))
}

type silenceInput struct {
	Matchers map[string]string `json:"matchers"`
	StartsAt time.Time         `json:"starts_at"`
	EndsAt   time.Time         `json:"ends_at"`
	Reason   string            `json:"reason"`
}

func (api httpAPI) listSilences(w http.ResponseWriter, r *http.Request, s alert.Scope, _ alert.Principal) {
	v, e := api.services.Repository.ListSilences(r.Context(), s)
	respondScoped(w, s, v, e, http.StatusOK)
}
func (api httpAPI) getSilence(w http.ResponseWriter, r *http.Request, s alert.Scope, _ alert.Principal) {
	v, e := api.services.Repository.GetSilence(r.Context(), s, r.PathValue("id"))
	respondScoped(w, s, v, e, http.StatusOK)
}
func (api httpAPI) createSilence(w http.ResponseWriter, r *http.Request, s alert.Scope, p alert.Principal) {
	var in silenceInput
	if !decodeJSON(w, r, &in) {
		return
	}
	id, e := api.services.Repository.NewID("silence")
	if e != nil {
		apiError(w, e)
		return
	}
	v, e := api.services.Repository.CreateSilence(alert.ContextWithAuditActor(r.Context(), p.Subject), alert.Silence{ID: id, Scope: s, Matchers: in.Matchers, StartsAt: in.StartsAt, EndsAt: in.EndsAt, CreatedBy: p.Subject, Reason: in.Reason})
	respondScoped(w, s, v, e, http.StatusCreated)
}
func (api httpAPI) updateSilence(w http.ResponseWriter, r *http.Request, s alert.Scope, p alert.Principal) {
	var in silenceInput
	if !decodeJSON(w, r, &in) {
		return
	}
	existing, e := api.services.Repository.GetSilence(r.Context(), s, r.PathValue("id"))
	if e != nil {
		apiError(w, e)
		return
	}
	if existing.Scope != s {
		writeAPIError(w, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	existing.Matchers, existing.StartsAt, existing.EndsAt, existing.Reason = in.Matchers, in.StartsAt, in.EndsAt, in.Reason
	v, e := api.services.Repository.UpdateSilence(alert.ContextWithAuditActor(r.Context(), p.Subject), existing)
	respondScoped(w, s, v, e, http.StatusOK)
}
func (api httpAPI) deleteSilence(w http.ResponseWriter, r *http.Request, s alert.Scope, p alert.Principal) {
	api.delete(w, api.services.Repository.DeleteSilence(alert.ContextWithAuditActor(r.Context(), p.Subject), s, r.PathValue("id")))
}

func (api httpAPI) delete(writer http.ResponseWriter, err error) {
	if err != nil {
		apiError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func eventFilter(request *http.Request) (alert.EventFilter, error) {
	filter := alert.EventFilter{Limit: 100}
	if raw := request.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 500 {
			return filter, errors.New("invalid limit")
		}
		filter.Limit = value
	}
	if raw := request.URL.Query().Get("offset"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return filter, errors.New("invalid offset")
		}
		filter.Offset = value
	}
	if raw := request.URL.Query().Get("state"); raw != "" {
		for _, value := range strings.Split(raw, ",") {
			state := alert.EventState(value)
			switch state {
			case alert.EventPending, alert.EventFiring, alert.EventAcknowledged, alert.EventResolved:
				filter.States = append(filter.States, state)
			default:
				return filter, errors.New("invalid state")
			}
		}
	}
	return filter, nil
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, target any) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, maxJSONBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return false
	}
	return true
}

func respondScoped(writer http.ResponseWriter, scope alert.Scope, value any, err error, status int) {
	if err != nil {
		apiError(writer, err)
		return
	}
	if !valueWithinScope(value, scope) {
		writeAPIError(writer, http.StatusInternalServerError, "internal", "internal server error")
		return
	}
	writeJSON(writer, status, value)
}

func valueWithinScope(value any, scope alert.Scope) bool {
	switch typed := value.(type) {
	case alert.AlertEvent:
		return typed.Scope == scope
	case []alert.AlertEvent:
		for _, item := range typed {
			if item.Scope != scope {
				return false
			}
		}
	case alert.AlertRule:
		return typed.Scope == scope
	case []alert.AlertRule:
		for _, item := range typed {
			if item.Scope != scope {
				return false
			}
		}
	case alert.NotificationPolicy:
		return typed.Scope == scope
	case []alert.NotificationPolicy:
		for _, item := range typed {
			if item.Scope != scope {
				return false
			}
		}
	case alert.NotificationTemplate:
		return typed.Scope == scope
	case []alert.NotificationTemplate:
		for _, item := range typed {
			if item.Scope != scope {
				return false
			}
		}
	case alert.Silence:
		return typed.Scope == scope
	case []alert.Silence:
		for _, item := range typed {
			if item.Scope != scope {
				return false
			}
		}
	case []alert.NotificationDelivery:
		for _, item := range typed {
			if item.Scope != scope {
				return false
			}
		}
	default:
		return false
	}
	return true
}
func apiError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, alert.ErrNotFound):
		writeAPIError(writer, http.StatusNotFound, "not_found", "resource was not found")
	case errors.Is(err, alert.ErrInvalidRule), errors.Is(err, alert.ErrInvalidEvent), errors.Is(err, alert.ErrInvalidEventTransition), errors.Is(err, alert.ErrInvalidEventTransitionTime), errors.Is(err, alert.ErrInvalidNotification), errors.Is(err, alert.ErrInvalidTemplate), errors.Is(err, alert.ErrInvalidScope):
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "request is invalid")
	default:
		writeAPIError(writer, http.StatusInternalServerError, "internal", "internal server error")
	}
}
func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
func writeAPIError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
