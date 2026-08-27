package controlplane

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/monitoring"
)

const monitoringSource = "control-plane"

type monitoringOverviewResponse struct {
	Source         string                `json:"source"`
	Scope          alert.Scope           `json:"scope"`
	From           time.Time             `json:"from"`
	To             time.Time             `json:"to"`
	TotalInstances int                   `json:"total_instances"`
	Healthy        int                   `json:"healthy"`
	Stale          int                   `json:"stale"`
	Offline        int                   `json:"offline"`
	Instances      []monitoring.Instance `json:"instances,omitempty"`
	Trend          monitoring.Series     `json:"trend"`
}

type monitoringInstancesResponse struct {
	Source     string                `json:"source"`
	Scope      alert.Scope           `json:"scope"`
	Items      []monitoring.Instance `json:"items"`
	NextOffset int                   `json:"next_offset"`
}

type monitoringInstanceResponse struct {
	Source   string              `json:"source"`
	Scope    alert.Scope         `json:"scope"`
	Instance monitoring.Instance `json:"instance"`
	Metrics  []monitoring.Series `json:"metrics,omitempty"`
}

type monitoringSeriesResponse struct {
	Source string            `json:"source"`
	Scope  alert.Scope       `json:"scope"`
	Series monitoring.Series `json:"series"`
}

type monitoringCapabilitiesResponse struct {
	Source string                  `json:"source"`
	Scope  alert.Scope             `json:"scope"`
	Items  []monitoring.Capability `json:"items"`
}

func (api httpAPI) monitoringOverview(writer http.ResponseWriter, request *http.Request, scope alert.Scope, _ alert.Principal) {
	rangeQuery, err := monitoringRange(request, api.services.Now())
	if err != nil {
		monitoringAPIError(writer, err)
		return
	}
	value, err := api.services.Monitoring.Overview(request.Context(), scope, rangeQuery)
	if err != nil {
		monitoringAPIError(writer, err)
		return
	}
	instances := redactMonitoringInstances(value.Instances)
	api.writeMonitoringJSON(writer, monitoringOverviewResponse{Source: monitoringSource, Scope: scope, From: value.From, To: value.To, TotalInstances: value.TotalInstances, Healthy: value.Healthy, Stale: value.Stale, Offline: value.Offline, Instances: instances, Trend: value.Trend})
}

func (api httpAPI) monitoringInstances(writer http.ResponseWriter, request *http.Request, scope alert.Scope, _ alert.Principal) {
	query, err := monitoringInstanceQuery(request)
	if err != nil {
		monitoringAPIError(writer, err)
		return
	}
	page, err := api.services.Monitoring.ListInstances(request.Context(), scope, query)
	if err != nil {
		monitoringAPIError(writer, err)
		return
	}
	api.writeMonitoringJSON(writer, monitoringInstancesResponse{Source: monitoringSource, Scope: scope, Items: redactMonitoringInstances(page.Items), NextOffset: page.NextOffset})
}

func (api httpAPI) monitoringInstance(writer http.ResponseWriter, request *http.Request, scope alert.Scope, _ alert.Principal) {
	rangeQuery, err := monitoringRange(request, api.services.Now())
	if err != nil {
		monitoringAPIError(writer, err)
		return
	}
	value, err := api.services.Monitoring.GetInstance(request.Context(), scope, request.PathValue("id"), rangeQuery)
	if err != nil {
		monitoringAPIError(writer, err)
		return
	}
	api.writeMonitoringJSON(writer, monitoringInstanceResponse{Source: monitoringSource, Scope: scope, Instance: redactMonitoringInstance(value.Instance), Metrics: value.Metrics})
}

func (api httpAPI) monitoringSeries(writer http.ResponseWriter, request *http.Request, scope alert.Scope, _ alert.Principal) {
	rangeQuery, err := monitoringRange(request, api.services.Now())
	if err != nil {
		monitoringAPIError(writer, err)
		return
	}
	query := monitoring.SeriesQuery{InstanceID: strings.TrimSpace(request.URL.Query().Get("instance_id")), Metric: strings.TrimSpace(request.URL.Query().Get("metric")), Range: rangeQuery}
	if query.InstanceID == "" || query.Metric == "" {
		monitoringAPIError(writer, monitoring.ErrInvalidQuery)
		return
	}
	value, err := api.services.Monitoring.Series(request.Context(), scope, query)
	if err != nil {
		monitoringAPIError(writer, err)
		return
	}
	api.writeMonitoringJSON(writer, monitoringSeriesResponse{Source: monitoringSource, Scope: scope, Series: value})
}

func (api httpAPI) monitoringCapabilities(writer http.ResponseWriter, request *http.Request, scope alert.Scope, _ alert.Principal) {
	values, err := api.services.Monitoring.Capabilities(request.Context(), scope)
	if err != nil {
		monitoringAPIError(writer, err)
		return
	}
	api.writeMonitoringJSON(writer, monitoringCapabilitiesResponse{Source: monitoringSource, Scope: scope, Items: values})
}

type monitoringResponseSizer interface{ ValidateResponse(any) error }

func (api httpAPI) writeMonitoringJSON(writer http.ResponseWriter, value any) {
	if sizer, ok := api.services.Monitoring.(monitoringResponseSizer); ok {
		if err := sizer.ValidateResponse(value); err != nil {
			monitoringAPIError(writer, err)
			return
		}
	}
	writeJSON(writer, http.StatusOK, value)
}

func monitoringRange(request *http.Request, now time.Time) (monitoring.RangeQuery, error) {
	query := request.URL.Query()
	result := monitoring.RangeQuery{}
	var err error
	if raw, present := query["from"]; present {
		if len(raw) != 1 || raw[0] == "" {
			return result, monitoring.ErrInvalidRange
		}
		result.From, err = time.Parse(time.RFC3339, raw[0])
		if err != nil {
			return result, monitoring.ErrInvalidRange
		}
	}
	if raw, present := query["to"]; present {
		if len(raw) != 1 || raw[0] == "" {
			return result, monitoring.ErrInvalidRange
		}
		result.To, err = time.Parse(time.RFC3339, raw[0])
		if err != nil {
			return result, monitoring.ErrInvalidRange
		}
	}
	if raw, present := query["step"]; present {
		if len(raw) != 1 || raw[0] == "" {
			return result, monitoring.ErrInvalidRange
		}
		result.Step, err = time.ParseDuration(raw[0])
		if err != nil || result.Step <= 0 {
			return result, monitoring.ErrInvalidRange
		}
	}
	if err := result.Validate(now.UTC()); err != nil {
		return result, err
	}
	return result, nil
}

func monitoringInstanceQuery(request *http.Request) (monitoring.InstanceQuery, error) {
	query := request.URL.Query()
	result := monitoring.InstanceQuery{}
	if raw, present := query["limit"]; present {
		if len(raw) != 1 {
			return result, monitoring.ErrInvalidQuery
		}
		value, err := strconv.Atoi(raw[0])
		if err != nil || value < 1 || value > monitoring.MaximumPageSize {
			return result, monitoring.ErrInvalidQuery
		}
		result.Limit = value
	}
	if raw, present := query["offset"]; present {
		if len(raw) != 1 {
			return result, monitoring.ErrInvalidQuery
		}
		value, err := strconv.Atoi(raw[0])
		if err != nil || value < 0 {
			return result, monitoring.ErrInvalidQuery
		}
		result.Offset = value
	}
	if raw, present := query["status"]; present {
		if len(raw) != 1 {
			return result, monitoring.ErrInvalidQuery
		}
		result.Status = monitoring.Status(raw[0])
		switch result.Status {
		case monitoring.StatusHealthy, monitoring.StatusStale, monitoring.StatusOffline:
		default:
			return result, monitoring.ErrInvalidQuery
		}
	}
	if raw, present := query["engine"]; present {
		if len(raw) != 1 {
			return result, monitoring.ErrInvalidQuery
		}
		result.Engine = database.EngineFamily(raw[0])
		if !allowedMonitoringEngine(result.Engine) {
			return result, monitoring.ErrInvalidQuery
		}
	}
	return result, nil
}

func allowedMonitoringEngine(engine database.EngineFamily) bool {
	switch engine {
	case database.MySQLFamily, database.MariaDBFamily, database.TiDBFamily, database.OceanBaseFamily, database.PostgresFamily, database.OpenGaussFamily, database.OracleFamily, database.DamengFamily, database.MongoFamily, database.HBaseFamily, database.Neo4JFamily:
		return true
	default:
		return false
	}
}

func monitoringAPIError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, monitoring.ErrInstanceNotFound), errors.Is(err, alert.ErrNotFound):
		writeAPIError(writer, http.StatusNotFound, "not_found", "resource was not found")
	case errors.Is(err, monitoring.ErrQueryLimit):
		writeAPIError(writer, http.StatusRequestEntityTooLarge, "query_limit_exceeded", "monitoring query exceeds configured limit")
	case errors.Is(err, monitoring.ErrInvalidRange), errors.Is(err, monitoring.ErrRangeTooLarge), errors.Is(err, monitoring.ErrTooManyBuckets), errors.Is(err, monitoring.ErrInvalidQuery):
		writeAPIError(writer, http.StatusBadRequest, "invalid_request", "query is invalid")
	default:
		writeAPIError(writer, http.StatusInternalServerError, "internal", "internal server error")
	}
}

func redactMonitoringInstance(instance monitoring.Instance) monitoring.Instance {
	instance = monitoring.RedactInstance(instance)
	instance.ErrorSummary = ""
	return instance
}

func redactMonitoringInstances(instances []monitoring.Instance) []monitoring.Instance {
	result := make([]monitoring.Instance, len(instances))
	for index, instance := range instances {
		result[index] = redactMonitoringInstance(instance)
	}
	return result
}
