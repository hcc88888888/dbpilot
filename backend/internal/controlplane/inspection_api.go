package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/inspection"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
)

const defaultInspectionPageLimit = 50

func (api platformAPI) ListInspectionItems(ctx context.Context, request openapi.ListInspectionItemsRequestObject) (openapi.ListInspectionItemsResponseObject, error) {
	scope, _, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := inspectionFilter(request.Params.Cursor, request.Params.Limit)
	page, err := api.services.Inspection.ListItems(ctx, scope, inspection.ItemFilter{CursorFilter: filter})
	if err != nil {
		return nil, err
	}
	items := make([]openapi.InspectionItem, len(page.Items))
	for index, value := range page.Items {
		if value.Scope != scope {
			return nil, errors.New("inspection service returned an out-of-scope item")
		}
		items[index], err = openAPIInspectionItem(value)
		if err != nil {
			return nil, err
		}
	}
	return openapi.ListInspectionItems200JSONResponse{Items: items, Page: inspectionPage(filter.Limit, page.More, page.NextCursor)}, nil
}

func (api platformAPI) CreateInspectionItem(ctx context.Context, request openapi.CreateInspectionItemRequestObject) (openapi.CreateInspectionItemResponseObject, error) {
	scope, principal, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	value, err := inspectionItemInput(*request.Body)
	if err != nil {
		return nil, err
	}
	created, err := api.services.Inspection.CreateItem(ctx, scope, principal.Subject, request.Params.IdempotencyKey, value)
	if err != nil {
		return nil, err
	}
	if created.Scope != scope {
		return nil, errors.New("inspection service returned an out-of-scope item")
	}
	response, err := openAPIInspectionItem(created)
	if err != nil {
		return nil, err
	}
	return openapi.CreateInspectionItem201JSONResponse(response), nil
}

func (api platformAPI) GetInspectionOverview(ctx context.Context, _ openapi.GetInspectionOverviewRequestObject) (openapi.GetInspectionOverviewResponseObject, error) {
	scope, _, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	value, err := api.services.Inspection.GetOverview(ctx, scope)
	if err != nil {
		return nil, err
	}
	response := openapi.InspectionOverview{TargetCount: value.TargetCount, OnlineTargetCount: value.OnlineTargetCount}
	setRunOverviewCounts(&response, value.RunStatusCounts)
	setFindingOverviewCounts(&response, value.FindingLevelCounts)
	return openapi.GetInspectionOverview200JSONResponse(response), nil
}

func (api platformAPI) ListInspectionPolicies(ctx context.Context, request openapi.ListInspectionPoliciesRequestObject) (openapi.ListInspectionPoliciesResponseObject, error) {
	scope, _, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := inspectionFilter(request.Params.Cursor, request.Params.Limit)
	page, err := api.services.Inspection.ListPolicies(ctx, scope, inspection.PolicyFilter{CursorFilter: filter})
	if err != nil {
		return nil, err
	}
	items := make([]openapi.InspectionPolicy, len(page.Items))
	for index, value := range page.Items {
		if value.Scope != scope {
			return nil, errors.New("inspection service returned an out-of-scope policy")
		}
		items[index], err = openAPIInspectionPolicy(value)
		if err != nil {
			return nil, err
		}
	}
	return openapi.ListInspectionPolicies200JSONResponse{Items: items, Page: inspectionPage(filter.Limit, page.More, page.NextCursor)}, nil
}

func (api platformAPI) CreateInspectionPolicy(ctx context.Context, request openapi.CreateInspectionPolicyRequestObject) (openapi.CreateInspectionPolicyResponseObject, error) {
	scope, principal, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	created, err := api.services.Inspection.CreatePolicy(ctx, scope, principal.Subject, request.Params.IdempotencyKey, inspectionPolicyInput(request.Body.Name, request.Body.Enabled, request.Body.Schedule, request.Body.ItemVersions, request.Body.TargetIds, request.Body.Labels, request.Body.TargetTimeoutSeconds, request.Body.MaxConcurrency))
	if err != nil {
		return nil, err
	}
	if created.Scope != scope {
		return nil, errors.New("inspection service returned an out-of-scope policy")
	}
	body, err := openAPIInspectionPolicy(created)
	if err != nil {
		return nil, err
	}
	return inspectionPolicyCreateResponse{Body: body, ETag: entityTag(created.Version)}, nil
}

func (api platformAPI) GetInspectionPolicy(ctx context.Context, request openapi.GetInspectionPolicyRequestObject) (openapi.GetInspectionPolicyResponseObject, error) {
	scope, _, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	value, err := api.services.Inspection.GetPolicy(ctx, scope, request.PolicyId)
	if err != nil {
		return nil, err
	}
	if value.Scope != scope || value.ID != request.PolicyId {
		return nil, errors.New("inspection service returned an out-of-scope policy")
	}
	body, err := openAPIInspectionPolicy(value)
	if err != nil {
		return nil, err
	}
	return inspectionPolicyGetResponse{Body: body, ETag: entityTag(value.Version)}, nil
}

func (api platformAPI) UpdateInspectionPolicy(ctx context.Context, request openapi.UpdateInspectionPolicyRequestObject) (openapi.UpdateInspectionPolicyResponseObject, error) {
	scope, principal, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	version, err := parseEntityTag(request.Params.IfMatch)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	value := inspectionPolicyInput(request.Body.Name, request.Body.Enabled, request.Body.Schedule, request.Body.ItemVersions, request.Body.TargetIds, request.Body.Labels, request.Body.TargetTimeoutSeconds, request.Body.MaxConcurrency)
	updated, err := api.services.Inspection.UpdatePolicy(ctx, scope, principal.Subject, request.Params.IdempotencyKey, request.PolicyId, version, value)
	if errors.Is(err, inspection.ErrConflict) {
		return nil, ErrPreconditionFailed
	}
	if err != nil {
		return nil, err
	}
	if updated.Scope != scope || updated.ID != request.PolicyId {
		return nil, errors.New("inspection service returned an out-of-scope policy")
	}
	body, err := openAPIInspectionPolicy(updated)
	if err != nil {
		return nil, err
	}
	return inspectionPolicyUpdateResponse{Body: body, ETag: entityTag(updated.Version)}, nil
}

func (api platformAPI) RunInspectionPolicy(ctx context.Context, request openapi.RunInspectionPolicyRequestObject) (openapi.RunInspectionPolicyResponseObject, error) {
	scope, principal, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	value, err := api.services.Inspection.RunPolicy(ctx, scope, principal.Subject, request.Params.IdempotencyKey, request.PolicyId)
	if err != nil {
		return nil, err
	}
	body, err := openAPIInspectionRun(value, scope, nil, nil)
	if err != nil {
		return nil, err
	}
	return openapi.RunInspectionPolicy202JSONResponse(body), nil
}

func (api platformAPI) ListInspectionReports(ctx context.Context, request openapi.ListInspectionReportsRequestObject) (openapi.ListInspectionReportsResponseObject, error) {
	scope, _, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := inspectionFilter(request.Params.Cursor, request.Params.Limit)
	page, err := api.services.Inspection.ListReports(ctx, scope, inspection.ReportFilter{CursorFilter: filter})
	if err != nil {
		return nil, err
	}
	items := make([]openapi.InspectionReport, len(page.Items))
	for index, value := range page.Items {
		items[index], err = openAPIInspectionReport(value, scope, false)
		if err != nil {
			return nil, err
		}
	}
	return openapi.ListInspectionReports200JSONResponse{Items: items, Page: inspectionPage(filter.Limit, page.More, page.NextCursor)}, nil
}

func (api platformAPI) GetInspectionReport(ctx context.Context, request openapi.GetInspectionReportRequestObject) (openapi.GetInspectionReportResponseObject, error) {
	scope, _, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	value, err := api.services.Inspection.GetReport(ctx, scope, request.ReportId)
	if err != nil {
		return nil, err
	}
	if value.ID != request.ReportId {
		return nil, errors.New("inspection service returned the wrong report")
	}
	body, err := openAPIInspectionReport(value, scope, true)
	if err != nil {
		return nil, err
	}
	return openapi.GetInspectionReport200JSONResponse(body), nil
}

func (api platformAPI) CreateInspectionReportDownload(ctx context.Context, request openapi.CreateInspectionReportDownloadRequestObject) (openapi.CreateInspectionReportDownloadResponseObject, error) {
	scope, principal, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	value, err := api.services.Inspection.CreateReportDownload(ctx, scope, principal.Subject, request.Params.IdempotencyKey, request.ReportId)
	if err != nil {
		return nil, err
	}
	return openapi.CreateInspectionReportDownload200JSONResponse(downloadDescriptor(value)), nil
}

func (api platformAPI) ListInspectionRuns(ctx context.Context, request openapi.ListInspectionRunsRequestObject) (openapi.ListInspectionRunsResponseObject, error) {
	scope, _, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := inspectionFilter(request.Params.Cursor, request.Params.Limit)
	page, err := api.services.Inspection.ListRuns(ctx, scope, inspection.RunFilter{CursorFilter: filter})
	if err != nil {
		return nil, err
	}
	items := make([]openapi.InspectionRun, len(page.Items))
	for index, value := range page.Items {
		items[index], err = openAPIInspectionRun(value, scope, nil, nil)
		if err != nil {
			return nil, err
		}
	}
	return openapi.ListInspectionRuns200JSONResponse{Items: items, Page: inspectionPage(filter.Limit, page.More, page.NextCursor)}, nil
}

func (api platformAPI) CreateInspectionRun(ctx context.Context, request openapi.CreateInspectionRunRequestObject) (openapi.CreateInspectionRunResponseObject, error) {
	scope, principal, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	value, err := api.services.Inspection.CreateRun(ctx, inspectionRunInput(ctx, scope, principal.Subject, request.Params.IdempotencyKey, *request.Body))
	if err != nil {
		return nil, err
	}
	body, err := openAPIInspectionRun(value, scope, nil, nil)
	if err != nil {
		return nil, err
	}
	return openapi.CreateInspectionRun202JSONResponse(body), nil
}

func (api platformAPI) GetInspectionRun(ctx context.Context, request openapi.GetInspectionRunRequestObject) (openapi.GetInspectionRunResponseObject, error) {
	scope, _, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	detail, err := api.services.Inspection.GetRun(ctx, scope, request.RunId)
	if err != nil {
		return nil, err
	}
	if detail.Run.ID != request.RunId {
		return nil, errors.New("inspection service returned the wrong run")
	}
	body, err := openAPIInspectionRun(detail.Run, scope, detail.Targets, detail.Findings)
	if err != nil {
		return nil, err
	}
	return openapi.GetInspectionRun200JSONResponse(body), nil
}

func (api platformAPI) CancelInspectionRun(ctx context.Context, request openapi.CancelInspectionRunRequestObject) (openapi.CancelInspectionRunResponseObject, error) {
	scope, principal, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	value, err := api.services.Inspection.CancelRun(ctx, scope, principal.Subject, request.Params.IdempotencyKey, request.RunId)
	if err != nil {
		return nil, err
	}
	body, err := openAPIInspectionRun(value, scope, nil, nil)
	if err != nil {
		return nil, err
	}
	return openapi.CancelInspectionRun202JSONResponse(body), nil
}

func (api platformAPI) RetryInspectionRun(ctx context.Context, request openapi.RetryInspectionRunRequestObject) (openapi.RetryInspectionRunResponseObject, error) {
	scope, principal, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	value, err := api.services.Inspection.RetryRun(ctx, scope, principal.Subject, request.Params.IdempotencyKey, request.RunId)
	if err != nil {
		return nil, err
	}
	body, err := openAPIInspectionRun(value, scope, nil, nil)
	if err != nil {
		return nil, err
	}
	return openapi.RetryInspectionRun202JSONResponse(body), nil
}

func (api platformAPI) ListInspectionTargets(ctx context.Context, request openapi.ListInspectionTargetsRequestObject) (openapi.ListInspectionTargetsResponseObject, error) {
	scope, _, err := api.inspectionIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := inspectionFilter(request.Params.Cursor, request.Params.Limit)
	page, err := api.services.Inspection.ListTargets(ctx, scope, filter)
	if err != nil {
		return nil, err
	}
	items := make([]openapi.InspectionTarget, len(page.Items))
	for index, value := range page.Items {
		if value.Scope != scope {
			return nil, errors.New("inspection service returned an out-of-scope target")
		}
		connectivity := openapi.InspectionConnectivity(value.Connectivity)
		if !connectivity.Valid() {
			return nil, errors.New("inspection target has invalid connectivity")
		}
		items[index] = openapi.InspectionTarget{AgentId: value.AgentID, DisplayName: value.DisplayName, Host: value.Host, Labels: cloneStringMap(value.Labels), Connectivity: connectivity, Capabilities: append([]string{}, value.Capabilities...)}
	}
	return openapi.ListInspectionTargets200JSONResponse{Items: items, Page: inspectionPage(filter.Limit, page.More, page.NextCursor)}, nil
}

func (api platformAPI) inspectionIdentity(ctx context.Context) (platformscope.Scope, Principal, error) {
	if api.services.Inspection == nil {
		return platformscope.Scope{}, Principal{}, ErrServiceUnavailable
	}
	return platformRequestIdentity(ctx)
}

func inspectionFilter(cursor *string, limit *int) inspection.CursorFilter {
	value := inspection.CursorFilter{Limit: defaultInspectionPageLimit}
	if cursor != nil {
		value.Cursor = *cursor
	}
	if limit != nil {
		value.Limit = *limit
	}
	return value
}

func inspectionPage(limit int, more bool, cursor string) openapi.Page {
	page := openapi.Page{Limit: limit, HasMore: more}
	if cursor != "" {
		page.NextCursor = &cursor
	}
	return page
}

func inspectionItemInput(body openapi.CreateInspectionItemRequest) (inspection.Item, error) {
	window, err := inspectionMetricWindow(body.MetricRule.Window)
	if err != nil {
		return inspection.Item{}, err
	}
	return inspection.Item{
		Version: 1, Name: body.Name, Description: body.Description, Category: body.Category,
		ScopeType: inspection.ScopeType(body.ScopeType), SourceType: inspection.SourceType(body.SourceType),
		MetricRule:       &inspection.MetricRule{MetricName: body.MetricRule.MetricName, Labels: cloneOptionalStringMap(body.MetricRule.Labels), Window: window, Aggregation: inspection.Aggregation(body.MetricRule.Aggregation), Operator: inspection.Operator(body.MetricRule.Operator), WarningThreshold: float64(body.MetricRule.WarningThreshold), CriticalThreshold: float64(body.MetricRule.CriticalThreshold)},
		EvidenceSelector: append([]string(nil), body.EvidenceSelector.Fields...), RequiredCapabilities: cloneOptionalStrings(body.RequiredCapabilities), RecommendationTemplate: body.RecommendationTemplate, DocumentationURL: optionalString(body.DocumentationUrl), Enabled: true,
	}, nil
}

func inspectionPolicyInput(name string, enabled bool, schedule *openapi.InspectionSchedule, items []openapi.InspectionPolicyItem, targetIDs []string, labels *map[string]string, timeoutSeconds, maxConcurrency *int) inspection.Policy {
	value := inspection.Policy{Name: name, Enabled: enabled, Items: make([]inspection.PolicyItem, len(items)), Selector: inspection.TargetSelector{AgentIDs: append([]string(nil), targetIDs...), Labels: cloneOptionalStringMap(labels)}, TargetTimeout: time.Minute, MaxConcurrency: 10}
	if schedule != nil {
		value.Schedule = &inspection.Schedule{Cron: schedule.Cron, Timezone: schedule.Timezone}
	}
	for index, item := range items {
		value.Items[index] = inspection.PolicyItem{ItemID: item.ItemId, Version: item.Version}
	}
	if timeoutSeconds != nil {
		value.TargetTimeout = time.Duration(*timeoutSeconds) * time.Second
	}
	if maxConcurrency != nil {
		value.MaxConcurrency = *maxConcurrency
	}
	return value
}

func inspectionRunInput(ctx context.Context, scope platformscope.Scope, actor, key string, body openapi.CreateInspectionRunRequest) inspection.CreateRunRequest {
	items := make([]inspection.PolicyItem, len(body.ItemVersions))
	for index, item := range body.ItemVersions {
		items[index] = inspection.PolicyItem{ItemID: item.ItemId, Version: item.Version}
	}
	timeout, concurrency := time.Minute, 10
	if body.TargetTimeoutSeconds != nil {
		timeout = time.Duration(*body.TargetTimeoutSeconds) * time.Second
	}
	if body.MaxConcurrency != nil {
		concurrency = *body.MaxConcurrency
	}
	return inspection.CreateRunRequest{Scope: scope, Selector: inspection.TargetSelector{AgentIDs: append([]string(nil), body.TargetIds...), Labels: map[string]string{}}, Items: items, TargetTimeout: timeout, MaxConcurrency: concurrency, IdempotencyKey: key, InitiatedBy: actor, RequestID: requestIDFromContext(ctx), TraceID: traceIDFromContext(ctx), Trigger: inspection.RunTriggerManual}
}

func openAPIInspectionItem(value inspection.Item) (openapi.InspectionItem, error) {
	if value.Validate() != nil || value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() {
		return openapi.InspectionItem{}, errors.New("inspection item cannot be represented by the platform contract")
	}
	response := openapi.InspectionItem{Id: value.ID, Version: value.Version, Name: value.Name, Description: value.Description, Category: value.Category, ScopeType: openapi.InspectionScopeType(value.ScopeType), SourceType: openapi.InspectionSourceType(value.SourceType), System: value.System, Enabled: value.Enabled, RecommendationTemplate: value.RecommendationTemplate, CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC()}
	if value.MetricRule != nil {
		window, err := openAPIInspectionMetricWindow(value.MetricRule.Window)
		if err != nil {
			return openapi.InspectionItem{}, err
		}
		response.MetricRule = &openapi.InspectionMetricRule{MetricName: value.MetricRule.MetricName, Labels: optionalMap(value.MetricRule.Labels), Window: window, Aggregation: openapi.InspectionMetricAggregation(value.MetricRule.Aggregation), Operator: openapi.InspectionMetricOperator(value.MetricRule.Operator), WarningThreshold: float32(value.MetricRule.WarningThreshold), CriticalThreshold: float32(value.MetricRule.CriticalThreshold)}
	}
	if len(value.EvidenceSelector) > 0 {
		response.EvidenceSelector = &openapi.InspectionEvidenceSelector{Fields: append([]string(nil), value.EvidenceSelector...)}
	}
	if len(value.RequiredCapabilities) > 0 {
		capabilities := append([]string(nil), value.RequiredCapabilities...)
		response.RequiredCapabilities = &capabilities
	}
	if value.DocumentationURL != "" {
		documentation := value.DocumentationURL
		response.DocumentationUrl = &documentation
	}
	return response, nil
}

func openAPIInspectionPolicy(value inspection.Policy) (openapi.InspectionPolicy, error) {
	if value.Scope.Validate() != nil || value.ID == "" || value.Version < 1 || value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() {
		return openapi.InspectionPolicy{}, errors.New("inspection policy cannot be represented by the platform contract")
	}
	items := make([]openapi.InspectionPolicyItem, len(value.Items))
	for index, item := range value.Items {
		items[index] = openapi.InspectionPolicyItem{ItemId: item.ItemID, Version: item.Version}
	}
	timeout, concurrency := int(value.TargetTimeout/time.Second), value.MaxConcurrency
	response := openapi.InspectionPolicy{Id: value.ID, Name: value.Name, Enabled: value.Enabled, Version: int(value.Version), ItemVersions: items, TargetIds: append([]string{}, value.Selector.AgentIDs...), Labels: cloneStringMap(value.Selector.Labels), TargetTimeoutSeconds: &timeout, MaxConcurrency: &concurrency, CreatedAt: value.CreatedAt.UTC(), UpdatedAt: value.UpdatedAt.UTC()}
	if value.Schedule != nil {
		response.Schedule = &openapi.InspectionSchedule{Cron: value.Schedule.Cron, Timezone: value.Schedule.Timezone}
	}
	if value.NextRunAt != nil {
		next := value.NextRunAt.UTC()
		response.NextRunAt = &next
	}
	return response, nil
}

func openAPIInspectionRun(value inspection.Run, scope platformscope.Scope, targets []inspection.TargetRun, findings []inspection.Finding) (openapi.InspectionRun, error) {
	status := openapi.InspectionRunStatus(value.Status)
	if value.Scope != scope || value.ID == "" || value.JobID == "" || value.CreatedAt.IsZero() || !status.Valid() {
		return openapi.InspectionRun{}, errors.New("inspection run cannot be represented by the platform contract")
	}
	jobID := openapi.JobId(value.JobID)
	response := openapi.InspectionRun{Id: value.ID, Status: status, JobId: &jobID, TargetCount: value.TargetCount, CompletedTargetCount: value.CompletedTargetCount, FailedTargetCount: value.FailedTargetCount, CreatedAt: value.CreatedAt.UTC(), StartedAt: utcTimePointer(value.StartedAt), FinishedAt: utcTimePointer(value.FinishedAt), ScheduledFor: utcTimePointer(value.ScheduledFor)}
	if value.PolicyID != "" {
		policy := value.PolicyID
		response.PolicyId = &policy
	}
	if value.ReportID != "" {
		report := value.ReportID
		response.ReportId = &report
	}
	if value.RetryOfRunID != "" {
		retry := value.RetryOfRunID
		response.RetryOfRunId = &retry
	}
	if targets != nil {
		mapped := make([]openapi.InspectionTargetRun, len(targets))
		for index, target := range targets {
			mapped[index] = openAPIInspectionTargetRun(target)
		}
		response.Targets = &mapped
	}
	if findings != nil {
		mapped, err := openAPIInspectionFindings(findings)
		if err != nil {
			return openapi.InspectionRun{}, err
		}
		response.Findings = &mapped
	}
	return response, nil
}

func openAPIInspectionReport(value inspection.ReportSnapshot, scope platformscope.Scope, includeFindings bool) (openapi.InspectionReport, error) {
	status := openapi.InspectionReportStatus(value.Status)
	if value.Scope != scope || value.ID == "" || value.RunID == "" || value.GeneratedAt.IsZero() || !status.Valid() {
		return openapi.InspectionReport{}, errors.New("inspection report cannot be represented by the platform contract")
	}
	artifacts := make([]openapi.ArtifactReference, len(value.Artifacts))
	for index, reference := range value.Artifacts {
		artifacts[index] = openapi.ArtifactReference{ArtifactId: reference.ArtifactID, Kind: reference.Kind}
	}
	response := openapi.InspectionReport{Id: value.ID, RunId: value.RunID, Status: status, Summary: value.Summary, Artifacts: artifacts, GeneratedAt: value.GeneratedAt.UTC()}
	if value.PolicyID != "" {
		policy := value.PolicyID
		response.PolicyId = &policy
	}
	if includeFindings {
		var document inspection.ReportDocument
		if value.Document != nil {
			document = *value.Document
		} else if json.Unmarshal(value.Snapshot, &document) != nil {
			return openapi.InspectionReport{}, errors.New("inspection report snapshot cannot be represented")
		}
		findings := make([]inspection.Finding, len(document.Findings))
		for index, finding := range document.Findings {
			findings[index] = inspection.Finding{ID: "inspection-report-finding-" + strconv.Itoa(index+1), Scope: scope, RunID: value.RunID, TargetID: finding.TargetID, ItemID: finding.ItemID, ItemVersion: finding.ItemVersion, Level: finding.Level, ObservedAt: finding.ObservedAt, WarningThreshold: finding.WarningThreshold, CriticalThreshold: finding.CriticalThreshold, Evidence: finding.Evidence, Summary: finding.Summary, Recommendation: finding.Recommendation}
		}
		mapped, err := openAPIInspectionFindings(findings)
		if err != nil {
			return openapi.InspectionReport{}, err
		}
		response.Findings = &mapped
	}
	return response, nil
}

func openAPIInspectionFindings(values []inspection.Finding) ([]openapi.InspectionFinding, error) {
	result := make([]openapi.InspectionFinding, len(values))
	for index, value := range values {
		if value.ID == "" || value.ObservedAt.IsZero() {
			return nil, errors.New("inspection finding cannot be represented")
		}
		evidence, err := json.Marshal(value.Evidence)
		if err != nil {
			return nil, err
		}
		result[index] = openapi.InspectionFinding{Id: value.ID, ItemId: value.ItemID, ItemVersion: value.ItemVersion, TargetId: value.TargetID, Level: openapi.InspectionFindingLevel(value.Level), ObservedAt: value.ObservedAt.UTC(), Evidence: string(evidence), Summary: value.Summary, Recommendation: value.Recommendation, WarningThreshold: float64ToFloat32(value.WarningThreshold), CriticalThreshold: float64ToFloat32(value.CriticalThreshold)}
	}
	return result, nil
}

func openAPIInspectionTargetRun(value inspection.TargetRun) openapi.InspectionTargetRun {
	response := openapi.InspectionTargetRun{TargetId: value.TargetID, AgentId: value.AgentID, Status: openapi.InspectionTargetRunStatus(value.Status)}
	if value.CommandID != "" {
		command := openapi.CommandId(value.CommandID)
		response.CommandId = &command
	}
	if value.ErrorCode != "" {
		code := value.ErrorCode
		response.ErrorCode = &code
	}
	if !value.ObservedAt.IsZero() {
		observed := value.ObservedAt.UTC()
		response.ObservedAt = &observed
	}
	return response
}

func downloadDescriptor(value artifact.Download) openapi.DownloadDescriptor {
	response := openapi.DownloadDescriptor{Url: value.URL, ExpiresAt: value.ExpiresAt.UTC()}
	if len(value.Headers) > 0 {
		headers := cloneStringMap(value.Headers)
		response.Headers = &headers
	}
	return response
}

func setRunOverviewCounts(response *openapi.InspectionOverview, counts map[inspection.RunStatus]int) {
	set := func(status inspection.RunStatus) *int {
		value, ok := counts[status]
		if !ok {
			return nil
		}
		return &value
	}
	response.LatestRunStatusCounts.Queued = set(inspection.RunQueued)
	response.LatestRunStatusCounts.Collecting = set(inspection.RunCollecting)
	response.LatestRunStatusCounts.Evaluating = set(inspection.RunEvaluating)
	response.LatestRunStatusCounts.GeneratingReport = set(inspection.RunGeneratingReport)
	response.LatestRunStatusCounts.Completed = set(inspection.RunCompleted)
	response.LatestRunStatusCounts.Partial = set(inspection.RunPartial)
	response.LatestRunStatusCounts.Failed = set(inspection.RunFailed)
	response.LatestRunStatusCounts.Cancelled = set(inspection.RunCancelled)
}

func setFindingOverviewCounts(response *openapi.InspectionOverview, counts map[inspection.FindingLevel]int) {
	set := func(level inspection.FindingLevel) *int {
		value, ok := counts[level]
		if !ok {
			return nil
		}
		return &value
	}
	response.FindingLevelCounts.Healthy = set(inspection.LevelHealthy)
	response.FindingLevelCounts.Warning = set(inspection.LevelWarning)
	response.FindingLevelCounts.Critical = set(inspection.LevelCritical)
	response.FindingLevelCounts.Unsupported = set(inspection.LevelUnsupported)
	response.FindingLevelCounts.MissingData = set(inspection.LevelMissingData)
}

func inspectionMetricWindow(value openapi.InspectionMetricWindow) (time.Duration, error) {
	switch value {
	case openapi.N5m:
		return 5 * time.Minute, nil
	case openapi.N15m:
		return 15 * time.Minute, nil
	case openapi.N1h:
		return time.Hour, nil
	default:
		return 0, ErrInvalidRequest
	}
}
func openAPIInspectionMetricWindow(value time.Duration) (openapi.InspectionMetricWindow, error) {
	switch value {
	case 5 * time.Minute:
		return openapi.N5m, nil
	case 15 * time.Minute:
		return openapi.N15m, nil
	case time.Hour:
		return openapi.N1h, nil
	default:
		return "", errors.New("inspection metric window cannot be represented")
	}
}
func cloneOptionalStrings(value *[]string) []string {
	if value == nil {
		return []string{}
	}
	return append([]string(nil), (*value)...)
}
func cloneOptionalStringMap(value *map[string]string) map[string]string {
	if value == nil {
		return map[string]string{}
	}
	return cloneStringMap(*value)
}
func cloneStringMap(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}
func optionalMap(value map[string]string) *map[string]string {
	if len(value) == 0 {
		return nil
	}
	cloned := cloneStringMap(value)
	return &cloned
}
func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func float64ToFloat32(value *float64) *float32 {
	if value == nil {
		return nil
	}
	result := float32(*value)
	return &result
}

type inspectionPolicyCreateResponse struct {
	Body openapi.InspectionPolicy
	ETag string
}

func (response inspectionPolicyCreateResponse) VisitCreateInspectionPolicyResponse(writer http.ResponseWriter) error {
	return writeInspectionJSON(writer, http.StatusCreated, response.ETag, response.Body)
}

type inspectionPolicyGetResponse struct {
	Body openapi.InspectionPolicy
	ETag string
}

func (response inspectionPolicyGetResponse) VisitGetInspectionPolicyResponse(writer http.ResponseWriter) error {
	return writeInspectionJSON(writer, http.StatusOK, response.ETag, response.Body)
}

type inspectionPolicyUpdateResponse struct {
	Body openapi.InspectionPolicy
	ETag string
}

func (response inspectionPolicyUpdateResponse) VisitUpdateInspectionPolicyResponse(writer http.ResponseWriter) error {
	return writeInspectionJSON(writer, http.StatusOK, response.ETag, response.Body)
}

func writeInspectionJSON(writer http.ResponseWriter, status int, etag string, value any) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(value); err != nil {
		return err
	}
	writer.Header().Set("Content-Type", "application/json")
	if etag != "" {
		writer.Header().Set("ETag", etag)
	}
	writer.WriteHeader(status)
	_, err := body.WriteTo(writer)
	return err
}

type inspectionApplicationService struct {
	repository  inspection.Repository
	runs        *inspection.Service
	targets     inspection.TargetResolver
	jobs        JobService
	artifacts   ArtifactService
	audit       AuditService
	idempotency IdempotencyService
	now         func() time.Time
}

// NewInspectionApplicationService constructs the production application
// boundary used by the strict HTTP handlers and the scheduler/worker wiring.
func NewInspectionApplicationService(repository inspection.Repository, runs *inspection.Service, targets inspection.TargetResolver, jobs JobService, artifacts ArtifactService, audit AuditService, idempotencyService IdempotencyService, now func() time.Time) (InspectionService, error) {
	if repository == nil || runs == nil || targets == nil || jobs == nil || artifacts == nil || audit == nil || idempotencyService == nil {
		return nil, errors.New("inspection application dependencies are incomplete")
	}
	return &inspectionApplicationService{repository: repository, runs: runs, targets: targets, jobs: jobs, artifacts: artifacts, audit: audit, idempotency: idempotencyService, now: now}, nil
}

func (service *inspectionApplicationService) ListItems(ctx context.Context, scope platformscope.Scope, filter inspection.ItemFilter) (inspection.ItemPage, error) {
	return service.repository.ListItems(ctx, scope, filter)
}

func (service *inspectionApplicationService) CreateItem(ctx context.Context, scope platformscope.Scope, actor, key string, value inspection.Item) (inspection.Item, error) {
	id := deterministicInspectionID("inspection-item", scope, actor, "CreateInspectionItem", key)
	now := service.currentTime()
	value.Scope, value.ID, value.Version, value.System, value.Enabled = scope, id, 1, false, true
	value.CreatedAt, value.UpdatedAt = now, now
	recover := func(recoveryContext context.Context) (inspection.Item, error) {
		page, err := service.repository.ListItems(recoveryContext, scope, inspection.ItemFilter{CursorFilter: inspection.CursorFilter{Limit: 2}, Versions: []inspection.PolicyItem{{ItemID: id, Version: 1}}})
		if err != nil {
			return inspection.Item{}, err
		}
		if len(page.Items) != 1 || page.Items[0].ID != id || page.Items[0].Scope != scope {
			return inspection.Item{}, idempotency.ErrInProgress
		}
		return page.Items[0], nil
	}
	return executeInspectionWrite(ctx, service, scope, actor, key, "CreateInspectionItem", "inspection.item.created", "inspection_item", id, http.StatusCreated, recover, func(context.Context) (inspection.Item, error) {
		return value, service.repository.CreateItem(ctx, value)
	})
}

func (service *inspectionApplicationService) GetOverview(ctx context.Context, scope platformscope.Scope) (InspectionOverview, error) {
	targets, err := service.targets.List(ctx, scope)
	if err != nil {
		return InspectionOverview{}, err
	}
	overview := InspectionOverview{TargetCount: len(targets), RunStatusCounts: make(map[inspection.RunStatus]int), FindingLevelCounts: make(map[inspection.FindingLevel]int)}
	for _, target := range targets {
		if target.Connectivity == string(openapi.Online) {
			overview.OnlineTargetCount++
		}
	}
	cursor := ""
	for {
		page, listErr := service.repository.ListRuns(ctx, scope, inspection.RunFilter{CursorFilter: inspection.CursorFilter{Cursor: cursor, Limit: 100}})
		if listErr != nil {
			return InspectionOverview{}, listErr
		}
		for _, value := range page.Items {
			overview.RunStatusCounts[value.Status]++
		}
		if !page.More {
			break
		}
		if page.NextCursor == "" || page.NextCursor == cursor {
			return InspectionOverview{}, inspection.ErrConflict
		}
		cursor = page.NextCursor
	}
	cursor = ""
	for {
		page, listErr := service.repository.ListReports(ctx, scope, inspection.ReportFilter{CursorFilter: inspection.CursorFilter{Cursor: cursor, Limit: 100}})
		if listErr != nil {
			return InspectionOverview{}, listErr
		}
		for _, report := range page.Items {
			var document inspection.ReportDocument
			if report.Document != nil {
				document = *report.Document
			} else if len(report.Snapshot) > 0 && json.Unmarshal(report.Snapshot, &document) != nil {
				return InspectionOverview{}, inspection.ErrInvalidReport
			}
			for _, finding := range document.Findings {
				overview.FindingLevelCounts[finding.Level]++
			}
		}
		if !page.More {
			break
		}
		if page.NextCursor == "" || page.NextCursor == cursor {
			return InspectionOverview{}, inspection.ErrConflict
		}
		cursor = page.NextCursor
	}
	return overview, nil
}

func (service *inspectionApplicationService) ListPolicies(ctx context.Context, scope platformscope.Scope, filter inspection.PolicyFilter) (inspection.PolicyPage, error) {
	return service.repository.ListPolicies(ctx, scope, filter)
}

func (service *inspectionApplicationService) CreatePolicy(ctx context.Context, scope platformscope.Scope, actor, key string, value inspection.Policy) (inspection.Policy, error) {
	id := deterministicInspectionID("inspection-policy", scope, actor, "CreateInspectionPolicy", key)
	now := service.currentTime()
	value.Scope, value.ID, value.Version = scope, id, 1
	value.CreatedAt, value.UpdatedAt = now, now
	if err := setInspectionNextRun(&value, now); err != nil {
		return inspection.Policy{}, err
	}
	recover := func(recoveryContext context.Context) (inspection.Policy, error) {
		stored, err := service.repository.GetPolicy(recoveryContext, scope, id)
		if errors.Is(err, inspection.ErrNotFound) {
			return inspection.Policy{}, idempotency.ErrInProgress
		}
		return stored, err
	}
	return executeInspectionWrite(ctx, service, scope, actor, key, "CreateInspectionPolicy", "inspection.policy.created", "inspection_policy", id, http.StatusCreated, recover, func(context.Context) (inspection.Policy, error) {
		return value, service.repository.CreatePolicy(ctx, value)
	})
}

func (service *inspectionApplicationService) GetPolicy(ctx context.Context, scope platformscope.Scope, id string) (inspection.Policy, error) {
	return service.repository.GetPolicy(ctx, scope, id)
}

func (service *inspectionApplicationService) UpdatePolicy(ctx context.Context, scope platformscope.Scope, actor, key, id string, current int64, value inspection.Policy) (inspection.Policy, error) {
	value.Scope, value.ID, value.Version = scope, id, current+1
	stored, err := service.repository.GetPolicy(ctx, scope, id)
	if err != nil {
		return inspection.Policy{}, err
	}
	value.CreatedAt, value.UpdatedAt = stored.CreatedAt.UTC(), service.currentTime()
	if err := setInspectionNextRun(&value, value.UpdatedAt); err != nil {
		return inspection.Policy{}, err
	}
	recover := func(recoveryContext context.Context) (inspection.Policy, error) {
		recovered, err := service.repository.GetPolicy(recoveryContext, scope, id)
		if err != nil {
			return inspection.Policy{}, err
		}
		if recovered.Version != current+1 {
			return inspection.Policy{}, idempotency.ErrInProgress
		}
		return recovered, nil
	}
	return executeInspectionWrite(ctx, service, scope, actor, key, "UpdateInspectionPolicy", "inspection.policy.updated", "inspection_policy", id, http.StatusOK, recover, func(context.Context) (inspection.Policy, error) {
		return service.repository.UpdatePolicy(ctx, value, current)
	})
}

func (service *inspectionApplicationService) RunPolicy(ctx context.Context, scope platformscope.Scope, actor, key, id string) (inspection.Run, error) {
	policy, err := service.repository.GetPolicy(ctx, scope, id)
	if err != nil {
		return inspection.Run{}, err
	}
	request := inspection.CreateRunRequest{Scope: scope, PolicyID: policy.ID, PolicyVersion: policy.Version, Selector: policy.Selector, Items: policy.Items, TargetTimeout: policy.TargetTimeout, MaxConcurrency: policy.MaxConcurrency, IdempotencyKey: key, InitiatedBy: actor, RequestID: requestIDFromContext(ctx), TraceID: traceIDFromContext(ctx), Trigger: inspection.RunTriggerManual, PolicySnapshot: &policy}
	return service.executeRun(ctx, scope, actor, key, "RunInspectionPolicy", id, request, func(runContext context.Context) (inspection.Run, error) {
		return service.runs.CreateRun(runContext, request)
	})
}

func (service *inspectionApplicationService) ListReports(ctx context.Context, scope platformscope.Scope, filter inspection.ReportFilter) (inspection.ReportPage, error) {
	return service.repository.ListReports(ctx, scope, filter)
}
func (service *inspectionApplicationService) GetReport(ctx context.Context, scope platformscope.Scope, id string) (inspection.ReportSnapshot, error) {
	return service.repository.GetReport(ctx, scope, id)
}

func (service *inspectionApplicationService) CreateReportDownload(ctx context.Context, scope platformscope.Scope, actor, key, id string) (artifact.Download, error) {
	report, err := service.repository.GetReport(ctx, scope, id)
	if err != nil {
		return artifact.Download{}, err
	}
	artifactID := preferredInspectionArtifact(report.Artifacts)
	if artifactID == "" {
		return artifact.Download{}, artifact.ErrNotFound
	}
	operation := "CreateInspectionReportDownload"
	fingerprint, err := platformIdempotencyFingerprint(ctx, operation, id, "")
	if err != nil {
		return artifact.Download{}, err
	}
	auditJSON, reconcile, err := httpActionAuditReconciliation(ctx, service.audit, scope, Principal{Subject: actor}, "inspection.report.download_authorized", "inspection_report", id, "success", operation, key)
	if err != nil {
		return artifact.Download{}, err
	}
	claim, err := service.idempotency.Begin(ctx, idempotency.Key{Scope: scope, Actor: actor, OperationID: operation, IdempotencyKey: key}, fingerprint, reconcile)
	if err != nil {
		return artifact.Download{}, err
	}
	if claim.Response != nil {
		return decodeInspectionResponse[artifact.Download](*claim.Response)
	}
	value, err := service.artifacts.CreateDownloadAt(ctx, scope, artifactID, service.currentTime(), artifact.MaximumDownloadTTL)
	if err != nil {
		_ = service.idempotency.Abort(ctx, idempotency.Key{Scope: scope, Actor: actor, OperationID: operation, IdempotencyKey: key}, fingerprint, claim.OwnerToken)
		return artifact.Download{}, err
	}
	response, err := encodeInspectionResponse(http.StatusOK, value)
	if err != nil {
		return artifact.Download{}, err
	}
	stored, err := service.idempotency.Complete(ctx, idempotency.Key{Scope: scope, Actor: actor, OperationID: operation, IdempotencyKey: key}, fingerprint, claim.OwnerToken, response, auditJSON, reconcile)
	if err != nil {
		return artifact.Download{}, err
	}
	return decodeInspectionResponse[artifact.Download](stored)
}

func (service *inspectionApplicationService) ListRuns(ctx context.Context, scope platformscope.Scope, filter inspection.RunFilter) (inspection.RunPage, error) {
	return service.repository.ListRuns(ctx, scope, filter)
}
func (service *inspectionApplicationService) CreateRun(ctx context.Context, request inspection.CreateRunRequest) (inspection.Run, error) {
	return service.executeRun(ctx, request.Scope, request.InitiatedBy, request.IdempotencyKey, "CreateInspectionRun", "ad-hoc", request, func(runContext context.Context) (inspection.Run, error) {
		return service.runs.CreateRun(runContext, request)
	})
}
func (service *inspectionApplicationService) GetRun(ctx context.Context, scope platformscope.Scope, id string) (inspection.RunDetail, error) {
	return service.repository.GetRun(ctx, scope, id)
}

func (service *inspectionApplicationService) CancelRun(ctx context.Context, scope platformscope.Scope, actor, key, id string) (inspection.Run, error) {
	detail, err := service.repository.GetRun(ctx, scope, id)
	if err != nil {
		return inspection.Run{}, err
	}
	value, err := service.jobs.Get(ctx, scope, detail.Run.JobID)
	if err != nil {
		return inspection.Run{}, err
	}
	operation := "CancelInspectionRun"
	fingerprint, err := platformIdempotencyFingerprint(ctx, operation, id, "")
	if err != nil {
		return inspection.Run{}, err
	}
	auditJSON, reconcile, err := httpActionAuditReconciliation(ctx, service.audit, scope, Principal{Subject: actor}, "inspection.run.cancel_requested", "inspection_run", id, "success", operation, key)
	if err != nil {
		return inspection.Run{}, err
	}
	idemKey := idempotency.Key{Scope: scope, Actor: actor, OperationID: operation, IdempotencyKey: key}
	correlation := job.CancellationSnapshotCorrelation{Actor: actor, OperationID: operation, IdempotencyKey: key, RequestFingerprint: fingerprint}
	snapshotKey := job.CancellationSnapshotKey{Actor: actor, OperationID: operation, IdempotencyKey: key, RequestFingerprint: fingerprint, IfMatch: entityTag(value.Version)}
	claim, err := service.idempotency.BeginRecoverable(ctx, idemKey, fingerprint, auditJSON, reconcile, func(recoveryContext context.Context, processing idempotency.ProcessingClaim) (idempotency.Response, error) {
		snapshot, snapshotErr := service.jobs.FindCancellationSnapshot(recoveryContext, scope, detail.Run.JobID, correlation)
		if errors.Is(snapshotErr, job.ErrNotFound) {
			return idempotency.Response{}, idempotency.ErrInProgress
		}
		if snapshotErr != nil {
			return idempotency.Response{}, snapshotErr
		}
		if snapshot.OwnerToken != processing.OwnerToken || snapshot.JobID != detail.Run.JobID || snapshot.Key.Actor != correlation.Actor || snapshot.Key.OperationID != correlation.OperationID || snapshot.Key.IdempotencyKey != correlation.IdempotencyKey || snapshot.Key.RequestFingerprint != correlation.RequestFingerprint || snapshot.Key.IfMatch != entityTag(snapshot.CurrentVersion) || !equalCanonicalJSON(snapshot.AuditEventJSON, processing.Reconciliation) {
			return idempotency.Response{}, errors.New("inspection cancellation snapshot is invalid")
		}
		current, currentErr := service.repository.GetRun(recoveryContext, scope, id)
		if currentErr != nil {
			return idempotency.Response{}, currentErr
		}
		return encodeInspectionResponse(http.StatusAccepted, current.Run)
	})
	if err != nil {
		return inspection.Run{}, err
	}
	if claim.Response != nil {
		return decodeInspectionResponse[inspection.Run](*claim.Response)
	}
	cancelledJob, err := service.jobs.RequestCancelWithSnapshot(ctx, scope, detail.Run.JobID, actor, value.Version, service.currentTime(), job.CancellationSnapshotInput{Key: snapshotKey, OwnerToken: claim.OwnerToken, AuditEventJSON: auditJSON})
	if err != nil {
		if jobTransitionFailedBeforeSideEffect(err) || errors.Is(err, job.ErrConflict) {
			_ = service.idempotency.Abort(ctx, idemKey, fingerprint, claim.OwnerToken)
		}
		return inspection.Run{}, err
	}
	if cancelledJob.ID != detail.Run.JobID || cancelledJob.Scope != scope || cancelledJob.Status != job.StatusCancelling {
		return inspection.Run{}, errors.New("inspection cancellation returned an invalid Job")
	}
	response, err := encodeInspectionResponse(http.StatusAccepted, detail.Run)
	if err != nil {
		return inspection.Run{}, err
	}
	stored, err := service.idempotency.Complete(ctx, idemKey, fingerprint, claim.OwnerToken, response, auditJSON, reconcile)
	if err != nil {
		return inspection.Run{}, err
	}
	return decodeInspectionResponse[inspection.Run](stored)
}

func (service *inspectionApplicationService) RetryRun(ctx context.Context, scope platformscope.Scope, actor, key, id string) (inspection.Run, error) {
	return service.executeRun(ctx, scope, actor, key, "RetryInspectionRun", id, inspection.CreateRunRequest{}, func(runContext context.Context) (inspection.Run, error) {
		return service.runs.RetryRun(runContext, scope, id, key, actor)
	})
}

func (service *inspectionApplicationService) ListTargets(ctx context.Context, scope platformscope.Scope, filter inspection.CursorFilter) (InspectionTargetPage, error) {
	if filter.Limit < 1 || filter.Limit > 100 {
		return InspectionTargetPage{}, inspection.ErrInvalid
	}
	values, err := service.targets.List(ctx, scope)
	if err != nil {
		return InspectionTargetPage{}, err
	}
	offset, err := decodeInspectionTargetCursor(scope, filter.Cursor)
	if err != nil {
		return InspectionTargetPage{}, err
	}
	if offset > len(values) {
		return InspectionTargetPage{}, inspection.ErrInvalid
	}
	end := offset + filter.Limit
	if end > len(values) {
		end = len(values)
	}
	page := InspectionTargetPage{Items: values[offset:end], More: end < len(values)}
	if page.More {
		page.NextCursor = encodeInspectionTargetCursor(scope, end)
	}
	return page, nil
}

func (service *inspectionApplicationService) executeRun(ctx context.Context, scope platformscope.Scope, actor, key, operation, resourceID string, request inspection.CreateRunRequest, create func(context.Context) (inspection.Run, error)) (inspection.Run, error) {
	recover := func(recoveryContext context.Context) (inspection.Run, error) {
		value, err := service.repository.GetRunByIdempotencyKey(recoveryContext, scope, key)
		if errors.Is(err, inspection.ErrNotFound) {
			return inspection.Run{}, idempotency.ErrInProgress
		}
		return value, err
	}
	return executeInspectionWrite(ctx, service, scope, actor, key, operation, "inspection.run.created", "inspection_run", resourceID, http.StatusAccepted, recover, create)
}

func executeInspectionWrite[T any](ctx context.Context, service *inspectionApplicationService, scope platformscope.Scope, actor, key, operation, action, resourceType, resourceID string, status int, recoverValue func(context.Context) (T, error), perform func(context.Context) (T, error)) (T, error) {
	var zero T
	fingerprint, err := platformIdempotencyFingerprint(ctx, operation, resourceID, "")
	if err != nil {
		return zero, err
	}
	auditJSON, reconcile, err := httpActionAuditReconciliation(ctx, service.audit, scope, Principal{Subject: actor}, action, resourceType, resourceID, "success", operation, key)
	if err != nil {
		return zero, err
	}
	idemKey := idempotency.Key{Scope: scope, Actor: actor, OperationID: operation, IdempotencyKey: key}
	claim, err := service.idempotency.BeginRecoverable(ctx, idemKey, fingerprint, auditJSON, reconcile, func(recoveryContext context.Context, _ idempotency.ProcessingClaim) (idempotency.Response, error) {
		value, recoverErr := recoverValue(recoveryContext)
		if recoverErr != nil {
			return idempotency.Response{}, recoverErr
		}
		return encodeInspectionResponse(status, value)
	})
	if err != nil {
		return zero, err
	}
	if claim.Response != nil {
		return decodeInspectionResponse[T](*claim.Response)
	}
	value, err := perform(ctx)
	if err != nil {
		if inspectionWriteFailedBeforeSideEffect(err) {
			_ = service.idempotency.Abort(ctx, idemKey, fingerprint, claim.OwnerToken)
		}
		return zero, err
	}
	response, err := encodeInspectionResponse(status, value)
	if err != nil {
		return zero, err
	}
	stored, err := service.idempotency.Complete(ctx, idemKey, fingerprint, claim.OwnerToken, response, auditJSON, reconcile)
	if err != nil {
		return zero, err
	}
	return decodeInspectionResponse[T](stored)
}

func encodeInspectionResponse(status int, value any) (idempotency.Response, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return idempotency.Response{}, err
	}
	return idempotency.Response{Status: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: body}, nil
}
func decodeInspectionResponse[T any](response idempotency.Response) (T, error) {
	var value T
	if err := json.Unmarshal(response.Body, &value); err != nil {
		return value, err
	}
	return value, nil
}

func deterministicInspectionID(prefix string, scope platformscope.Scope, actor, operation, key string) string {
	digest := sha256.Sum256([]byte(scope.Key() + "\x00" + actor + "\x00" + operation + "\x00" + key))
	return prefix + "-" + hex.EncodeToString(digest[:16])
}
func setInspectionNextRun(value *inspection.Policy, after time.Time) error {
	if value.Schedule == nil {
		value.NextRunAt = nil
		return nil
	}
	next, err := inspection.NextScheduledOccurrence(*value.Schedule, after)
	if err != nil {
		return err
	}
	value.NextRunAt = &next
	return nil
}
func inspectionWriteFailedBeforeSideEffect(err error) bool {
	return errors.Is(err, inspection.ErrInvalid) || errors.Is(err, inspection.ErrInvalidItem) || errors.Is(err, inspection.ErrInvalidSchedule) || errors.Is(err, inspection.ErrNotFound) || errors.Is(err, inspection.ErrConflict) || errors.Is(err, inspection.ErrRunNotRetryable) || errors.Is(err, inspection.ErrUnknownTarget) || errors.Is(err, inspection.ErrNoTargets)
}
func preferredInspectionArtifact(values []job.ArtifactReference) string {
	for _, value := range values {
		if strings.HasSuffix(strings.ToLower(value.ArtifactID), ".html") {
			return value.ArtifactID
		}
	}
	for _, value := range values {
		if strings.HasSuffix(strings.ToLower(value.ArtifactID), ".json") {
			return value.ArtifactID
		}
	}
	return ""
}

type inspectionTargetCursor struct {
	Scope  platformscope.Scope `json:"scope"`
	Offset int                 `json:"offset"`
}

func encodeInspectionTargetCursor(scope platformscope.Scope, offset int) string {
	encoded, _ := json.Marshal(inspectionTargetCursor{Scope: scope, Offset: offset})
	return base64.RawURLEncoding.EncodeToString(encoded)
}
func decodeInspectionTargetCursor(scope platformscope.Scope, cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	encoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, inspection.ErrInvalid
	}
	var value inspectionTargetCursor
	if json.Unmarshal(encoded, &value) != nil || value.Scope != scope || value.Offset < 0 {
		return 0, inspection.ErrInvalid
	}
	return value.Offset, nil
}
func (service *inspectionApplicationService) currentTime() time.Time {
	if service.now != nil {
		return service.now().UTC()
	}
	return time.Now().UTC()
}

var _ InspectionService = (*inspectionApplicationService)(nil)
