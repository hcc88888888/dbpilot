package controlplane

import (
	"context"
	"errors"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/metrictemplate"
)

func (api platformAPI) ListMetricTemplates(ctx context.Context, request openapi.ListMetricTemplatesRequestObject) (openapi.ListMetricTemplatesResponseObject, error) {
	if api.services.MetricTemplates == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := metrictemplate.Filter{}
	if request.Params.DatabaseFamily != nil {
		filter.DatabaseFamily = string(*request.Params.DatabaseFamily)
	}
	if request.Params.Cursor != nil {
		filter.Cursor = *request.Params.Cursor
	}
	if request.Params.Limit != nil {
		filter.Limit = *request.Params.Limit
	}
	page, err := api.services.MetricTemplates.ListTemplates(ctx, scope, filter)
	if err != nil {
		return nil, err
	}
	items := make([]openapi.MetricTemplate, len(page.Items))
	for index, value := range page.Items {
		items[index], err = openAPIMetricTemplate(value)
		if err != nil {
			return nil, err
		}
	}
	limit := filter.Limit
	if limit == 0 {
		limit = metrictemplate.DefaultListLimit
	}
	return openapi.ListMetricTemplates200JSONResponse{Items: items, Page: openAPIPage(limit, page.NextCursor != "", page.NextCursor)}, nil
}

func (api platformAPI) CreateMetricTemplate(ctx context.Context, request openapi.CreateMetricTemplateRequestObject) (openapi.CreateMetricTemplateResponseObject, error) {
	if api.services.MetricTemplates == nil {
		return nil, ErrServiceUnavailable
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	actor, err := metricTemplateActor(ctx, principal.Subject, "createMetricTemplate", request.Params.IdempotencyKey, request.Body.TemplateId, "")
	if err != nil {
		return nil, err
	}
	description := ""
	if request.Body.Description != nil {
		description = *request.Body.Description
	}
	value, err := api.services.MetricTemplates.CreateTemplate(ctx, scope, metrictemplate.TemplateDraft{ID: request.Body.TemplateId, DatabaseFamily: string(request.Body.DatabaseFamily), Name: request.Body.Name, Description: description}, actor)
	if err != nil {
		return nil, err
	}
	body, err := openAPIMetricTemplate(value)
	if err != nil {
		return nil, err
	}
	return openapi.CreateMetricTemplate201JSONResponse(body), nil
}

func (api platformAPI) ListMetricTemplateRevisions(ctx context.Context, request openapi.ListMetricTemplateRevisionsRequestObject) (openapi.ListMetricTemplateRevisionsResponseObject, error) {
	if api.services.MetricTemplates == nil {
		return nil, ErrServiceUnavailable
	}
	scope, _, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	filter := metrictemplate.RevisionFilter{}
	if request.Params.Cursor != nil {
		filter.Cursor = *request.Params.Cursor
	}
	if request.Params.Limit != nil {
		filter.Limit = *request.Params.Limit
	}
	page, err := api.services.MetricTemplates.ListRevisions(ctx, scope, request.TemplateId, filter)
	if err != nil {
		return nil, err
	}
	items := make([]openapi.MetricTemplateRevision, len(page.Items))
	for index, value := range page.Items {
		items[index], err = openAPIMetricTemplateRevision(value)
		if err != nil {
			return nil, err
		}
	}
	limit := filter.Limit
	if limit == 0 {
		limit = metrictemplate.DefaultListLimit
	}
	return openapi.ListMetricTemplateRevisions200JSONResponse{Items: items, Page: openAPIPage(limit, page.NextCursor != "", page.NextCursor)}, nil
}

func (api platformAPI) CreateMetricTemplateRevision(ctx context.Context, request openapi.CreateMetricTemplateRevisionRequestObject) (openapi.CreateMetricTemplateRevisionResponseObject, error) {
	if api.services.MetricTemplates == nil {
		return nil, ErrServiceUnavailable
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	actor, err := metricTemplateActor(ctx, principal.Subject, "createMetricTemplateRevision", request.Params.IdempotencyKey, request.TemplateId, "")
	if err != nil {
		return nil, err
	}
	draft := metrictemplate.Draft{TemplateDefinition: definitionFromOpenAPI(*request.Body), CreatedBy: principal.Subject}
	value, err := api.services.MetricTemplates.CreateDraft(ctx, scope, request.TemplateId, draft, actor)
	if err != nil {
		return nil, err
	}
	body, err := openAPIMetricTemplateRevision(value)
	if err != nil {
		return nil, err
	}
	return openapi.CreateMetricTemplateRevision201JSONResponse{Body: body, Headers: openapi.CreateMetricTemplateRevision201ResponseHeaders{ETag: value.ETag()}}, nil
}

func (api platformAPI) ValidateMetricTemplateRevision(ctx context.Context, request openapi.ValidateMetricTemplateRevisionRequestObject) (openapi.ValidateMetricTemplateRevisionResponseObject, error) {
	if api.services.MetricTemplates == nil {
		return nil, ErrServiceUnavailable
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	expected, err := parseEntityTag(request.Params.IfMatch)
	if err != nil || expected < 1 {
		return nil, ErrInvalidRequest
	}
	actor, err := metricTemplateActor(ctx, principal.Subject, "validateMetricTemplateRevision", request.Params.IdempotencyKey, request.RevisionId, request.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	value, err := api.services.MetricTemplates.Validate(ctx, scope, request.RevisionId, uint64(expected), actor)
	if err != nil {
		return nil, err
	}
	body, err := openAPIMetricTemplateRevision(value)
	if err != nil {
		return nil, err
	}
	return openapi.ValidateMetricTemplateRevision200JSONResponse{Body: body, Headers: openapi.ValidateMetricTemplateRevision200ResponseHeaders{ETag: value.ETag()}}, nil
}

func (api platformAPI) TrialMetricTemplateRevision(ctx context.Context, request openapi.TrialMetricTemplateRevisionRequestObject) (openapi.TrialMetricTemplateRevisionResponseObject, error) {
	if api.services.MetricTemplates == nil {
		return nil, ErrServiceUnavailable
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	actor, err := metricTemplateActor(ctx, principal.Subject, "trialMetricTemplateRevision", request.Params.IdempotencyKey, request.RevisionId, "")
	if err != nil {
		return nil, err
	}
	value, err := api.services.MetricTemplates.StartTrial(ctx, scope, request.RevisionId, metrictemplate.TrialRequest{InstanceID: string(request.Body.InstanceId), PluginVersionID: request.Body.PluginVersionId, Actor: actor})
	if err != nil {
		return nil, err
	}
	body, err := openAPIJob(value)
	if err != nil {
		return nil, err
	}
	return openapi.TrialMetricTemplateRevision202JSONResponse(body), nil
}

func (api platformAPI) ApproveMetricTemplateRevision(ctx context.Context, request openapi.ApproveMetricTemplateRevisionRequestObject) (openapi.ApproveMetricTemplateRevisionResponseObject, error) {
	if api.services.MetricTemplates == nil {
		return nil, ErrServiceUnavailable
	}
	if request.Body == nil || !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	expected, err := parseEntityTag(request.Params.IfMatch)
	if err != nil || expected < 1 {
		return nil, ErrInvalidRequest
	}
	actor, err := metricTemplateActor(ctx, principal.Subject, "approveMetricTemplateRevision", request.Params.IdempotencyKey, request.RevisionId, request.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	value, err := api.services.MetricTemplates.Approve(ctx, scope, request.RevisionId, uint64(expected), actor)
	if err != nil {
		return nil, err
	}
	body, err := openAPIMetricTemplateRevision(value)
	if err != nil {
		return nil, err
	}
	return openapi.ApproveMetricTemplateRevision200JSONResponse{Body: body, Headers: openapi.ApproveMetricTemplateRevision200ResponseHeaders{ETag: value.ETag()}}, nil
}

func (api platformAPI) PublishMetricTemplateRevision(ctx context.Context, request openapi.PublishMetricTemplateRevisionRequestObject) (openapi.PublishMetricTemplateRevisionResponseObject, error) {
	if api.services.MetricTemplates == nil {
		return nil, ErrServiceUnavailable
	}
	if !validIdempotencyKey(request.Params.IdempotencyKey) {
		return nil, ErrInvalidRequest
	}
	scope, principal, err := platformRequestIdentity(ctx)
	if err != nil {
		return nil, err
	}
	expected, err := parseEntityTag(request.Params.IfMatch)
	if err != nil || expected < 1 {
		return nil, ErrInvalidRequest
	}
	actor, err := metricTemplateActor(ctx, principal.Subject, "publishMetricTemplateRevision", request.Params.IdempotencyKey, request.RevisionId, request.Params.IfMatch)
	if err != nil {
		return nil, err
	}
	value, err := api.services.MetricTemplates.Publish(ctx, scope, request.RevisionId, uint64(expected), metrictemplate.PublishScope{Actor: actor})
	if err != nil {
		return nil, err
	}
	body, err := openAPIMetricTemplateRevision(value)
	if err != nil {
		return nil, err
	}
	return openapi.PublishMetricTemplateRevision200JSONResponse{Body: body, Headers: openapi.PublishMetricTemplateRevision200ResponseHeaders{ETag: value.ETag()}}, nil
}

func metricTemplateActor(ctx context.Context, subject, operation, key, resource, ifMatch string) (metrictemplate.Actor, error) {
	fingerprint, err := platformIdempotencyFingerprint(ctx, operation, resource, ifMatch)
	if err != nil {
		return metrictemplate.Actor{}, err
	}
	return metrictemplate.Actor{Subject: subject, OperationID: operation, IdempotencyKey: key, RequestFingerprint: fingerprint, RequestID: requestIDFromContext(ctx), TraceID: traceIDFromContext(ctx)}, nil
}

func definitionFromOpenAPI(value openapi.CreateMetricTemplateRevisionRequest) metrictemplate.TemplateDefinition {
	description, databaseRange, pluginRange := "", "", ""
	if value.Description != nil {
		description = *value.Description
	}
	if value.DatabaseVersionRange != nil {
		databaseRange = *value.DatabaseVersionRange
	}
	if value.PluginVersionRange != nil {
		pluginRange = *value.PluginVersionRange
	}
	variants := make([]string, len(value.Variants))
	for index, item := range value.Variants {
		variants[index] = string(item)
	}
	values := make([]metrictemplate.ValueMapping, len(value.ValueMappings))
	for index, item := range value.ValueMappings {
		values[index] = metrictemplate.ValueMapping{SourceColumn: item.SourceColumn, MetricName: item.MetricName, MetricType: metrictemplate.MetricType(item.MetricType), Unit: item.Unit}
	}
	labels := make([]metrictemplate.LabelMapping, len(value.LabelMappings))
	for index, item := range value.LabelMappings {
		labels[index] = metrictemplate.LabelMapping{SourceColumn: item.SourceColumn, Label: item.Label}
	}
	return metrictemplate.TemplateDefinition{Variants: variants, Name: value.Name, Description: description, QueryKind: metrictemplate.QueryKind(value.QueryKind), ReadOnlyStatement: value.ReadOnlyStatement, CollectionIntervalSeconds: value.CollectionIntervalSeconds, TimeoutSeconds: value.TimeoutSeconds, MaxRows: value.MaxRows, MaxColumns: value.MaxColumns, ValueMappings: values, LabelMappings: labels, DatabaseVersionRange: databaseRange, PluginVersionRange: pluginRange, CardinalityLimit: value.CardinalityLimit}
}

func openAPIMetricTemplate(value metrictemplate.Template) (openapi.MetricTemplate, error) {
	if value.Validate() != nil {
		return openapi.MetricTemplate{}, errors.New("metric template cannot be represented by the platform contract")
	}
	result := openapi.MetricTemplate{TemplateId: value.ID, DatabaseFamily: openapi.DatabaseFamily(value.DatabaseFamily), Name: value.Name, Builtin: value.Builtin, LatestRevision: int64(value.LatestRevision), CreatedAt: value.CreatedAt.UTC()}
	if value.Description != "" {
		result.Description = &value.Description
	}
	if value.PublishedRevision != nil {
		revision := int64(*value.PublishedRevision)
		result.PublishedRevision = &revision
	}
	return result, nil
}

func openAPIMetricTemplateRevision(value metrictemplate.Revision) (openapi.MetricTemplateRevision, error) {
	if value.Validate() != nil {
		return openapi.MetricTemplateRevision{}, errors.New("metric template revision cannot be represented by the platform contract")
	}
	variants := make([]openapi.DatabaseVariant, len(value.Variants))
	for index, item := range value.Variants {
		variants[index] = openapi.DatabaseVariant(item)
	}
	values := make([]openapi.MetricValueMapping, len(value.ValueMappings))
	for index, item := range value.ValueMappings {
		values[index] = openapi.MetricValueMapping{SourceColumn: item.SourceColumn, MetricName: item.MetricName, MetricType: openapi.MetricValueType(item.MetricType), Unit: item.Unit}
	}
	labels := make([]openapi.MetricLabelMapping, len(value.LabelMappings))
	for index, item := range value.LabelMappings {
		labels[index] = openapi.MetricLabelMapping{SourceColumn: item.SourceColumn, Label: item.Label}
	}
	result := openapi.MetricTemplateRevision{RevisionId: value.ID, TemplateId: value.TemplateID, Revision: int64(value.Revision), DatabaseFamily: openapi.DatabaseFamily(value.DatabaseFamily), Variants: variants, Name: value.Name, QueryKind: openapi.MetricQueryKind(value.QueryKind), CollectionIntervalSeconds: value.CollectionIntervalSeconds, TimeoutSeconds: value.TimeoutSeconds, MaxRows: value.MaxRows, MaxColumns: value.MaxColumns, ValueMappings: values, LabelMappings: labels, CardinalityLimit: value.CardinalityLimit, CreatedBy: value.CreatedBy, QueryDigest: value.QueryDigest, Status: openapi.MetricTemplateRevisionStatus(value.Status), CreatedAt: value.CreatedAt.UTC(), Etag: value.ETag()}
	if value.Description != "" {
		result.Description = &value.Description
	}
	if value.DatabaseVersionRange != "" {
		result.DatabaseVersionRange = &value.DatabaseVersionRange
	}
	if value.PluginVersionRange != "" {
		result.PluginVersionRange = &value.PluginVersionRange
	}
	if value.ApprovedBy != "" {
		result.ApprovedBy = &value.ApprovedBy
	}
	return result, nil
}
