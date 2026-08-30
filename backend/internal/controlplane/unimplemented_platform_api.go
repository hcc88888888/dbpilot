package controlplane

import (
	"context"

	"dbpilot.local/platform/gen/openapi"
)

// unimplementedPlatformAPI owns only Task 1 operations whose product modules
// have not landed yet. Each later module removes its method from this adapter
// when platformAPI gains the real implementation.
type unimplementedPlatformAPI struct{}

func (unimplementedPlatformAPI) ApproveMetricTemplateRevision(context.Context, openapi.ApproveMetricTemplateRevisionRequestObject) (openapi.ApproveMetricTemplateRevisionResponseObject, error) {
	return nil, ErrServiceUnavailable
}

func (unimplementedPlatformAPI) CreateMetricTemplate(context.Context, openapi.CreateMetricTemplateRequestObject) (openapi.CreateMetricTemplateResponseObject, error) {
	return nil, ErrServiceUnavailable
}

func (unimplementedPlatformAPI) CreateMetricTemplateRevision(context.Context, openapi.CreateMetricTemplateRevisionRequestObject) (openapi.CreateMetricTemplateRevisionResponseObject, error) {
	return nil, ErrServiceUnavailable
}

func (unimplementedPlatformAPI) GetPluginAssignment(context.Context, openapi.GetPluginAssignmentRequestObject) (openapi.GetPluginAssignmentResponseObject, error) {
	return nil, ErrServiceUnavailable
}

func (unimplementedPlatformAPI) ListMetricTemplateRevisions(context.Context, openapi.ListMetricTemplateRevisionsRequestObject) (openapi.ListMetricTemplateRevisionsResponseObject, error) {
	return nil, ErrServiceUnavailable
}

func (unimplementedPlatformAPI) ListMetricTemplates(context.Context, openapi.ListMetricTemplatesRequestObject) (openapi.ListMetricTemplatesResponseObject, error) {
	return nil, ErrServiceUnavailable
}

func (unimplementedPlatformAPI) ListPluginAssignments(context.Context, openapi.ListPluginAssignmentsRequestObject) (openapi.ListPluginAssignmentsResponseObject, error) {
	return nil, ErrServiceUnavailable
}

func (unimplementedPlatformAPI) PublishMetricTemplateRevision(context.Context, openapi.PublishMetricTemplateRevisionRequestObject) (openapi.PublishMetricTemplateRevisionResponseObject, error) {
	return nil, ErrServiceUnavailable
}

func (unimplementedPlatformAPI) ReconcilePluginAssignment(context.Context, openapi.ReconcilePluginAssignmentRequestObject) (openapi.ReconcilePluginAssignmentResponseObject, error) {
	return nil, ErrServiceUnavailable
}

func (unimplementedPlatformAPI) RediscoverHost(context.Context, openapi.RediscoverHostRequestObject) (openapi.RediscoverHostResponseObject, error) {
	return nil, ErrServiceUnavailable
}

func (unimplementedPlatformAPI) TrialMetricTemplateRevision(context.Context, openapi.TrialMetricTemplateRevisionRequestObject) (openapi.TrialMetricTemplateRevisionResponseObject, error) {
	return nil, ErrServiceUnavailable
}

func (unimplementedPlatformAPI) UpdatePluginAssignment(context.Context, openapi.UpdatePluginAssignmentRequestObject) (openapi.UpdatePluginAssignmentResponseObject, error) {
	return nil, ErrServiceUnavailable
}

func (unimplementedPlatformAPI) ValidateMetricTemplateRevision(context.Context, openapi.ValidateMetricTemplateRevisionRequestObject) (openapi.ValidateMetricTemplateRevisionResponseObject, error) {
	return nil, ErrServiceUnavailable
}
