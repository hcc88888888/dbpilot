package main

import (
	"context"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/metrictemplate"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestMetricTrialRecorderNeverPromotesFailedTopLevelTypedSuccess(t *testing.T) {
	store := &recordingMetricTrialStore{}
	recorder := metricTrialResultRecorder{Store: store}
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	digest := make([]byte, 32)
	command := &agentv1.CollectDatabaseMetrics{Trial: true, TemplateRevisions: []*agentv1.MetricTemplateCommandReference{{TemplateId: "template-a", RevisionId: "revision-a", QueryDigest: digest, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, CardinalityLimit: 1}}}
	typed := &agentv1.MetricTemplateTrialResult{RevisionId: "revision-a", QueryDigest: digest, StatusCode: "succeeded", MetricCount: 1, CandidateMetrics: []*agentv1.MetricTemplateCandidateMetric{{MetricName: "mysql.custom.value", Value: 1, Unit: "1", MetricType: "gauge"}}}
	err := recorder.RecordMetricTemplateTrial(context.Background(), scope, "job-a", "command-a", command, &agentv1.CommandResult{State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, MetricTemplateTrialResult: typed}, time.Now().UTC())
	require.NoError(t, err)
	require.Equal(t, "command_failed", store.result.StatusCode)
	require.Empty(t, store.result.Metrics)
	succeeded, err := recorder.ClassifyMetricTemplateTrial(context.Background(), scope, "job-a", command, &agentv1.CommandResult{State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, MetricTemplateTrialResult: typed})
	require.NoError(t, err)
	require.False(t, succeeded)

	typed.CandidateMetrics = []*agentv1.MetricTemplateCandidateMetric{nil}
	succeeded, err = recorder.ClassifyMetricTemplateTrial(context.Background(), scope, "job-a", command, &agentv1.CommandResult{State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, MetricTemplateTrialResult: typed})
	require.NoError(t, err)
	require.False(t, succeeded)
	require.Equal(t, "invalid_result", store.result.StatusCode)
}

type recordingMetricTrialStore struct{ result metrictemplate.TrialResult }

func (store *recordingMetricTrialStore) ClassifyTrialResult(_ context.Context, _ platformscope.Scope, _ string, result metrictemplate.TrialResult) (metrictemplate.TrialResult, error) {
	store.result = result
	return result, nil
}

func (store *recordingMetricTrialStore) RecordTrialResult(_ context.Context, _ platformscope.Scope, _ string, result metrictemplate.TrialResult, _ time.Time) (metrictemplate.Revision, error) {
	store.result = result
	return metrictemplate.Revision{}, nil
}
