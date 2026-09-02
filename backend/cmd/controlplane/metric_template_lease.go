package main

import (
	"context"
	"encoding/hex"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/credentiallease"
	"dbpilot.local/platform/internal/metrictemplate"
	"dbpilot.local/platform/internal/platformscope"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type metricTemplateLeaseService interface {
	Issue(context.Context, metrictemplate.AuthenticatedAgent, metrictemplate.LeaseRequest) (metrictemplate.MetricTemplateLease, error)
}

type metricTemplateLeaseIssuer struct{ Service metricTemplateLeaseService }

type metricTrialResultStore interface {
	ClassifyTrialResult(context.Context, platformscope.Scope, string, metrictemplate.TrialResult) (metrictemplate.TrialResult, error)
	RecordTrialResult(context.Context, platformscope.Scope, string, metrictemplate.TrialResult, time.Time) (metrictemplate.Revision, error)
}

type metricTrialResultRecorder struct{ Store metricTrialResultStore }

func (recorder metricTrialResultRecorder) ClassifyMetricTemplateTrial(ctx context.Context, scope platformscope.Scope, jobID string, command *agentv1.CollectDatabaseMetrics, result *agentv1.CommandResult) (bool, error) {
	value, err := normalizedMetricTrialResult(command, result)
	if err != nil || recorder.Store == nil {
		return false, metrictemplate.ErrInvalid
	}
	value, err = recorder.Store.ClassifyTrialResult(ctx, scope, jobID, value)
	return err == nil && value.StatusCode == "succeeded", err
}

func (recorder metricTrialResultRecorder) RecordMetricTemplateTrial(ctx context.Context, scope platformscope.Scope, jobID, _ string, command *agentv1.CollectDatabaseMetrics, result *agentv1.CommandResult, at time.Time) error {
	value, err := normalizedMetricTrialResult(command, result)
	if err != nil || recorder.Store == nil {
		return metrictemplate.ErrInvalid
	}
	value, err = recorder.Store.ClassifyTrialResult(ctx, scope, jobID, value)
	if err != nil {
		return err
	}
	_, err = recorder.Store.RecordTrialResult(ctx, scope, jobID, value, at.UTC())
	return err
}

func normalizedMetricTrialResult(command *agentv1.CollectDatabaseMetrics, result *agentv1.CommandResult) (metrictemplate.TrialResult, error) {
	if command == nil || !command.GetTrial() || len(command.GetTemplateRevisions()) != 1 || result == nil || command.GetTemplateRevisions()[0] == nil {
		return metrictemplate.TrialResult{}, metrictemplate.ErrInvalid
	}
	reference := command.GetTemplateRevisions()[0]
	value := metrictemplate.TrialResult{RevisionID: reference.GetRevisionId(), QueryDigest: hex.EncodeToString(reference.GetQueryDigest()), StatusCode: fixedTrialStatus(result.GetState())}
	typed := result.GetMetricTemplateTrialResult()
	typedMatches := typed != nil && typed.GetRevisionId() == reference.GetRevisionId() && hex.EncodeToString(typed.GetQueryDigest()) == value.QueryDigest
	if result.GetState() == agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED && typedMatches && typed.GetStatusCode() == "succeeded" {
		value.StatusCode = "succeeded"
		value.RowCount = int(typed.GetRowCount())
		value.ColumnCount = int(typed.GetColumnCount())
		value.MetricCount = int(typed.GetMetricCount())
		value.DurationMillis = int64(typed.GetDurationMillis())
		for _, metric := range typed.GetCandidateMetrics() {
			if metric == nil {
				value.StatusCode = "invalid_result"
				value.Metrics = nil
				value.MetricCount = 0
				break
			}
			labels := make(map[string]string, len(metric.GetLabels()))
			for name, label := range metric.GetLabels() {
				labels[name] = label
			}
			value.Metrics = append(value.Metrics, metrictemplate.CandidateMetric{Name: metric.GetMetricName(), Value: metric.GetValue(), Unit: metric.GetUnit(), MetricType: metrictemplate.MetricType(metric.GetMetricType()), Labels: labels})
		}
	}
	if result.GetState() == agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED && value.StatusCode != "succeeded" {
		value = metrictemplate.TrialResult{RevisionID: value.RevisionID, QueryDigest: value.QueryDigest, StatusCode: "invalid_result"}
	} else if result.GetState() != agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED {
		statusCode := fixedTrialStatus(result.GetState())
		rowCount, columnCount, durationMillis := 0, 0, int64(0)
		if typedMatches && (typed.GetStatusCode() == "high_cardinality" || typed.GetStatusCode() == "bounds_exceeded") {
			statusCode = typed.GetStatusCode()
			rowCount, columnCount, durationMillis = int(typed.GetRowCount()), int(typed.GetColumnCount()), int64(typed.GetDurationMillis())
		}
		value = metrictemplate.TrialResult{RevisionID: value.RevisionID, QueryDigest: value.QueryDigest, StatusCode: statusCode, RowCount: rowCount, ColumnCount: columnCount, DurationMillis: durationMillis}
	}
	if value.Validate() != nil {
		value = metrictemplate.TrialResult{RevisionID: reference.GetRevisionId(), QueryDigest: hex.EncodeToString(reference.GetQueryDigest()), StatusCode: "invalid_result"}
	}
	return value, nil
}

func fixedTrialStatus(state agentv1.CommandResultState) string {
	switch state {
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED:
		return "job_cancelled"
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT:
		return "job_timed_out"
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED:
		return "job_interrupted"
	default:
		return "command_failed"
	}
}
func fixedMetricTrialCode(value string) string {
	switch value {
	case "succeeded", "lease_unavailable", "gateway_unavailable", "trial_rejected", "command_failed", "job_cancelled", "job_timed_out", "job_interrupted", "invalid_result", "high_cardinality", "bounds_exceeded":
		return value
	default:
		return ""
	}
}

func (issuer metricTemplateLeaseIssuer) Issue(ctx context.Context, agent credentiallease.AuthenticatedAgent, request *agentv1.MetricTemplateLeaseRequest) (*agentv1.MetricTemplateLeaseResponse, error) {
	if issuer.Service == nil || request == nil {
		return nil, metrictemplate.ErrLeaseRejected
	}
	lease, err := issuer.Service.Issue(ctx, metrictemplate.AuthenticatedAgent{AgentID: agent.AgentID, SessionID: agent.SessionID}, metrictemplate.LeaseRequest{Nonce: append([]byte(nil), request.GetRequestNonce()...), CommandID: request.GetCommandId(), AssignmentID: request.GetAssignmentId(), InstanceID: request.GetInstanceId(), ConfigurationRevision: request.GetConfigurationRevision(), OperationRevision: request.GetOperationRevision(), TemplateID: request.GetTemplateId(), RevisionID: request.GetRevisionId(), QueryDigest: hex.EncodeToString(request.GetQueryDigest())})
	if err != nil {
		return nil, metrictemplate.ErrLeaseRejected
	}
	defer lease.Release()
	definition := &agentv1.MetricTemplateDefinition{Revision: lease.Definition.Revision, QueryKind: "sql", ReadOnlyStatement: append([]byte(nil), lease.Definition.StatementBytes...), CollectionIntervalSeconds: uint32(lease.Definition.CollectionIntervalSeconds), TimeoutSeconds: uint32(lease.Definition.TimeoutSeconds), MaxRows: uint32(lease.Definition.MaxRows), MaxColumns: uint32(lease.Definition.MaxColumns), CardinalityLimit: uint32(lease.Definition.CardinalityLimit)}
	for _, mapping := range lease.Definition.ValueMappings {
		definition.ValueMappings = append(definition.ValueMappings, &agentv1.MetricTemplateValueMapping{SourceColumn: mapping.SourceColumn, MetricName: mapping.MetricName, MetricType: string(mapping.MetricType), Unit: mapping.Unit})
	}
	for _, mapping := range lease.Definition.LabelMappings {
		definition.LabelMappings = append(definition.LabelMappings, &agentv1.MetricTemplateLabelMapping{SourceColumn: mapping.SourceColumn, Label: mapping.Label})
	}
	digest, err := hex.DecodeString(lease.QueryDigest)
	if err != nil {
		return nil, metrictemplate.ErrLeaseRejected
	}
	return &agentv1.MetricTemplateLeaseResponse{RequestNonce: append([]byte(nil), request.GetRequestNonce()...), LeaseId: lease.ID, CommandId: request.GetCommandId(), AssignmentId: lease.AssignmentID, InstanceId: lease.InstanceID, ConfigurationRevision: lease.ConfigurationRevision, OperationRevision: lease.OperationRevision, TemplateId: lease.TemplateID, RevisionId: lease.RevisionID, QueryDigest: digest, ExpiresAt: timestamppb.New(lease.ExpiresAt), Definition: definition, ValidForSeconds: uint32(lease.ValidFor / time.Second)}, nil
}
