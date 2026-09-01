package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/metrictemplatelease"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
)

type MetricTemplateLeaser interface {
	LeaseMetricTemplate(context.Context, metrictemplatelease.Request) (metrictemplatelease.Material, error)
}

type MetricTemplateTrialGateway interface {
	TrialMetricTemplate(context.Context, string, uint64, uint64, string, *pluginv1.TrialMetricTemplateDefinition) (plugingateway.TrialResult, error)
}

type MetricTemplateTrialExecutor struct {
	leaser  MetricTemplateLeaser
	gateway MetricTemplateTrialGateway
}

func NewMetricTemplateTrialExecutor(leaser MetricTemplateLeaser, gateway MetricTemplateTrialGateway) (*MetricTemplateTrialExecutor, error) {
	if leaser == nil || gateway == nil {
		return nil, errors.New("metric template trial dependencies are required")
	}
	return &MetricTemplateTrialExecutor{leaser: leaser, gateway: gateway}, nil
}

func (*MetricTemplateTrialExecutor) AdditionalCapabilities() []string {
	return []string{"metric_template_lease.v1"}
}

func (executor *MetricTemplateTrialExecutor) Execute(ctx context.Context, envelope *agentv1.CommandEnvelope, reporter ProgressReporter) (*agentv1.CommandResult, error) {
	if executor == nil || executor.leaser == nil || executor.gateway == nil || ctx == nil || envelope == nil || reporter == nil {
		return nil, errors.New("metric template trial is invalid")
	}
	command := envelope.GetCollectDatabaseMetrics()
	if command == nil || !command.GetTrial() || len(command.GetInstanceIds()) != 1 || len(command.GetTemplateIds()) != 1 || len(command.GetTemplateRevisions()) != 1 {
		return nil, errors.New("metric template trial command is invalid")
	}
	fenced, ok := reporter.(interface {
		ExecutionFence() pluginsupervisor.ExecutionFence
	})
	if !ok || fenced.ExecutionFence().Validate() != nil || fenced.ExecutionFence().CommandID != envelope.GetCommandId() {
		return nil, pluginsupervisor.ErrInvalidFence
	}
	reference := command.GetTemplateRevisions()[0]
	if reference == nil || reference.GetTemplateId() != command.GetTemplateIds()[0] || len(reference.GetQueryDigest()) != sha256.Size {
		return nil, errors.New("metric template trial reference is invalid")
	}
	if err := reporter.Report(&agentv1.CommandProgress{CommandId: envelope.GetCommandId(), Percent: 10, Stage: "template_lease", Message: "metric template lease requested"}); err != nil {
		return nil, err
	}
	base := &agentv1.MetricTemplateTrialResult{RevisionId: reference.GetRevisionId(), QueryDigest: append([]byte(nil), reference.GetQueryDigest()...)}
	material, err := executor.leaser.LeaseMetricTemplate(ctx, metrictemplatelease.Request{CommandID: envelope.GetCommandId(), AssignmentID: command.GetAssignmentId(), InstanceID: command.GetInstanceIds()[0], ConfigurationRevision: command.GetConfigurationRevision(), OperationRevision: command.GetOperationRevision(), TemplateID: reference.GetTemplateId(), RevisionID: reference.GetRevisionId(), QueryDigest: append([]byte(nil), reference.GetQueryDigest()...)})
	if err != nil {
		base.StatusCode = "lease_unavailable"
		return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, ErrorCode: "METRIC_TEMPLATE_TRIAL_FAILED", Summary: "metric template trial failed", MetricTemplateTrialResult: base}, nil
	}
	defer material.Release()
	if material.ConfigurationRevision != command.GetConfigurationRevision() || material.OperationRevision != command.GetOperationRevision() || material.TemplateID != reference.GetTemplateId() || material.RevisionID != reference.GetRevisionId() || material.QueryDigest != hex.EncodeToString(reference.GetQueryDigest()) || material.TimeoutSeconds != int(reference.GetTimeoutSeconds()) || material.MaxRows != int(reference.GetMaxRows()) || material.MaxColumns != int(reference.GetMaxColumns()) || material.CardinalityLimit != int(reference.GetCardinalityLimit()) {
		return nil, errors.New("metric template lease does not match command")
	}
	definition := trialDefinitionFromMaterial(material)
	defer clearTrialDefinition(definition)
	if err := reporter.Report(&agentv1.CommandProgress{CommandId: envelope.GetCommandId(), Percent: 50, Stage: "template_trial", Message: "metric template trial running"}); err != nil {
		return nil, err
	}
	trial, trialErr := executor.gateway.TrialMetricTemplate(ctx, command.GetAssignmentId(), command.GetConfigurationRevision(), command.GetOperationRevision(), command.GetInstanceIds()[0], definition)
	if trialErr != nil {
		base.StatusCode = "gateway_unavailable"
		return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, ErrorCode: "METRIC_TEMPLATE_TRIAL_FAILED", Summary: "metric template trial failed", MetricTemplateTrialResult: base}, nil
	}
	base.RowCount, base.ColumnCount, base.MetricCount, base.DurationMillis = trial.RowCount, trial.ColumnCount, trial.MetricCount, trial.DurationMillis
	base.StatusCode = trial.ErrorCode
	if trial.Succeeded {
		base.StatusCode = "succeeded"
	}
	for _, metric := range trial.Metrics {
		labels := make(map[string]string, len(metric.Labels))
		for name, value := range metric.Labels {
			labels[name] = value
		}
		base.CandidateMetrics = append(base.CandidateMetrics, &agentv1.MetricTemplateCandidateMetric{MetricName: metric.Name, Value: metric.Value, Unit: metric.Unit, MetricType: metric.MetricType, Labels: labels})
	}
	state := agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED
	if !trial.Succeeded {
		state = agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED
	}
	if err := reporter.Report(&agentv1.CommandProgress{CommandId: envelope.GetCommandId(), Percent: 100, Stage: "template_trial_complete", Message: "metric template trial completed"}); err != nil {
		return nil, err
	}
	return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: state, Summary: "metric template trial completed", MetricTemplateTrialResult: base}, nil
}

func trialDefinitionFromMaterial(value metrictemplatelease.Material) *pluginv1.TrialMetricTemplateDefinition {
	result := &pluginv1.TrialMetricTemplateDefinition{TemplateId: value.TemplateID, Revision: value.Revision, QueryDigest: decodeMetricTemplateDigest(value.QueryDigest), QueryKind: "sql", ReadOnlyStatement: append([]byte(nil), value.StatementBytes...), CollectionIntervalSeconds: uint32(value.CollectionIntervalSeconds), TimeoutSeconds: uint32(value.TimeoutSeconds), MaxRows: uint32(value.MaxRows), MaxColumns: uint32(value.MaxColumns), CardinalityLimit: uint32(value.CardinalityLimit)}
	for _, mapping := range value.ValueMappings {
		result.ValueMappings = append(result.ValueMappings, &pluginv1.MetricValueMapping{SourceColumn: mapping.SourceColumn, MetricName: mapping.MetricName, MetricType: mapping.MetricType, Unit: mapping.Unit})
	}
	for _, mapping := range value.LabelMappings {
		result.LabelMappings = append(result.LabelMappings, &pluginv1.MetricLabelMapping{SourceColumn: mapping.SourceColumn, Label: mapping.Label})
	}
	return result
}

func decodeMetricTemplateDigest(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}
func clearTrialDefinition(value *pluginv1.TrialMetricTemplateDefinition) {
	if value == nil {
		return
	}
	for index := range value.ReadOnlyStatement {
		value.ReadOnlyStatement[index] = 0
	}
	value.ReadOnlyStatement = nil
}

var _ CommandExecutor = (*MetricTemplateTrialExecutor)(nil)
