// Package commandvalidation owns the semantic and target-ownership checks
// shared by the control-plane dispatcher and Agent verifier.
package commandvalidation

import (
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/discovery"
	"google.golang.org/protobuf/proto"
)

const (
	MaximumTimeoutSeconds = 24 * 60 * 60
	maximumListItems      = 128
	maximumParameters     = 32
	maximumParameterValue = 1024
)

var (
	ErrInvalidCommand     = errors.New("typed command is semantically invalid")
	ErrTargetUnauthorized = errors.New("command target is not authorized for Agent")
	safeIdentifier        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
)

// TargetAuthorizer proves that an authenticated Agent owns an instance-bound
// target. A nil authorizer fails closed whenever a command names an instance.
type TargetAuthorizer interface {
	AuthorizeTarget(context.Context, string, string) error
}

func Validate(ctx context.Context, envelope *agentv1.CommandEnvelope, authorizer TargetAuthorizer) error {
	if ctx == nil || envelope == nil || !validIdentifier(envelope.GetAgentId()) || envelope.GetCommand() == nil {
		return ErrInvalidCommand
	}
	var targets []string
	switch command := envelope.GetCommand().(type) {
	case *agentv1.CommandEnvelope_CollectNow:
		if command.CollectNow == nil || !validIdentifierList(command.CollectNow.GetCollectionKinds(), true) || !validIdentifierList(command.CollectNow.GetInstanceIds(), false) {
			return ErrInvalidCommand
		}
		targets = command.CollectNow.GetInstanceIds()
	case *agentv1.CommandEnvelope_InspectInstance:
		if command.InspectInstance == nil || !validIdentifier(command.InspectInstance.GetInstanceId()) || !validIdentifierList(command.InspectInstance.GetInspectionKinds(), true) {
			return ErrInvalidCommand
		}
		targets = []string{command.InspectInstance.GetInstanceId()}
	case *agentv1.CommandEnvelope_ExecuteSql:
		value := command.ExecuteSql
		if value == nil || !validIdentifier(value.GetInstanceId()) || !validIdentifier(value.GetWorkorderId()) || value.GetReviewRevision() <= 0 || len(value.GetSqlDigest()) != sha256.Size || !validTransactionPolicy(value.GetTransactionPolicy()) || value.GetTimeoutSeconds() == 0 || value.GetTimeoutSeconds() > MaximumTimeoutSeconds {
			return ErrInvalidCommand
		}
		targets = []string{value.GetInstanceId()}
	case *agentv1.CommandEnvelope_ExecuteRegisteredProcess:
		value := command.ExecuteRegisteredProcess
		if value == nil || !validIdentifier(value.GetProcessId()) || len(value.GetParameters()) > maximumParameters {
			return ErrInvalidCommand
		}
		for key, parameter := range value.GetParameters() {
			if !validIdentifier(key) || strings.TrimSpace(parameter) == "" || len(parameter) > maximumParameterValue || !utf8.ValidString(parameter) || strings.ContainsAny(parameter, "\x00\r\n") {
				return ErrInvalidCommand
			}
		}
	case *agentv1.CommandEnvelope_CollectDiagnostic:
		if command.CollectDiagnostic == nil || !validIdentifier(command.CollectDiagnostic.GetInstanceId()) || !validIdentifierList(command.CollectDiagnostic.GetDiagnosticKinds(), true) {
			return ErrInvalidCommand
		}
		targets = []string{command.CollectDiagnostic.GetInstanceId()}
	case *agentv1.CommandEnvelope_DiscoverDatabases:
		value := command.DiscoverDatabases
		if value == nil || !validIdentifier(value.GetHostId()) || value.GetRuleRevision() == 0 || (!value.GetIncludeNative() && !value.GetIncludeDocker()) {
			return ErrInvalidCommand
		}
	case *agentv1.CommandEnvelope_ReconcilePlugin:
		value := command.ReconcilePlugin
		if value == nil || !validIdentifier(value.GetAssignmentId()) || !validIdentifier(value.GetPluginId()) || !validIdentifier(value.GetDatabaseFamily()) || !validVersion(value.GetDesiredVersion()) || !validPluginDesiredState(value.GetDesiredState()) || !validIdentifier(value.GetArtifactId()) || len(value.GetArtifactSha256()) != sha256.Size || len(value.GetManifestDigest()) != sha256.Size || value.GetConfigurationRevision() == 0 || value.GetOperationRevision() == 0 || !validIdentifierList(value.GetInstanceIds(), value.GetDesiredState() != agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_ABSENT) || !validIdentifierList(value.GetTemplateIds(), false) || !validPluginDescriptorShape(value) || !validReconcileTemplateShape(value) {
			return ErrInvalidCommand
		}
		targets = value.GetInstanceIds()
	case *agentv1.CommandEnvelope_CollectDatabaseMetrics:
		value := command.CollectDatabaseMetrics
		if value == nil || !validIdentifier(value.GetAssignmentId()) || value.GetConfigurationRevision() == 0 || value.GetOperationRevision() == 0 || !validIdentifierList(value.GetInstanceIds(), true) || !validIdentifierList(value.GetTemplateIds(), true) || !validMetricTemplateReferences(value.GetTemplateIds(), value.GetTemplateRevisions()) || value.GetTrial() && (len(value.GetInstanceIds()) != 1 || len(value.GetTemplateRevisions()) != 1) {
			return ErrInvalidCommand
		}
		targets = value.GetInstanceIds()
	default:
		return ErrInvalidCommand
	}
	if len(targets) == 0 {
		return nil
	}
	if authorizer == nil {
		return ErrTargetUnauthorized
	}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if _, duplicate := seen[target]; duplicate {
			return ErrInvalidCommand
		}
		seen[target] = struct{}{}
		if err := authorizer.AuthorizeTarget(ctx, envelope.GetAgentId(), target); err != nil {
			return ErrTargetUnauthorized
		}
	}
	return nil
}

func validReconcileTemplateShape(value *agentv1.ReconcilePlugin) bool {
	if len(value.GetTemplateRevisions()) == 0 && len(value.GetInstanceTemplateRevisions()) == 0 {
		return true
	}
	if value.GetDesiredState() != agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_RUNNING || !validMetricTemplateReferences(value.GetTemplateIds(), value.GetTemplateRevisions()) || len(value.GetInstanceTemplateRevisions()) != len(value.GetInstanceIds()) {
		return false
	}
	byRevision := map[string]*agentv1.MetricTemplateCommandReference{}
	for _, reference := range value.GetTemplateRevisions() {
		byRevision[reference.GetRevisionId()] = reference
	}
	seenInstances, used := map[string]struct{}{}, map[string]struct{}{}
	for _, instance := range value.GetInstanceTemplateRevisions() {
		if instance == nil || !containsString(value.GetInstanceIds(), instance.GetInstanceId()) {
			return false
		}
		if _, duplicate := seenInstances[instance.GetInstanceId()]; duplicate {
			return false
		}
		seenInstances[instance.GetInstanceId()] = struct{}{}
		seenTemplates := map[string]struct{}{}
		for _, reference := range instance.GetTemplates() {
			authoritative := byRevision[reference.GetRevisionId()]
			if authoritative == nil || !proto.Equal(authoritative, reference) {
				return false
			}
			if _, duplicate := seenTemplates[reference.GetTemplateId()]; duplicate {
				return false
			}
			seenTemplates[reference.GetTemplateId()], used[reference.GetRevisionId()] = struct{}{}, struct{}{}
		}
	}
	return len(used) == len(byRevision)
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func validMetricTemplateReferences(ids []string, values []*agentv1.MetricTemplateCommandReference) bool {
	if len(values) != len(ids) || len(values) == 0 || len(values) > maximumListItems {
		return false
	}
	for index, value := range values {
		if value == nil || value.GetTemplateId() != ids[index] || !validIdentifier(value.GetRevisionId()) || len(value.GetQueryDigest()) != sha256.Size || value.GetTimeoutSeconds() == 0 || value.GetTimeoutSeconds() > 30 || value.GetMaxRows() == 0 || value.GetMaxRows() > 100 || value.GetMaxColumns() == 0 || value.GetMaxColumns() > 32 || value.GetCardinalityLimit() == 0 || value.GetCardinalityLimit() > 10000 {
			return false
		}
	}
	return true
}

func validPluginDescriptorShape(value *agentv1.ReconcilePlugin) bool {
	requires := value.GetDesiredState() == agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_RUNNING || value.GetDesiredState() == agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_INSTALLED
	if requires {
		return validPluginDescriptors(value.GetInstanceIds(), value.GetInstanceDescriptors())
	}
	return len(value.GetInstanceDescriptors()) == 0
}

// ValidateStart enforces the execution fence and bounded authorization window
// that must be durable before an Agent may invoke an executor.
func ValidateStart(start *agentv1.CommandStart, at time.Time) error {
	if err := ValidateStartShape(start); err != nil || !start.GetStartDeadline().AsTime().After(at.UTC()) {
		return ErrInvalidCommand
	}
	return nil
}

// ValidateStartShape validates immutable wire structure without applying
// freshness. Agent ingress defers deadline classification to its durable
// journal so running duplicates can be identified before expiry handling.
func ValidateStartShape(start *agentv1.CommandStart) error {
	if start == nil || !validIdentifier(start.GetCommandId()) || len(start.GetExecutionToken()) != sha256.Size || start.GetLeaseRevision() == 0 || start.GetLeaseSeconds() == 0 || start.GetLeaseSeconds() > MaximumTimeoutSeconds || start.GetStartDeadline() == nil || !start.GetStartDeadline().IsValid() {
		return ErrInvalidCommand
	}
	return nil
}

func ValidatePrepared(prepared *agentv1.CommandPrepared) error {
	if prepared == nil || !validIdentifier(prepared.GetCommandId()) || len(prepared.GetEnvelopeDigest()) != sha256.Size {
		return ErrInvalidCommand
	}
	return nil
}

func ValidateProgress(progress *agentv1.CommandProgress) error {
	if progress == nil || progress.GetPercent() > 100 || !validExecutionFence(progress.GetCommandId(), progress.GetExecutionToken(), progress.GetLeaseRevision()) {
		return ErrInvalidCommand
	}
	return nil
}

func ValidateResult(result *agentv1.CommandResult) error {
	if result == nil || !validExecutionFence(result.GetCommandId(), result.GetExecutionToken(), result.GetLeaseRevision()) {
		return ErrInvalidCommand
	}
	if result.GetMetricTemplateTrialResult() != nil && !validMetricTemplateTrialResult(result.GetMetricTemplateTrialResult()) {
		return ErrInvalidCommand
	}
	switch result.GetState() {
	case agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED,
		agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED,
		agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED,
		agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT,
		agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED:
		return nil
	default:
		return ErrInvalidCommand
	}
}

func validMetricTemplateTrialResult(value *agentv1.MetricTemplateTrialResult) bool {
	if value == nil || !validIdentifier(value.GetRevisionId()) || len(value.GetQueryDigest()) != sha256.Size || !validIdentifier(value.GetStatusCode()) || value.GetMetricCount() != uint32(len(value.GetCandidateMetrics())) || value.GetRowCount() > 100 || value.GetColumnCount() > 32 || value.GetMetricCount() > 3200 || value.GetDurationMillis() > 30000 {
		return false
	}
	for _, metric := range value.GetCandidateMetrics() {
		if metric == nil || !validIdentifier(metric.GetMetricName()) || metric.GetUnit() == "" || len(metric.GetUnit()) > 32 || math.IsNaN(metric.GetValue()) || math.IsInf(metric.GetValue(), 0) || len(metric.GetLabels()) > 16 {
			return false
		}
		for name, label := range metric.GetLabels() {
			if !validIdentifier(name) || !utf8.ValidString(label) || len([]byte(label)) > 128 || strings.ContainsAny(label, "\x00\r\n") {
				return false
			}
		}
	}
	return true
}

func ValidateCancellation(cancellation *agentv1.CommandCancellation) error {
	if cancellation == nil || !validIdentifier(cancellation.GetCommandId()) {
		return ErrInvalidCommand
	}
	if len(cancellation.GetExecutionToken()) == 0 && cancellation.GetLeaseRevision() == 0 {
		return nil
	}
	if !validExecutionFence(cancellation.GetCommandId(), cancellation.GetExecutionToken(), cancellation.GetLeaseRevision()) {
		return ErrInvalidCommand
	}
	return nil
}

func ValidateResultAcknowledgement(acknowledgement *agentv1.CommandResultAcknowledgement) error {
	if acknowledgement == nil || !validIdentifier(acknowledgement.GetCommandId()) || len(acknowledgement.GetResultDigest()) != sha256.Size || (acknowledgement.GetPersisted() && acknowledgement.GetRetryable()) || (!acknowledgement.GetPersisted() && !validIdentifier(acknowledgement.GetReasonCode())) {
		return ErrInvalidCommand
	}
	return nil
}

func validExecutionFence(commandID string, executionToken []byte, leaseRevision uint64) bool {
	return validIdentifier(commandID) && len(executionToken) == sha256.Size && leaseRevision > 0
}

func validTransactionPolicy(value agentv1.TransactionPolicy) bool {
	return value == agentv1.TransactionPolicy_TRANSACTION_POLICY_REQUIRED || value == agentv1.TransactionPolicy_TRANSACTION_POLICY_FORBIDDEN || value == agentv1.TransactionPolicy_TRANSACTION_POLICY_AUTO_COMMIT
}

func validPluginDesiredState(value agentv1.PluginDesiredState) bool {
	return value == agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_ABSENT || value == agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_INSTALLED || value == agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_RUNNING || value == agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_STOPPED
}

func validVersion(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 64 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n\t/\\") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune(".+_-", character) {
			continue
		}
		return false
	}
	return true
}

func validIdentifier(value string) bool {
	return value == strings.TrimSpace(value) && safeIdentifier.MatchString(value)
}

func validIdentifierList(values []string, required bool) bool {
	if len(values) > maximumListItems || (required && len(values) == 0) {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validIdentifier(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validPluginDescriptors(instanceIDs []string, descriptors []*agentv1.PluginInstanceDescriptor) bool {
	if len(descriptors) != len(instanceIDs) || len(descriptors) > maximumListItems {
		return false
	}
	allowed := make(map[string]struct{}, len(instanceIDs))
	for _, instanceID := range instanceIDs {
		allowed[instanceID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(descriptors))
	for _, descriptor := range descriptors {
		if descriptor == nil || !validIdentifier(descriptor.GetInstanceId()) || !validIdentifier(descriptor.GetDatabaseVariant()) || len(descriptor.GetEndpoint()) > 512 || len(descriptor.GetUnixSocket()) > 512 || (descriptor.GetEndpoint() == "") == (descriptor.GetUnixSocket() == "") {
			return false
		}
		if descriptor.GetEndpoint() != "" {
			normalized, err := discovery.NormalizeEndpoint(descriptor.GetEndpoint())
			if err != nil || normalized != descriptor.GetEndpoint() {
				return false
			}
		} else if !strings.HasPrefix(descriptor.GetUnixSocket(), "/") || path.Clean(descriptor.GetUnixSocket()) != descriptor.GetUnixSocket() || strings.Contains(descriptor.GetUnixSocket(), "..") {
			return false
		}
		if _, ok := allowed[descriptor.GetInstanceId()]; !ok {
			return false
		}
		if _, duplicate := seen[descriptor.GetInstanceId()]; duplicate {
			return false
		}
		seen[descriptor.GetInstanceId()] = struct{}{}
	}
	return true
}
