// Package commandvalidation owns the semantic and target-ownership checks
// shared by the control-plane dispatcher and Agent verifier.
package commandvalidation

import (
	"context"
	"crypto/sha256"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
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

func validTransactionPolicy(value agentv1.TransactionPolicy) bool {
	return value == agentv1.TransactionPolicy_TRANSACTION_POLICY_REQUIRED || value == agentv1.TransactionPolicy_TRANSACTION_POLICY_FORBIDDEN || value == agentv1.TransactionPolicy_TRANSACTION_POLICY_AUTO_COMMIT
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
