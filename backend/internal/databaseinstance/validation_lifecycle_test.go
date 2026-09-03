package databaseinstance

import (
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/job"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestBuildValidationJobBindsExactInstanceAssignmentAndRuntimeFences(t *testing.T) {
	instance := validInstance()
	instance.PluginID = "mysql"
	instance.PluginAssignmentRevision = 7
	instance.CapabilityState = CapabilityPluginAvailable
	target := ValidationTarget{AssignmentID: "assignment-a", ConfigurationRevision: 7, OperationRevision: 9}
	request := ValidationRequest{Audit: MutationAudit{Actor: "operator-a", OperationID: "testDatabaseInstanceConnection", IdempotencyKey: "validate-a", RequestFingerprint: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", RequestID: "request-a", TraceID: "trace-a"}}
	at := time.Date(2026, 9, 4, 5, 0, 0, 0, time.UTC)

	created, message, err := BuildValidationJob(instance, target, request, at)

	require.NoError(t, err)
	require.Equal(t, "database_instance.validate", created.Type)
	require.Equal(t, instance.ID, created.InstanceID)
	require.Equal(t, int64(1), created.Version)
	require.Equal(t, []string{instance.AgentID}, created.TargetResourceIDs)
	require.Equal(t, job.ResourceReference{ResourceType: "database_instance", ResourceID: instance.ID}, created.SourceResource)
	envelope := new(agentv1.CommandEnvelope)
	require.NoError(t, proto.Unmarshal(message.Payload, envelope))
	require.Equal(t, instance.AgentID, envelope.GetAgentId())
	require.Equal(t, target.AssignmentID, envelope.GetValidateDatabaseInstance().GetAssignmentId())
	require.Equal(t, instance.ID, envelope.GetValidateDatabaseInstance().GetInstanceId())
	require.Equal(t, target.ConfigurationRevision, envelope.GetValidateDatabaseInstance().GetConfigurationRevision())
	require.NotContains(t, string(message.Payload), instance.CredentialRef)
	require.NotContains(t, string(message.Payload), instance.TLSRef)
}

func TestManagedInstanceAcceptsCompleteCapabilityAndConnectionLifecycleOnly(t *testing.T) {
	value := validInstance()
	for _, capability := range []CapabilityState{CapabilityPluginNotInstalled, CapabilityPluginAvailable, CapabilityPluginUnavailable, CapabilityPluginFailed, CapabilityDegraded} {
		value.CapabilityState = capability
		require.NoError(t, value.Validate(), capability)
	}
	for _, status := range []ConnectionTestStatus{ConnectionNotTested, ConnectionQueued, ConnectionRunning, ConnectionSucceeded, ConnectionAuthenticationFailed, ConnectionTLSFailed, ConnectionUnreachable, ConnectionUnsupportedVersion, ConnectionPluginFailed} {
		value.ConnectionTestStatus = status
		value.ConnectionTestErrorCode = connectionErrorForStatus(status)
		at := value.UpdatedAt
		if status == ConnectionNotTested {
			value.ConnectionTestAt = nil
		} else {
			value.ConnectionTestAt = &at
		}
		require.NoError(t, value.Validate(), status)
	}
	value.ConnectionTestStatus = ConnectionAuthenticationFailed
	value.ConnectionTestErrorCode = "raw driver password=secret"
	require.ErrorIs(t, value.Validate(), ErrInvalid)
}

func connectionErrorForStatus(status ConnectionTestStatus) ConnectionTestErrorCode {
	switch status {
	case ConnectionAuthenticationFailed:
		return ConnectionErrorAuthentication
	case ConnectionTLSFailed:
		return ConnectionErrorTLS
	case ConnectionUnreachable:
		return ConnectionErrorUnreachable
	case ConnectionUnsupportedVersion:
		return ConnectionErrorUnsupportedVersion
	case ConnectionPluginFailed:
		return ConnectionErrorPlugin
	default:
		return ""
	}
}
