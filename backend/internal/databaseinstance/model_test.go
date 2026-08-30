package databaseinstance

import (
	"testing"
	"time"

	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestAcceptRequestRejectsSecretBearingConnectionsAndNonSecretReferences(t *testing.T) {
	valid := validAcceptRequest()
	for name, mutate := range map[string]func(*AcceptCandidateRequest){
		"credential userinfo": func(value *AcceptCandidateRequest) { value.CredentialRef = "secret://user:pass@vault/mysql" },
		"credential query":    func(value *AcceptCandidateRequest) { value.CredentialRef = "secret://vault/mysql?token=value" },
		"credential local":    func(value *AcceptCandidateRequest) { value.CredentialRef = "C:\\secrets\\mysql.txt" },
		"TLS fragment":        func(value *AcceptCandidateRequest) { value.TLSRef = "secret://vault/mysql-tls#private" },
		"endpoint URL":        func(value *AcceptCandidateRequest) { value.Endpoint = "mysql://user:pass@127.0.0.1:3306/db" },
		"both connections":    func(value *AcceptCandidateRequest) { value.UnixSocket = "/run/mysqld/mysqld.sock" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid

			mutate(&candidate)

			require.ErrorIs(t, candidate.Validate(), ErrInvalid)
		})
	}
	require.NoError(t, valid.Validate())
}

func TestManagedInstanceKeepsFamilyVariantAndSourceFactsSeparate(t *testing.T) {
	value := validInstance()

	require.NoError(t, value.Validate())
	require.Equal(t, "mysql", value.DatabaseFamily)
	require.Equal(t, "percona", value.DatabaseVariant)
	require.Equal(t, discovery.SourceNative, value.DiscoverySource)
	require.Equal(t, "agent-1\x00mysql", value.FutureAssignmentKey())
	require.Equal(t, CapabilityPluginNotInstalled, value.CapabilityState)
}

func TestAcceptRequestAllowsDiscoveryCanonicalDNSAndIPv6Endpoints(t *testing.T) {
	for _, endpoint := range []string{"db.internal:3306", "[2001:db8::1]:3306"} {
		request := validAcceptRequest()
		request.Endpoint = endpoint
		require.NoError(t, request.Validate(), endpoint)
	}
}

func TestUpdateValidationRequiresOneMutableFieldAndStrictSecretReferences(t *testing.T) {
	require.ErrorIs(t, (Update{}).Validate(), ErrInvalid)
	displayName := "Orders MySQL"
	require.NoError(t, (Update{DisplayName: &displayName}).Validate())
	credential := "file:///etc/mysql/password"
	require.ErrorIs(t, (Update{CredentialRef: &credential}).Validate(), ErrInvalid)
	emptyTLS := ""
	require.ErrorIs(t, (Update{TLSRef: &emptyTLS}).Validate(), ErrInvalid, "v1 does not implicitly clear TLS configuration")
}

func TestRetiredInstanceRequiresRetirementTimestamp(t *testing.T) {
	value := validInstance()
	value.ManagementStatus = StatusRetired
	require.ErrorIs(t, value.Validate(), ErrInvalid)
	retired := value.UpdatedAt
	value.RetiredAt = &retired
	require.NoError(t, value.Validate())
}

func validAcceptRequest() AcceptCandidateRequest {
	return AcceptCandidateRequest{
		DisplayName: "Orders MySQL", DatabaseFamily: "mysql", DatabaseVariant: "percona",
		Endpoint: "127.0.0.1:3306", CredentialRef: "secret://vault/database/mysql/orders",
		TLSRef: "secret://vault/database/mysql/orders-tls", Labels: map[string]string{"service": "orders"},
		ExpectedCandidateRevision: 7, CandidateFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Audit: MutationAudit{Actor: "operator-1", OperationID: "acceptDiscoveryCandidate", IdempotencyKey: "accept-1", RequestFingerprint: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", RequestID: "request-1"},
	}
}

func validInstance() Instance {
	now := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	return Instance{
		ID: "instance-1", Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		HostID: "host-1", AgentID: "agent-1", CandidateID: "candidate-1", DiscoverySource: discovery.SourceNative,
		SourceFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SourceIdentity: "native:mysqld.service",
		DatabaseFamily: "mysql", DatabaseVariant: "percona", DisplayName: "Orders MySQL", Endpoint: "127.0.0.1:3306",
		CredentialRef: "secret://vault/database/mysql/orders", TLSRef: "secret://vault/database/mysql/orders-tls",
		Labels: map[string]string{"service": "orders"}, Capabilities: []string{}, CapabilityState: CapabilityPluginNotInstalled,
		ConnectionTestStatus: ConnectionNotTested, ManagementStatus: StatusAccepted, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
}
