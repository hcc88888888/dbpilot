package metrictemplate

import (
	"bytes"
	"context"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestMetricTemplateLeaseIsMemoryOnlyReplayFencedAndReleasesQueryBytes(t *testing.T) {
	now := time.Date(2026, 9, 1, 5, 0, 0, 0, time.UTC)
	statement := []byte("SELECT value FROM metrics")
	authorizer := &leaseAuthorizerFixture{authorization: LeaseAuthorization{Scope: platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, HostID: "host-a", AgentID: "agent-a", AssignmentID: "assignment-a", InstanceID: "instance-a", ConfigurationRevision: 7, OperationRevision: 9, TemplateID: "template-a", RevisionID: "revision-a", QueryDigest: DefinitionDigest(string(statement)), Definition: LeaseDefinition{Revision: 1, StatementBytes: append([]byte(nil), statement...), CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2, CardinalityLimit: 10, ValueMappings: []ValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: MetricGauge, Unit: "1"}}, LabelMappings: []LabelMapping{}}, AuthorizedAt: now}}
	audits := &leaseAuditFixture{}
	service, err := NewLeaseService(LeaseConfig{Authorizer: authorizer, Audit: audits, Now: func() time.Time { return now }, TTL: 30 * time.Second, MaximumLive: 2})
	require.NoError(t, err)
	defer service.Close()
	request := LeaseRequest{Nonce: bytes.Repeat([]byte{1}, 32), CommandID: "command-a", AssignmentID: "assignment-a", InstanceID: "instance-a", ConfigurationRevision: 7, OperationRevision: 9, TemplateID: "template-a", RevisionID: "revision-a", QueryDigest: authorizer.authorization.QueryDigest}
	lease, err := service.Issue(context.Background(), AuthenticatedAgent{AgentID: "agent-a", SessionID: "session-a"}, request)
	require.NoError(t, err)
	require.Equal(t, statement, lease.Definition.StatementBytes)
	require.Equal(t, 1, audits.issued)
	replayed, err := service.Issue(context.Background(), AuthenticatedAgent{AgentID: "agent-a", SessionID: "session-a"}, request)
	require.NoError(t, err)
	require.Equal(t, lease.ID, replayed.ID)
	require.Equal(t, statement, replayed.Definition.StatementBytes)
	replayed.Definition.StatementBytes[0] = 'X'
	require.Equal(t, statement, lease.Definition.StatementBytes, "replay returns an isolated in-memory copy")
	conflict := request
	conflict.RevisionID = "revision-b"
	_, err = service.Issue(context.Background(), AuthenticatedAgent{AgentID: "agent-a", SessionID: "session-a"}, conflict)
	require.ErrorIs(t, err, ErrLeaseRejected)
	lease.Release()
	require.Empty(t, lease.Definition.StatementBytes)
}

func TestMetricTemplateLeaseRejectsMismatchedAuthorizationWithoutReturningQuery(t *testing.T) {
	now := time.Date(2026, 9, 1, 5, 0, 0, 0, time.UTC)
	authorization := LeaseAuthorization{Scope: platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, HostID: "host-a", AgentID: "agent-b", AssignmentID: "assignment-a", InstanceID: "instance-a", ConfigurationRevision: 7, OperationRevision: 9, TemplateID: "template-a", RevisionID: "revision-a", QueryDigest: strings64("a"), Definition: LeaseDefinition{Revision: 1, StatementBytes: []byte("SELECT secret"), CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, CardinalityLimit: 1, ValueMappings: []ValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: MetricGauge, Unit: "1"}}}, AuthorizedAt: now}
	service, err := NewLeaseService(LeaseConfig{Authorizer: &leaseAuthorizerFixture{authorization: authorization}, Audit: &leaseAuditFixture{}, Now: func() time.Time { return now }})
	require.NoError(t, err)
	defer service.Close()
	_, err = service.Issue(context.Background(), AuthenticatedAgent{AgentID: "agent-a", SessionID: "session-a"}, LeaseRequest{Nonce: bytes.Repeat([]byte{1}, 32), CommandID: "command-a", AssignmentID: "assignment-a", InstanceID: "instance-a", ConfigurationRevision: 7, OperationRevision: 9, TemplateID: "template-a", RevisionID: "revision-a", QueryDigest: strings64("a")})
	require.ErrorIs(t, err, ErrLeaseRejected)
}

type leaseAuthorizerFixture struct {
	authorization LeaseAuthorization
	err           error
	calls         int
}

func (fixture *leaseAuthorizerFixture) AuthorizeMetricTemplateLease(context.Context, AuthenticatedAgent, LeaseRequest) (LeaseAuthorization, error) {
	fixture.calls++
	value := fixture.authorization
	value.Definition = value.Definition.Clone()
	return value, fixture.err
}

type leaseAuditFixture struct {
	issued, rejected int
	records          []LeaseAudit
}

func (fixture *leaseAuditFixture) Record(_ context.Context, value LeaseAudit) error {
	fixture.records = append(fixture.records, value)
	if value.Result == LeaseIssued {
		fixture.issued++
	} else {
		fixture.rejected++
	}
	return nil
}
