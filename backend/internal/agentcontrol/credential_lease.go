package agentcontrol

import (
	"context"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/credentiallease"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CredentialLeaseIssuer struct{ Service credentiallease.Service }

func (issuer CredentialLeaseIssuer) Issue(ctx context.Context, agent credentiallease.AuthenticatedAgent, request *agentv1.CredentialLeaseRequest) (*agentv1.CredentialLeaseResponse, error) {
	if issuer.Service == nil || request == nil {
		return nil, credentiallease.ErrLeaseRejected
	}
	lease, err := issuer.Service.Lease(ctx, agent, credentiallease.LeaseRequest{Nonce: append([]byte(nil), request.GetRequestNonce()...), InstanceID: request.GetInstanceId(), AssignmentID: request.GetAssignmentId(), DatabaseFamily: request.GetDatabaseFamily(), ConfigurationRevision: request.GetConfigurationRevision(), OperationRevision: request.GetOperationRevision()})
	if err != nil {
		return nil, credentiallease.ErrLeaseRejected
	}
	defer lease.Release()
	return &agentv1.CredentialLeaseResponse{RequestNonce: append([]byte(nil), request.GetRequestNonce()...), LeaseId: lease.ID, InstanceId: lease.InstanceID, AssignmentId: lease.AssignmentID, CredentialRevision: lease.CredentialRevision, ExpiresAt: timestamppb.New(lease.ExpiresAt), Credential: &agentv1.CredentialMaterial{Username: lease.Username, SecretBytes: append([]byte(nil), lease.SecretBytes...)}, DatabaseFamily: lease.DatabaseFamily, ConfigurationRevision: lease.ConfigurationRevision, OperationRevision: lease.OperationRevision, ValidForSeconds: uint32(lease.ValidFor / time.Second)}, nil
}

var _ CredentialLeaseIssueService = CredentialLeaseIssuer{}
