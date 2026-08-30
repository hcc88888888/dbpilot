package enrollment

import (
	"context"
	"errors"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/hostinventory"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type GRPCServer struct {
	agentv1.UnimplementedAgentEnrollmentServer
	service *ApplicationService
}

func NewGRPCServer(service *ApplicationService) *GRPCServer { return &GRPCServer{service: service} }

func (server *GRPCServer) Enroll(ctx context.Context, request *agentv1.EnrollAgentRequest) (*agentv1.EnrollAgentResponse, error) {
	if server == nil || server.service == nil {
		return nil, status.Error(codes.Unavailable, "Agent enrollment is unavailable")
	}
	model, err := enrollmentRequestFromProto(request)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "Agent enrollment request is invalid")
	}
	result, err := server.service.Enroll(ctx, model)
	if err != nil {
		switch {
		case errors.Is(err, ErrEnrollmentRequestInvalid):
			return nil, status.Error(codes.InvalidArgument, "Agent enrollment request is invalid")
		case errors.Is(err, ErrEnrollmentTokenInvalid):
			return nil, status.Error(codes.PermissionDenied, "Agent enrollment token is invalid")
		case errors.Is(err, ErrEnrollmentConflict):
			return nil, status.Error(codes.AlreadyExists, "Agent enrollment conflicts with existing state")
		case errors.Is(err, context.Canceled):
			return nil, status.Error(codes.Canceled, "Agent enrollment was cancelled")
		case errors.Is(err, context.DeadlineExceeded):
			return nil, status.Error(codes.DeadlineExceeded, "Agent enrollment timed out")
		default:
			return nil, status.Error(codes.Unavailable, "Agent enrollment could not be completed")
		}
	}
	return &agentv1.EnrollAgentResponse{
		HostId: result.HostID, AgentId: result.AgentID, CertificatePem: append([]byte(nil), result.CertificatePEM...),
		CertificateChainPem: append([]byte(nil), result.CertificateChainPEM...), ExpiresAt: timestamppb.New(result.ExpiresAt),
		EnrollmentRevision: result.EnrollmentRevision,
	}, nil
}

func enrollmentRequestFromProto(request *agentv1.EnrollAgentRequest) (EnrollRequest, error) {
	if request == nil || request.GetHostObservation() == nil || request.GetHostObservation().GetObservedAt() == nil || request.GetHostObservation().GetObservedAt().CheckValid() != nil {
		return EnrollRequest{}, ErrEnrollmentRequestInvalid
	}
	provided := request.GetHostObservation()
	filesystems := make([]hostinventory.FilesystemSummary, len(provided.GetFilesystems()))
	for index, filesystem := range provided.GetFilesystems() {
		if filesystem == nil {
			return EnrollRequest{}, ErrEnrollmentRequestInvalid
		}
		filesystems[index] = hostinventory.FilesystemSummary{MountPoint: filesystem.GetMountPoint(), CapacityBytes: filesystem.GetCapacityBytes(), AvailableBytes: filesystem.GetAvailableBytes()}
	}
	return EnrollRequest{
		Token: append([]byte(nil), request.GetEnrollmentToken()...), AgentID: request.GetAgentId(),
		CSRPEM: append([]byte(nil), request.GetCertificateSigningRequestPem()...), CSRPublicKey: append([]byte(nil), request.GetCsrPublicKey()...),
		CSRProof: append([]byte(nil), request.GetCsrProof()...),
		Observation: hostinventory.Observation{
			HostID: provided.GetHostId(), AgentID: provided.GetAgentId(), Revision: provided.GetObservationRevision(),
			AgentVersion: provided.GetAgentVersion(), Hostname: provided.GetHostname(), OS: provided.GetOperatingSystem(),
			OSVersion: provided.GetOperatingSystemVersion(), Kernel: provided.GetKernelVersion(), Architecture: provided.GetArchitecture(),
			LogicalCPUCount: provided.GetLogicalCpuCount(), MemoryCapacityBytes: provided.GetMemoryCapacityBytes(), Filesystems: filesystems,
			NetworkAddresses: append([]string(nil), provided.GetNetworkAddresses()...), Capabilities: append([]string(nil), provided.GetCapabilities()...),
			ObservedAt: provided.GetObservedAt().AsTime().UTC(),
		},
	}, nil
}

var _ agentv1.AgentEnrollmentServer = (*GRPCServer)(nil)
