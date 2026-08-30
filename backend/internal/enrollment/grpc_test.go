package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGRPCEnrollMapsAuthenticatedHostObservationAndCertificateResponse(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	raw := bytes.Repeat([]byte{0x63}, EnrollmentTokenBytes)
	caCertificate, caKey := testCertificateAuthority(t, now)
	issuer, err := NewAgentCertificateIssuer(caCertificate, caKey, time.Hour, func() time.Time { return now }, rand.Reader)
	require.NoError(t, err)
	store := newAttemptMemoryStore(validEnrollmentToken(HashToken(raw), now).Grant())
	service := &ApplicationService{Tokens: store, Certificates: issuer, Now: func() time.Time { return now }}
	modelRequest := signedEnrollRequest(t, raw, "agent-1", now)
	server := NewGRPCServer(service)

	response, err := server.Enroll(context.Background(), protoEnrollRequest(modelRequest))

	require.NoError(t, err)
	require.Equal(t, "host-1", response.GetHostId())
	require.Equal(t, "agent-1", response.GetAgentId())
	require.NotEmpty(t, response.GetCertificatePem())
	require.Equal(t, now.Add(time.Hour), response.GetExpiresAt().AsTime())
	require.Equal(t, uint64(1), response.GetEnrollmentRevision())
}

func TestGRPCEnrollUsesFixedStatusWithoutEchoingToken(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	raw := bytes.Repeat([]byte("secret-token"), 3)[:EnrollmentTokenBytes]
	request := signedEnrollRequest(t, raw, "agent-1", now)
	store := newAttemptMemoryStore(validEnrollmentToken(HashToken(raw), now).Grant())
	store.resolveErr = ErrEnrollmentTokenInvalid
	service := &ApplicationService{Tokens: store, Certificates: rejectingIssuer{}, Now: func() time.Time { return now }}

	_, err := NewGRPCServer(service).Enroll(context.Background(), protoEnrollRequest(request))

	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.NotContains(t, err.Error(), string(raw))
}

func protoEnrollRequest(request EnrollRequest) *agentv1.EnrollAgentRequest {
	observation := request.Observation
	filesystems := make([]*agentv1.FilesystemObservation, len(observation.Filesystems))
	for index, filesystem := range observation.Filesystems {
		filesystems[index] = &agentv1.FilesystemObservation{MountPoint: filesystem.MountPoint, CapacityBytes: filesystem.CapacityBytes, AvailableBytes: filesystem.AvailableBytes}
	}
	return &agentv1.EnrollAgentRequest{
		EnrollmentToken: append([]byte(nil), request.Token...), AgentId: request.AgentID,
		CertificateSigningRequestPem: append([]byte(nil), request.CSRPEM...), CsrPublicKey: append([]byte(nil), request.CSRPublicKey...),
		CsrProof: append([]byte(nil), request.CSRProof...),
		HostObservation: &agentv1.HostObservation{
			HostId: observation.HostID, AgentId: observation.AgentID, ObservationRevision: observation.Revision,
			Hostname: observation.Hostname, OperatingSystem: observation.OS, OperatingSystemVersion: observation.OSVersion,
			KernelVersion: observation.Kernel, Architecture: observation.Architecture, LogicalCpuCount: observation.LogicalCPUCount,
			MemoryCapacityBytes: observation.MemoryCapacityBytes, Filesystems: filesystems,
			NetworkAddresses: append([]string(nil), observation.NetworkAddresses...), Capabilities: append([]string(nil), observation.Capabilities...),
			AgentVersion: observation.AgentVersion, ObservedAt: timestamppb.New(observation.ObservedAt),
		},
	}
}
