package dockerdiscovery

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	discoveryv1 "dbpilot.local/platform/gen/discovery/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maximumGRPCMessageBytes = 4 << 20
	maximumAllowedLabels    = 32
)

var labelKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type Service struct {
	discoveryv1.UnimplementedDockerDiscoveryServer
	engine  Engine
	allowed map[string]struct{}
	now     func() time.Time
}

func NewService(engine Engine, allowedLabelKeys []string) (*Service, error) {
	if engine == nil || len(allowedLabelKeys) > maximumAllowedLabels {
		return nil, errors.New("invalid Docker discovery service configuration")
	}
	allowed := make(map[string]struct{}, len(allowedLabelKeys))
	for _, key := range allowedLabelKeys {
		if !labelKeyPattern.MatchString(key) {
			return nil, errors.New("invalid Docker label allowlist")
		}
		if _, duplicate := allowed[key]; duplicate {
			return nil, errors.New("duplicate Docker label allowlist entry")
		}
		allowed[key] = struct{}{}
	}
	return &Service{engine: engine, allowed: allowed, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (service *Service) Snapshot(ctx context.Context, request *discoveryv1.DockerSnapshotRequest) (*discoveryv1.DockerSnapshotResponse, error) {
	allowed, err := service.validateRequest(request.GetRuleRevision(), request.GetAllowedLabelKeys())
	if err != nil {
		return nil, err
	}
	containers, err := service.engine.ListContainers(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "Docker discovery unavailable")
	}
	if len(containers) > maximumContainers {
		return nil, status.Error(codes.ResourceExhausted, "Docker discovery response exceeds bound")
	}
	result := make([]*discoveryv1.DockerContainerObservation, 0, len(containers))
	for _, summary := range containers {
		observation, inspectErr := service.engine.InspectContainer(ctx, summary.ContainerID)
		if inspectErr != nil {
			if errors.Is(inspectErr, ErrContainerNotFound) {
				continue
			}
			return nil, status.Error(codes.Unavailable, "Docker inspect unavailable")
		}
		wire, convertErr := protobufObservation(observation, allowed)
		if convertErr != nil {
			return nil, status.Error(codes.DataLoss, "Docker inspect rejected")
		}
		result = append(result, wire)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ContainerId < result[j].ContainerId })
	return &discoveryv1.DockerSnapshotResponse{Containers: result, ObservedAt: timestamppb.New(service.now())}, nil
}

func (service *Service) Watch(request *discoveryv1.DockerWatchRequest, stream grpc.ServerStreamingServer[discoveryv1.DockerEvent]) error {
	allowed, err := service.validateRequest(request.GetRuleRevision(), request.GetAllowedLabelKeys())
	if err != nil {
		return err
	}
	events, failures := service.engine.Events(stream.Context(), service.now())
	if err := stream.SendHeader(metadata.Pairs("dbpilot-docker-watch-ready", "1")); err != nil {
		return err
	}
	for events != nil || failures != nil {
		select {
		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			observation := ContainerObservation{ContainerID: event.ContainerID, Name: event.Name, Image: event.Image, ObservedAt: event.OccurredAt}
			if event.Action != "destroy" {
				current, inspectErr := service.engine.InspectContainer(stream.Context(), event.ContainerID)
				if inspectErr != nil {
					return status.Error(codes.Unavailable, "Docker inspect unavailable")
				}
				observation = current
			}
			wire, convertErr := protobufObservation(observation, allowed)
			if convertErr != nil {
				return status.Error(codes.DataLoss, "Docker event rejected")
			}
			if err := stream.Send(&discoveryv1.DockerEvent{EventId: event.ContainerID + ":" + event.Action + ":" + event.OccurredAt.UTC().Format(time.RFC3339Nano), Type: protobufEventType(event.Action), Container: wire, OccurredAt: timestamppb.New(event.OccurredAt.UTC())}); err != nil {
				return err
			}
		case failure, ok := <-failures:
			if !ok {
				failures = nil
				continue
			}
			if failure != nil {
				return status.Errorf(codes.Unavailable, "Docker event stream unavailable: %v", failure)
			}
		}
	}
	return nil
}

func (service *Service) validateRequest(revision uint64, keys []string) ([]string, error) {
	if revision == 0 || len(keys) > maximumAllowedLabels {
		return nil, status.Error(codes.InvalidArgument, "invalid Docker discovery request")
	}
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if !labelKeyPattern.MatchString(key) {
			return nil, status.Error(codes.InvalidArgument, "invalid Docker label request")
		}
		if _, configured := service.allowed[key]; !configured {
			return nil, status.Error(codes.PermissionDenied, "Docker label is not locally allowlisted")
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, status.Error(codes.InvalidArgument, "duplicate Docker label request")
		}
		seen[key] = struct{}{}
	}
	result := append([]string(nil), keys...)
	sort.Strings(result)
	return result, nil
}

func protobufObservation(observation ContainerObservation, allowed []string) (*discoveryv1.DockerContainerObservation, error) {
	if !containerIDPattern.MatchString(observation.ContainerID) || len(observation.Name) > 256 || len(observation.Image) > 512 || strings.ContainsAny(observation.Name+observation.Image+observation.CommandSummary+observation.Cgroup, "\x00\r\n") || len(observation.CommandSummary) > maximumCommandSummaryBytes || len(observation.Cgroup) > 512 {
		return nil, errors.New("invalid Docker observation")
	}
	ports := make([]*discoveryv1.DockerPortMapping, 0, len(observation.Ports))
	for _, value := range observation.Ports {
		if value.HostPort == 0 || value.ContainerPort == 0 || (value.Protocol != "tcp" && value.Protocol != "udp") || net.ParseIP(value.HostAddress) == nil {
			return nil, errors.New("invalid Docker port")
		}
		ports = append(ports, &discoveryv1.DockerPortMapping{HostAddress: value.HostAddress, HostPort: uint32(value.HostPort), ContainerPort: uint32(value.ContainerPort), Protocol: value.Protocol})
	}
	return &discoveryv1.DockerContainerObservation{ContainerId: observation.ContainerID, Name: observation.Name, Image: observation.Image, Status: protobufStatus(observation.State), Ports: ports, Labels: FilterLabels(observation.Labels, allowed), CommandSummary: RedactCommand(strings.Fields(observation.CommandSummary)), HostProcessId: observation.HostProcessID, Cgroup: observation.Cgroup, ObservedAt: timestamppb.New(observation.ObservedAt.UTC())}, nil
}

func protobufStatus(value string) discoveryv1.DockerContainerStatus {
	return map[string]discoveryv1.DockerContainerStatus{"created": discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_CREATED, "running": discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RUNNING, "paused": discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_PAUSED, "restarting": discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RESTARTING, "removing": discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_REMOVING, "exited": discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_EXITED, "dead": discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_DEAD}[value]
}

func protobufEventType(value string) discoveryv1.DockerEventType {
	return map[string]discoveryv1.DockerEventType{"start": discoveryv1.DockerEventType_DOCKER_EVENT_TYPE_START, "stop": discoveryv1.DockerEventType_DOCKER_EVENT_TYPE_STOP, "die": discoveryv1.DockerEventType_DOCKER_EVENT_TYPE_DIE, "destroy": discoveryv1.DockerEventType_DOCKER_EVENT_TYPE_DESTROY}[value]
}

type ServerConfig struct {
	SocketPath       string
	AllowedUID       uint32
	AllowedGID       uint32
	Engine           Engine
	AllowedLabelKeys []string
	Ready            chan<- struct{}
}

func Serve(ctx context.Context, config ServerConfig) error {
	if ctx == nil || config.AllowedUID == 0 || config.AllowedGID == 0 || !filepath.IsAbs(config.SocketPath) {
		return errors.New("invalid Docker discovery server configuration")
	}
	service, err := NewService(config.Engine, config.AllowedLabelKeys)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(config.SocketPath), 0o755); err != nil {
		return err
	}
	if info, statErr := os.Lstat(config.SocketPath); statErr == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Docker discovery socket path is unsafe")
		}
		if err := os.Remove(config.SocketPath); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	listener, err := net.Listen("unix", config.SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(config.SocketPath)
	if err := os.Chown(config.SocketPath, int(config.AllowedUID), int(config.AllowedGID)); err != nil {
		return err
	}
	if err := os.Chmod(config.SocketPath, 0o600); err != nil {
		return err
	}
	verified := &peerListener{Listener: listener, uid: config.AllowedUID, gid: config.AllowedGID}
	server := grpc.NewServer(grpc.MaxRecvMsgSize(maximumGRPCMessageBytes), grpc.MaxSendMsgSize(maximumGRPCMessageBytes), grpc.ConnectionTimeout(5*time.Second))
	discoveryv1.RegisterDockerDiscoveryServer(server, service)
	go func() { <-ctx.Done(); server.GracefulStop() }()
	if config.Ready != nil {
		close(config.Ready)
	}
	err = server.Serve(verified)
	if ctx.Err() != nil || errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	return err
}

type peerListener struct {
	net.Listener
	uid, gid uint32
}

func (listener *peerListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, gid, err := peerCredentials(connection)
		if err == nil && uid == listener.uid && gid == listener.gid {
			return connection, nil
		}
		_ = connection.Close()
	}
}

func Dial(ctx context.Context, socketPath string) (*grpc.ClientConn, error) {
	if ctx == nil || !filepath.IsAbs(socketPath) {
		return nil, errors.New("invalid Docker discovery socket path")
	}
	return grpc.NewClient("passthrough:///dbpilot-docker-discovery", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socketPath)
	}), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maximumGRPCMessageBytes), grpc.MaxCallSendMsgSize(maximumGRPCMessageBytes)))
}
