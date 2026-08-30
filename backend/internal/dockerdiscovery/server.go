package dockerdiscovery

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	discoveryv1 "dbpilot.local/platform/gen/discovery/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maximumGRPCMessageBytes = 4 << 20
	maximumAllowedLabels    = 32
	maximumInspectWorkers   = 4
	maximumSnapshotDTOBytes = 3 << 20
	snapshotTimeout         = 8 * time.Second
	eventInspectTimeout     = 2 * time.Second
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
	snapshotContext, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()
	if _, err := service.engine.Info(snapshotContext); err != nil {
		if snapshotContext.Err() != nil {
			return nil, status.Error(codes.DeadlineExceeded, "Docker snapshot deadline exceeded")
		}
		return nil, status.Error(codes.Unavailable, "Docker discovery unavailable")
	}
	containers, err := service.engine.ListContainers(snapshotContext)
	if err != nil {
		if snapshotContext.Err() != nil {
			return nil, status.Error(codes.DeadlineExceeded, "Docker snapshot deadline exceeded")
		}
		return nil, status.Error(codes.Unavailable, "Docker discovery unavailable")
	}
	if len(containers) > maximumContainers {
		return nil, status.Error(codes.ResourceExhausted, "Docker discovery response exceeds bound")
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].ContainerID < containers[j].ContainerID })
	type inspectJob struct {
		index int
		id    string
	}
	type inspectResult struct {
		index       int
		observation *discoveryv1.DockerContainerObservation
		err         error
		missing     bool
	}
	jobs := make(chan inspectJob)
	results := make(chan inspectResult, len(containers))
	workers := maximumInspectWorkers
	if len(containers) < workers {
		workers = len(containers)
	}
	var group sync.WaitGroup
	var budgetMutex sync.Mutex
	budgetBytes := 0
	budgetExceeded := false
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for job := range jobs {
				observation, inspectErr := service.engine.InspectContainer(snapshotContext, job.id)
				if errors.Is(inspectErr, ErrContainerNotFound) {
					results <- inspectResult{index: job.index, missing: true}
					continue
				}
				if inspectErr != nil {
					results <- inspectResult{index: job.index, err: inspectErr}
					continue
				}
				wire, convertErr := protobufObservation(observation, allowed)
				if convertErr == nil {
					budgetMutex.Lock()
					budgetBytes += proto.Size(wire)
					if budgetBytes > maximumSnapshotDTOBytes {
						budgetExceeded = true
						convertErr = errSnapshotBudget
						cancel()
					}
					budgetMutex.Unlock()
				}
				results <- inspectResult{index: job.index, observation: wire, err: convertErr}
			}
		}()
	}
	go func() {
		for index, summary := range containers {
			jobs <- inspectJob{index: index, id: summary.ContainerID}
		}
		close(jobs)
		group.Wait()
		close(results)
	}()
	ordered := make([]*discoveryv1.DockerContainerObservation, len(containers))
	for inspected := range results {
		if inspected.err != nil {
			cancel()
			budgetMutex.Lock()
			exhausted := budgetExceeded
			budgetMutex.Unlock()
			if exhausted {
				return nil, status.Error(codes.ResourceExhausted, "Docker discovery response exceeds bound")
			}
			if snapshotContext.Err() != nil {
				return nil, status.Error(codes.DeadlineExceeded, "Docker snapshot deadline exceeded")
			}
			return nil, status.Error(codes.Unavailable, "Docker inspect unavailable")
		}
		if !inspected.missing {
			ordered[inspected.index] = inspected.observation
		}
	}
	result := make([]*discoveryv1.DockerContainerObservation, 0, len(ordered))
	for _, observation := range ordered {
		if observation != nil {
			result = append(result, observation)
		}
	}
	response := &discoveryv1.DockerSnapshotResponse{Containers: result, ObservedAt: timestamppb.New(service.now())}
	if proto.Size(response) > maximumSnapshotDTOBytes {
		return nil, status.Error(codes.ResourceExhausted, "Docker discovery response exceeds bound")
	}
	return response, nil
}

var errSnapshotBudget = errors.New("Docker snapshot DTO budget exceeded")

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
				inspectContext, cancelInspect := context.WithTimeout(stream.Context(), eventInspectTimeout)
				current, inspectErr := service.engine.InspectContainer(inspectContext, event.ContainerID)
				cancelInspect()
				if inspectErr != nil {
					if errors.Is(inspectErr, ErrContainerNotFound) {
						continue
					}
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
				return status.Error(codes.Unavailable, "Docker event stream unavailable")
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
	listener, activated, err := activatedDockerListener()
	if err != nil {
		return err
	}
	if activated {
		defer listener.Close()
		return serveDockerGRPC(ctx, listener, service, config)
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
	listener, err = net.Listen("unix", config.SocketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(config.SocketPath)
	// In direct/container deployments the helper has the Agent GID only as a
	// supplementary group. Keep the distinct helper UID as socket owner.
	if err := os.Chown(config.SocketPath, -1, int(config.AllowedGID)); err != nil {
		return err
	}
	if err := os.Chmod(config.SocketPath, 0o660); err != nil {
		return err
	}
	return serveDockerGRPC(ctx, listener, service, config)
}

func serveDockerGRPC(ctx context.Context, listener net.Listener, service *Service, config ServerConfig) error {
	verified := &peerListener{Listener: listener, uid: config.AllowedUID, gid: config.AllowedGID}
	server := grpc.NewServer(grpc.MaxRecvMsgSize(maximumGRPCMessageBytes), grpc.MaxSendMsgSize(maximumGRPCMessageBytes), grpc.ConnectionTimeout(5*time.Second))
	discoveryv1.RegisterDockerDiscoveryServer(server, service)
	go func() { <-ctx.Done(); server.GracefulStop() }()
	if config.Ready != nil {
		close(config.Ready)
	}
	err := server.Serve(verified)
	if ctx.Err() != nil || errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	return err
}

func activatedDockerListener() (net.Listener, bool, error) {
	pid, pidErr := strconv.Atoi(os.Getenv("LISTEN_PID"))
	fds, fdsErr := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if fdsErr != nil || fds != 1 || (pidErr == nil && pid != os.Getpid()) || (pidErr != nil && os.Getenv("LISTEN_PID") != "") {
		return nil, false, nil
	}
	file := os.NewFile(3, "dbpilot-docker-discovery.socket")
	if file == nil {
		return nil, false, errors.New("invalid activated Docker discovery socket")
	}
	defer file.Close()
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, false, err
	}
	if _, ok := listener.(*net.UnixListener); !ok {
		_ = listener.Close()
		return nil, false, errors.New("activated Docker discovery listener is not AF_UNIX")
	}
	return listener, true, nil
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
