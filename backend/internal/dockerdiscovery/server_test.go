package dockerdiscovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	discoveryv1 "dbpilot.local/platform/gen/discovery/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestDockerServerSnapshotReturnsOnlyFixedAllowlistedDTO(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	engine := &fakeEngine{list: []ContainerObservation{{ContainerID: id}}, inspect: ContainerObservation{
		ContainerID: id, Name: "mysql-a", Image: "mysql:8.4", State: "running", HostProcessID: 42,
		Labels:         map[string]string{"dbpilot.discovery.family": "mysql", "password": "secret", "other": "hidden"},
		CommandSummary: "mysqld --password=[REDACTED]", Ports: []PortMapping{{HostAddress: "127.0.0.1", HostPort: 49161, ContainerPort: 3306, Protocol: "tcp"}},
	}}
	service, err := NewService(engine, []string{"dbpilot.discovery.family", "password"})
	require.NoError(t, err)
	response, err := service.Snapshot(context.Background(), &discoveryv1.DockerSnapshotRequest{RuleRevision: 7, AllowedLabelKeys: []string{"dbpilot.discovery.family", "password"}})
	require.NoError(t, err)
	require.Len(t, response.Containers, 1)
	container := response.Containers[0]
	require.Equal(t, map[string]string{"dbpilot.discovery.family": "mysql", "password": "[REDACTED]"}, container.Labels)
	require.NotContains(t, container.CommandSummary, "secret")
	require.Equal(t, uint32(42), container.HostProcessId)
}

func TestDockerServerReturnsOnlyLocallyAndPerRequestAllowlistedInternalEndpoints(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	engine := &fakeEngine{list: []ContainerObservation{{ContainerID: id}}, inspect: ContainerObservation{
		ContainerID: id, Name: "mysql-a", Image: "mysql:8.4", State: "running", ObservedAt: time.Now().UTC(),
		InternalEndpoints: []InternalEndpoint{
			{NetworkName: "dbpilot_acceptance", Address: "172.30.0.10", Port: 3306, Protocol: "tcp"},
			{NetworkName: "other_network", Address: "172.31.0.10", Port: 3306, Protocol: "tcp"},
		},
	}}
	service, err := NewService(engine, nil, []string{"dbpilot_acceptance"})
	require.NoError(t, err)
	response, err := service.Snapshot(context.Background(), &discoveryv1.DockerSnapshotRequest{RuleRevision: 7, AllowedNetworkNames: []string{"dbpilot_acceptance"}})
	require.NoError(t, err)
	require.Len(t, response.GetContainers(), 1)
	require.True(t, proto.Equal(&discoveryv1.DockerContainerObservation{InternalEndpoints: []*discoveryv1.DockerInternalEndpoint{{NetworkName: "dbpilot_acceptance", Address: "172.30.0.10", Port: 3306, Protocol: "tcp"}}}, &discoveryv1.DockerContainerObservation{InternalEndpoints: response.GetContainers()[0].GetInternalEndpoints()}))

	_, err = service.Snapshot(context.Background(), &discoveryv1.DockerSnapshotRequest{RuleRevision: 7, AllowedNetworkNames: []string{"other_network"}})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestDockerServerRejectsInvalidInternalEndpointInsteadOfForwardingRawInspectData(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for name, endpoint := range map[string]InternalEndpoint{
		"empty address":  {NetworkName: "dbpilot_acceptance", Port: 3306, Protocol: "tcp"},
		"non IP address": {NetworkName: "dbpilot_acceptance", Address: "mysql-a", Port: 3306, Protocol: "tcp"},
		"wrong network":  {NetworkName: "other_network", Address: "172.31.0.10", Port: 3306, Protocol: "tcp"},
	} {
		t.Run(name, func(t *testing.T) {
			wire, err := protobufObservation(ContainerObservation{ContainerID: id, Name: "mysql-a", Image: "mysql:8.4", State: "running", ObservedAt: time.Now().UTC(), InternalEndpoints: []InternalEndpoint{endpoint}}, nil, []string{"dbpilot_acceptance"})
			if name == "wrong network" {
				require.NoError(t, err)
				require.Empty(t, wire.GetInternalEndpoints())
				return
			}
			require.Error(t, err)
		})
	}
}

func TestDockerServerRejectsUnsafeInternalAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "::", "127.0.0.1", "::1", "169.254.10.20", "fe80::1", "224.0.0.1", "ff02::1"} {
		t.Run(address, func(t *testing.T) {
			_, err := protobufObservation(ContainerObservation{
				ContainerID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Name: "mysql-a", Image: "mysql:8.4", State: "running", ObservedAt: time.Now().UTC(),
				InternalEndpoints: []InternalEndpoint{{NetworkName: "dbpilot_acceptance", Address: address, Port: 3306, Protocol: "tcp"}},
			}, nil, []string{"dbpilot_acceptance"})
			require.Error(t, err)
		})
	}
}

func TestDockerServerRejectsUnknownLabelsAndInvalidRuleRevision(t *testing.T) {
	service, err := NewService(&fakeEngine{}, []string{"dbpilot.discovery.family"})
	require.NoError(t, err)
	_, err = service.Snapshot(context.Background(), &discoveryv1.DockerSnapshotRequest{RuleRevision: 0})
	require.Error(t, err)
	_, err = service.Snapshot(context.Background(), &discoveryv1.DockerSnapshotRequest{RuleRevision: 1, AllowedLabelKeys: []string{"not-approved"}})
	require.Error(t, err)
}

func TestDockerSnapshotRequiresBoundedInfoHealthProbeBeforeInventory(t *testing.T) {
	engine := &fakeEngine{infoErr: errors.New("engine unavailable")}
	service, err := NewService(engine, nil)
	require.NoError(t, err)
	_, err = service.Snapshot(context.Background(), &discoveryv1.DockerSnapshotRequest{RuleRevision: 1})
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Zero(t, engine.listCalls)
}

func TestDockerServerSkipsContainerRemovedBetweenListAndInspect(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	service, err := NewService(&fakeEngine{list: []ContainerObservation{{ContainerID: id}}, inspectErr: ErrContainerNotFound}, []string{"dbpilot.discovery.family"})
	require.NoError(t, err)
	response, err := service.Snapshot(context.Background(), &discoveryv1.DockerSnapshotRequest{RuleRevision: 1, AllowedLabelKeys: []string{"dbpilot.discovery.family"}})
	require.NoError(t, err)
	require.Empty(t, response.GetContainers())
}

func TestDockerSnapshotUsesBoundedWorkersAndDeterministicOrder(t *testing.T) {
	engine := newConcurrentEngine(12)
	service, err := NewService(engine, []string{"dbpilot.discovery.family"})
	require.NoError(t, err)
	response, err := service.Snapshot(context.Background(), &discoveryv1.DockerSnapshotRequest{RuleRevision: 1, AllowedLabelKeys: []string{"dbpilot.discovery.family"}})
	require.NoError(t, err)
	ids := make([]string, len(response.GetContainers()))
	for index, container := range response.GetContainers() {
		ids[index] = container.GetContainerId()
	}
	require.True(t, sort.StringsAreSorted(ids))
	require.LessOrEqual(t, engine.maximumConcurrent(), maximumInspectWorkers)
	require.Greater(t, engine.maximumConcurrent(), 1)
}

func TestDockerSnapshotHonorsOneAggregateDeadline(t *testing.T) {
	engine := newConcurrentEngine(1)
	engine.block = true
	service, err := NewService(engine, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = service.Snapshot(ctx, &discoveryv1.DockerSnapshotRequest{RuleRevision: 1})
	require.Error(t, err)
	require.Less(t, time.Since(started), 500*time.Millisecond)
	require.Equal(t, codes.DeadlineExceeded, status.Code(err))
}

func TestDockerSnapshotListUsesAggregateDeadline(t *testing.T) {
	engine := newConcurrentEngine(1)
	engine.blockList = true
	service, err := NewService(engine, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = service.Snapshot(ctx, &discoveryv1.DockerSnapshotRequest{RuleRevision: 1})
	require.Equal(t, codes.DeadlineExceeded, status.Code(err))
	require.Less(t, time.Since(started), 500*time.Millisecond)
}

func TestDockerSnapshotRejectsAggregateSerializedDTOBudget(t *testing.T) {
	engine := newConcurrentEngine(400)
	labels := make(map[string]string, 32)
	allowed := make([]string, 32)
	for index := range allowed {
		allowed[index] = fmt.Sprintf("dbpilot.label.%02d", index)
		labels[allowed[index]] = strings.Repeat("x", 256)
	}
	engine.labels = labels
	service, err := NewService(engine, allowed)
	require.NoError(t, err)
	_, err = service.Snapshot(context.Background(), &discoveryv1.DockerSnapshotRequest{RuleRevision: 1, AllowedLabelKeys: allowed})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestDockerServerCreatesPrivateUnixSocketAndRejectsWrongPeer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED is a Linux contract")
	}
	path := filepath.Join(t.TempDir(), "docker-discovery.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- Serve(ctx, ServerConfig{SocketPath: path, AllowedUID: uint32(os.Getuid() + 1), AllowedGID: uint32(os.Getgid() + 1), Engine: &fakeEngine{}, AllowedLabelKeys: []string{"dbpilot.discovery.family"}, Ready: ready})
	}()
	<-ready
	info, err := os.Lstat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o660), info.Mode().Perm())
	connection, err := Dial(context.Background(), path)
	require.NoError(t, err)
	defer connection.Close()
	client := discoveryv1.NewDockerDiscoveryClient(connection)
	callContext, stop := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer stop()
	_, err = client.Snapshot(callContext, &discoveryv1.DockerSnapshotRequest{RuleRevision: 1})
	require.Error(t, err)
	cancel()
	require.NoError(t, <-errCh)
}

func TestDockerPeerListenerRequiresExactUIDAndGIDIndependently(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED is a Linux contract")
	}
	for _, test := range []struct {
		name string
		uid  uint32
		gid  uint32
	}{
		{name: "wrong uid", uid: uint32(os.Getuid() + 1), gid: uint32(os.Getgid())},
		{name: "wrong gid", uid: uint32(os.Getuid()), gid: uint32(os.Getgid() + 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "peer.sock")
			base, err := net.Listen("unix", path)
			require.NoError(t, err)
			verified := &peerListener{Listener: base, uid: test.uid, gid: test.gid}
			accepted := make(chan error, 1)
			go func() {
				connection, acceptErr := verified.Accept()
				if connection != nil {
					_ = connection.Close()
				}
				accepted <- acceptErr
			}()
			client, err := net.DialTimeout("unix", path, time.Second)
			require.NoError(t, err)
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			_, err = client.Read(make([]byte, 1))
			require.ErrorIs(t, err, io.EOF)
			require.NoError(t, client.Close())
			require.NoError(t, base.Close())
			require.Error(t, <-accepted)
		})
	}
}

type fakeEngine struct {
	list       []ContainerObservation
	inspect    ContainerObservation
	listErr    error
	inspectErr error
	infoErr    error
	listCalls  int
}

func (engine *fakeEngine) ListContainers(context.Context) ([]ContainerObservation, error) {
	engine.listCalls++
	return engine.list, engine.listErr
}
func (engine *fakeEngine) InspectContainer(context.Context, string) (ContainerObservation, error) {
	return engine.inspect, engine.inspectErr
}
func (engine *fakeEngine) Events(context.Context, time.Time) (<-chan ContainerEvent, <-chan error) {
	events := make(chan ContainerEvent)
	errs := make(chan error, 1)
	close(events)
	errs <- engine.listErr
	close(errs)
	return events, errs
}
func (engine *fakeEngine) Info(context.Context) (EngineInfo, error) {
	return EngineInfo{ID: "engine-test"}, engine.infoErr
}

type concurrentEngine struct {
	ids       []ContainerObservation
	labels    map[string]string
	block     bool
	blockList bool
	mu        sync.Mutex
	active    int
	maximum   int
}

func newConcurrentEngine(count int) *concurrentEngine {
	values := make([]ContainerObservation, count)
	for index := range values {
		values[index].ContainerID = fmt.Sprintf("%064x", count-index)
	}
	return &concurrentEngine{ids: values}
}
func (engine *concurrentEngine) ListContainers(ctx context.Context) ([]ContainerObservation, error) {
	if engine.blockList {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return append([]ContainerObservation(nil), engine.ids...), nil
}
func (engine *concurrentEngine) InspectContainer(ctx context.Context, id string) (ContainerObservation, error) {
	engine.mu.Lock()
	engine.active++
	if engine.active > engine.maximum {
		engine.maximum = engine.active
	}
	engine.mu.Unlock()
	defer func() { engine.mu.Lock(); engine.active--; engine.mu.Unlock() }()
	if engine.block {
		<-ctx.Done()
		return ContainerObservation{}, ctx.Err()
	}
	time.Sleep(time.Duration(id[len(id)-1]%4+1) * time.Millisecond)
	return ContainerObservation{ContainerID: id, Name: "mysql-" + id[len(id)-4:], Image: "mysql:8.4", State: "running", Labels: engine.labels, ObservedAt: time.Now().UTC()}, nil
}
func (engine *concurrentEngine) Events(context.Context, time.Time) (<-chan ContainerEvent, <-chan error) {
	events := make(chan ContainerEvent)
	failures := make(chan error)
	close(events)
	close(failures)
	return events, failures
}
func (engine *concurrentEngine) Info(context.Context) (EngineInfo, error) {
	return EngineInfo{ID: "engine-test"}, nil
}
func (engine *concurrentEngine) maximumConcurrent() int {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.maximum
}
