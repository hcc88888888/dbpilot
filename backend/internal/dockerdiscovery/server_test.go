package dockerdiscovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	discoveryv1 "dbpilot.local/platform/gen/discovery/v1"
	"github.com/stretchr/testify/require"
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

func TestDockerServerRejectsUnknownLabelsAndInvalidRuleRevision(t *testing.T) {
	service, err := NewService(&fakeEngine{}, []string{"dbpilot.discovery.family"})
	require.NoError(t, err)
	_, err = service.Snapshot(context.Background(), &discoveryv1.DockerSnapshotRequest{RuleRevision: 0})
	require.Error(t, err)
	_, err = service.Snapshot(context.Background(), &discoveryv1.DockerSnapshotRequest{RuleRevision: 1, AllowedLabelKeys: []string{"not-approved"}})
	require.Error(t, err)
}

func TestDockerServerSkipsContainerRemovedBetweenListAndInspect(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	service, err := NewService(&fakeEngine{list: []ContainerObservation{{ContainerID: id}}, inspectErr: ErrContainerNotFound}, []string{"dbpilot.discovery.family"})
	require.NoError(t, err)
	response, err := service.Snapshot(context.Background(), &discoveryv1.DockerSnapshotRequest{RuleRevision: 1, AllowedLabelKeys: []string{"dbpilot.discovery.family"}})
	require.NoError(t, err)
	require.Empty(t, response.GetContainers())
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
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
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

type fakeEngine struct {
	list       []ContainerObservation
	inspect    ContainerObservation
	listErr    error
	inspectErr error
}

func (engine *fakeEngine) ListContainers(context.Context) ([]ContainerObservation, error) {
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
	return EngineInfo{}, errors.New("unused")
}
