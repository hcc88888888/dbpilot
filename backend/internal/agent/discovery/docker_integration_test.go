package discovery

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	discoveryv1 "dbpilot.local/platform/gen/discovery/v1"
	domain "dbpilot.local/platform/internal/discovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDockerHelperTwoMySQLContainersAndEventReconciliation(t *testing.T) {
	socket := os.Getenv("DBPILOT_DOCKER_HELPER_SOCKET")
	runLabel := os.Getenv("DBPILOT_DOCKER_TEST_RUN")
	readyFile := os.Getenv("DBPILOT_DOCKER_TEST_READY_FILE")
	restartID := os.Getenv("DBPILOT_DOCKER_TEST_RESTART_ID")
	if socket == "" || runLabel == "" || readyFile == "" || restartID == "" {
		t.Skip("real restricted Docker helper integration is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	detector, connection, err := NewDockerDetectorAt(ctx, socket, 1, []string{"dbpilot.discovery.family", "dbpilot.run"})
	require.NoError(t, err)
	defer connection.Close()
	rule := domain.Rule{ID: "mysql-docker", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", DockerImagePatterns: []string{`^mysql:8\.4$`}, DockerLabelSelectors: []string{"dbpilot.discovery.family=mysql", "dbpilot.run=" + runLabel}, DefaultPorts: []uint16{3306}}

	raw, err := discoveryv1.NewDockerDiscoveryClient(connection).Snapshot(ctx, &discoveryv1.DockerSnapshotRequest{RuleRevision: 1, AllowedLabelKeys: []string{"dbpilot.discovery.family", "dbpilot.run"}})
	require.NoError(t, err)
	for _, container := range raw.GetContainers() {
		if container.GetLabels()["dbpilot.run"] == runLabel && container.GetLabels()["dbpilot.discovery.family"] == "mysql" {
			t.Logf("owned container DTO: id=%s image=%q status=%s labels=%v ports=%v", container.GetContainerId(), container.GetImage(), container.GetStatus(), container.GetLabels(), container.GetPorts())
		}
	}
	candidates, err := detector.Discover(ctx, []domain.Rule{rule})
	require.NoError(t, err)
	require.Len(t, candidates, 2)
	require.NotEqual(t, candidates[0].ContainerIdentity, candidates[1].ContainerIdentity)

	matched := 0
	for _, container := range raw.GetContainers() {
		if container.GetLabels()["dbpilot.run"] != runLabel || container.GetLabels()["dbpilot.discovery.family"] != "mysql" {
			continue
		}
		matched++
		require.NotContains(t, strings.ToLower(container.GetCommandSummary()), "password")
		require.NotContains(t, strings.ToLower(container.GetCommandSummary()), "token")
		require.Subset(t, []string{"dbpilot.discovery.family", "dbpilot.run"}, mapKeys(container.GetLabels()))
	}
	require.Equal(t, 2, matched)

	eventStream, err := discoveryv1.NewDockerDiscoveryClient(connection).Watch(ctx, &discoveryv1.DockerWatchRequest{RuleRevision: 1, AllowedLabelKeys: []string{"dbpilot.discovery.family", "dbpilot.run"}})
	require.NoError(t, err)
	headers, err := eventStream.Header()
	require.NoError(t, err)
	require.Equal(t, []string{"1"}, headers.Get("dbpilot-docker-watch-ready"))
	require.NoError(t, os.WriteFile(readyFile, []byte("ready"), 0o600))
	for {
		event, receiveErr := eventStream.Recv()
		require.NoError(t, receiveErr, "Docker event stream did not reconcile a container restart")
		if event.GetContainer().GetContainerId() == restartID && (event.GetType() == discoveryv1.DockerEventType_DOCKER_EVENT_TYPE_STOP || event.GetType() == discoveryv1.DockerEventType_DOCKER_EVENT_TYPE_DIE) {
			break
		}
	}
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		reconciled, discoverErr := detector.Discover(ctx, []domain.Rule{rule})
		require.NoError(collect, discoverErr)
		require.Len(collect, reconciled, 2)
	}, 10*time.Second, 200*time.Millisecond)
}

func mapKeys(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	return result
}
