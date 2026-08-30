package dockerdiscovery

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDockerClientUsesOnlyExactReadAllowlist(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var mu sync.Mutex
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		mu.Unlock()
		switch request.URL.Path {
		case "/info":
			_, _ = writer.Write([]byte(`{"ID":"engine-a"}`))
		case "/containers/json":
			require.Equal(t, "all=1", request.URL.RawQuery)
			_, _ = writer.Write([]byte(`[{"Id":"` + id + `"}]`))
		case "/containers/" + id + "/json":
			require.Empty(t, request.URL.RawQuery)
			_, _ = writer.Write([]byte(`{"Id":"` + id + `","Name":"/mysql-a","Config":{"Image":"mysql:8.4","Entrypoint":["docker-entrypoint.sh"],"Cmd":["mysqld"]},"State":{"Status":"running","Pid":123},"NetworkSettings":{"Ports":{"3306/tcp":[{"HostIp":"127.0.0.1","HostPort":"49161"}]}}}`))
		default:
			http.Error(writer, "unexpected", http.StatusForbidden)
		}
	}))
	defer server.Close()

	client := newHTTPClient(server.Client(), server.URL)
	_, err := client.Info(context.Background())
	require.NoError(t, err)
	containers, err := client.ListContainers(context.Background())
	require.NoError(t, err)
	require.Len(t, containers, 1)
	_, err = client.InspectContainer(context.Background(), id)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"GET /info", "GET /containers/json?all=1", "GET /containers/" + id + "/json"}, requests)
}

func TestDockerClientDialsOnlyConfiguredUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Docker Engine AF_UNIX client is verified in Linux cross/container gates")
	}
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/info", request.URL.Path)
		_, _ = writer.Write([]byte(`{"ID":"engine-a"}`))
	})}
	go server.Serve(listener)
	defer server.Shutdown(context.Background())
	client, err := NewClient(socket)
	require.NoError(t, err)
	info, err := client.Info(context.Background())
	require.NoError(t, err)
	require.Equal(t, "engine-a", info.ID)
	require.NoError(t, os.Chmod(socket, 0o600))
}

func TestDockerClientRejectsContainerIDPathAndQueryInjectionBeforeRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	client := newHTTPClient(server.Client(), server.URL)
	for _, value := range []string{"", "short", "../../info", strings.Repeat("a", 64) + "?logs=1", strings.Repeat("g", 64), url.PathEscape("../info")} {
		_, err := client.InspectContainer(context.Background(), value)
		require.Error(t, err, value)
	}
	require.Zero(t, requests)
}

func TestDockerEndpointGuardRejectsEveryForbiddenOperationAndQuery(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		path  string
		query url.Values
	}{
		{path: "/containers/create"},
		{path: "/containers/" + id + "/start"},
		{path: "/containers/" + id + "/stop"},
		{path: "/containers/" + id + "/exec"},
		{path: "/containers/" + id + "/attach"},
		{path: "/containers/" + id + "/logs"},
		{path: "/containers/" + id + "/archive"},
		{path: "/containers/" + id + "/stats"},
		{path: "/images/json"},
		{path: "/networks"},
		{path: "/volumes"},
		{path: "/containers/json", query: url.Values{"all": {"1"}, "size": {"1"}}},
		{path: "/containers/" + id + "/json", query: url.Values{"logs": {"1"}}},
		{path: "/events", query: url.Values{"since": {"0"}, "until": {"1"}, "filters": {`{"type":["container"]}`}}},
	}
	for _, test := range tests {
		require.False(t, allowedPath(test.path, test.query), test.path+"?"+test.query.Encode())
	}
}

func TestDockerClientDoesNotFollowRedirectsOrAcceptOversizedResponses(t *testing.T) {
	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetHits++ }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/info" {
			http.Redirect(writer, request, target.URL+"/containers/json", http.StatusTemporaryRedirect)
			return
		}
		_, _ = writer.Write([]byte(`[` + strings.Repeat(`{"Id":"x"},`, maximumEngineResponseBytes) + `{}` + `]`))
	}))
	defer server.Close()
	client := newHTTPClient(server.Client(), server.URL)
	_, err := client.Info(context.Background())
	require.Error(t, err)
	require.Zero(t, targetHits)
	_, err = client.ListContainers(context.Background())
	require.Error(t, err)
}

func TestDockerClientClassifiesInspectNotFoundWithoutFollowingOrRetrying(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		http.Error(writer, "gone", http.StatusNotFound)
	}))
	defer server.Close()
	client := newHTTPClient(server.Client(), server.URL)
	_, err := client.InspectContainer(context.Background(), id)
	require.ErrorIs(t, err, ErrContainerNotFound)
	require.Equal(t, 1, requests)
}

func TestDockerClientExtractsBoundedCgroupAssociation(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "42"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "42", "cgroup"), []byte("0::/system.slice/docker-012345.scope\n"), 0o600))
	value, err := readCgroupAt(root, 42)
	require.NoError(t, err)
	require.Equal(t, "/system.slice/docker-012345.scope", value)

	require.NoError(t, os.WriteFile(filepath.Join(root, "42", "cgroup"), []byte(strings.Repeat("x", maximumCgroupFileBytes+1)), 0o600))
	_, err = readCgroupAt(root, 42)
	require.Error(t, err)
}

func TestDockerClientEventsUsesBoundedExactFiltersAndRedactsActorData(t *testing.T) {
	const id = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, http.MethodGet, request.Method)
		require.Equal(t, "/events", request.URL.Path)
		query := request.URL.Query()
		require.Equal(t, "1788148800", query.Get("since"))
		var filters map[string][]string
		require.NoError(t, json.Unmarshal([]byte(query.Get("filters")), &filters))
		require.Equal(t, []string{"container"}, filters["type"])
		require.Equal(t, []string{"destroy", "die", "start", "stop"}, filters["event"])
		_, _ = writer.Write([]byte(`{"status":"start","id":"` + id + `","from":"mysql:8.4","Actor":{"Attributes":{"name":"mysql-a","password":"never-return"}},"time":1788148801}` + "\n"))
	}))
	defer server.Close()
	client := newHTTPClient(server.Client(), server.URL)
	events, errs := client.Events(context.Background(), time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC))
	event := <-events
	require.Equal(t, id, event.ContainerID)
	require.Equal(t, "mysql-a", event.Name)
	require.NotContains(t, event.Name, "never-return")
	require.NoError(t, <-errs)
}

func TestDockerClientAcceptsModernActorOnlyContainerEvent(t *testing.T) {
	const id = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`{"Type":"container","Action":"start","Actor":{"ID":"` + id + `","Attributes":{"name":"mysql-a","image":"mysql:8.4","secret":"never-return"}},"time":1788148801}` + "\n"))
	}))
	defer server.Close()
	client := newHTTPClient(server.Client(), server.URL)
	events, errs := client.Events(context.Background(), time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC))
	event := <-events
	require.Equal(t, id, event.ContainerID)
	require.Equal(t, "start", event.Action)
	require.Equal(t, "mysql-a", event.Name)
	require.Equal(t, "mysql:8.4", event.Image)
	require.NoError(t, <-errs)
}
