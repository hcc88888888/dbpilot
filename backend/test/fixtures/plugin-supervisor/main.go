package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func main() {
	values, ok := arguments(os.Args[1:])
	if !ok {
		os.Exit(2)
	}
	var instances []string
	if json.Unmarshal([]byte(values["--instance-ids"]), &instances) != nil || len(instances) == 0 {
		os.Exit(2)
	}
	runtimeDirectory := values["--runtime-dir"]
	if !filepath.IsAbs(runtimeDirectory) {
		os.Exit(2)
	}
	configurationRevision, err := strconv.ParseUint(values["--configuration-revision"], 10, 64)
	if err != nil || configurationRevision == 0 {
		os.Exit(2)
	}
	operationRevision, err := strconv.ParseUint(values["--operation-revision"], 10, 64)
	if err != nil || operationRevision == 0 {
		os.Exit(2)
	}
	nonceFD, err := strconv.Atoi(values["--launch-nonce-fd"])
	if err != nil || nonceFD != 3 {
		os.Exit(2)
	}
	nonceFile := os.NewFile(uintptr(nonceFD), "launch-nonce")
	launchNonce := make([]byte, sha256.Size)
	if nonceFile == nil {
		os.Exit(2)
	}
	_, nonceErr := io.ReadFull(nonceFile, launchNonce)
	closeErr := nonceFile.Close()
	if nonceErr != nil || closeErr != nil {
		os.Exit(2)
	}
	self, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		os.Exit(1)
	}
	digest := sha256.Sum256(body)
	record := map[string]any{"args": os.Args[1:], "uid": currentUID(), "gid": currentGID(), "pid": os.Getpid(), "instance_ids": instances, "environment": selectedEnvironment()}
	encoded, _ := json.Marshal(record)
	if os.WriteFile(filepath.Join(runtimeDirectory, "launch.json"), encoded, 0o600) != nil {
		os.Exit(1)
	}
	socket := filepath.Join(runtimeDirectory, "plugin.sock")
	_ = os.Remove(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil || os.Chmod(socket, 0o600) != nil {
		os.Exit(1)
	}
	defer os.Remove(socket)
	server := grpc.NewServer()
	fixture := &runtimeServer{assignmentID: values["--assignment-id"], pluginID: values["--plugin-id"], family: values["--database-family"], version: values["--version"], configurationRevision: configurationRevision, operationRevision: operationRevision, instances: instances, executableDigest: digest[:], launchNonce: launchNonce}
	pluginv1.RegisterPluginRuntimeServer(server, fixture)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { _ = server.Serve(listener) }()
	if values["--version"] == "1.2.0" {
		go func() { time.Sleep(150 * time.Millisecond); os.Exit(17) }()
	}
	<-ctx.Done()
	server.GracefulStop()
}

type runtimeServer struct {
	pluginv1.UnimplementedPluginRuntimeServer
	assignmentID          string
	pluginID              string
	family                string
	version               string
	configurationRevision uint64
	operationRevision     uint64
	instances             []string
	executableDigest      []byte
	launchNonce           []byte
}

func (server *runtimeServer) Handshake(_ context.Context, request *pluginv1.PluginHandshakeRequest) (*pluginv1.PluginHandshakeResponse, error) {
	if server.version == "1.1.0" {
		return nil, errors.New("fixture upgrade handshake failure")
	}
	proof := pluginsupervisor.LaunchProof(server.launchNonce, request.GetLaunchNonceChallenge(), server.assignmentID, server.version, server.configurationRevision, server.operationRevision, server.instances)
	return &pluginv1.PluginHandshakeResponse{PluginId: server.pluginID, DatabaseFamily: server.family, Version: server.version, ProtocolVersion: "v1", SupportedVariants: []string{"mysql"}, DatabaseVersionRange: ">=8 <9", Capabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1, ExecutableDigest: append([]byte(nil), server.executableDigest...), LaunchNonceProof: proof}, nil
}

func (server *runtimeServer) GetHealth(_ context.Context, request *pluginv1.GetPluginHealthRequest) (*pluginv1.PluginHealth, error) {
	if request.GetAssignmentId() != server.assignmentID {
		return nil, errors.New("assignment mismatch")
	}
	instances := make([]*pluginv1.PluginInstanceHealth, 0, len(server.instances))
	for _, id := range server.instances {
		instances = append(instances, &pluginv1.PluginInstanceHealth{InstanceId: id, State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY})
	}
	return &pluginv1.PluginHealth{AssignmentId: server.assignmentID, State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY, ActiveConfigurationRevision: server.configurationRevision, BoundInstanceCount: uint32(len(instances)), Instances: instances, ObservedAt: timestamppb.Now()}, nil
}

func arguments(values []string) (map[string]string, bool) {
	if len(values) == 0 || len(values)%2 != 0 {
		return nil, false
	}
	allowed := map[string]struct{}{"--runtime-dir": {}, "--assignment-id": {}, "--plugin-id": {}, "--database-family": {}, "--version": {}, "--slot": {}, "--configuration-revision": {}, "--operation-revision": {}, "--instance-ids": {}, "--template-ids": {}, "--launch-nonce-fd": {}}
	result := make(map[string]string, len(allowed))
	for index := 0; index < len(values); index += 2 {
		if _, ok := allowed[values[index]]; !ok || values[index+1] == "" {
			return nil, false
		}
		if _, duplicate := result[values[index]]; duplicate {
			return nil, false
		}
		result[values[index]] = values[index+1]
	}
	return result, len(result) == len(allowed)
}

func selectedEnvironment() map[string]string {
	keys := []string{"PATH", "LANG", "LC_ALL", "HOME", "DBPILOT_PLUGIN_PROCESS", "DBPILOT_SECRET_SENTINEL"}
	sort.Strings(keys)
	result := map[string]string{}
	for _, key := range keys {
		if value, exists := os.LookupEnv(key); exists {
			result[key] = value
		}
	}
	return result
}
