package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
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
	var templates []string
	if json.Unmarshal([]byte(values["--template-ids"]), &templates) != nil || len(templates) == 0 {
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
	fixture := &runtimeServer{assignmentID: values["--assignment-id"], pluginID: values["--plugin-id"], family: values["--database-family"], version: values["--version"], configurationRevision: configurationRevision, operationRevision: operationRevision, instances: instances, templates: templates, runtimeDirectory: runtimeDirectory, collectedAt: persistentCollectionTime(runtimeDirectory, configurationRevision), cursors: loadPluginCursors(runtimeDirectory), executableDigest: digest[:], launchNonce: launchNonce}
	pluginv1.RegisterPluginRuntimeServer(server, fixture)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { _ = server.Serve(listener) }()
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
	templates             []string
	runtimeDirectory      string
	collectedAt           time.Time
	executableDigest      []byte
	launchNonce           []byte
	mu                    sync.Mutex
	applied               bool
	cursors               map[string]uint64
}

func (server *runtimeServer) ApplyConfiguration(_ context.Context, request *pluginv1.ApplyPluginConfigurationRequest) (*pluginv1.ApplyPluginConfigurationResponse, error) {
	if request.GetAssignmentId() != server.assignmentID || request.GetConfigurationRevision() != server.configurationRevision || len(request.GetInstances()) != len(server.instances) {
		return nil, errors.New("configuration mismatch")
	}
	results := make([]*pluginv1.PluginInstanceConfigurationResult, 0, len(server.instances))
	for _, instance := range request.GetInstances() {
		if len(instance.GetTemplates()) != len(server.templates) {
			return nil, errors.New("template coverage mismatch")
		}
		results = append(results, &pluginv1.PluginInstanceConfigurationResult{InstanceId: instance.GetInstanceId(), Applied: true})
	}
	server.mu.Lock()
	server.applied = true
	server.mu.Unlock()
	server.record("apply")
	return &pluginv1.ApplyPluginConfigurationResponse{ActiveConfigurationRevision: server.configurationRevision, Results: results}, nil
}

func (server *runtimeServer) ValidateInstance(_ context.Context, request *pluginv1.ValidatePluginInstanceRequest) (*pluginv1.ValidatePluginInstanceResponse, error) {
	if request.GetAssignmentId() != server.assignmentID || request.GetConfigurationRevision() != server.configurationRevision || !contains(server.instances, request.GetInstanceId()) {
		return nil, errors.New("validation mismatch")
	}
	server.record("validate:" + request.GetInstanceId())
	return &pluginv1.ValidatePluginInstanceResponse{InstanceId: request.GetInstanceId(), Valid: true, DatabaseVersion: "8.4.0", DatabaseEdition: "community", Capabilities: []string{"metrics.collect"}}, nil
}

func (server *runtimeServer) CollectNow(_ context.Context, request *pluginv1.CollectPluginMetricsRequest) (*pluginv1.CollectPluginMetricsResponse, error) {
	if request.GetAssignmentId() != server.assignmentID || request.GetConfigurationRevision() != server.configurationRevision {
		return nil, errors.New("collect mismatch")
	}
	batches := make([]*pluginv1.PluginMetricBatch, 0, len(request.GetInstanceIds())*len(request.GetTemplateIds()))
	for _, instanceID := range request.GetInstanceIds() {
		for _, templateID := range request.GetTemplateIds() {
			batches = append(batches, server.batch(instanceID, templateID, server.nextSequence(instanceID, templateID)))
		}
	}
	server.record("collect")
	return &pluginv1.CollectPluginMetricsResponse{Batches: batches}, nil
}

func (server *runtimeServer) StreamMetrics(request *pluginv1.StreamPluginMetricsRequest, stream pluginv1.PluginRuntime_StreamMetricsServer) error {
	if request.GetAssignmentId() != server.assignmentID || request.GetConfigurationRevision() != server.configurationRevision || len(request.GetResumeCursors()) != len(server.instances)*len(server.templates) {
		return errors.New("resume coverage mismatch")
	}
	server.record(fmt.Sprintf("stream:%d:%d", len(request.GetResumeCursors()), request.GetResumeCursors()[0].GetSequence()))
	if err := stream.SendHeader(metadata.MD{}); err != nil {
		return err
	}
	if server.version == "1.2.0" {
		time.Sleep(150 * time.Millisecond)
		return errors.New("injected stream failure")
	}
	timer := time.NewTimer(1500 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	streamSequence := request.GetResumeCursors()[0].GetSequence() + 1
	if err := stream.Send(server.batch(server.instances[0], server.templates[0], streamSequence)); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func (server *runtimeServer) batch(instanceID, templateID string, sequence uint64) *pluginv1.PluginMetricBatch {
	now := server.collectedAt.Add(time.Duration(sequence) * time.Second)
	return &pluginv1.PluginMetricBatch{PluginId: server.pluginID, PluginVersion: server.version, DatabaseFamily: server.family, DatabaseVariant: "mysql", InstanceId: instanceID, ConfigurationRevision: server.configurationRevision, TemplateId: templateID, TemplateRevision: 1, CollectedAt: timestamppb.New(now), Sequence: sequence, CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, Samples: []*pluginv1.PluginMetricSample{{MetricName: "mysql.connections.current", Value: float64(sequence), Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, SampledAt: timestamppb.New(now)}}}
}

func persistentCollectionTime(directory string, revision uint64) time.Time {
	path := filepath.Join(directory, fmt.Sprintf("collection-%d.timestamp", revision))
	if body, err := os.ReadFile(path); err == nil {
		if value, parseErr := time.Parse(time.RFC3339Nano, string(body)); parseErr == nil {
			return value.UTC()
		}
	}
	value := time.Now().UTC().Truncate(time.Millisecond)
	_ = os.WriteFile(path, []byte(value.Format(time.RFC3339Nano)), 0o600)
	return value
}

func (server *runtimeServer) record(value string) {
	server.mu.Lock()
	defer server.mu.Unlock()
	file, err := os.OpenFile(filepath.Join(server.runtimeDirectory, "protocol.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = file.WriteString(value + "\n")
	_ = file.Sync()
	_ = file.Close()
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

func (*runtimeServer) Shutdown(context.Context, *pluginv1.ShutdownPluginRequest) (*pluginv1.ShutdownPluginResponse, error) {
	return &pluginv1.ShutdownPluginResponse{Drained: true}, nil
}

func (server *runtimeServer) AcknowledgeMetrics(_ context.Context, request *pluginv1.AcknowledgePluginMetricsRequest) (*pluginv1.AcknowledgePluginMetricsResponse, error) {
	server.mu.Lock()
	for _, cursor := range request.GetCursors() {
		key := pluginCursorKey(server.configurationRevision, cursor.GetInstanceId(), cursor.GetTemplateId())
		if cursor.GetSequence() > server.cursors[key] {
			server.cursors[key] = cursor.GetSequence()
		}
	}
	encoded, _ := json.Marshal(server.cursors)
	_ = os.WriteFile(filepath.Join(server.runtimeDirectory, "plugin-cursors.json"), encoded, 0o600)
	server.mu.Unlock()
	server.record(fmt.Sprintf("ack:%d", request.GetCursors()[0].GetSequence()))
	return &pluginv1.AcknowledgePluginMetricsResponse{AcceptedCursors: request.GetCursors()}, nil
}

func (server *runtimeServer) nextSequence(instanceID, templateID string) uint64 {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.cursors[pluginCursorKey(server.configurationRevision, instanceID, templateID)] + 1
}

func pluginCursorKey(revision uint64, instanceID, templateID string) string {
	return fmt.Sprintf("%d:%s:%s", revision, instanceID, templateID)
}

func loadPluginCursors(directory string) map[string]uint64 {
	result := map[string]uint64{}
	body, err := os.ReadFile(filepath.Join(directory, "plugin-cursors.json"))
	if err == nil {
		_ = json.Unmarshal(body, &result)
	}
	return result
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
