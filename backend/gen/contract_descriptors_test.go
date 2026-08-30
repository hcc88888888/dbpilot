package gen_test

import (
	"testing"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	discoveryv1 "dbpilot.local/platform/gen/discovery/v1"
	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func requireMessage(t *testing.T, file protoreflect.FileDescriptor, name protoreflect.Name) protoreflect.MessageDescriptor {
	t.Helper()
	message := file.Messages().ByName(name)
	if message == nil {
		t.Fatalf("%s message is absent from %s", name, file.Path())
	}
	return message
}

func requireField(t *testing.T, message protoreflect.MessageDescriptor, name protoreflect.Name) protoreflect.FieldDescriptor {
	t.Helper()
	field := message.Fields().ByName(name)
	if field == nil {
		t.Fatalf("%s.%s field is absent", message.FullName(), name)
	}
	return field
}

func requireEnumField(t *testing.T, message protoreflect.MessageDescriptor, name protoreflect.Name, enum protoreflect.FullName) {
	t.Helper()
	field := requireField(t, message, name)
	if field.Kind() != protoreflect.EnumKind || field.Enum().FullName() != enum {
		t.Fatalf("%s.%s = %s %v, want enum %s", message.FullName(), name, field.Kind(), field.Enum(), enum)
	}
}

func requireOneofField(t *testing.T, message protoreflect.MessageDescriptor, fieldName, oneofName protoreflect.Name) {
	t.Helper()
	field := requireField(t, message, fieldName)
	if field.ContainingOneof() == nil || field.ContainingOneof().Name() != oneofName {
		t.Fatalf("%s.%s is not in oneof %s", message.FullName(), fieldName, oneofName)
	}
}

func requireReserved(t *testing.T, message protoreflect.MessageDescriptor, numbers ...protoreflect.FieldNumber) {
	t.Helper()
	for _, number := range numbers {
		if !message.ReservedRanges().Has(number) {
			t.Fatalf("%s does not reserve field %d", message.FullName(), number)
		}
	}
}

func requireFileIdentity(t *testing.T, file protoreflect.FileDescriptor, pkg protoreflect.FullName, goPackage string, imports ...string) {
	t.Helper()
	if file.Package() != pkg {
		t.Fatalf("%s package = %s, want %s", file.Path(), file.Package(), pkg)
	}
	options, ok := file.Options().(*descriptorpb.FileOptions)
	if !ok || options.GetGoPackage() != goPackage {
		t.Fatalf("%s go_package = %q, want %q", file.Path(), options.GetGoPackage(), goPackage)
	}
	gotImports := make(map[string]bool, file.Imports().Len())
	for index := 0; index < file.Imports().Len(); index++ {
		gotImports[file.Imports().Get(index).Path()] = true
	}
	for _, path := range imports {
		if !gotImports[path] {
			t.Fatalf("%s does not import %s", file.Path(), path)
		}
	}
}

func TestAgentDescriptorsKeepCommandsAndLeasesInTypedOneofs(t *testing.T) {
	file := agentv1.File_agent_v1_command_proto
	requireFileIdentity(t, file, "dbpilot.agent.v1", "dbpilot.local/platform/gen/agent/v1;agentv1",
		"agent/v1/inventory.proto", "agent/v1/policy.proto", "google/protobuf/timestamp.proto")

	envelope := requireMessage(t, file, "CommandEnvelope")
	for _, name := range []protoreflect.Name{
		"discover_databases", "reconcile_plugin", "apply_plugin_configuration",
		"validate_database_instance", "drain_plugin", "collect_database_metrics",
	} {
		requireOneofField(t, envelope, name, "command")
	}
	requireReserved(t, envelope, 31, 49)
	if envelope.Fields().ByName("download_url") != nil || envelope.Fields().ByName("credential_lease_response") != nil {
		t.Fatal("persisted CommandEnvelope exposes a lease payload or URL")
	}

	agentMessage := requireMessage(t, file, "AgentMessage")
	requireOneofField(t, agentMessage, "credential_lease_request", "message")
	requireOneofField(t, agentMessage, "plugin_artifact_lease_request", "message")
	requireReserved(t, agentMessage, 32, 49)
	serverMessage := requireMessage(t, file, "ServerMessage")
	requireOneofField(t, serverMessage, "credential_lease_response", "message")
	requireOneofField(t, serverMessage, "plugin_artifact_lease_response", "message")
	requireReserved(t, serverMessage, 29, 49)

	service := file.Services().ByName("AgentControl")
	if service == nil || service.Methods().ByName("Connect") == nil {
		t.Fatal("AgentControl.Connect is absent")
	}
}

func TestObservationDescriptorsCloseLifecycleEnumsAndExposeCircuitState(t *testing.T) {
	inventory := agentv1.File_agent_v1_inventory_proto
	requireFileIdentity(t, inventory, "dbpilot.agent.v1", "dbpilot.local/platform/gen/agent/v1;agentv1",
		"google/protobuf/timestamp.proto")
	candidate := requireMessage(t, inventory, "DiscoveryCandidateObservation")
	requireEnumField(t, candidate, "source", "dbpilot.agent.v1.DiscoverySource")
	evidence := requireField(t, candidate, "evidence")
	if evidence.Kind() != protoreflect.MessageKind || evidence.Message().FullName() != "dbpilot.agent.v1.DiscoveryEvidence" {
		t.Fatalf("DiscoveryCandidateObservation.evidence = %s, want typed DiscoveryEvidence", evidence.Kind())
	}
	assignment := requireMessage(t, inventory, "PluginAssignmentObservation")
	requireEnumField(t, assignment, "active_slot", "dbpilot.agent.v1.PluginActiveSlot")
	requireEnumField(t, assignment, "process_state", "dbpilot.agent.v1.PluginProcessState")
	requireEnumField(t, assignment, "health", "dbpilot.agent.v1.PluginHealthState")
	requireEnumField(t, assignment, "circuit_state", "dbpilot.agent.v1.PluginCircuitState")

	docker := discoveryv1.File_discovery_v1_docker_proto
	requireFileIdentity(t, docker, "dbpilot.discovery.v1", "dbpilot.local/platform/gen/discovery/v1;discoveryv1",
		"google/protobuf/timestamp.proto")
	container := requireMessage(t, docker, "DockerContainerObservation")
	requireEnumField(t, container, "status", "dbpilot.discovery.v1.DockerContainerStatus")
}

func TestPluginAndDockerDescriptorsExposeExactServices(t *testing.T) {
	plugin := pluginv1.File_plugin_v1_plugin_proto
	requireFileIdentity(t, plugin, "dbpilot.plugin.v1", "dbpilot.local/platform/gen/plugin/v1;pluginv1",
		"plugin/v1/health.proto", "plugin/v1/instance.proto", "plugin/v1/metrics.proto")
	service := plugin.Services().ByName("PluginRuntime")
	if service == nil {
		t.Fatal("PluginRuntime service is absent")
	}
	expected := map[protoreflect.Name][3]string{
		"Handshake":           {"dbpilot.plugin.v1.PluginHandshakeRequest", "dbpilot.plugin.v1.PluginHandshakeResponse", "false"},
		"ApplyConfiguration": {"dbpilot.plugin.v1.ApplyPluginConfigurationRequest", "dbpilot.plugin.v1.ApplyPluginConfigurationResponse", "false"},
		"ValidateInstance":    {"dbpilot.plugin.v1.ValidatePluginInstanceRequest", "dbpilot.plugin.v1.ValidatePluginInstanceResponse", "false"},
		"CollectNow":          {"dbpilot.plugin.v1.CollectPluginMetricsRequest", "dbpilot.plugin.v1.CollectPluginMetricsResponse", "false"},
		"StreamMetrics":       {"dbpilot.plugin.v1.StreamPluginMetricsRequest", "dbpilot.plugin.v1.PluginMetricBatch", "true"},
		"GetHealth":           {"dbpilot.plugin.v1.GetPluginHealthRequest", "dbpilot.plugin.v1.PluginHealth", "false"},
		"Shutdown":            {"dbpilot.plugin.v1.ShutdownPluginRequest", "dbpilot.plugin.v1.ShutdownPluginResponse", "false"},
	}
	if service.Methods().Len() != len(expected) {
		t.Fatalf("PluginRuntime method count = %d, want %d", service.Methods().Len(), len(expected))
	}
	for name, want := range expected {
		method := service.Methods().ByName(name)
		if method == nil || string(method.Input().FullName()) != want[0] || string(method.Output().FullName()) != want[1] || method.IsStreamingServer() != (want[2] == "true") {
			t.Fatalf("PluginRuntime.%s descriptor mismatch", name)
		}
	}

	docker := discoveryv1.File_discovery_v1_docker_proto.Services().ByName("DockerDiscovery")
	if docker == nil || docker.Methods().Len() != 2 {
		t.Fatal("DockerDiscovery must expose exactly Snapshot and Watch")
	}
	if docker.Methods().ByName("Snapshot") == nil || docker.Methods().ByName("Watch") == nil || !docker.Methods().ByName("Watch").IsStreamingServer() {
		t.Fatal("DockerDiscovery RPC descriptors are incorrect")
	}
}
