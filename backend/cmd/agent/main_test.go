package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/spool"
	"dbpilot.local/platform/internal/telemetry"
	"github.com/stretchr/testify/require"
)

func TestProcHelperRequiresExplicitNonzeroPeerIdentity(t *testing.T) {
	var stdout, stderr bytes.Buffer
	require.Equal(t, 2, run([]string{"proc-helper"}, &stdout, &stderr))
	require.Contains(t, stderr.String(), "--allowed-uid and --allowed-gid")
}

func TestProcHelperRequiresLocalDatabaseProcessAllowlist(t *testing.T) {
	var stdout, stderr bytes.Buffer
	require.Equal(t, 2, run([]string{"proc-helper", "--allowed-uid", "19001", "--allowed-gid", "19001"}, &stdout, &stderr))
	require.Contains(t, stderr.String(), "--allowed-process-names")
}

func TestConfiguredCommandExecutorsAdvertiseCollectNowWithHostCollector(t *testing.T) {
	var typedNil *mainHostCollector
	withoutCollector, err := configuredCommandExecutors(typedNil, nil)
	require.NoError(t, err)
	require.Empty(t, withoutCollector.Capabilities())

	withHost, err := configuredCommandExecutors(&mainHostCollector{}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{string(agent.CommandKindCollectNow), agent.CapabilityCollectNowHostV1}, withHost.Capabilities())

	store, err := spool.Open(t.TempDir(), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 64 << 10})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	collector, err := agent.NewDependencyCollector(agent.DependencyCollectorConfig{
		AgentID: "agent-a",
		Definitions: []database.ComponentDefinition{{
			ID: "hdfs-a", Kind: database.HDFSComponent,
			Endpoints: []database.Endpoint{{URL: "http://127.0.0.1:9870/jmx", Role: "namenode"}},
			SecretRef: "secret://hdfs/reader",
		}},
		SecretResolver: database.StaticSecretResolver{"secret://hdfs/reader": []byte("runtime-only")},
		Store:          store,
	})
	require.NoError(t, err)
	withCollector, err := configuredCommandExecutors(&mainHostCollector{}, collector)
	require.NoError(t, err)
	require.Equal(t, []string{string(agent.CommandKindCollectNow), agent.CapabilityCollectNowDependenciesV1, agent.CapabilityCollectNowHostV1}, withCollector.Capabilities())
}

func TestProductionHostSnapshotCollectorSharesEngineLimitAndLogIndex(t *testing.T) {
	store, err := spool.Open(t.TempDir(), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 64 << 10})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	engine := telemetry.NewEngine(nil)
	logs := telemetry.NewLogSummaryIndex()
	settings := agentConfig{AgentID: "agent-a", DatabaseProcessNames: []string{"postgres"}}

	collector := newHostSnapshotCollector(settings, store, engine, logs)

	require.Same(t, engine, collector.BatchLimits)
	require.Same(t, logs, collector.Logs)
	require.Equal(t, []string{"postgres"}, collector.ProcessNames)
}

type mainHostCollector struct{}

func (*mainHostCollector) Collect(context.Context, agent.CollectionRequest) error { return nil }

func TestLoadConfigRejectsRelativePrivateAndDataPaths(t *testing.T) {
	path := writeConfig(t, `
agent_id: agent-a
server_address: ingest.example:9443
ca_file: relative/ca.pem
cert_file: /etc/dbpilot/agent.pem
key_file: /etc/dbpilot/key.pem
policy_public_key_file: /etc/dbpilot/policy.pem
data_directory: /var/lib/dbpilot-agent
allowed_log_roots: [/var/log]
file_collection_enabled: true
`)

	_, err := loadConfig(path)
	require.Error(t, err)
}

func TestLoadConfigRequiresAllowedRootsForFileCollection(t *testing.T) {
	path := writeConfig(t, `
agent_id: agent-a
server_address: ingest.example:9443
ca_file: /etc/dbpilot/ca.pem
cert_file: /etc/dbpilot/agent.pem
key_file: /etc/dbpilot/key.pem
policy_public_key_file: /etc/dbpilot/policy.pem
data_directory: /var/lib/dbpilot-agent
file_collection_enabled: true
`)

	_, err := loadConfig(path)
	require.Error(t, err)
}

func TestLoadConfigAcceptsAbsoluteRestrictedConfiguration(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(dir, 0o700))
	}
	ca := writeSecret(t, dir, "ca.pem")
	cert := writeSecret(t, dir, "agent.pem")
	key := writeSecret(t, dir, "key.pem")
	policyKey := writeSecret(t, dir, "policy.pem")
	policyFile := writeSecret(t, dir, "policy-envelope.json")
	path := writeConfig(t, "\nagent_id: agent-a\nserver_address: ingest.example:9443\nca_file: "+filepath.ToSlash(ca)+"\ncert_file: "+filepath.ToSlash(cert)+"\nkey_file: "+filepath.ToSlash(key)+"\npolicy_public_key_file: "+filepath.ToSlash(policyKey)+"\npolicy_file: "+filepath.ToSlash(policyFile)+"\ndata_directory: "+filepath.ToSlash(dir)+"\nallowed_log_roots: ["+filepath.ToSlash(dir)+"]\nfile_collection_enabled: true\n")

	config, err := loadConfig(path)
	require.NoError(t, err)
	require.Equal(t, "agent-a", config.AgentID)
}

func TestLoadConfigAcceptsDurableControlSettings(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(dir, 0o700))
	}
	ca, cert, key := writeSecret(t, dir, "ca.pem"), writeSecret(t, dir, "agent.pem"), writeSecret(t, dir, "key.pem")
	policyKey, controlKey, policyFile := writeSecret(t, dir, "policy.pem"), writeSecret(t, dir, "control.pem"), writeSecret(t, dir, "policy.json")
	journalPath := filepath.Join(dir, "commands.db")
	body := "agent_id: agent-a\nserver_address: ingest.example:9443\nca_file: " + filepath.ToSlash(ca) + "\ncert_file: " + filepath.ToSlash(cert) + "\nkey_file: " + filepath.ToSlash(key) + "\npolicy_public_key_file: " + filepath.ToSlash(policyKey) + "\npolicy_file: " + filepath.ToSlash(policyFile) + "\ndata_directory: " + filepath.ToSlash(dir) + "\ncontrol:\n  public_key_file: " + filepath.ToSlash(controlKey) + "\n  journal_path: " + filepath.ToSlash(journalPath) + "\n  heartbeat_interval: 15s\n  reconnect_backoff: 250ms\n"

	config, err := loadConfig(writeConfig(t, body))

	require.NoError(t, err)
	require.Equal(t, filepath.ToSlash(controlKey), config.Control.PublicKeyFile)
	require.Equal(t, filepath.ToSlash(journalPath), config.Control.JournalPath)
	require.Equal(t, 15*time.Second, config.Control.HeartbeatInterval)
	require.Equal(t, 250*time.Millisecond, config.Control.ReconnectBackoff)
}

func TestLoadConfigRejectsDockerDiscoveryWithoutHostEnrollmentRules(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(dir, 0o700))
	}
	ca, cert, key := writeSecret(t, dir, "ca.pem"), writeSecret(t, dir, "agent.pem"), writeSecret(t, dir, "key.pem")
	policyKey, policyFile := writeSecret(t, dir, "policy.pem"), writeSecret(t, dir, "policy.json")
	body := "agent_id: agent-a\nserver_address: ingest.example:9443\nca_file: " + filepath.ToSlash(ca) + "\ncert_file: " + filepath.ToSlash(cert) + "\nkey_file: " + filepath.ToSlash(key) + "\npolicy_public_key_file: " + filepath.ToSlash(policyKey) + "\npolicy_file: " + filepath.ToSlash(policyFile) + "\ndata_directory: " + filepath.ToSlash(dir) + "\ndocker_discovery: true\ndocker_discovery_socket: /run/dbpilot-agent/docker-discovery.sock\n"

	_, err := loadConfig(writeConfig(t, body))
	require.ErrorContains(t, err, "host enrollment")
}

func TestLoadConfigAcceptsComponentCollectorConfiguration(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(dir, 0o700))
	}
	ca, cert, key := writeSecret(t, dir, "ca.pem"), writeSecret(t, dir, "agent.pem"), writeSecret(t, dir, "key.pem")
	policyKey, policyFile := writeSecret(t, dir, "policy.pem"), writeSecret(t, dir, "policy.json")
	body := "agent_id: agent-a\nserver_address: ingest.example:9443\nca_file: " + filepath.ToSlash(ca) + "\ncert_file: " + filepath.ToSlash(cert) + "\nkey_file: " + filepath.ToSlash(key) + "\npolicy_public_key_file: " + filepath.ToSlash(policyKey) + "\npolicy_file: " + filepath.ToSlash(policyFile) + "\ndata_directory: " + filepath.ToSlash(dir) + "\n" + `component_secrets:
  provider: environment
component_collection:
  interval_seconds: 15
  request_timeout_seconds: 2
  max_attempts: 2
  initial_backoff_milliseconds: 10
  max_backoff_milliseconds: 20
components:
  - id: hbase-prod
    kind: hbase
    endpoints:
      - url: http://127.0.0.1:16030/jmx
        role: regionserver
    secret_ref: secret://hbase/reader
    dependencies:
      hdfs_cluster_id: hdfs-prod
      zookeeper_cluster_id: zk-prod
`
	config, err := loadConfig(writeConfig(t, body))
	require.NoError(t, err)
	require.Equal(t, database.HBaseComponent, config.Components[0].Kind)
	require.Equal(t, 15*time.Second, config.ComponentCollection.interval())
}

func TestLoadConfigNormalizesTrustedDatabaseProcessNames(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(dir, 0o700))
	}
	ca, cert, key := writeSecret(t, dir, "ca.pem"), writeSecret(t, dir, "agent.pem"), writeSecret(t, dir, "key.pem")
	policyKey, policyFile := writeSecret(t, dir, "policy.pem"), writeSecret(t, dir, "policy.json")
	body := "agent_id: agent-a\nserver_address: ingest.example:9443\nca_file: " + filepath.ToSlash(ca) + "\ncert_file: " + filepath.ToSlash(cert) + "\nkey_file: " + filepath.ToSlash(key) + "\npolicy_public_key_file: " + filepath.ToSlash(policyKey) + "\npolicy_file: " + filepath.ToSlash(policyFile) + "\ndata_directory: " + filepath.ToSlash(dir) + "\ndatabase_process_names: [Postgres, mysqld, postgres]\n"

	config, err := loadConfig(writeConfig(t, body))

	require.NoError(t, err)
	require.Equal(t, []string{"mysqld", "postgres"}, config.DatabaseProcessNames)
}

func TestLoadConfigRejectsUntrustedDatabaseProcessNames(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(dir, 0o700))
	}
	ca, cert, key := writeSecret(t, dir, "ca.pem"), writeSecret(t, dir, "agent.pem"), writeSecret(t, dir, "key.pem")
	policyKey, policyFile := writeSecret(t, dir, "policy.pem"), writeSecret(t, dir, "policy.json")
	base := "agent_id: agent-a\nserver_address: ingest.example:9443\nca_file: " + filepath.ToSlash(ca) + "\ncert_file: " + filepath.ToSlash(cert) + "\nkey_file: " + filepath.ToSlash(key) + "\npolicy_public_key_file: " + filepath.ToSlash(policyKey) + "\npolicy_file: " + filepath.ToSlash(policyFile) + "\ndata_directory: " + filepath.ToSlash(dir) + "\n"
	tests := []struct {
		name  string
		value string
	}{
		{name: "path", value: "database_process_names: ['../../bin/postgres']\n"},
		{name: "too many", value: func() string {
			result := "database_process_names:\n"
			for index := 0; index < agent.MaxDatabaseProcessNames+1; index++ {
				result += fmt.Sprintf("  - process-%d\n", index)
			}
			return result
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadConfig(writeConfig(t, base+test.value))
			require.Error(t, err)
		})
	}
}

func TestLoadConfigRejectsUnsupportedComponentSecretProvider(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(dir, 0o700))
	}
	ca, cert, key := writeSecret(t, dir, "ca.pem"), writeSecret(t, dir, "agent.pem"), writeSecret(t, dir, "key.pem")
	policyKey, policyFile := writeSecret(t, dir, "policy.pem"), writeSecret(t, dir, "policy.json")
	body := "agent_id: agent-a\nserver_address: ingest.example:9443\nca_file: " + filepath.ToSlash(ca) + "\ncert_file: " + filepath.ToSlash(cert) + "\nkey_file: " + filepath.ToSlash(key) + "\npolicy_public_key_file: " + filepath.ToSlash(policyKey) + "\npolicy_file: " + filepath.ToSlash(policyFile) + "\ndata_directory: " + filepath.ToSlash(dir) + "\ncomponent_secrets:\n  provider: inline\ncomponents:\n  - id: hdfs-a\n    kind: hdfs\n    endpoints: [{url: http://127.0.0.1/jmx, role: namenode}]\n    secret_ref: secret://hdfs/reader\n"
	_, err := loadConfig(writeConfig(t, body))
	require.ErrorContains(t, err, "component_secrets.provider")
}

func TestLoadConfigRejectsAllowedLogRootThatIsNotDirectory(t *testing.T) {
	dir := t.TempDir()
	file := writeSecret(t, dir, "not-a-directory")
	ca := writeSecret(t, dir, "ca.pem")
	cert := writeSecret(t, dir, "agent.pem")
	key := writeSecret(t, dir, "key.pem")
	policyKey := writeSecret(t, dir, "policy.pem")
	policyFile := writeSecret(t, dir, "policy.json")
	path := writeConfig(t, "agent_id: agent-a\nserver_address: ingest.example:9443\nca_file: "+filepath.ToSlash(ca)+"\ncert_file: "+filepath.ToSlash(cert)+"\nkey_file: "+filepath.ToSlash(key)+"\npolicy_public_key_file: "+filepath.ToSlash(policyKey)+"\npolicy_file: "+filepath.ToSlash(policyFile)+"\ndata_directory: "+filepath.ToSlash(dir)+"\nallowed_log_roots: ["+filepath.ToSlash(file)+"]\nfile_collection_enabled: true\n")
	_, err := loadConfig(path)
	require.Error(t, err)
}

func writeSecret(t *testing.T, directory, name string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	require.NoError(t, os.WriteFile(path, []byte("test"), 0o600))
	return path
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}
