package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"dbpilot.local/platform/internal/database"
	"github.com/stretchr/testify/require"
)

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
