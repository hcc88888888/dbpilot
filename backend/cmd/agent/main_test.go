package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

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
	path := writeConfig(t, "\nagent_id: agent-a\nserver_address: ingest.example:9443\nca_file: "+filepath.ToSlash(ca)+"\ncert_file: "+filepath.ToSlash(cert)+"\nkey_file: "+filepath.ToSlash(key)+"\npolicy_public_key_file: "+filepath.ToSlash(policyKey)+"\ndata_directory: "+filepath.ToSlash(dir)+"\nallowed_log_roots: ["+filepath.ToSlash(dir)+"]\nfile_collection_enabled: true\n")

	config, err := loadConfig(path)
	require.NoError(t, err)
	require.Equal(t, "agent-a", config.AgentID)
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
