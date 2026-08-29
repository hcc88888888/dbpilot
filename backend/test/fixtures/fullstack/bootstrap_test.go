package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/policy"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestGenerateBootstrapCreatesAcceptanceTreeWithoutManifestSecrets(t *testing.T) {
	now := time.Date(2026, 8, 29, 2, 3, 4, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "acceptance")
	manifest, err := GenerateBootstrap(context.Background(), BootstrapOptions{
		Root: root, Issuer: "https://oidc:9444", Audience: "dbpilot-control-plane",
		TenantID: "tenant-acceptance", ProjectID: "project-acceptance",
		OnlineAgentID: "agent-online", OfflineAgentID: "agent-offline",
		Now: now, Random: newDeterministicReader("bootstrap-acceptance"),
	})
	require.NoError(t, err)
	require.Equal(t, "https://oidc:9444", manifest.Issuer)
	require.Equal(t, "dbpilot-control-plane", manifest.Audience)
	require.Equal(t, "tenant-acceptance", manifest.TenantID)
	require.Equal(t, "project-acceptance", manifest.ProjectID)
	require.Equal(t, "agent-online", manifest.OnlineAgentID)
	require.Equal(t, "agent-offline", manifest.OfflineAgentID)

	wantFiles := []string{
		"agent_config", "agent_mismatch_cert", "agent_mismatch_config", "agent_mismatch_key",
		"agent_online_cert", "agent_online_key", "agent_untrusted_cert", "agent_untrusted_config",
		"agent_untrusted_key", "artifact_key", "ca_cert", "command_private_key", "command_public_key",
		"controlplane_config", "controlplane_grpc_cert", "controlplane_grpc_key", "controlplane_http_cert",
		"controlplane_http_key", "execution_key", "frontend_cert", "frontend_key", "jwks", "manifest", "oidc_cert", "oidc_config",
		"oidc_key", "oidc_signing_key", "policy", "policy_private_key", "policy_public_key", "postgres_password",
		"token_credential", "untrusted_ca_cert",
	}
	gotFiles := make([]string, 0, len(manifest.Files))
	for name, path := range manifest.Files {
		gotFiles = append(gotFiles, name)
		absolute, absoluteErr := filepath.Abs(path)
		require.NoError(t, absoluteErr)
		require.Equal(t, filepath.Clean(path), absolute, name)
		relative, relativeErr := filepath.Rel(root, path)
		require.NoError(t, relativeErr)
		require.False(t, relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)), name)
		info, statErr := os.Lstat(path)
		require.NoError(t, statErr, name)
		require.True(t, info.Mode().IsRegular(), name)
		require.Zero(t, info.Mode()&os.ModeSymlink, name)
	}
	sort.Strings(gotFiles)
	require.Equal(t, wantFiles, gotFiles)

	if runtime.GOOS != "windows" {
		for _, name := range []string{"agent_mismatch_key", "agent_online_key", "agent_untrusted_key", "artifact_key", "command_private_key", "controlplane_config", "execution_key", "frontend_key", "oidc_key", "oidc_signing_key", "policy_private_key", "postgres_password", "token_credential"} {
			info, statErr := os.Stat(manifest.Files[name])
			require.NoError(t, statErr)
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), name)
		}
		for _, directory := range []string{root, filepath.Join(root, "config"), filepath.Join(root, "secrets"), filepath.Join(root, "state"), filepath.Join(root, "state", "agent-online"), filepath.Join(root, "state", "agent-mismatch"), filepath.Join(root, "state", "agent-untrusted"), filepath.Join(root, "state", "artifacts")} {
			info, statErr := os.Stat(directory)
			require.NoError(t, statErr)
			require.Equal(t, os.FileMode(0o700), info.Mode().Perm(), directory)
		}
	}
	for _, directory := range []string{"agent-online", "agent-mismatch", "agent-untrusted", "artifacts"} {
		info, statErr := os.Stat(filepath.Join(root, "state", directory))
		require.NoError(t, statErr, directory)
		require.True(t, info.IsDir(), directory)
	}

	manifestBody := mustRead(t, manifest.Files["manifest"])
	var stored BootstrapManifest
	require.NoError(t, json.Unmarshal(manifestBody, &stored))
	require.Equal(t, manifest, stored)
	for _, name := range []string{"agent_online_key", "artifact_key", "command_private_key", "execution_key", "frontend_key", "oidc_signing_key", "policy_private_key", "postgres_password", "token_credential"} {
		secret := bytes.TrimSpace(mustRead(t, manifest.Files[name]))
		require.NotEmpty(t, secret, name)
		require.NotContains(t, string(manifestBody), string(secret), name)
	}
}

func TestGenerateBootstrapUsesExactCertificateIdentitiesAndKeyAlgorithms(t *testing.T) {
	manifest := generateBootstrapForTest(t)
	ca := mustCertificate(t, manifest.Files["ca_cert"])
	require.True(t, ca.IsCA)
	require.IsType(t, ed25519.PublicKey{}, ca.PublicKey)

	for _, name := range []string{"controlplane_http_cert", "controlplane_grpc_cert"} {
		certificate := mustCertificate(t, manifest.Files[name])
		require.Equal(t, []string{"controlplane"}, certificate.DNSNames, name)
		require.Empty(t, certificate.URIs, name)
		require.IsType(t, ed25519.PublicKey{}, certificate.PublicKey, name)
	}
	oidcCertificate := mustCertificate(t, manifest.Files["oidc_cert"])
	require.Equal(t, []string{"oidc"}, oidcCertificate.DNSNames)
	require.Empty(t, oidcCertificate.URIs)
	require.IsType(t, ed25519.PublicKey{}, oidcCertificate.PublicKey)
	frontendCertificate := mustCertificate(t, manifest.Files["frontend_cert"])
	require.Equal(t, []string{"frontend"}, frontendCertificate.DNSNames)
	require.Empty(t, frontendCertificate.URIs)
	require.IsType(t, ed25519.PublicKey{}, frontendCertificate.PublicKey)
	require.NoError(t, frontendCertificate.CheckSignatureFrom(ca))
	frontendKey, ok := mustPrivateKey(t, manifest.Files["frontend_key"]).(ed25519.PrivateKey)
	require.True(t, ok)
	require.Equal(t, ed25519.PublicKey(frontendKey.Public().(ed25519.PublicKey)), frontendCertificate.PublicKey)

	wantAgentURIs := map[string]string{
		"agent_online_cert":    "spiffe://dbpilot.local/agent/agent-online",
		"agent_mismatch_cert":  "spiffe://dbpilot.local/agent/agent-certificate-id",
		"agent_untrusted_cert": "spiffe://dbpilot.local/agent/agent-untrusted",
	}
	for name, wantURI := range wantAgentURIs {
		certificate := mustCertificate(t, manifest.Files[name])
		require.Empty(t, certificate.DNSNames, name)
		require.Len(t, certificate.URIs, 1, name)
		require.Equal(t, wantURI, certificate.URIs[0].String(), name)
		require.IsType(t, ed25519.PublicKey{}, certificate.PublicKey, name)
	}

	commandKey := mustPrivateKey(t, manifest.Files["command_private_key"])
	require.IsType(t, ed25519.PrivateKey{}, commandKey)
	policyKey := mustPrivateKey(t, manifest.Files["policy_private_key"])
	require.IsType(t, ed25519.PrivateKey{}, policyKey)
	oidcKey := mustPrivateKey(t, manifest.Files["oidc_signing_key"])
	rsaKey, ok := oidcKey.(*rsa.PrivateKey)
	require.True(t, ok)
	require.Equal(t, 2048, rsaKey.N.BitLen())
}

func TestGenerateBootstrapProducesBoundedPolicyInventoryAndOIDCConfig(t *testing.T) {
	manifest := generateBootstrapForTest(t)

	var envelope policy.SignatureEnvelope
	require.NoError(t, json.Unmarshal(mustRead(t, manifest.Files["policy"]), &envelope))
	publicKeyValue := mustPublicKey(t, manifest.Files["policy_public_key"])
	publicKey, ok := publicKeyValue.(ed25519.PublicKey)
	require.True(t, ok)
	verified, err := policy.Verify(publicKey, envelope, time.Date(2026, 8, 29, 2, 3, 4, 0, time.UTC))
	require.NoError(t, err)
	require.Equal(t, "agent-online", verified.AgentID)
	require.Len(t, verified.Sources, 2)
	require.Equal(t, policy.SourceHostMetrics, verified.Sources[0].Kind)
	require.Equal(t, policy.SourceFileLog, verified.Sources[1].Kind)
	require.Equal(t, "/var/log/dbpilot/acceptance.log", verified.Sources[1].Path)
	require.Positive(t, verified.Limits.MaxSpoolBytes)
	require.Positive(t, verified.Limits.MaxBatchBytes)
	require.Positive(t, verified.Limits.MaxEventsPerSec)

	var controlplane map[string]any
	require.NoError(t, yaml.Unmarshal(mustRead(t, manifest.Files["controlplane_config"]), &controlplane))
	require.Equal(t, "oidc", nestedString(t, controlplane, "identity", "mode"))
	require.Equal(t, "https://oidc:9444", nestedString(t, controlplane, "identity", "issuer"))
	require.Equal(t, "dbpilot-control-plane", nestedString(t, controlplane, "identity", "audience"))
	require.Equal(t, "https://frontend:8443", controlplane["event_url_base"])
	agents := controlplane["agents"].(map[string]any)
	require.ElementsMatch(t, []string{"agent-online", "agent-offline"}, mapKeys(agents))
	for _, id := range []string{"agent-online", "agent-offline"} {
		assignment := agents[id].(map[string]any)
		require.Equal(t, "tenant-acceptance", assignment["tenant_id"])
		require.Equal(t, "project-acceptance", assignment["project_id"])
	}

	var agent map[string]any
	require.NoError(t, yaml.Unmarshal(mustRead(t, manifest.Files["agent_config"]), &agent))
	require.Equal(t, "agent-online", agent["agent_id"])
	require.Contains(t, agent["database_process_names"].([]any), "dbpilot-agent")

	var oidc struct {
		Issuer   string        `json:"issuer"`
		Audience string        `json:"audience"`
		TokenTTL time.Duration `json:"token_ttl"`
	}
	require.NoError(t, json.Unmarshal(mustRead(t, manifest.Files["oidc_config"]), &oidc))
	require.Equal(t, "https://oidc:9444", oidc.Issuer)
	require.Equal(t, "dbpilot-control-plane", oidc.Audience)
	require.Equal(t, 15*time.Minute, oidc.TokenTTL)
}

func TestGenerateBootstrapRejectsUnsafeOutputRoots(t *testing.T) {
	base := t.TempDir()
	existing := filepath.Join(base, "existing")
	require.NoError(t, os.Mkdir(existing, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(existing, "sentinel"), []byte("keep"), 0o600))
	rootVolume := filepath.VolumeName(base) + string(filepath.Separator)
	tests := map[string]string{
		"relative":        "relative-output",
		"filesystem root": rootVolume,
		"existing files":  existing,
	}
	for name, root := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := GenerateBootstrap(context.Background(), validBootstrapOptions(root))
			require.Error(t, err)
		})
	}
	require.Equal(t, []byte("keep"), mustRead(t, filepath.Join(existing, "sentinel")))
}

func TestGenerateBootstrapHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := filepath.Join(t.TempDir(), "cancelled")
	_, err := GenerateBootstrap(ctx, validBootstrapOptions(root))
	require.ErrorIs(t, err, context.Canceled)
	require.NoFileExists(t, filepath.Join(root, "manifest.json"))
}

func TestRunBootstrapPrintsOnlyNonSecretManifest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cli-bootstrap")
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := run([]string{
		"bootstrap", "--root", root, "--issuer", "https://oidc:9444", "--audience", "dbpilot-control-plane",
		"--tenant-id", "tenant-acceptance", "--project-id", "project-acceptance",
		"--online-agent-id", "agent-online", "--offline-agent-id", "agent-offline",
	}, stdout, stderr)
	require.Zero(t, code, stderr.String())
	require.Empty(t, stderr.String())
	var manifest BootstrapManifest
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &manifest))
	credential := strings.TrimSpace(string(mustRead(t, manifest.Files["token_credential"])))
	require.NotContains(t, stdout.String(), credential)
}

func TestRunRejectsUnknownAndIncompleteSubcommands(t *testing.T) {
	for name, args := range map[string][]string{
		"missing":                nil,
		"unknown":                {"unknown"},
		"OIDC relative config":   {"oidc", "--config", "relative.json"},
		"database missing files": {"database"},
		"journal missing files":  {"journal"},
	} {
		t.Run(name, func(t *testing.T) {
			code := run(args, io.Discard, io.Discard)
			require.Equal(t, 2, code)
		})
	}
}

func generateBootstrapForTest(t *testing.T) BootstrapManifest {
	t.Helper()
	root := filepath.Join(t.TempDir(), "acceptance")
	manifest, err := GenerateBootstrap(context.Background(), validBootstrapOptions(root))
	require.NoError(t, err)
	return manifest
}

func validBootstrapOptions(root string) BootstrapOptions {
	return BootstrapOptions{
		Root: root, Issuer: "https://oidc:9444", Audience: "dbpilot-control-plane",
		TenantID: "tenant-acceptance", ProjectID: "project-acceptance",
		OnlineAgentID: "agent-online", OfflineAgentID: "agent-offline",
		Now: time.Date(2026, 8, 29, 2, 3, 4, 0, time.UTC), Random: newDeterministicReader("bootstrap-acceptance"),
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	return contents
}

func mustCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(mustRead(t, path))
	require.NotNil(t, block)
	certificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return certificate
}

func mustPrivateKey(t *testing.T, path string) any {
	t.Helper()
	block, _ := pem.Decode(mustRead(t, path))
	require.NotNil(t, block)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key
}

func mustPublicKey(t *testing.T, path string) any {
	t.Helper()
	block, _ := pem.Decode(mustRead(t, path))
	require.NotNil(t, block)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	return key
}

func nestedString(t *testing.T, values map[string]any, keys ...string) string {
	t.Helper()
	current := values
	for _, key := range keys[:len(keys)-1] {
		current = current[key].(map[string]any)
	}
	return current[keys[len(keys)-1]].(string)
}

func mapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

type deterministicReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func newDeterministicReader(seed string) *deterministicReader {
	return &deterministicReader{seed: []byte(seed)}
}

func (reader *deterministicReader) Read(target []byte) (int, error) {
	total := len(target)
	for len(target) > 0 {
		if len(reader.buffer) == 0 {
			reader.counter++
			counter := make([]byte, 8)
			binary.BigEndian.PutUint64(counter, reader.counter)
			digest := sha256.Sum256(append(append([]byte(nil), reader.seed...), counter...))
			reader.buffer = append(reader.buffer[:0], digest[:]...)
		}
		copied := copy(target, reader.buffer)
		target = target[copied:]
		reader.buffer = reader.buffer[copied:]
	}
	return total, nil
}
