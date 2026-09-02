package plugincatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"debug/elf"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNodeAcceptancePackageIsAcceptedByProductionVerifier(t *testing.T) {
	node, err := exec.LookPath("node")
	require.NoError(t, err)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	require.NoError(t, err)
	directory := t.TempDir()
	binaryPath := filepath.Join(directory, "dbpilot-plugin-mysql")
	keyPath := filepath.Join(directory, "publisher.pem")
	archivePath := filepath.Join(directory, "plugin.tar.gz")
	require.NoError(t, os.WriteFile(binaryPath, independentStaticELF(elf.EM_X86_64), 0o500))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600))
	script, err := filepath.Abs(filepath.Join("..", "..", "test", "e2e", "host-plugin-full-stack", "plugin-package.mjs"))
	require.NoError(t, err)
	command := exec.Command(node, script, binaryPath, keyPath, "1.0.0", archivePath, "amd64")
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
	archive, err := os.ReadFile(archivePath)
	require.NoError(t, err)
	verifier, err := NewStreamingPackageVerifier(PackageVerifierConfig{Publishers: testPublisherStore{"acceptance-publisher\x00acceptance-key": public}, TemporaryDirectory: t.TempDir(), Limits: testPackageLimits()})
	require.NoError(t, err)
	archiveFile, err := os.Open(archivePath)
	require.NoError(t, err)
	manifestBytes, signature, entries, err := verifier.inspectArchive(context.Background(), archiveFile)
	require.NoError(t, archiveFile.Close())
	require.NoError(t, err, "archive framing")
	var generic any
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.UseNumber()
	require.NoError(t, decoder.Decode(&generic))
	canonical, err := json.Marshal(generic)
	require.NoError(t, err)
	require.Equal(t, string(canonical), string(manifestBytes), "canonical manifest bytes")
	var manifest Manifest
	strict := json.NewDecoder(bytes.NewReader(manifestBytes))
	strict.DisallowUnknownFields()
	require.NoError(t, strict.Decode(&manifest), "strict manifest")
	require.NoError(t, validateManifest(manifest, entries, testPackageLimits()), "manifest entries")
	require.Len(t, signature, ed25519.SignatureSize)
	verified, err := verifier.Verify(context.Background(), bytes.NewReader(archive), int64(len(archive)))
	require.NoError(t, err)
	require.NoError(t, verified.Close())
}
