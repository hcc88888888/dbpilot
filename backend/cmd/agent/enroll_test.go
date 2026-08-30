package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/platformscope"
	gopsutilnet "github.com/shirou/gopsutil/v4/net"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPrepareEnrollmentGenerationPrecedesRPCAndResumesSameCSR(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "credentials")
	token := bytes.Repeat([]byte{0x41}, enrollment.EnrollmentTokenBytes)
	observation := validCLIHostObservation()

	first, err := prepareEnrollmentGeneration(output, "agent-1", token, observation, rand.Reader)
	require.NoError(t, err)
	require.NoFileExists(t, output)
	require.DirExists(t, first.stageDirectory)
	require.FileExists(t, filepath.Join(first.stageDirectory, agentKeyFilename))
	require.FileExists(t, filepath.Join(first.stageDirectory, enrollmentCSRFilename))
	firstCSR := append([]byte(nil), first.request.GetCertificateSigningRequestPem()...)

	second, err := prepareEnrollmentGeneration(output, "agent-1", token, observation, bytes.NewReader(bytes.Repeat([]byte{0x99}, 128)))
	require.NoError(t, err)
	require.Equal(t, first.stageDirectory, second.stageDirectory)
	require.Equal(t, firstCSR, second.request.GetCertificateSigningRequestPem(), "lost-response retry must reuse the proven CSR/private key")
	require.Equal(t, first.files.PrivateKeyPEM, second.files.PrivateKeyPEM)
	// The Server committed this response for the first request, but the first
	// transport response was lost. Replaying the exact CSR must still publish it.
	committedResponse, serverCA := testEnrollmentResponse(t, first.request)
	require.NoError(t, second.complete(committedResponse, serverCA))
	require.NoError(t, second.publish(serverCA))
	require.DirExists(t, output)
}

func TestEnrollmentGenerationCompletesManifestAndPublishesDirectoryAtomically(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "credentials")
	token := bytes.Repeat([]byte{0x42}, enrollment.EnrollmentTokenBytes)
	observation := validCLIHostObservation()
	generation, err := prepareEnrollmentGeneration(output, "agent-1", token, observation, rand.Reader)
	require.NoError(t, err)
	response, serverCA := testEnrollmentResponse(t, generation.request)

	require.NoError(t, generation.complete(response, serverCA))
	// Re-entry after a crash between complete-manifest fsync and directory rename
	// validates the existing generation instead of rewriting partial files.
	require.NoError(t, generation.complete(response, serverCA))
	require.NoError(t, generation.publish(serverCA))

	require.DirExists(t, output)
	require.NoDirExists(t, generation.stageDirectory)
	for _, name := range []string{agentKeyFilename, agentCertificateFilename, agentCAFilename, enrollmentCommitFilename} {
		require.FileExists(t, filepath.Join(output, name))
		info, statErr := os.Lstat(filepath.Join(output, name))
		require.NoError(t, statErr)
		require.True(t, info.Mode().IsRegular())
		require.Zero(t, info.Mode()&os.ModeSymlink)
		if runtime.GOOS == "linux" {
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		}
	}
	manifest, err := readEnrollmentGenerationManifest(filepath.Join(output, enrollmentCommitFilename))
	require.NoError(t, err)
	require.Equal(t, enrollmentGenerationFinalized, manifest.State)
	require.Equal(t, "agent-1", manifest.AgentID)
	entries, err := os.ReadDir(output)
	require.NoError(t, err)
	require.Len(t, entries, 4, "only the committed credential generation may become visible")
}

func TestPrepareEnrollmentGenerationResumesCompletedStageWithoutRegenerating(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "credentials")
	token := bytes.Repeat([]byte{0x43}, enrollment.EnrollmentTokenBytes)
	first, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), rand.Reader)
	require.NoError(t, err)
	response, serverCA := testEnrollmentResponse(t, first.request)
	require.NoError(t, first.complete(response, serverCA))

	resumed, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), failingEnrollmentReader{})
	require.NoError(t, err)
	require.True(t, resumed.readyToPublish())
	require.NoError(t, resumed.publish(serverCA))
	require.DirExists(t, output)
}

func TestPrepareEnrollmentGenerationRejectsSymlinkedParentAndStage(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Creating symlinks requires a Windows developer-mode or elevated process.
		// The same path validation is exercised on Linux CI and production targets.
		t.Skip("symlink creation is not reliably available on Windows")
	}
	token := bytes.Repeat([]byte{0x44}, enrollment.EnrollmentTokenBytes)

	t.Run("parent", func(t *testing.T) {
		root := t.TempDir()
		realParent := filepath.Join(root, "real")
		require.NoError(t, os.Mkdir(realParent, 0o700))
		linkedParent := filepath.Join(root, "linked")
		require.NoError(t, os.Symlink(realParent, linkedParent))
		_, err := prepareEnrollmentGeneration(filepath.Join(linkedParent, "credentials"), "agent-1", token, validCLIHostObservation(), rand.Reader)
		require.Error(t, err)
		require.Empty(t, mustReadDirectory(t, realParent))
	})

	t.Run("stage", func(t *testing.T) {
		root := t.TempDir()
		output := filepath.Join(root, "credentials")
		outside := filepath.Join(root, "outside")
		require.NoError(t, os.Mkdir(outside, 0o700))
		require.NoError(t, os.Symlink(outside, enrollmentStageDirectory(output)))
		_, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), rand.Reader)
		require.Error(t, err)
		require.Empty(t, mustReadDirectory(t, outside))
	})
}

func TestEnrollmentGenerationPublishRejectsOutputCollisionWithoutChangingIt(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "credentials")
	token := bytes.Repeat([]byte{0x45}, enrollment.EnrollmentTokenBytes)
	generation, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), rand.Reader)
	require.NoError(t, err)
	response, serverCA := testEnrollmentResponse(t, generation.request)
	require.NoError(t, generation.complete(response, serverCA))
	require.NoError(t, os.Mkdir(output, 0o700))
	sentinel := filepath.Join(output, "sentinel")
	require.NoError(t, os.WriteFile(sentinel, []byte("unchanged"), 0o600))

	err = generation.publish(serverCA)
	require.Error(t, err)
	contents, readErr := os.ReadFile(sentinel)
	require.NoError(t, readErr)
	require.Equal(t, []byte("unchanged"), contents)
	require.DirExists(t, generation.stageDirectory)
}

func TestEnrollmentGenerationPublishRejectsUnexpectedStageEntry(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "credentials")
	token := bytes.Repeat([]byte{0x46}, enrollment.EnrollmentTokenBytes)
	generation, err := prepareEnrollmentGeneration(output, "agent-1", token, validCLIHostObservation(), rand.Reader)
	require.NoError(t, err)
	response, serverCA := testEnrollmentResponse(t, generation.request)
	require.NoError(t, generation.complete(response, serverCA))
	require.NoError(t, os.WriteFile(filepath.Join(generation.stageDirectory, "unexpected"), []byte("do not publish"), 0o600))

	err = generation.publish(serverCA)
	require.Error(t, err)
	require.NoDirExists(t, output)
	require.FileExists(t, filepath.Join(generation.stageDirectory, "unexpected"))
}

func TestWriteFullRejectsSilentShortWrite(t *testing.T) {
	err := writeFull(shortEnrollmentWriter{}, []byte("credential material"))
	require.ErrorIs(t, err, io.ErrShortWrite)
}

func TestGenerateEnrollmentMaterialKeepsPrivateKeyLocalAndProvesEd25519CSR(t *testing.T) {
	token := bytes.Repeat([]byte{0x41}, enrollment.EnrollmentTokenBytes)
	observation := validCLIHostObservation()

	request, files, err := generateEnrollmentMaterial("agent-1", token, observation, rand.Reader)

	require.NoError(t, err)
	require.NotEmpty(t, files.PrivateKeyPEM)
	require.NotContains(t, string(request.GetCertificateSigningRequestPem()), "PRIVATE KEY")
	require.NotContains(t, string(request.GetCsrPublicKey()), "PRIVATE KEY")
	block, rest := pem.Decode(files.PrivateKeyPEM)
	require.NotNil(t, block)
	require.Empty(t, strings.TrimSpace(string(rest)))
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	privateKey, ok := parsed.(ed25519.PrivateKey)
	require.True(t, ok)
	message, err := enrollment.CSRProofMessage("agent-1", request.GetCertificateSigningRequestPem(), request.GetCsrPublicKey())
	require.NoError(t, err)
	require.True(t, ed25519.Verify(privateKey.Public().(ed25519.PublicKey), message, request.GetCsrProof()))
}

func TestRunRecognizesEnrollSubcommandBeforeConfigMode(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"enroll"}, &stdout, &stderr)

	require.Equal(t, 2, code)
	require.Contains(t, stderr.String(), "--server")
	require.NotContains(t, stderr.String(), "--config is required")
}

func TestEnrollmentNetworkAddressesStayUniqueSortedAndBounded(t *testing.T) {
	interfaces := make([]gopsutilnet.InterfaceStat, 40)
	for index := range interfaces {
		interfaces[index].Addrs = []gopsutilnet.InterfaceAddr{{Addr: fmt.Sprintf("10.0.0.%d/24", 40-index)}, {Addr: "127.0.0.1/8"}}
	}

	addresses := enrollmentNetworkAddresses(interfaces)

	require.Len(t, addresses, 32)
	require.True(t, sort.StringsAreSorted(addresses))
	require.Equal(t, 1, strings.Count(strings.Join(addresses, ","), "127.0.0.1"))
}

func validCLIHostObservation() hostinventory.Observation {
	return hostinventory.Observation{
		AgentID: "agent-1", Revision: 1, AgentVersion: "dev", Hostname: "db-1.example",
		OS: "kylin", OSVersion: "V10 SP1", Kernel: "5.10", Architecture: "amd64",
		LogicalCPUCount: 4, MemoryCapacityBytes: 8 << 30, NetworkAddresses: []string{"10.0.0.10"},
		Capabilities: []string{"host.inventory.v1"}, ObservedAt: time.Now().UTC(),
	}
}

type shortEnrollmentWriter struct{}

func (shortEnrollmentWriter) Write(value []byte) (int, error) { return len(value) - 1, nil }

type failingEnrollmentReader struct{}

func (failingEnrollmentReader) Read([]byte) (int, error) {
	return 0, errors.New("randomness must not be used")
}

func mustReadDirectory(t *testing.T, path string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(path)
	require.NoError(t, err)
	return entries
}

func testEnrollmentResponse(t *testing.T, request *agentv1.EnrollAgentRequest) (*agentv1.EnrollAgentResponse, []byte) {
	t.Helper()
	now := time.Now().UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DBPilot Agent CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, publicKey, privateKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	issuer, err := enrollment.NewAgentCertificateIssuer(caPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), time.Hour, func() time.Time { return now }, rand.Reader)
	require.NoError(t, err)
	certificate, chain, expiresAt, err := issuer.SignAgentCSR(context.Background(), enrollment.EnrollmentGrant{
		Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, HostID: "host-1", AgentID: "agent-1", DisplayName: "Host", Labels: map[string]string{}, EnrollmentRevision: 1,
	}, request.GetCertificateSigningRequestPem())
	require.NoError(t, err)
	return &agentv1.EnrollAgentResponse{
		HostId: "host-1", AgentId: "agent-1", CertificatePem: certificate, CertificateChainPem: chain,
		ExpiresAt: timestamppb.New(expiresAt), EnrollmentRevision: 1,
	}, caPEM
}
