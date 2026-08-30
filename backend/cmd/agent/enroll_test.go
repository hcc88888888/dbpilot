package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/hostinventory"
	gopsutilnet "github.com/shirou/gopsutil/v4/net"
	"github.com/stretchr/testify/require"
)

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

func TestWriteEnrollmentFilesUsesCreateExclusive0600AndRejectsCollisions(t *testing.T) {
	material := enrollmentFiles{PrivateKeyPEM: []byte("private"), CertificatePEM: []byte("certificate"), ChainPEM: []byte("chain")}

	t.Run("success", func(t *testing.T) {
		directory := t.TempDir()
		require.NoError(t, writeEnrollmentFiles(directory, material))
		for name, want := range map[string][]byte{agentKeyFilename: material.PrivateKeyPEM, agentCertificateFilename: material.CertificatePEM, agentCAFilename: material.ChainPEM} {
			path := filepath.Join(directory, name)
			got, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, want, got)
			info, err := os.Lstat(path)
			require.NoError(t, err)
			require.True(t, info.Mode().IsRegular())
			require.Zero(t, info.Mode()&os.ModeSymlink)
			if runtime.GOOS == "linux" {
				require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
			}
		}
	})

	t.Run("existing path", func(t *testing.T) {
		directory := t.TempDir()
		keyPath := filepath.Join(directory, agentKeyFilename)
		require.NoError(t, os.WriteFile(keyPath, []byte("existing"), 0o600))
		err := writeEnrollmentFiles(directory, material)
		require.Error(t, err)
		contents, readErr := os.ReadFile(keyPath)
		require.NoError(t, readErr)
		require.Equal(t, []byte("existing"), contents)
		_, certificateErr := os.Lstat(filepath.Join(directory, agentCertificateFilename))
		require.ErrorIs(t, certificateErr, os.ErrNotExist)
		require.NotContains(t, err.Error(), string(material.PrivateKeyPEM))
	})

	t.Run("symlink path", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "outside")
		require.NoError(t, os.WriteFile(target, []byte("unchanged"), 0o600))
		collision := filepath.Join(directory, agentCertificateFilename)
		if err := os.Symlink(target, collision); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("symlink creation unavailable: %v", err)
			}
			require.NoError(t, err)
		}
		err := writeEnrollmentFiles(directory, material)
		require.Error(t, err)
		contents, readErr := os.ReadFile(target)
		require.NoError(t, readErr)
		require.Equal(t, []byte("unchanged"), contents)
		_, keyErr := os.Lstat(filepath.Join(directory, agentKeyFilename))
		require.ErrorIs(t, keyErr, os.ErrNotExist)
	})
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
