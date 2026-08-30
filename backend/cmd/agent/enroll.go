package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/hostinventory"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	gopsutilnet "github.com/shirou/gopsutil/v4/net"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	agentKeyFilename         = "agent.key"
	agentCertificateFilename = "agent.crt"
	agentCAFilename          = "ca.crt"
)

type enrollmentFiles struct {
	PrivateKeyPEM  []byte
	CertificatePEM []byte
	ChainPEM       []byte
}

func runEnroll(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dbpilot-agent enroll", flag.ContinueOnError)
	flags.SetOutput(stderr)
	serverAddress := flags.String("server", "", "enrollment server host:port")
	caFile := flags.String("ca-file", "", "absolute server CA file")
	tokenFile := flags.String("token-file", "", "absolute one-time enrollment token file")
	agentID := flags.String("agent-id", "", "Agent identity")
	outputDirectory := flags.String("output-dir", "", "absolute output directory")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if strings.TrimSpace(*serverAddress) == "" || strings.TrimSpace(*agentID) == "" || !filepath.IsAbs(*caFile) || !filepath.IsAbs(*tokenFile) || !filepath.IsAbs(*outputDirectory) {
		fmt.Fprintln(stderr, "--server, --ca-file <abs>, --token-file <abs>, --agent-id, and --output-dir <abs> are required")
		return 2
	}
	for _, path := range []string{*caFile, *tokenFile} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			fmt.Fprintln(stderr, "enrollment input is unavailable")
			return 2
		}
	}
	outputInfo, err := os.Lstat(*outputDirectory)
	if err != nil || !outputInfo.IsDir() || outputInfo.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintln(stderr, "--output-dir must be an existing non-symlink directory")
		return 2
	}
	encodedToken, err := readBoundedFile(*tokenFile, 128)
	if err != nil {
		fmt.Fprintln(stderr, "read enrollment token failed")
		return 1
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encodedToken)))
	zeroBytes(encodedToken)
	if err != nil || len(token) != enrollment.EnrollmentTokenBytes {
		zeroBytes(token)
		fmt.Fprintln(stderr, "enrollment token is invalid")
		return 2
	}
	defer zeroBytes(token)
	serverCA, err := readBoundedFile(*caFile, 1<<20)
	if err != nil {
		fmt.Fprintln(stderr, "read enrollment CA failed")
		return 1
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(serverCA) {
		fmt.Fprintln(stderr, "enrollment CA contains no certificates")
		return 2
	}
	observation, err := collectEnrollmentObservation(context.Background(), *agentID)
	if err != nil {
		fmt.Fprintln(stderr, "collect host observation failed")
		return 1
	}
	request, material, err := generateEnrollmentMaterial(*agentID, token, observation, rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "generate enrollment CSR failed")
		return 1
	}
	defer zeroBytes(material.PrivateKeyPEM)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(ctx, *serverAddress, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})), grpc.WithBlock())
	if err != nil {
		fmt.Fprintln(stderr, "connect enrollment server failed")
		return 1
	}
	defer connection.Close()
	response, err := agentv1.NewAgentEnrollmentClient(connection).Enroll(ctx, request)
	if err != nil {
		fmt.Fprintln(stderr, "Agent enrollment failed")
		return 1
	}
	if err := verifyEnrollmentResponse(*agentID, material.PrivateKeyPEM, response); err != nil {
		fmt.Fprintln(stderr, "Agent enrollment response is invalid")
		return 1
	}
	material.CertificatePEM = append(append([]byte(nil), response.GetCertificatePem()...), response.GetCertificateChainPem()...)
	material.ChainPEM = append([]byte(nil), serverCA...)
	if err := writeEnrollmentFiles(*outputDirectory, material); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "enrolled Agent %s as host %s\n", response.GetAgentId(), response.GetHostId())
	return 0
}

func generateEnrollmentMaterial(agentID string, token []byte, observation hostinventory.Observation, random io.Reader) (*agentv1.EnrollAgentRequest, enrollmentFiles, error) {
	probe := observation
	if probe.HostID == "" {
		probe.HostID = "enrollment-host"
	}
	if len(token) != enrollment.EnrollmentTokenBytes || observation.AgentID != agentID || probe.Validate() != nil || random == nil {
		return nil, enrollmentFiles{}, enrollment.ErrEnrollmentRequestInvalid
	}
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, enrollmentFiles{}, errors.New("generate Ed25519 enrollment key")
	}
	csrDER, err := x509.CreateCertificateRequest(random, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		return nil, enrollmentFiles{}, errors.New("generate enrollment CSR")
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, enrollmentFiles{}, errors.New("encode enrollment public key")
	}
	proofMessage, err := enrollment.CSRProofMessage(agentID, csrPEM, publicDER)
	if err != nil {
		return nil, enrollmentFiles{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, enrollmentFiles{}, errors.New("encode enrollment private key")
	}
	filesystems := make([]*agentv1.FilesystemObservation, len(observation.Filesystems))
	for index, filesystem := range observation.Filesystems {
		filesystems[index] = &agentv1.FilesystemObservation{MountPoint: filesystem.MountPoint, CapacityBytes: filesystem.CapacityBytes, AvailableBytes: filesystem.AvailableBytes}
	}
	request := &agentv1.EnrollAgentRequest{
		EnrollmentToken: append([]byte(nil), token...), AgentId: agentID, CertificateSigningRequestPem: csrPEM,
		CsrPublicKey: publicDER, CsrProof: ed25519.Sign(privateKey, proofMessage),
		HostObservation: &agentv1.HostObservation{
			HostId: observation.HostID, AgentId: agentID, ObservationRevision: observation.Revision,
			Hostname: observation.Hostname, OperatingSystem: observation.OS, OperatingSystemVersion: observation.OSVersion,
			KernelVersion: observation.Kernel, Architecture: observation.Architecture, LogicalCpuCount: observation.LogicalCPUCount,
			MemoryCapacityBytes: observation.MemoryCapacityBytes, Filesystems: filesystems,
			NetworkAddresses: append([]string(nil), observation.NetworkAddresses...), Capabilities: append([]string(nil), observation.Capabilities...),
			AgentVersion: observation.AgentVersion, ObservedAt: timestamppb.New(observation.ObservedAt),
		},
	}
	return request, enrollmentFiles{PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})}, nil
}

func writeEnrollmentFiles(directory string, material enrollmentFiles) error {
	if !filepath.IsAbs(directory) || len(material.PrivateKeyPEM) == 0 || len(material.CertificatePEM) == 0 || len(material.ChainPEM) == 0 {
		return errors.New("enrollment output is invalid")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("enrollment output directory is unavailable")
	}
	outputs := []struct {
		name string
		body []byte
	}{
		{name: agentKeyFilename, body: material.PrivateKeyPEM},
		{name: agentCertificateFilename, body: material.CertificatePEM},
		{name: agentCAFilename, body: material.ChainPEM},
	}
	for _, output := range outputs {
		if _, err := os.Lstat(filepath.Join(directory, output.name)); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("enrollment output path already exists: %s", output.name)
		}
	}
	type stagedFile struct{ temporary, final string }
	staged := make([]stagedFile, 0, len(outputs))
	cleanupStaged := func() {
		for _, file := range staged {
			_ = os.Remove(file.temporary)
		}
	}
	defer cleanupStaged()
	for _, output := range outputs {
		file, err := os.CreateTemp(directory, ".dbpilot-enroll-")
		if err != nil {
			return errors.New("stage enrollment output failed")
		}
		temporary := file.Name()
		if err := file.Chmod(0o600); err == nil {
			_, err = file.Write(output.body)
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		staged = append(staged, stagedFile{temporary: temporary, final: filepath.Join(directory, output.name)})
		if err != nil {
			return errors.New("stage enrollment output failed")
		}
	}
	created := make([]string, 0, len(staged))
	for _, file := range staged {
		if err := os.Link(file.temporary, file.final); err != nil {
			for _, path := range created {
				_ = os.Remove(path)
			}
			return errors.New("commit enrollment output failed because a path collided or atomic linking is unavailable")
		}
		created = append(created, file.final)
	}
	return nil
}

func verifyEnrollmentResponse(agentID string, privateKeyPEM []byte, response *agentv1.EnrollAgentResponse) error {
	if response == nil || response.GetAgentId() != agentID || response.GetHostId() == "" || response.GetEnrollmentRevision() == 0 ||
		response.GetExpiresAt() == nil || response.GetExpiresAt().CheckValid() != nil {
		return errors.New("invalid enrollment response identity")
	}
	keyPair, err := tls.X509KeyPair(response.GetCertificatePem(), privateKeyPEM)
	if err != nil || len(keyPair.Certificate) == 0 {
		return errors.New("enrollment certificate does not match the local key")
	}
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil || len(leaf.URIs) != 1 {
		return errors.New("invalid enrollment certificate")
	}
	want := (&url.URL{Scheme: "spiffe", Host: "dbpilot.local", Path: "/agent/" + agentID}).String()
	if leaf.URIs[0].String() != want {
		return errors.New("enrollment certificate identity mismatch")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(response.GetCertificateChainPem()) {
		return errors.New("enrollment certificate chain is invalid")
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now()})
	return err
}

func collectEnrollmentObservation(ctx context.Context, agentID string) (hostinventory.Observation, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return hostinventory.Observation{}, err
	}
	info, err := host.InfoWithContext(ctx)
	if err != nil {
		return hostinventory.Observation{}, err
	}
	logicalCPUs, err := cpu.CountsWithContext(ctx, true)
	if err != nil || logicalCPUs < 1 {
		return hostinventory.Observation{}, errors.New("logical CPU inventory is unavailable")
	}
	memory, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil || memory.Total == 0 {
		return hostinventory.Observation{}, errors.New("memory inventory is unavailable")
	}
	partitions, _ := disk.PartitionsWithContext(ctx, false)
	filesystems := make([]hostinventory.FilesystemSummary, 0, len(partitions))
	seenMounts := make(map[string]struct{})
	for _, partition := range partitions {
		if partition.Mountpoint == "" {
			continue
		}
		if _, exists := seenMounts[partition.Mountpoint]; exists {
			continue
		}
		usage, usageErr := disk.UsageWithContext(ctx, partition.Mountpoint)
		if usageErr != nil {
			continue
		}
		seenMounts[partition.Mountpoint] = struct{}{}
		filesystems = append(filesystems, hostinventory.FilesystemSummary{MountPoint: partition.Mountpoint, CapacityBytes: usage.Total, AvailableBytes: usage.Free})
		if len(filesystems) == 128 {
			break
		}
	}
	interfaces, _ := gopsutilnet.InterfacesWithContext(ctx)
	addresses := enrollmentNetworkAddresses(interfaces)
	observation := hostinventory.Observation{
		AgentID: agentID, Revision: 1, AgentVersion: version, Hostname: hostname,
		OS: info.Platform, OSVersion: info.PlatformVersion, Kernel: info.KernelVersion, Architecture: runtime.GOARCH,
		LogicalCPUCount: uint32(logicalCPUs), MemoryCapacityBytes: memory.Total, Filesystems: filesystems,
		NetworkAddresses: addresses, Capabilities: []string{"host.inventory.v1"}, ObservedAt: time.Now().UTC(),
	}
	probe := observation
	probe.HostID = "enrollment-host"
	if probe.Validate() != nil {
		return hostinventory.Observation{}, errors.New("host observation is invalid")
	}
	return observation, nil
}

func enrollmentNetworkAddresses(interfaces []gopsutilnet.InterfaceStat) []string {
	addresses := make([]string, 0, 32)
	seenAddresses := make(map[string]struct{})
	maximumReached := false
	for _, networkInterface := range interfaces {
		for _, address := range networkInterface.Addrs {
			value := strings.Split(address.Addr, "/")[0]
			if value == "" {
				continue
			}
			if _, exists := seenAddresses[value]; exists {
				continue
			}
			seenAddresses[value] = struct{}{}
			addresses = append(addresses, value)
			if len(addresses) == 32 {
				maximumReached = true
				break
			}
		}
		if maximumReached {
			break
		}
	}
	sort.Strings(addresses)
	return addresses
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maximum+1))
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
