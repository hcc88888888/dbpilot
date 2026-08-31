//go:build linux

package pluginsupervisor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GRPCHealthCheckerConfig struct {
	Timeout time.Duration
}

type GRPCHealthChecker struct{ timeout time.Duration }

func NewGRPCHealthChecker(config GRPCHealthCheckerConfig) *GRPCHealthChecker {
	if config.Timeout <= 0 || config.Timeout > time.Minute {
		config.Timeout = 10 * time.Second
	}
	return &GRPCHealthChecker{timeout: config.Timeout}
}

func (checker *GRPCHealthChecker) Handshake(ctx context.Context, process Process, request HealthRequest) error {
	if checker == nil || ctx == nil || ctx.Err() != nil || !resourceIdentifier.MatchString(request.AssignmentID) || !familyIdentifier.MatchString(request.PluginID) || !familyIdentifier.MatchString(request.DatabaseFamily) || !boundedVersion(request.Version) || request.ProtocolVersion != "v1" || len(request.ExecutableSHA256) != sha256.Size || len(request.LaunchNonce) != sha256.Size || request.ConfigurationRevision == 0 || request.OperationRevision == 0 || !uniqueResources(request.InstanceIDs) || !filepath.IsAbs(request.RuntimeDirectory) || filepath.Clean(request.RuntimeDirectory) != request.RuntimeDirectory || !filepath.IsAbs(request.ExecutablePath) || request.ExpectedUserID == 0 || request.ExpectedGroupID == 0 {
		return ErrHealthHandshake
	}
	if process == nil || process.PID() <= 0 || verifyProcessExecutable(process.PID(), request.ExecutablePath, request.ExecutableSHA256) != nil {
		return ErrHealthHandshake
	}
	socket := filepath.Join(request.RuntimeDirectory, "plugin.sock")
	handshakeContext, cancel := context.WithTimeout(ctx, checker.timeout)
	defer cancel()
	if err := waitForPrivatePluginSocket(handshakeContext, socket); err != nil {
		return ErrHealthHandshake
	}
	connection, err := grpc.DialContext(handshakeContext, "unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(dialContext context.Context, _ string) (net.Conn, error) {
		connection, dialErr := (&net.Dialer{}).DialContext(dialContext, "unix", socket)
		if dialErr != nil {
			return nil, dialErr
		}
		unixConnection, ok := connection.(*net.UnixConn)
		if !ok {
			_ = connection.Close()
			return nil, ErrHealthHandshake
		}
		raw, controlErr := unixConnection.SyscallConn()
		if controlErr != nil {
			_ = connection.Close()
			return nil, controlErr
		}
		var credential *unix.Ucred
		var credentialErr error
		if controlErr = raw.Control(func(fd uintptr) {
			credential, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		}); controlErr != nil || credentialErr != nil || credential == nil || int(credential.Pid) != process.PID() || credential.Uid != request.ExpectedUserID || credential.Gid != request.ExpectedGroupID {
			_ = connection.Close()
			return nil, ErrHealthHandshake
		}
		return connection, nil
	}), grpc.WithBlock())
	if err != nil {
		return ErrHealthHandshake
	}
	defer connection.Close()
	client := pluginv1.NewPluginRuntimeClient(connection)
	challenge := make([]byte, sha256.Size)
	if _, err := rand.Read(challenge); err != nil {
		return ErrHealthHandshake
	}
	response, err := client.Handshake(handshakeContext, &pluginv1.PluginHandshakeRequest{ExpectedPluginId: request.PluginID, ExpectedDatabaseFamily: request.DatabaseFamily, ExpectedVersion: request.Version, ExpectedProtocolVersion: request.ProtocolVersion, LaunchNonceChallenge: challenge})
	expectedProof := LaunchProof(request.LaunchNonce, challenge, request.AssignmentID, request.Version, request.ConfigurationRevision, request.OperationRevision, request.InstanceIDs)
	if err != nil || response.GetPluginId() != request.PluginID || response.GetDatabaseFamily() != request.DatabaseFamily || response.GetVersion() != request.Version || response.GetProtocolVersion() != request.ProtocolVersion || !bytes.Equal(response.GetExecutableDigest(), request.ExecutableSHA256) || len(expectedProof) == 0 || len(response.GetLaunchNonceProof()) != len(expectedProof) || subtle.ConstantTimeCompare(response.GetLaunchNonceProof(), expectedProof) != 1 {
		return ErrHealthHandshake
	}
	health, err := client.GetHealth(handshakeContext, &pluginv1.GetPluginHealthRequest{AssignmentId: request.AssignmentID})
	if err != nil || health.GetAssignmentId() != request.AssignmentID || health.GetState() != pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY || health.GetActiveConfigurationRevision() != request.ConfigurationRevision || int(health.GetBoundInstanceCount()) != len(request.InstanceIDs) || len(health.GetInstances()) != len(request.InstanceIDs) || health.GetObservedAt() == nil || !health.GetObservedAt().IsValid() {
		return ErrHealthHandshake
	}
	want := append([]string(nil), request.InstanceIDs...)
	got := make([]string, 0, len(health.GetInstances()))
	for _, instance := range health.GetInstances() {
		if instance == nil || instance.GetState() != pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY || instance.GetErrorCode() != "" {
			return ErrHealthHandshake
		}
		got = append(got, instance.GetInstanceId())
	}
	sort.Strings(want)
	sort.Strings(got)
	if !equalStrings(want, got) {
		return ErrHealthHandshake
	}
	return nil
}

func verifyProcessExecutable(pid int, expectedPath string, expectedDigest []byte) error {
	actualPath, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return err
	}
	actualInfo, err := os.Stat(actualPath)
	if err != nil {
		return err
	}
	expectedInfo, err := os.Stat(expectedPath)
	if err != nil || !os.SameFile(actualInfo, expectedInfo) {
		return ErrHealthHandshake
	}
	file, err := os.Open(actualPath)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != hex.EncodeToString(expectedDigest) {
		return ErrHealthHandshake
	}
	return nil
}

func waitForPrivatePluginSocket(ctx context.Context, socket string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := os.Lstat(socket)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 {
				return ErrHealthHandshake
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return ErrHealthHandshake
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

var _ HealthChecker = (*GRPCHealthChecker)(nil)
