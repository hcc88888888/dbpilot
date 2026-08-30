//go:build linux

package discovery

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const DefaultLegacyProcHelperSocket = "/run/dbpilot-agent/proc-helper.sock"

const (
	procHelperStatusOK       = uint16(0)
	procHelperStatusRejected = uint16(2)
)

var legacyMagic = [4]byte{'D', 'B', 'P', 'F'}

// RunLegacyProcHelper serves the bounded, path-free local proc protocol.
// Modern packaging runs it as dbpilot-proc with SYS_PTRACE; the CentOS 7
// profile runs it as root with SYS_PTRACE plus DAC_READ_SEARCH.
func RunLegacyProcHelper(ctx context.Context, allowedUID, allowedGID uint32, allowedProcessNames []string) error {
	if allowedUID == 0 || allowedGID == 0 {
		return errors.New("invalid legacy proc helper peer")
	}
	normalized, err := NormalizeProcHelperProcessNames(allowedProcessNames)
	if err != nil {
		return err
	}
	return serveLegacyProcHelperAt(ctx, DefaultLegacyProcHelperSocket, allowedUID, allowedGID, normalized)
}

func serveLegacyProcHelperAt(ctx context.Context, socketPath string, allowedUID, allowedGID uint32, allowedProcessNames []string) error {
	if ctx == nil || socketPath == "" {
		return errors.New("invalid legacy proc helper configuration")
	}
	normalized, err := NormalizeProcHelperProcessNames(allowedProcessNames)
	if err != nil {
		return err
	}
	allowed := make(map[string]struct{}, len(normalized))
	for _, name := range normalized {
		allowed[name] = struct{}{}
	}
	listener, activated, err := activatedLegacyListener()
	if err != nil {
		return err
	}
	if activated {
		defer listener.Close()
		return serveLegacyConnections(ctx, listener, allowedUID, allowedGID, allowed)
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return err
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("legacy proc helper socket path is unsafe")
		}
		if err := os.Remove(socketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	if err := os.Chown(socketPath, -1, int(allowedGID)); err != nil {
		return err
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		return err
	}
	return serveLegacyConnections(ctx, listener, allowedUID, allowedGID, allowed)
}

func serveLegacyConnections(ctx context.Context, listener *net.UnixListener, allowedUID, allowedGID uint32, allowed map[string]struct{}) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return acceptErr
		}
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		peerUID, peerGID := peerCredentials(connection)
		if peerUID == allowedUID && peerGID == allowedGID {
			_ = handleLegacyProcRequest(connection, allowed)
		}
		_ = connection.Close()
	}
}

func activatedLegacyListener() (*net.UnixListener, bool, error) {
	pid, pidErr := strconv.Atoi(os.Getenv("LISTEN_PID"))
	fds, fdsErr := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if fdsErr != nil || fds != 1 || (pidErr == nil && pid != os.Getpid()) || (pidErr != nil && os.Getenv("LISTEN_PID") != "") {
		return nil, false, nil
	}
	file := os.NewFile(3, "dbpilot-proc-helper.socket")
	if file == nil {
		return nil, false, errors.New("invalid activated legacy helper socket")
	}
	defer file.Close()
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, false, err
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return nil, false, errors.New("activated legacy helper listener is not AF_UNIX")
	}
	return unixListener, true, nil
}

func peerCredentials(connection *net.UnixConn) (uint32, uint32) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return ^uint32(0), ^uint32(0)
	}
	uid := ^uint32(0)
	gid := ^uint32(0)
	_ = raw.Control(func(fd uintptr) {
		credentials, credentialErr := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credentialErr == nil {
			uid = credentials.Uid
			gid = credentials.Gid
		}
	})
	return uid, gid
}

func handleLegacyProcRequest(connection io.ReadWriter, allowed map[string]struct{}) error {
	request := make([]byte, 16)
	if _, err := io.ReadFull(connection, request); err != nil {
		return err
	}
	operation := binary.BigEndian.Uint16(request[6:8])
	if string(request[:4]) != string(legacyMagic[:]) || binary.BigEndian.Uint16(request[4:6]) != 1 || (operation != 1 && operation != 2) {
		return errors.New("invalid legacy proc helper request")
	}
	pid := binary.BigEndian.Uint32(request[8:12])
	maximum := binary.BigEndian.Uint32(request[12:16])
	if pid == 0 || maximum == 0 || maximum > maximumFDEntries {
		return errors.New("invalid legacy proc helper bounds")
	}
	process, err := NewProcReader("/proc", nil).process(int(pid))
	if err != nil {
		return err
	}
	if !procHelperProcessAllowed(process, allowed) {
		return writeLegacyStatus(connection, procHelperStatusRejected)
	}
	if operation == 2 {
		return writeLegacyProcess(connection, process)
	}
	inodes, err := socketInodesFromDirectory(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "fd"))
	if err != nil {
		return err
	}
	if len(inodes) > int(maximum) {
		return ErrNativeDiscoveryDataTooLarge
	}
	response := make([]byte, 12+8*len(inodes))
	copy(response[:4], legacyMagic[:])
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint32(response[8:12], uint32(len(inodes)))
	offset := 12
	for raw := range inodes {
		inode, parseErr := strconv.ParseUint(raw, 10, 64)
		if parseErr != nil {
			return parseErr
		}
		binary.BigEndian.PutUint64(response[offset:offset+8], inode)
		offset += 8
	}
	_, err = connection.Write(response)
	return err
}

func procHelperProcessAllowed(process ProcessObservation, allowed map[string]struct{}) bool {
	_, byExecutable := allowed[filepath.Base(strings.TrimSuffix(process.Executable, " (deleted)"))]
	_, byName := allowed[process.Name]
	return byExecutable || byName
}

func writeLegacyStatus(writer io.Writer, status uint16) error {
	response := make([]byte, 8)
	copy(response[:4], legacyMagic[:])
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], status)
	_, err := writer.Write(response)
	return err
}

func writeLegacyProcess(writer io.Writer, process ProcessObservation) error {
	values := []string{process.Executable, process.Name, process.RequestedSocket, process.Cgroup}
	total := 32
	for _, value := range values {
		if len(value) > 65535 {
			return ErrNativeDiscoveryDataTooLarge
		}
		total += len(value)
	}
	response := make([]byte, total)
	copy(response[:4], legacyMagic[:])
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint64(response[8:16], process.StartTime)
	binary.BigEndian.PutUint32(response[16:20], process.UID)
	binary.BigEndian.PutUint16(response[20:22], process.RequestedPort)
	offset := 24
	for index, value := range values {
		binary.BigEndian.PutUint16(response[offset+index*2:offset+index*2+2], uint16(len(value)))
	}
	offset = 32
	for _, value := range values {
		copy(response[offset:], value)
		offset += len(value)
	}
	_, err := writer.Write(response)
	return err
}

func requestLegacyProcess(pid int) (ProcessObservation, error) {
	return requestLegacyProcessAt(DefaultLegacyProcHelperSocket, pid)
}

func requestLegacyProcessAt(socketPath string, pid int) (ProcessObservation, error) {
	connection, err := dialLegacyHelperAt(socketPath, pid, maximumFDEntries, 2)
	if err != nil {
		return ProcessObservation{}, err
	}
	defer connection.Close()
	header := make([]byte, 32)
	if _, err := io.ReadFull(connection, header[:8]); err != nil || string(header[:4]) != string(legacyMagic[:]) || binary.BigEndian.Uint16(header[4:6]) != 1 {
		return ProcessObservation{}, fmt.Errorf("%w: legacy_proc_helper_unavailable", ErrNativeDiscoveryPermissionDenied)
	}
	if binary.BigEndian.Uint16(header[6:8]) == procHelperStatusRejected {
		return ProcessObservation{}, os.ErrNotExist
	}
	if binary.BigEndian.Uint16(header[6:8]) != procHelperStatusOK {
		return ProcessObservation{}, fmt.Errorf("%w: legacy_proc_helper_unavailable", ErrNativeDiscoveryPermissionDenied)
	}
	if _, err := io.ReadFull(connection, header[8:]); err != nil {
		return ProcessObservation{}, fmt.Errorf("%w: legacy_proc_helper_unavailable", ErrNativeDiscoveryPermissionDenied)
	}
	lengths := [4]uint16{}
	total := 0
	for index := range lengths {
		lengths[index] = binary.BigEndian.Uint16(header[24+index*2 : 26+index*2])
		total += int(lengths[index])
	}
	if total > maximumCmdlineBytes+maximumCgroupBytes+maximumExecutableBytes+maximumCommBytes {
		return ProcessObservation{}, ErrNativeDiscoveryDataTooLarge
	}
	encoded := make([]byte, total)
	if _, err := io.ReadFull(connection, encoded); err != nil {
		return ProcessObservation{}, fmt.Errorf("%w: legacy_proc_helper_unavailable", ErrNativeDiscoveryPermissionDenied)
	}
	values := [4]string{}
	offset := 0
	for index, length := range lengths {
		values[index] = string(encoded[offset : offset+int(length)])
		offset += int(length)
	}
	return ProcessObservation{PID: pid, StartTime: binary.BigEndian.Uint64(header[8:16]), UID: binary.BigEndian.Uint32(header[16:20]), RequestedPort: binary.BigEndian.Uint16(header[20:22]), Executable: values[0], Name: values[1], RequestedSocket: values[2], Cgroup: values[3]}, nil
}

func requestLegacySocketInodes(pid, maximum int) (map[string]struct{}, error) {
	return requestLegacySocketInodesAt(DefaultLegacyProcHelperSocket, pid, maximum)
}

func requestLegacySocketInodesAt(socketPath string, pid, maximum int) (map[string]struct{}, error) {
	if pid <= 0 || maximum <= 0 || maximum > maximumFDEntries {
		return nil, errors.New("invalid legacy proc helper request")
	}
	connection, err := dialLegacyHelperAt(socketPath, pid, maximum, 1)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	header := make([]byte, 12)
	if _, err := io.ReadFull(connection, header[:8]); err != nil || string(header[:4]) != string(legacyMagic[:]) || binary.BigEndian.Uint16(header[4:6]) != 1 {
		return nil, fmt.Errorf("%w: legacy_proc_helper_unavailable", ErrNativeDiscoveryPermissionDenied)
	}
	if binary.BigEndian.Uint16(header[6:8]) == procHelperStatusRejected {
		return nil, os.ErrNotExist
	}
	if binary.BigEndian.Uint16(header[6:8]) != procHelperStatusOK {
		return nil, fmt.Errorf("%w: legacy_proc_helper_unavailable", ErrNativeDiscoveryPermissionDenied)
	}
	if _, err := io.ReadFull(connection, header[8:]); err != nil {
		return nil, fmt.Errorf("%w: legacy_proc_helper_unavailable", ErrNativeDiscoveryPermissionDenied)
	}
	count := binary.BigEndian.Uint32(header[8:12])
	if count > uint32(maximum) {
		return nil, ErrNativeDiscoveryDataTooLarge
	}
	encoded := make([]byte, int(count)*8)
	if _, err := io.ReadFull(connection, encoded); err != nil {
		return nil, fmt.Errorf("%w: legacy_proc_helper_unavailable", ErrNativeDiscoveryPermissionDenied)
	}
	result := make(map[string]struct{}, count)
	for offset := 0; offset < len(encoded); offset += 8 {
		result[strconv.FormatUint(binary.BigEndian.Uint64(encoded[offset:offset+8]), 10)] = struct{}{}
	}
	return result, nil
}

func dialLegacyHelper(pid, maximum int, operation uint16) (net.Conn, error) {
	return dialLegacyHelperAt(DefaultLegacyProcHelperSocket, pid, maximum, operation)
}
func dialLegacyHelperAt(socketPath string, pid, maximum int, operation uint16) (net.Conn, error) {
	connection, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w: legacy_proc_helper_unavailable", ErrNativeDiscoveryPermissionDenied)
	}
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	request := make([]byte, 16)
	copy(request[:4], legacyMagic[:])
	binary.BigEndian.PutUint16(request[4:6], 1)
	binary.BigEndian.PutUint16(request[6:8], operation)
	binary.BigEndian.PutUint32(request[8:12], uint32(pid))
	binary.BigEndian.PutUint32(request[12:16], uint32(maximum))
	if _, err := connection.Write(request); err != nil {
		_ = connection.Close()
		return nil, fmt.Errorf("%w: legacy_proc_helper_unavailable", ErrNativeDiscoveryPermissionDenied)
	}
	return connection, nil
}
