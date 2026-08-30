//go:build linux

package discovery

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	domain "dbpilot.local/platform/internal/discovery"
	"golang.org/x/sys/unix"
)

const (
	maximumCommBytes         = 4 << 10
	maximumCmdlineBytes      = 64 << 10
	maximumStatusBytes       = 64 << 10
	maximumStatBytes         = 8 << 10
	maximumCgroupBytes       = 64 << 10
	maximumExecutableBytes   = 4 << 10
	maximumNetworkTableBytes = 16 << 20
	maximumProcEntries       = 1 << 16
	maximumFDEntries         = 1 << 12
)

var (
	ErrNativeDiscoveryPermissionDenied = errors.New("native discovery unavailable: permission_denied")
	ErrNativeDiscoveryDataTooLarge     = errors.New("native discovery proc data exceeds configured bound")
	errProcessSnapshotChanged          = errors.New("process snapshot changed")
	pidfdOpen                          = unix.PidfdOpen
	pidfdGetfd                         = unix.PidfdGetfd
	legacySocketInodeReader            = requestLegacySocketInodes
)

type ProcessObservation struct {
	PID             int
	Name            string
	Executable      string
	RequestedPort   uint16
	RequestedSocket string
	UID             uint32
	StartTime       uint64
	Cgroup          string
}

type EndpointObservation struct {
	Network string
	Address string
}

type NativeReader interface {
	Processes(context.Context) ([]ProcessObservation, error)
	ListeningEndpoints(context.Context, int) ([]EndpointObservation, error)
	SystemdUnit(context.Context, int) (string, bool, error)
}

type SystemdFacts interface {
	UnitForPID(context.Context, int) (string, bool, error)
}

type ProcReader struct {
	root              string
	systemd           SystemdFacts
	readFile          func(string, int64) ([]byte, error)
	readLink          func(string, int) (string, error)
	readDir           func(string, int) ([]os.DirEntry, error)
	forceLegacyHelper bool
}

// NewLegacyProcReader selects the fixed-protocol local helper used on kernels
// without pidfd support. The helper socket path is fixed and not configurable.
func NewLegacyProcReader(root string, systemd SystemdFacts) *ProcReader {
	reader := NewProcReader(root, systemd)
	reader.forceLegacyHelper = true
	return reader
}

func NewProcReader(root string, systemd SystemdFacts) *ProcReader {
	if root == "" {
		root = "/proc"
	}
	return &ProcReader{
		root: filepath.Clean(root), systemd: systemd,
		readFile: readBoundedFile, readLink: readLinkBounded, readDir: readDirectoryBounded,
	}
}

func (reader *ProcReader) Processes(ctx context.Context) ([]ProcessObservation, error) {
	entries, err := reader.readDir(reader.root, maximumProcEntries)
	if err != nil {
		return nil, err
	}
	processes := make([]ProcessObservation, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		var process ProcessObservation
		if reader.forceLegacyHelper {
			process, err = requestLegacyProcess(pid)
		} else {
			process, err = reader.process(pid)
		}
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, errProcessSnapshotChanged) {
			continue
		}
		if isPermission(err) {
			return nil, fmt.Errorf("%w: inspect pid %d", ErrNativeDiscoveryPermissionDenied, pid)
		}
		if err != nil {
			return nil, err
		}
		processes = append(processes, process)
	}
	sort.Slice(processes, func(left, right int) bool { return processes[left].PID < processes[right].PID })
	return processes, nil
}

func (reader *ProcReader) process(pid int) (ProcessObservation, error) {
	base := filepath.Join(reader.root, strconv.Itoa(pid))
	initialStat, err := reader.readFile(filepath.Join(base, "stat"), maximumStatBytes)
	if err != nil {
		return ProcessObservation{}, err
	}
	initialStartTime := parseStartTime(string(initialStat))
	if initialStartTime == 0 {
		return ProcessObservation{}, errProcessSnapshotChanged
	}
	executable, err := reader.readLink(filepath.Join(base, "exe"), maximumExecutableBytes)
	if err != nil {
		return ProcessObservation{}, err
	}
	if !filepath.IsAbs(executable) || strings.ContainsAny(executable, "\x00\r\n") {
		return ProcessObservation{}, errProcessSnapshotChanged
	}
	comm, err := reader.readFile(filepath.Join(base, "comm"), maximumCommBytes)
	if err != nil {
		return ProcessObservation{}, err
	}
	cmdline, err := reader.readFile(filepath.Join(base, "cmdline"), maximumCmdlineBytes)
	if err != nil {
		return ProcessObservation{}, err
	}
	status, err := reader.readFile(filepath.Join(base, "status"), maximumStatusBytes)
	if err != nil {
		return ProcessObservation{}, err
	}
	cgroup, err := reader.readFile(filepath.Join(base, "cgroup"), maximumCgroupBytes)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ProcessObservation{}, err
	}
	finalStat, err := reader.readFile(filepath.Join(base, "stat"), maximumStatBytes)
	if err != nil {
		return ProcessObservation{}, err
	}
	finalStartTime := parseStartTime(string(finalStat))
	if finalStartTime == 0 || finalStartTime != initialStartTime {
		return ProcessObservation{}, errProcessSnapshotChanged
	}
	requestedPort, requestedSocket := parseAllowedArguments(cmdline)
	uid := parseUID(string(status))
	return ProcessObservation{PID: pid, Name: bounded(strings.TrimSpace(string(comm)), domain.MaximumEvidenceBytes), Executable: executable, RequestedPort: requestedPort, RequestedSocket: requestedSocket, UID: uid, StartTime: initialStartTime, Cgroup: strings.TrimSpace(string(cgroup))}, nil
}

func (reader *ProcReader) ListeningEndpoints(ctx context.Context, pid int) ([]EndpointObservation, error) {
	var inodes map[string]struct{}
	var err error
	if reader.forceLegacyHelper {
		inodes, err = legacySocketInodeReader(pid, maximumFDEntries)
	} else {
		inodes, err = socketInodes(pid, filepath.Join(reader.root, strconv.Itoa(pid), "fd"))
	}
	if err != nil {
		return nil, err
	}
	endpoints := make([]EndpointObservation, 0)
	for _, name := range []string{"tcp", "tcp6"} {
		values, err := readTCP(filepath.Join(reader.root, "net", name), name, inodes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, values...)
	}
	unixValues, err := readUnix(filepath.Join(reader.root, "net", "unix"), inodes)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	endpoints = append(endpoints, unixValues...)
	return endpoints, ctx.Err()
}

func (reader *ProcReader) SystemdUnit(ctx context.Context, pid int) (string, bool, error) {
	if reader.systemd != nil {
		return reader.systemd.UnitForPID(ctx, pid)
	}
	value, err := reader.readFile(filepath.Join(reader.root, strconv.Itoa(pid), "cgroup"), maximumCgroupBytes)
	if err != nil {
		return "", false, err
	}
	for _, field := range strings.FieldsFunc(string(value), func(r rune) bool { return r == '/' || r == '\n' || r == ':' }) {
		if strings.HasSuffix(field, ".service") && domainSafeName(field) {
			return field, true, nil
		}
	}
	return "", false, nil
}

type NativeDetector struct{ reader NativeReader }

func NewNativeDetector(reader NativeReader) *NativeDetector { return &NativeDetector{reader: reader} }

func (detector *NativeDetector) Discover(ctx context.Context, rules []domain.Rule) ([]domain.CandidateObservation, error) {
	if detector == nil || detector.reader == nil {
		return nil, domain.ErrInvalid
	}
	processes, err := detector.reader.Processes(ctx)
	if err != nil {
		return nil, err
	}
	candidates := make([]domain.CandidateObservation, 0)
	for _, process := range processes {
		service, _, serviceErr := detector.reader.SystemdUnit(ctx, process.PID)
		if isPermission(serviceErr) {
			return nil, fmt.Errorf("%w: inspect systemd unit for pid %d", ErrNativeDiscoveryPermissionDenied, process.PID)
		}
		if serviceErr != nil && !errors.Is(serviceErr, os.ErrNotExist) {
			return nil, serviceErr
		}
		for _, rule := range rules {
			if rule.Validate() != nil || !matchesRule(process, service, rule) {
				continue
			}
			endpoints, err := detector.reader.ListeningEndpoints(ctx, process.PID)
			if isPermission(err) {
				return nil, fmt.Errorf("%w: inspect listening endpoints for pid %d", ErrNativeDiscoveryPermissionDenied, process.PID)
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			endpoint := selectEndpoint(endpoints, rule.DefaultPorts, process.RequestedPort)
			socket := ""
			if matchesSocketPattern(process.RequestedSocket, rule.UnixSocketPatterns) {
				socket = process.RequestedSocket
			}
			if socket == "" {
				socket = selectUnixSocket(endpoints, rule.UnixSocketPatterns)
			}
			if endpoint == "" && socket == "" {
				continue
			}
			evidence := []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: bounded(process.Name, domain.MaximumEvidenceBytes)}}
			if process.Executable != "" && len(process.Executable) <= domain.MaximumEvidenceBytes {
				evidence = append(evidence, domain.Evidence{Kind: domain.EvidenceExecutablePath, Value: process.Executable})
			}
			if service != "" {
				evidence = append(evidence, domain.Evidence{Kind: domain.EvidenceSystemdUnit, Value: service})
			}
			if endpoint != "" {
				evidence = append(evidence, domain.Evidence{Kind: domain.EvidenceListenEndpoint, Value: endpoint})
			}
			if socket != "" {
				evidence = append(evidence, domain.Evidence{Kind: domain.EvidenceUnixSocket, Value: socket})
			}
			candidates = append(candidates, domain.CandidateObservation{ObservationID: fmt.Sprintf("proc-%d-%d", process.PID, process.StartTime), Source: domain.SourceNative, DatabaseFamily: rule.DatabaseFamily, DatabaseVariant: rule.DatabaseVariant, NormalizedEndpoint: endpoint, UnixSocket: socket, ProcessIdentity: process.Executable, ServiceName: service, Confidence: confidence(process, endpoint, service), Evidence: evidence})
		}
	}
	return candidates, nil
}

func matchesRule(process ProcessObservation, service string, rule domain.Rule) bool {
	executableName := filepath.Base(strings.TrimSuffix(process.Executable, " (deleted)"))
	for _, name := range rule.ProcessNames {
		if executableName == name {
			return true
		}
	}
	for _, pattern := range rule.ExecutablePathPatterns {
		compiled, _ := regexp.Compile(pattern)
		if compiled != nil && compiled.MatchString(process.Executable) {
			return true
		}
	}
	for _, unit := range rule.SystemdUnits {
		if service == unit {
			return true
		}
	}
	return false
}

func selectEndpoint(values []EndpointObservation, defaults []uint16, requested uint16) string {
	for _, value := range values {
		_, portRaw, err := net.SplitHostPort(value.Address)
		port, _ := strconv.ParseUint(portRaw, 10, 16)
		if err == nil && (requested == 0 || uint16(port) == requested) {
			normalized, err := domain.NormalizeEndpoint(value.Address)
			if err == nil {
				return normalized
			}
		}
	}
	for _, defaultPort := range defaults {
		for _, value := range values {
			_, raw, _ := net.SplitHostPort(value.Address)
			port, _ := strconv.ParseUint(raw, 10, 16)
			if uint16(port) == defaultPort {
				normalized, _ := domain.NormalizeEndpoint(value.Address)
				return normalized
			}
		}
	}
	return ""
}

func splitNUL(value []byte) []string {
	parts := strings.Split(strings.TrimRight(string(value), "\x00"), "\x00")
	if len(parts) == 1 && parts[0] == "" {
		return nil
	}
	return parts
}

func parseAllowedArguments(cmdline []byte) (uint16, string) {
	arguments := splitNUL(cmdline)
	if len(arguments) < 2 {
		return 0, ""
	}
	var port uint16
	var socket string
	for index := 1; index < len(arguments); index++ {
		value := arguments[index]
		switch {
		case strings.HasPrefix(value, "--port="):
			port = parsePort(strings.TrimPrefix(value, "--port="))
		case value == "--port" && index+1 < len(arguments):
			index++
			port = parsePort(arguments[index])
		case strings.HasPrefix(value, "--socket="):
			socket = normalizeSocketArgument(strings.TrimPrefix(value, "--socket="))
		case value == "--socket" && index+1 < len(arguments):
			index++
			socket = normalizeSocketArgument(arguments[index])
		}
	}
	return port, socket
}

func parsePort(raw string) uint16 {
	parsed, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || parsed == 0 {
		return 0
	}
	return uint16(parsed)
}

func normalizeSocketArgument(raw string) string {
	if !strings.HasPrefix(raw, "/") || len(raw) > 512 || strings.ContainsAny(raw, "\x00\r\n") {
		return ""
	}
	return filepath.Clean(raw)
}

func matchesSocketPattern(socket string, patterns []string) bool {
	if socket == "" || len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err == nil && compiled.MatchString(socket) {
			return true
		}
	}
	return false
}

func parseUID(status string) uint32 {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			value, _ := strconv.ParseUint(fields[1], 10, 32)
			return uint32(value)
		}
	}
	return 0
}

func parseStartTime(stat string) uint64 {
	end := strings.LastIndex(stat, ")")
	if end < 0 {
		return 0
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) <= 19 {
		return 0
	}
	value, _ := strconv.ParseUint(fields[19], 10, 64)
	return value
}

func socketInodes(pid int, directory string) (map[string]struct{}, error) {
	result, err := socketInodesFromDirectory(directory)
	if isPermission(err) {
		return socketInodesViaPIDFD(pid, maximumFDEntries)
	}
	return result, err
}

func socketInodesFromDirectory(directory string) (map[string]struct{}, error) {
	entries, err := readDirectoryBounded(directory, maximumFDEntries)
	if err != nil {
		return nil, err
	}
	result := make(map[string]struct{})
	for _, entry := range entries {
		target, err := readLinkBounded(filepath.Join(directory, entry.Name()), maximumExecutableBytes)
		if err == nil && strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			result[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = struct{}{}
		}
	}
	return result, nil
}

func socketInodesViaPIDFD(pid, maximum int) (map[string]struct{}, error) {
	pidfd, err := pidfdOpen(pid, 0)
	if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) {
		return legacySocketInodeReader(pid, maximum)
	}
	if err != nil {
		return nil, err
	}
	defer unix.Close(pidfd)
	result := make(map[string]struct{})
	for targetFD := 0; targetFD < maximum; targetFD++ {
		duplicate, duplicateErr := pidfdGetfd(pidfd, targetFD, 0)
		if errors.Is(duplicateErr, syscall.ENOSYS) || errors.Is(duplicateErr, syscall.EINVAL) {
			return legacySocketInodeReader(pid, maximum)
		}
		if errors.Is(duplicateErr, syscall.EBADF) {
			continue
		}
		if duplicateErr != nil {
			return nil, duplicateErr
		}
		var status unix.Stat_t
		statErr := unix.Fstat(duplicate, &status)
		closeErr := unix.Close(duplicate)
		if statErr != nil {
			return nil, statErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if status.Mode&unix.S_IFMT == unix.S_IFSOCK {
			result[strconv.FormatUint(status.Ino, 10)] = struct{}{}
		}
	}
	return result, nil
}

func readTCP(file, network string, inodes map[string]struct{}) ([]EndpointObservation, error) {
	contents, err := readBoundedFile(file, maximumNetworkTableBytes)
	if err != nil {
		return nil, err
	}
	result := []EndpointObservation{}
	scanner := bufio.NewScanner(strings.NewReader(string(contents)))
	scanner.Buffer(make([]byte, 4096), maximumCommBytes)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[3] != "0A" {
			continue
		}
		if _, ok := inodes[fields[9]]; !ok {
			continue
		}
		address, err := decodeProcAddress(fields[1], network == "tcp6")
		if err == nil {
			result = append(result, EndpointObservation{Network: network, Address: address})
		}
	}
	return result, scanner.Err()
}

func readUnix(file string, inodes map[string]struct{}) ([]EndpointObservation, error) {
	contents, err := readBoundedFile(file, maximumNetworkTableBytes)
	if err != nil {
		return nil, err
	}
	result := []EndpointObservation{}
	scanner := bufio.NewScanner(strings.NewReader(string(contents)))
	scanner.Buffer(make([]byte, 4096), maximumCommBytes)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		inode := fields[6]
		if _, ok := inodes[inode]; !ok {
			continue
		}
		socket := fields[7]
		if strings.HasPrefix(socket, "/") && !strings.ContainsAny(socket, "\x00\r\n") {
			result = append(result, EndpointObservation{Network: "unix", Address: filepath.Clean(socket)})
		}
	}
	return result, scanner.Err()
}

func selectUnixSocket(values []EndpointObservation, patterns []string) string {
	for _, value := range values {
		if value.Network != "unix" {
			continue
		}
		if len(patterns) == 0 {
			return value.Address
		}
		for _, pattern := range patterns {
			compiled, _ := regexp.Compile(pattern)
			if compiled != nil && compiled.MatchString(value.Address) {
				return value.Address
			}
		}
	}
	return ""
}

func decodeProcAddress(raw string, ipv6 bool) (string, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return "", domain.ErrInvalid
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil || port == 0 {
		return "", domain.ErrInvalid
	}
	bytes, err := hex.DecodeString(parts[0])
	if err != nil || (!ipv6 && len(bytes) != 4) || (ipv6 && len(bytes) != 16) {
		return "", domain.ErrInvalid
	}
	if ipv6 {
		for offset := 0; offset < 16; offset += 4 {
			bytes[offset], bytes[offset+3] = bytes[offset+3], bytes[offset]
			bytes[offset+1], bytes[offset+2] = bytes[offset+2], bytes[offset+1]
		}
	} else {
		bytes[0], bytes[3] = bytes[3], bytes[0]
		bytes[1], bytes[2] = bytes[2], bytes[1]
	}
	return net.JoinHostPort(net.IP(bytes).String(), strconv.FormatUint(port, 10)), nil
}

func confidence(_ ProcessObservation, endpoint, service string) float64 {
	value := 0.5
	if endpoint != "" {
		value += 0.3
	}
	if service != "" {
		value += 0.2
	}
	return value
}

func bounded(value string, maximum int) string {
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}

func domainSafeName(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n/\\")
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	contents, err := io.ReadAll(io.LimitReader(handle, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > maximum {
		return nil, fmt.Errorf("%w: %s", ErrNativeDiscoveryDataTooLarge, filepath.Base(path))
	}
	return contents, nil
}

func readLinkBounded(path string, maximum int) (string, error) {
	buffer := make([]byte, maximum+1)
	length, err := unix.Readlink(path, buffer)
	if err != nil {
		return "", err
	}
	if length > maximum {
		return "", fmt.Errorf("%w: %s", ErrNativeDiscoveryDataTooLarge, filepath.Base(path))
	}
	return string(buffer[:length]), nil
}

func readDirectoryBounded(path string, maximum int) ([]os.DirEntry, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	entries, err := handle.ReadDir(maximum + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maximum {
		return nil, fmt.Errorf("%w: %s directory", ErrNativeDiscoveryDataTooLarge, filepath.Base(path))
	}
	return entries, nil
}

func isPermission(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}
