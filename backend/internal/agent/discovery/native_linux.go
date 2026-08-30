//go:build linux

package discovery

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	domain "dbpilot.local/platform/internal/discovery"
)

type ProcessObservation struct {
	PID        int
	Name       string
	Executable string
	Arguments  []string
	UID        uint32
	StartTime  uint64
	Cgroup     string
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
	root    string
	systemd SystemdFacts
}

func NewProcReader(root string, systemd SystemdFacts) *ProcReader {
	if root == "" {
		root = "/proc"
	}
	return &ProcReader{root: filepath.Clean(root), systemd: systemd}
}

func (reader *ProcReader) Processes(ctx context.Context) ([]ProcessObservation, error) {
	entries, err := os.ReadDir(reader.root)
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
		process, err := reader.process(pid)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			continue
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
	comm, err := os.ReadFile(filepath.Join(base, "comm"))
	if err != nil {
		return ProcessObservation{}, err
	}
	cmdline, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err != nil {
		return ProcessObservation{}, err
	}
	status, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return ProcessObservation{}, err
	}
	stat, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return ProcessObservation{}, err
	}
	cgroup, err := os.ReadFile(filepath.Join(base, "cgroup"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ProcessObservation{}, err
	}
	arguments := splitNUL(cmdline)
	executable := ""
	if len(arguments) > 0 {
		executable = arguments[0]
	}
	uid := parseUID(string(status))
	startTime := parseStartTime(string(stat))
	return ProcessObservation{PID: pid, Name: strings.TrimSpace(string(comm)), Executable: executable, Arguments: arguments[1:], UID: uid, StartTime: startTime, Cgroup: strings.TrimSpace(string(cgroup))}, nil
}

func (reader *ProcReader) ListeningEndpoints(ctx context.Context, pid int) ([]EndpointObservation, error) {
	inodes, err := socketInodes(filepath.Join(reader.root, strconv.Itoa(pid), "fd"))
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
	value, err := os.ReadFile(filepath.Join(reader.root, strconv.Itoa(pid), "cgroup"))
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
		service, _, _ := detector.reader.SystemdUnit(ctx, process.PID)
		for _, rule := range rules {
			if rule.Validate() != nil || !matchesRule(process, service, rule) {
				continue
			}
			endpoints, err := detector.reader.ListeningEndpoints(ctx, process.PID)
			if err != nil && !errors.Is(err, os.ErrPermission) && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			endpoint := selectEndpoint(endpoints, rule.DefaultPorts, process.Arguments)
			socket := socketArgument(process.Arguments)
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
			identity := service
			if identity == "" {
				identity = process.Name
			}
			candidates = append(candidates, domain.CandidateObservation{ObservationID: fmt.Sprintf("proc-%d-%d", process.PID, process.StartTime), Source: domain.SourceNative, DatabaseFamily: rule.DatabaseFamily, DatabaseVariant: rule.DatabaseVariant, NormalizedEndpoint: endpoint, UnixSocket: socket, ProcessIdentity: process.Name, ServiceName: service, Confidence: confidence(process, endpoint, service), Evidence: evidence})
		}
	}
	return candidates, nil
}

func matchesRule(process ProcessObservation, service string, rule domain.Rule) bool {
	for _, name := range rule.ProcessNames {
		if process.Name == name || filepath.Base(process.Executable) == name {
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

func selectEndpoint(values []EndpointObservation, defaults []uint16, arguments []string) string {
	requested := argumentPort(arguments)
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

func argumentPort(arguments []string) uint16 {
	for index, value := range arguments {
		raw := ""
		if strings.HasPrefix(value, "--port=") {
			raw = strings.TrimPrefix(value, "--port=")
		} else if value == "--port" && index+1 < len(arguments) {
			raw = arguments[index+1]
		}
		parsed, err := strconv.ParseUint(raw, 10, 16)
		if err == nil && parsed > 0 {
			return uint16(parsed)
		}
	}
	return 0
}

func socketArgument(arguments []string) string {
	for index, value := range arguments {
		raw := ""
		if strings.HasPrefix(value, "--socket=") {
			raw = strings.TrimPrefix(value, "--socket=")
		} else if value == "--socket" && index+1 < len(arguments) {
			raw = arguments[index+1]
		}
		if strings.HasPrefix(raw, "/") && len(raw) <= 512 && !strings.ContainsAny(raw, "\x00\r\n") {
			return filepath.Clean(raw)
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

func socketInodes(directory string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	result := make(map[string]struct{})
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(directory, entry.Name()))
		if err == nil && strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			result[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = struct{}{}
		}
	}
	return result, nil
}

func readTCP(file, network string, inodes map[string]struct{}) ([]EndpointObservation, error) {
	handle, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	result := []EndpointObservation{}
	scanner := bufio.NewScanner(handle)
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
	handle, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	result := []EndpointObservation{}
	scanner := bufio.NewScanner(handle)
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
