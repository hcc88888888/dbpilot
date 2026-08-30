//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	agentdiscovery "dbpilot.local/platform/internal/agent/discovery"
	domain "dbpilot.local/platform/internal/discovery"
	"golang.org/x/sys/unix"
)

const expectedPtraceCapability = "0000000000080000"

func main() {
	mode := flag.String("mode", "", "positive or permission")
	port := flag.Uint("port", 0, "fixture listen port")
	legacy := flag.Bool("legacy", false, "force the fixed legacy proc helper")
	agentBinary := flag.String("agent", "/probe/dbpilot-agent", "Agent binary used by socket activator")
	flag.Parse()
	if *mode == "activate-helper" {
		activateHelper(*agentBinary)
		return
	}
	if *mode == "helper" {
		if os.Geteuid() != 0 {
			fail("helper probe must run as root")
		}
		capabilities := capabilitySets()
		if capabilities["CapBnd"] != "0000000000080004" || capabilities["CapEff"] != "0000000000080004" {
			fail("helper must retain exactly SYS_PTRACE and DAC_READ_SEARCH")
		}
		fail(agentdiscovery.RunLegacyProcHelper(context.Background(), 19001, 19001, []string{"mysqld"}).Error())
	}
	if *mode == "wrong-gid" {
		if os.Geteuid() != 19001 || os.Getegid() == 19001 {
			fail("wrong-gid probe identity is invalid")
		}
		if connection, err := net.DialTimeout("unix", agentdiscovery.DefaultLegacyProcHelperSocket, time.Second); err == nil {
			_, _ = connection.Write(legacyRequest(1, uint32(os.Getpid()), 16))
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			response, _ := io.ReadAll(io.LimitReader(connection, 64))
			_ = connection.Close()
			if len(response) != 0 {
				fail("wrong GID received a helper response")
			}
		}
		fmt.Println("PASS WRONG_GID_REJECTED")
		return
	}
	if *mode == "wrong-peer" {
		if os.Geteuid() == 19001 {
			fail("wrong-peer probe identity is invalid")
		}
		if connection, err := net.DialTimeout("unix", agentdiscovery.DefaultLegacyProcHelperSocket, time.Second); err == nil {
			_ = connection.Close()
			fail("wrong peer connected to helper")
		}
		fmt.Println("PASS WRONG_PEER_REJECTED")
		return
	}
	if os.Geteuid() != 19001 || os.Getegid() != 19001 {
		fail("probe must run as dbpilot uid/gid 19001")
	}
	switch *mode {
	case "positive":
		runPositive(uint16(*port), *legacy)
	case "permission":
		runPermission()
	case "protocol-negative":
		runProtocolNegatives()
	default:
		fail("unknown probe mode")
	}
}

func activateHelper(agentBinary string) {
	if os.Geteuid() != 0 || filepath.Clean(agentBinary) != "/probe/dbpilot-agent" {
		fail("invalid helper activator identity or Agent path")
	}
	if err := os.MkdirAll(filepath.Dir(agentdiscovery.DefaultLegacyProcHelperSocket), 0o755); err != nil {
		fail(err.Error())
	}
	_ = os.Remove(agentdiscovery.DefaultLegacyProcHelperSocket)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: agentdiscovery.DefaultLegacyProcHelperSocket, Net: "unix"})
	if err != nil {
		fail(err.Error())
	}
	defer listener.Close()
	defer os.Remove(agentdiscovery.DefaultLegacyProcHelperSocket)
	if err := os.Chmod(agentdiscovery.DefaultLegacyProcHelperSocket, 0o600); err != nil {
		fail(err.Error())
	}
	if err := os.Chown(agentdiscovery.DefaultLegacyProcHelperSocket, 19001, 19001); err != nil {
		fail(err.Error())
	}
	file, err := listener.File()
	if err != nil {
		fail(err.Error())
	}
	defer file.Close()
	if err := unix.Prctl(unix.PR_CAPBSET_DROP, unix.CAP_CHOWN, 0, 0, 0); err != nil {
		fail(err.Error())
	}
	if err := unix.Prctl(unix.PR_CAPBSET_DROP, unix.CAP_SETPCAP, 0, 0, 0); err != nil {
		fail(err.Error())
	}
	if err := unix.Prctl(unix.PR_CAPBSET_DROP, unix.CAP_SETUID, 0, 0, 0); err != nil {
		fail(err.Error())
	}
	if err := unix.Prctl(unix.PR_CAPBSET_DROP, unix.CAP_SETGID, 0, 0, 0); err != nil {
		fail(err.Error())
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fail(err.Error())
	}
	command := exec.Command(agentBinary, "proc-helper", "--allowed-uid=19001", "--allowed-gid=19001", "--allowed-process-names=mysqld-dbp")
	command.ExtraFiles = []*os.File{file}
	command.Env = append(os.Environ(), "LISTEN_FDS=1")
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		fail(err.Error())
	}
	time.Sleep(200 * time.Millisecond)
	status, err := os.ReadFile("/proc/" + strconv.Itoa(command.Process.Pid) + "/status")
	if err != nil {
		fail(err.Error())
	}
	text := string(status)
	if !strings.Contains(text, "CapBnd:\t0000000000080004") || !strings.Contains(text, "CapEff:\t0000000000080004") || !strings.Contains(text, "NoNewPrivs:\t1") {
		_ = command.Process.Kill()
		fail("helper did not retain exactly SYS_PTRACE+DAC_READ_SEARCH with NoNewPrivs")
	}
	fmt.Println("HELPER_READY CAP_BND=0000000000080004 CAP_EFF=0000000000080004 NO_NEW_PRIVS=1")
	if err := command.Wait(); err != nil {
		fail(err.Error())
	}
}

func runProtocolNegatives() {
	requests := [][]byte{legacyRequest(1, uint32(os.Getpid()), 16), legacyRequest(99, uint32(os.Getpid()), 16), legacyRequest(1, uint32(os.Getpid()), 4097)}
	copy(requests[0][:4], []byte("PATH"))
	for _, request := range requests {
		connection, err := net.DialTimeout("unix", agentdiscovery.DefaultLegacyProcHelperSocket, time.Second)
		if err != nil {
			fail(err.Error())
		}
		_, err = connection.Write(request)
		if err != nil {
			fail(err.Error())
		}
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		response, readErr := io.ReadAll(io.LimitReader(connection, 64))
		_ = connection.Close()
		if readErr != nil || len(response) != 0 {
			fail("invalid helper request was not rejected")
		}
	}
	fmt.Println("PASS MALFORMED_OVERSIZE_FORBIDDEN_PATH_REJECTED")
}

func legacyRequest(operation uint16, pid, maximum uint32) []byte {
	request := make([]byte, 16)
	copy(request[:4], []byte("DBPF"))
	binary.BigEndian.PutUint16(request[4:6], 1)
	binary.BigEndian.PutUint16(request[6:8], operation)
	binary.BigEndian.PutUint32(request[8:12], pid)
	binary.BigEndian.PutUint32(request[12:16], maximum)
	return request
}

func runPositive(port uint16, legacy bool) {
	if port == 0 {
		fail("positive probe requires a port")
	}
	capabilities := capabilitySets()
	if legacy {
		if capabilities["CapAmb"] != "0000000000000000" || capabilities["CapEff"] != "0000000000000000" {
			fail("legacy Agent must not retain effective or ambient capabilities")
		}
	} else {
		for _, field := range []string{"CapBnd", "CapAmb", "CapEff"} {
			if capabilities[field] != expectedPtraceCapability {
				fail(field + " must contain exactly CAP_SYS_PTRACE")
			}
		}
	}
	reader := agentdiscovery.NewProcReader("/proc", nil)
	if legacy {
		reader = agentdiscovery.NewLegacyProcReader("/proc", nil)
	}
	detector := agentdiscovery.NewNativeDetector(reader)
	candidates, err := detector.Discover(context.Background(), []domain.Rule{{
		ID: "mysql-kylin", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql",
		ProcessNames: []string{"mysqld-dbp"}, DefaultPorts: []uint16{port},
	}})
	if err != nil {
		fail(err.Error())
	}
	if len(candidates) != 1 || candidates[0].NormalizedEndpoint != "127.0.0.1:"+strconv.Itoa(int(port)) || candidates[0].ProcessIdentity != "/probe/mysqld-dbp" {
		fail("expected exactly one trusted MySQL candidate")
	}
	encoded, err := json.Marshal(candidates)
	if err != nil {
		fail(err.Error())
	}
	text := string(encoded)
	if strings.Contains(text, "dbpilot-probe-secret") || strings.Contains(text, "dbpilot-spoof-secret") || strings.Contains(text, "not-a-database") {
		fail("candidate output contains a secret or spoofed executable")
	}
	path := "modern"
	if legacy {
		path = "legacy_helper"
	}
	fmt.Printf("PASS POSITIVE PATH=%s UID=19001 CAP_BND=%s CAP_AMB=%s CAP_EFF=%s CANDIDATES=%s\n", path, capabilities["CapBnd"], capabilities["CapAmb"], capabilities["CapEff"], text)
}

func runPermission() {
	capabilities := capabilitySets()
	if capabilities["CapBnd"] != "0000000000000000" || capabilities["CapAmb"] != "0000000000000000" || capabilities["CapEff"] != "0000000000000000" {
		fail("negative probe must not retain capabilities")
	}
	_, err := agentdiscovery.NewProcReader("/proc", nil).Processes(context.Background())
	if !errors.Is(err, agentdiscovery.ErrNativeDiscoveryPermissionDenied) {
		fail("expected explicit native discovery permission denial")
	}
	fmt.Println("PASS NEGATIVE UID=19001 CAP_BND=0000000000000000 CAP_AMB=0000000000000000 CAP_EFF=0000000000000000 CAPABILITY_STATE=unavailable REASON=permission_denied")
}

func capabilitySets() map[string]string {
	handle, err := os.Open("/proc/self/status")
	if err != nil {
		fail(err.Error())
	}
	contents, err := io.ReadAll(io.LimitReader(handle, 64<<10+1))
	closeErr := handle.Close()
	if err != nil || closeErr != nil || len(contents) > 64<<10 {
		fail("read bounded capability status")
	}
	result := map[string]string{}
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			key := strings.TrimSuffix(fields[0], ":")
			if key == "CapBnd" || key == "CapAmb" || key == "CapEff" {
				result[key] = fields[1]
			}
		}
	}
	return result
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "FAIL:", message)
	os.Exit(1)
}
