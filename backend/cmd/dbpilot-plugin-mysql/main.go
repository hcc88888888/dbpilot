package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/mysqlplugin"
	"google.golang.org/grpc"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	values, ok := arguments(args)
	if !ok {
		return 2
	}
	if values["--plugin-id"] != mysqlplugin.PluginID || values["--database-family"] != mysqlplugin.DatabaseFamily || values["--version"] == "" || values["--slot"] != "A" && values["--slot"] != "B" {
		return 2
	}
	runtimeDirectory := values["--runtime-dir"]
	if !filepath.IsAbs(runtimeDirectory) {
		return 2
	}
	configurationRevision, err := strconv.ParseUint(values["--configuration-revision"], 10, 64)
	if err != nil || configurationRevision == 0 {
		return 2
	}
	operationRevision, err := strconv.ParseUint(values["--operation-revision"], 10, 64)
	if err != nil || operationRevision == 0 {
		return 2
	}
	var instanceIDs, templateIDs []string
	if json.Unmarshal([]byte(values["--instance-ids"]), &instanceIDs) != nil || len(instanceIDs) == 0 || len(instanceIDs) > mysqlplugin.MaxInstances || !uniqueNonempty(instanceIDs) || json.Unmarshal([]byte(values["--template-ids"]), &templateIDs) != nil || len(templateIDs) > mysqlplugin.MaxTemplates || !uniqueNonempty(templateIDs) {
		return 2
	}
	nonceFD, err := strconv.Atoi(values["--launch-nonce-fd"])
	if err != nil || nonceFD != 3 {
		return 2
	}
	nonceFile := os.NewFile(uintptr(nonceFD), "launch-nonce")
	if nonceFile == nil {
		return 2
	}
	nonce := make([]byte, sha256.Size)
	_, readErr := io.ReadFull(nonceFile, nonce)
	closeErr := nonceFile.Close()
	if readErr != nil || closeErr != nil {
		return 2
	}
	executable, err := os.Executable()
	if err != nil {
		return 1
	}
	body, err := os.ReadFile(executable)
	if err != nil {
		return 1
	}
	digest := sha256.Sum256(body)
	clear(body)
	if info, lstatErr := os.Lstat(runtimeDirectory); lstatErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return 1
		}
	} else if !os.IsNotExist(lstatErr) {
		return 1
	}
	if os.MkdirAll(runtimeDirectory, 0o700) != nil || os.Chmod(runtimeDirectory, 0o700) != nil {
		return 1
	}
	socket := filepath.Join(runtimeDirectory, "plugin.sock")
	_ = os.Remove(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return 1
	}
	defer listener.Close()
	defer os.Remove(socket)
	if os.Chmod(socket, 0o600) != nil {
		return 1
	}
	runtime := mysqlplugin.NewRuntime(mysqlplugin.MySQLPoolFactory{}, mysqlplugin.RuntimeOptions{})
	service := mysqlplugin.NewServer(mysqlplugin.ServerConfig{AssignmentID: values["--assignment-id"], PluginID: values["--plugin-id"], Version: values["--version"], ConfigurationRevision: configurationRevision, OperationRevision: operationRevision, ExpectedInstanceIDs: instanceIDs, ExecutableDigest: digest[:], LaunchNonce: nonce, Runtime: runtime})
	defer clear(nonce)
	server := grpc.NewServer(grpc.MaxRecvMsgSize(4<<20), grpc.MaxSendMsgSize(4<<20))
	pluginv1.RegisterPluginRuntimeServer(server, service)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { _ = server.Serve(listener) }()
	<-ctx.Done()
	drainContext, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, _ = service.Shutdown(drainContext, &pluginv1.ShutdownPluginRequest{AssignmentId: values["--assignment-id"], DrainTimeoutSeconds: 5})
	drainCancel()
	graceful := make(chan struct{})
	go func() { server.GracefulStop(); close(graceful) }()
	select {
	case <-graceful:
	case <-time.After(6 * time.Second):
		server.Stop()
	}
	runtime.Close()
	return 0
}

func arguments(values []string) (map[string]string, bool) {
	if len(values) == 0 || len(values)%2 != 0 {
		return nil, false
	}
	allowed := map[string]struct{}{"--runtime-dir": {}, "--assignment-id": {}, "--plugin-id": {}, "--database-family": {}, "--version": {}, "--slot": {}, "--configuration-revision": {}, "--operation-revision": {}, "--instance-ids": {}, "--template-ids": {}, "--launch-nonce-fd": {}}
	result := make(map[string]string, len(allowed))
	for index := 0; index < len(values); index += 2 {
		if _, ok := allowed[values[index]]; !ok || values[index+1] == "" {
			return nil, false
		}
		if _, duplicate := result[values[index]]; duplicate {
			return nil, false
		}
		result[values[index]] = values[index+1]
	}
	return result, len(result) == len(allowed)
}

func uniqueNonempty(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
