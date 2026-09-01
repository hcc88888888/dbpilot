package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
	"dbpilot.local/platform/internal/mysqlplugin"
	"dbpilot.local/platform/internal/spool"
	"github.com/go-sql-driver/mysql"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mysql plugin verification failed")
		os.Exit(1)
	}
	fmt.Println("mysql plugin verification passed")
}

func run() error {
	if os.Geteuid() == 0 {
		return fmt.Errorf("root verifier rejected")
	}
	pluginPath := os.Getenv("DBPILOT_MYSQL_PLUGIN")
	password := os.Getenv("DBPILOT_MYSQL_TEST_PASSWORD")
	if pluginPath == "" || password == "" {
		return fmt.Errorf("configuration rejected")
	}
	runtimeRoot, err := os.MkdirTemp("", "dbpilot-mysql-plugin-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(runtimeRoot)
	runtimeDirectory := filepath.Join(runtimeRoot, "mysql")
	if err = os.Mkdir(runtimeDirectory, 0o700); err != nil {
		return err
	}
	nonce := make([]byte, sha256.Size)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	instanceIDs := `["mysql-a","mysql-b"]`
	templates := `[]`
	command := exec.Command(pluginPath, "--runtime-dir", runtimeDirectory, "--assignment-id", "assignment-a", "--plugin-id", "mysql", "--database-family", "mysql", "--version", "1.0.0", "--slot", "A", "--configuration-revision", "1", "--operation-revision", "1", "--instance-ids", instanceIDs, "--template-ids", templates, "--launch-nonce-fd", "3")
	command.ExtraFiles = []*os.File{reader}
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp", "LANG=C.UTF-8", "DBPILOT_PLUGIN_PROCESS=1"}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err = command.Start(); err != nil {
		return err
	}
	_ = reader.Close()
	processDone := false
	defer func() {
		if !processDone {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	}()
	if _, err = writer.Write(nonce); err != nil {
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	socket := filepath.Join(runtimeDirectory, "plugin.sock")
	deadline := time.Now().Add(15 * time.Second)
	for {
		info, statErr := os.Stat(socket)
		if statErr == nil {
			if info.Mode().Perm() != 0o600 {
				return fmt.Errorf("socket mode rejected")
			}
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("socket unavailable")
		}
		time.Sleep(50 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connection, err := grpc.NewClient("passthrough:///plugin", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		dialer := net.Dialer{}
		return dialer.DialContext(ctx, "unix", socket)
	}))
	if err != nil {
		return err
	}
	defer connection.Close()
	client := pluginv1.NewPluginRuntimeClient(connection)
	body, err := os.ReadFile(pluginPath)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	clear(body)
	spoolStore, err := spool.Open(filepath.Join(runtimeRoot, "spool"), spool.Limits{MaxBytes: 8 << 20, SegmentBytes: 1 << 20})
	if err != nil {
		return err
	}
	defer spoolStore.Close()
	gatewayClient, err := plugingateway.NewClient(plugingateway.ClientConfig{RuntimeRoot: runtimeRoot, Scope: plugingateway.MetricScope{TenantID: "tenant-a", ProjectID: "project-a", AgentID: "agent-a", HostID: "host-a"}, Store: spoolStore, Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	process := &fixtureProcess{command: command, startedAt: time.Now().UTC()}
	checker := pluginsupervisor.NewGatewayHealthCheckerWithCredentials(gatewayClient, fixtureCredentialLeaser{password: password})
	healthRequest := pluginsupervisor.HealthRequest{AssignmentID: "assignment-a", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", ExecutableSHA256: digest[:], ExecutablePath: pluginPath, ConfigurationRevision: 1, OperationRevision: 1, InstanceIDs: []string{"mysql-a", "mysql-b"}, InstanceDescriptors: []pluginsupervisor.InstanceDescriptor{{InstanceID: "mysql-a", DatabaseVariant: "mysql", Endpoint: "mysql-a:3306"}, {InstanceID: "mysql-b", DatabaseVariant: "mysql", Endpoint: "mysql-b:3306"}}, SupportedVariants: []string{"mysql"}, SignedCapabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1, CredentialsComplete: true, RuntimeDirectory: runtimeDirectory, LaunchNonce: nonce, ExpectedUserID: uint32(os.Geteuid()), ExpectedGroupID: uint32(os.Getegid())}
	if err = checker.Handshake(ctx, process, healthRequest); err != nil {
		return fmt.Errorf("agent gateway handshake rejected")
	}
	activation, code := checker.ActivationState(process)
	if string(activation) != "healthy" || code != "" {
		return fmt.Errorf("agent gateway activation rejected")
	}
	pending, err := spoolStore.Pending(ctx, spool.Metric, 20)
	if err != nil || len(pending) != 10 {
		return fmt.Errorf("agent builtin seed rejected")
	}
	apply := func(revision uint64, passwordA string) (*pluginv1.ApplyPluginConfigurationResponse, error) {
		expires := timestamppb.New(time.Now().Add(5 * time.Minute))
		return client.ApplyConfiguration(ctx, &pluginv1.ApplyPluginConfigurationRequest{AssignmentId: "assignment-a", ConfigurationRevision: revision, Instances: []*pluginv1.PluginInstanceConfiguration{{InstanceId: "mysql-a", DatabaseVariant: "mysql", Endpoint: "mysql-a:3306", CredentialLease: &pluginv1.CredentialLease{LeaseId: fmt.Sprintf("lease-a-%d", revision), CredentialRevision: revision, Username: "root", SecretBytes: []byte(passwordA), ExpiresAt: expires}}, {InstanceId: "mysql-b", DatabaseVariant: "mysql", Endpoint: "mysql-b:3306", CredentialLease: &pluginv1.CredentialLease{LeaseId: fmt.Sprintf("lease-b-%d", revision), CredentialRevision: revision, Username: "root", SecretBytes: []byte(password), ExpiresAt: expires}}}})
	}
	for _, id := range []string{"mysql-a", "mysql-b"} {
		validation, callErr := client.ValidateInstance(ctx, &pluginv1.ValidatePluginInstanceRequest{AssignmentId: "assignment-a", InstanceId: id, ConfigurationRevision: 1})
		if callErr != nil || !validation.GetValid() {
			return fmt.Errorf("validation rejected")
		}
	}
	health, err := client.GetHealth(ctx, &pluginv1.GetPluginHealthRequest{AssignmentId: "assignment-a"})
	if err != nil || health.GetBoundInstanceCount() != 2 || health.GetState() != pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY {
		return fmt.Errorf("health rejected")
	}
	ids := mysqlplugin.SortedBuiltinTemplateIDs(mysqlplugin.BuiltinCatalog())
	collected, err := client.CollectNow(ctx, &pluginv1.CollectPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 1, InstanceIds: []string{"mysql-a", "mysql-b"}, TemplateIds: ids})
	if err != nil || len(collected.GetBatches()) != 10 {
		return fmt.Errorf("collection rejected")
	}
	seen := map[string]bool{}
	for _, batch := range collected.GetBatches() {
		if batch.GetCollectionStatus() != pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED || len(batch.GetSamples()) != 1 {
			return fmt.Errorf("metric rejected")
		}
		seen[batch.GetInstanceId()+"\x00"+batch.GetTemplateId()] = true
	}
	if len(seen) != 10 {
		return fmt.Errorf("metric coverage rejected")
	}
	beforeA, beforeAOK := metricValue(collected, "mysql-a", "mysql.connections.current")
	_, beforeBOK := metricValue(collected, "mysql-b", "mysql.connections.current")
	if !beforeAOK || !beforeBOK {
		return fmt.Errorf("connection metric rejected")
	}
	directConfig := mysql.NewConfig()
	directConfig.User = "root"
	directConfig.Passwd = password
	directConfig.Net = "tcp"
	directConfig.Addr = "mysql-a:3306"
	directDatabase, err := sql.Open("mysql", directConfig.FormatDSN())
	directConfig.Passwd = ""
	if err != nil {
		return err
	}
	defer directDatabase.Close()
	directDatabase.SetMaxOpenConns(1)
	directDatabase.SetMaxIdleConns(1)
	if err = directDatabase.PingContext(ctx); err != nil {
		return err
	}
	changed, err := client.CollectNow(ctx, &pluginv1.CollectPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 1, InstanceIds: []string{"mysql-a", "mysql-b"}, TemplateIds: []string{"mysql.connections.current"}})
	if err != nil {
		return err
	}
	afterA, afterAOK := metricValue(changed, "mysql-a", "mysql.connections.current")
	afterB, afterBOK := metricValue(changed, "mysql-b", "mysql.connections.current")
	if !afterAOK || !afterBOK || afterA < beforeA+1 || afterA <= afterB {
		return fmt.Errorf("connection count did not change")
	}
	failed, err := apply(2, password+"-invalid")
	if err != nil || failed.GetErrorCode() != "connection_rejected" {
		return fmt.Errorf("bad credential accepted")
	}
	isolated, err := client.CollectNow(ctx, &pluginv1.CollectPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 1, InstanceIds: []string{"mysql-a", "mysql-b"}, TemplateIds: ids})
	if err != nil || len(isolated.GetBatches()) != 10 {
		return fmt.Errorf("instance isolation rejected")
	}
	for _, batch := range isolated.GetBatches() {
		if batch.GetCollectionStatus() != pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED {
			return fmt.Errorf("old configuration damaged")
		}
	}
	if err = checker.Shutdown(ctx, process, 5*time.Second); err != nil {
		return fmt.Errorf("agent gateway shutdown rejected")
	}
	if err = command.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	exitDone := make(chan error, 1)
	go func() { exitDone <- command.Wait() }()
	select {
	case waitErr := <-exitDone:
		if waitErr != nil {
			return fmt.Errorf("signal drain rejected")
		}
		processDone = true
		checker.CleanupUnexpectedExit(process)
	case <-time.After(10 * time.Second):
		return fmt.Errorf("signal drain timeout")
	}
	return nil
}

func metricValue(response *pluginv1.CollectPluginMetricsResponse, instanceID, templateID string) (float64, bool) {
	for _, batch := range response.GetBatches() {
		if batch.GetInstanceId() == instanceID && batch.GetTemplateId() == templateID && len(batch.GetSamples()) == 1 {
			return batch.GetSamples()[0].GetValue(), true
		}
	}
	return 0, false
}

type fixtureCredentialLeaser struct{ password string }

func (leaser fixtureCredentialLeaser) LeaseCredential(_ context.Context, request pluginsupervisor.CredentialLeaseRequest) (pluginsupervisor.CredentialLease, error) {
	expires := time.Now().UTC().Add(5 * time.Minute)
	return pluginsupervisor.CredentialLease{LeaseID: "lease-" + request.InstanceID, AssignmentID: request.AssignmentID, InstanceID: request.InstanceID, DatabaseFamily: request.DatabaseFamily, CredentialRevision: 1, ConfigurationRevision: request.ConfigurationRevision, OperationRevision: request.OperationRevision, ExpiresAt: expires, ValidFor: 5 * time.Minute, Username: "root", SecretBytes: []byte(leaser.password)}, nil
}

type fixtureProcess struct {
	command   *exec.Cmd
	startedAt time.Time
}

func (process *fixtureProcess) PID() int             { return process.command.Process.Pid }
func (*fixtureProcess) StartTicks() uint64           { return 1 }
func (process *fixtureProcess) StartedAt() time.Time { return process.startedAt }
func (process *fixtureProcess) Drain(context.Context) error {
	return process.command.Process.Signal(syscall.SIGTERM)
}
func (process *fixtureProcess) Stop(context.Context) error {
	return process.command.Process.Signal(syscall.SIGTERM)
}
func (process *fixtureProcess) Kill() error { return process.command.Process.Kill() }
func (process *fixtureProcess) Wait() error { return process.command.Wait() }
