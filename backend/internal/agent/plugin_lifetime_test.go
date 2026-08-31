package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/commandjournal"
	"dbpilot.local/platform/internal/agent/pluginstate"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestControlClientSuccessfulResultDoesNotOwnHealthyPluginLifetime(t *testing.T) {
	stateRoot, runtimeRoot := t.TempDir(), t.TempDir()
	stateStore, err := pluginstate.NewFileStore(stateRoot)
	require.NoError(t, err)
	runner := &lifetimeRunner{}
	supervisor, err := pluginsupervisor.NewPluginSupervisor(pluginsupervisor.PluginSupervisorConfig{AgentID: "agent-a", HostID: "host-a", RuntimeRoot: runtimeRoot, Store: stateStore, Installer: &lifetimeInstaller{}, Leases: lifetimeLease{}, Downloader: lifetimeDownload{}, Processes: runner, Health: lifetimeHealth{}, DrainTimeout: time.Second, FailureWindow: 10 * time.Minute, FailureThreshold: 5, RestartBase: time.Millisecond, RestartMaximum: 10 * time.Millisecond})
	require.NoError(t, err)
	executor, err := NewReconcilePluginExecutor(supervisor)
	require.NoError(t, err)
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindReconcilePlugin, executor))
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	now := time.Now().UTC()
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	envelope := signedLifetimeReconcile(t, privateKey, now)
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: envelope}}
	client, err := NewControlClient(ControlClientConfig{AgentID: "agent-a", StreamOpener: (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open, Journal: journal, Verifier: verifier, Executors: registry, HeartbeatInterval: time.Hour, ReconnectBackoff: time.Hour, Now: func() time.Time { return now }})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	require.Eventually(t, func() bool { return countPrepared(stream.sentMessages()) == 1 }, time.Second, time.Millisecond)
	stream.receive <- commandStartMessage(envelope.GetCommandId(), bytes.Repeat([]byte{9}, sha256.Size), 1, now.Add(time.Minute))
	require.Eventually(t, func() bool { return countResults(stream.sentMessages()) == 1 && runner.current() != nil }, time.Second, time.Millisecond)
	process := runner.current()
	select {
	case <-process.done:
		t.Fatal("terminal result cancelled healthy plugin lifetime")
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	require.NoError(t, <-done)
	select {
	case <-process.done:
		t.Fatal("ControlClient shutdown cancelled Supervisor-owned plugin")
	case <-time.After(30 * time.Millisecond):
	}
	require.NoError(t, supervisor.Stop(context.Background()))
	select {
	case <-process.done:
	case <-time.After(time.Second):
		t.Fatal("Supervisor stop did not terminate plugin")
	}
}

func signedLifetimeReconcile(t *testing.T, key ed25519.PrivateKey, now time.Time) *agentv1.CommandEnvelope {
	t.Helper()
	envelope := &agentv1.CommandEnvelope{CommandId: "command-plugin-lifetime", AgentId: "agent-a", Nonce: bytes.Repeat([]byte{3}, 32), LeaseSeconds: 60, IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Minute)), Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{AssignmentId: "assignment-1", PluginId: "mysql", DatabaseFamily: "mysql", DesiredVersion: "1.0.0", DesiredState: agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_RUNNING, ArtifactId: "artifact-1", ArtifactSha256: bytes.Repeat([]byte{1}, 32), ManifestDigest: bytes.Repeat([]byte{2}, 32), ConfigurationRevision: 1, OperationRevision: 1, InstanceIds: []string{"mysql-1"}, TemplateIds: []string{"template-1"}}}}
	payload, err := CommandSigningBytes(envelope)
	require.NoError(t, err)
	envelope.Signature = ed25519.Sign(key, payload)
	return envelope
}

type lifetimeInstaller struct {
	slot pluginsupervisor.InstalledSlot
}

func (i *lifetimeInstaller) InstallInactive(_ context.Context, r pluginsupervisor.InstallRequest, s pluginstate.Slot) (pluginsupervisor.InstalledSlot, error) {
	i.slot = pluginsupervisor.InstalledSlot{Slot: s, Version: r.Version, ExecutablePath: "/verified/plugin", ExecutableSHA256: string(bytes.Repeat([]byte{'a'}, 64)), ArtifactSHA256: hexLifetime(r.ArtifactSHA256), ManifestDigest: hexLifetime(r.ManifestDigest)}
	return i.slot, nil
}
func (i *lifetimeInstaller) Installed(context.Context, pluginsupervisor.SlotIdentity, pluginstate.Slot) (pluginsupervisor.InstalledSlot, error) {
	return i.slot, nil
}
func (*lifetimeInstaller) Activate(context.Context, pluginsupervisor.SlotIdentity, pluginstate.Slot) error {
	return nil
}
func (*lifetimeInstaller) RemoveInactive(context.Context, string, pluginstate.Slot) error { return nil }
func (*lifetimeInstaller) RemoveFamily(context.Context, string) error                     { return nil }
func (*lifetimeInstaller) Recover(context.Context, string) error                          { return nil }

type lifetimeLease struct{}

func (lifetimeLease) LeasePluginArtifact(_ context.Context, r pluginsupervisor.ArtifactLeaseRequest) (pluginsupervisor.ArtifactLease, error) {
	return pluginsupervisor.ArtifactLease{LeaseID: "lease-1", AssignmentID: r.AssignmentID, ArtifactID: r.ArtifactID, OperationRevision: r.OperationRevision, ExpiresAt: time.Now().Add(time.Minute), DownloadURL: "https://server/plugin"}, nil
}

type lifetimeDownload struct{}

func (lifetimeDownload) Download(context.Context, pluginsupervisor.ArtifactLease) (pluginsupervisor.DownloadedArtifact, error) {
	return pluginsupervisor.DownloadedArtifact{Body: io.NopCloser(bytes.NewReader([]byte("archive"))), Size: 7}, nil
}

type lifetimeHealth struct{}

func (lifetimeHealth) Handshake(context.Context, pluginsupervisor.Process, pluginsupervisor.HealthRequest) error {
	return nil
}

type lifetimeRunner struct {
	mu      sync.Mutex
	process *lifetimeProcess
}

func (r *lifetimeRunner) Start(ctx context.Context, _ pluginsupervisor.Executable, _ pluginsupervisor.LaunchConfiguration) (pluginsupervisor.Process, error) {
	p := &lifetimeProcess{ctx: ctx, done: make(chan struct{})}
	r.mu.Lock()
	r.process = p
	r.mu.Unlock()
	go func() { <-ctx.Done(); p.once.Do(func() { close(p.done) }) }()
	return p, nil
}
func (r *lifetimeRunner) current() *lifetimeProcess {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.process
}

type lifetimeProcess struct {
	ctx  context.Context
	done chan struct{}
	once sync.Once
}

func (*lifetimeProcess) PID() int                      { return 123 }
func (*lifetimeProcess) StartTicks() uint64            { return 456 }
func (*lifetimeProcess) StartedAt() time.Time          { return time.Now().UTC() }
func (p *lifetimeProcess) Drain(context.Context) error { return nil }
func (p *lifetimeProcess) Stop(context.Context) error  { return nil }
func (p *lifetimeProcess) Kill() error                 { return nil }
func (p *lifetimeProcess) Wait() error                 { <-p.done; return p.ctx.Err() }
func hexLifetime(value []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2], out[i*2+1] = digits[b>>4], digits[b&15]
	}
	return string(out)
}
