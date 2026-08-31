//go:build linux

package pluginsupervisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type OSProcessRunnerConfig struct {
	OutputLimit     int
	Now             func() time.Time
	FailureObserver func(string, error)
}

type OSProcessRunner struct {
	outputLimit     int
	now             func() time.Time
	failureObserver func(string, error)
}

func NewOSProcessRunner(config OSProcessRunnerConfig) *OSProcessRunner {
	if config.OutputLimit <= 0 || config.OutputLimit > MaxPluginOutputBytes {
		config.OutputLimit = MaxPluginOutputBytes
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &OSProcessRunner{outputLimit: config.OutputLimit, now: config.Now, failureObserver: config.FailureObserver}
}

func (runner *OSProcessRunner) Start(ctx context.Context, executable Executable, config LaunchConfiguration) (Process, error) {
	if runner == nil || ctx == nil || ctx.Err() != nil || validateLaunch(executable, config) != nil {
		return nil, runner.failure("validation", ErrProcessStart)
	}
	if err := verifyExecutable(executable); err != nil {
		return nil, runner.failure("executable_verification", err)
	}
	args, environment, err := buildLaunch(config)
	if err != nil {
		return nil, runner.failure("launch_configuration", err)
	}
	command := exec.CommandContext(ctx, executable.Path, args...)
	command.Dir = config.RuntimeDirectory
	command.Env = environment
	if os.Geteuid() == 0 || config.UserID != uint32(os.Geteuid()) || config.GroupID != uint32(os.Getegid()) {
		return nil, runner.failure("process_identity", ErrProcessStart)
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	stdout := newBoundedOutput(runner.outputLimit)
	stderr := newBoundedOutput(runner.outputLimit)
	command.Stdout, command.Stderr = stdout, stderr
	startedAt := runner.now().UTC()
	if err := command.Start(); err != nil {
		return nil, runner.failure("direct_exec", err)
	}
	startTicks, err := readProcessStartTicks(command.Process.Pid)
	if err != nil {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
		return nil, runner.failure("process_start_time", err)
	}
	process := &osProcess{command: command, pid: command.Process.Pid, startTicks: startTicks, startedAt: startedAt, stdout: stdout, stderr: stderr, done: make(chan struct{})}
	go process.wait()
	return process, nil
}

func (runner *OSProcessRunner) failure(stage string, cause error) error {
	if runner != nil && runner.failureObserver != nil {
		runner.failureObserver(stage, cause)
	}
	return ErrProcessStart
}

type osProcess struct {
	command    *exec.Cmd
	pid        int
	startTicks uint64
	startedAt  time.Time
	stdout     *boundedOutput
	stderr     *boundedOutput
	done       chan struct{}
	waitOnce   sync.Once
	waitErr    error
}

func (process *osProcess) PID() int             { return process.pid }
func (process *osProcess) StartTicks() uint64   { return process.startTicks }
func (process *osProcess) StartedAt() time.Time { return process.startedAt }

func (process *osProcess) wait() {
	process.waitOnce.Do(func() {
		process.waitErr = process.command.Wait()
		close(process.done)
	})
}

func (process *osProcess) Wait() error {
	if process == nil {
		return ErrProcessStart
	}
	<-process.done
	return normalizeExit(process.waitErr)
}

func (process *osProcess) Drain(ctx context.Context) error {
	return process.terminate(ctx)
}

func (process *osProcess) Stop(ctx context.Context) error {
	return process.terminate(ctx)
}

func (process *osProcess) terminate(ctx context.Context) error {
	if process == nil || ctx == nil {
		return ErrProcessStart
	}
	select {
	case <-process.done:
		return nil
	default:
	}
	if err := syscall.Kill(-process.pid, syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH) {
		return ErrProcessStart
	}
	select {
	case <-process.done:
		return nil
	case <-ctx.Done():
		if err := process.Kill(); err != nil {
			return err
		}
		<-process.done
		return nil
	}
}

func (process *osProcess) Kill() error {
	if process == nil {
		return ErrProcessStart
	}
	if err := syscall.Kill(-process.pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return ErrProcessStart
	}
	return nil
}

func (process *osProcess) Output() (string, string) {
	if process == nil {
		return "", ""
	}
	return redactOutput(process.stdout.String()), redactOutput(process.stderr.String())
}

func validateLaunch(executable Executable, config LaunchConfiguration) error {
	if !filepath.IsAbs(executable.Path) || filepath.Clean(executable.Path) != executable.Path || len(executable.SHA256) != sha256.Size*2 || !resourceIdentifier.MatchString(config.AssignmentID) || !familyIdentifier.MatchString(config.PluginID) || !familyIdentifier.MatchString(config.DatabaseFamily) || !boundedVersion(config.Version) || config.Slot != "A" && config.Slot != "B" || config.ConfigurationRevision == 0 || config.OperationRevision == 0 || !filepath.IsAbs(config.RuntimeDirectory) || filepath.Clean(config.RuntimeDirectory) != config.RuntimeDirectory || len(config.InstanceIDs) > MaxAssignedInstances || len(config.TemplateIDs) > MaxAssignedTemplates || !uniqueResources(config.InstanceIDs) || !uniqueResources(config.TemplateIDs) {
		return ErrProcessStart
	}
	return nil
}

func verifyExecutable(executable Executable) error {
	info, err := os.Lstat(executable.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o500 || linkCount(info) > 1 {
		return ErrProcessStart
	}
	file, err := os.Open(executable.Path)
	if err != nil {
		return ErrProcessStart
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, 512<<20+1)); err != nil || hex.EncodeToString(hash.Sum(nil)) != executable.SHA256 {
		return ErrProcessStart
	}
	return nil
}

func buildLaunch(config LaunchConfiguration) ([]string, []string, error) {
	instances, err := json.Marshal(config.InstanceIDs)
	if err != nil || len(instances) > 128<<10 {
		return nil, nil, ErrProcessStart
	}
	templates, err := json.Marshal(config.TemplateIDs)
	if err != nil || len(templates) > 128<<10 {
		return nil, nil, ErrProcessStart
	}
	args := []string{
		"--runtime-dir", config.RuntimeDirectory,
		"--assignment-id", config.AssignmentID,
		"--plugin-id", config.PluginID,
		"--database-family", config.DatabaseFamily,
		"--version", config.Version,
		"--slot", string(config.Slot),
		"--configuration-revision", strconv.FormatUint(config.ConfigurationRevision, 10),
		"--operation-revision", strconv.FormatUint(config.OperationRevision, 10),
		"--instance-ids", string(instances),
		"--template-ids", string(templates),
	}
	environment := []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + config.RuntimeDirectory, "DBPILOT_PLUGIN_PROCESS=1"}
	return args, environment, nil
}

func readProcessStartTicks(pid int) (uint64, error) {
	body, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	closing := bytes.LastIndexByte(body, ')')
	if closing < 0 || closing+2 >= len(body) {
		return 0, ErrProcessStart
	}
	fields := strings.Fields(string(body[closing+2:]))
	// Field 22 overall is offset 19 after pid and comm are removed.
	if len(fields) <= 19 {
		return 0, ErrProcessStart
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || value == 0 {
		return 0, ErrProcessStart
	}
	return value, nil
}

type boundedOutput struct {
	mu    sync.Mutex
	limit int
	value []byte
}

func newBoundedOutput(limit int) *boundedOutput { return &boundedOutput{limit: limit} }

func (output *boundedOutput) Write(value []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	remaining := output.limit - len(output.value)
	if remaining > 0 {
		if len(value) < remaining {
			remaining = len(value)
		}
		output.value = append(output.value, value[:remaining]...)
	}
	return len(value), nil
}

func (output *boundedOutput) String() string {
	output.mu.Lock()
	defer output.mu.Unlock()
	return string(append([]byte(nil), output.value...))
}

func redactOutput(value string) string {
	for _, marker := range []string{"password=", "passwd=", "secret=", "token=", "authorization:"} {
		lower := strings.ToLower(value)
		for {
			index := strings.Index(lower, marker)
			if index < 0 {
				break
			}
			end := index + len(marker)
			for end < len(value) && value[end] != ' ' && value[end] != '\n' && value[end] != '\r' && value[end] != '\t' {
				end++
			}
			value = value[:index] + marker + "<redacted>" + value[end:]
			lower = strings.ToLower(value)
		}
	}
	return value
}

func normalizeExit(err error) error {
	if err == nil {
		return nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return nil
	}
	return fmt.Errorf("%w", ErrProcessStart)
}

var _ ProcessRunner = (*OSProcessRunner)(nil)
var _ Process = (*osProcess)(nil)

func CurrentProcessIdentity() (uint32, uint32, bool) {
	if os.Geteuid() <= 0 || os.Getegid() <= 0 {
		return 0, 0, false
	}
	return uint32(os.Geteuid()), uint32(os.Getegid()), true
}
