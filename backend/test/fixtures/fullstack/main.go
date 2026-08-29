package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if len(arguments) == 0 {
		fmt.Fprintln(stderr, "subcommand is required: bootstrap, oidc, database, journal, or replay")
		return 2
	}
	switch arguments[0] {
	case "bootstrap":
		return runBootstrap(arguments[1:], stdout, stderr)
	case "oidc":
		return runOIDC(arguments[1:], stderr)
	case "database":
		return runDatabaseAssertions(arguments[1:], stderr)
	case "journal":
		return runJournalAssertions(arguments[1:], stderr)
	case "replay":
		return runReplayAssertions(arguments[1:], stderr)
	default:
		fmt.Fprintln(stderr, "unknown subcommand")
		return 2
	}
}

func runReplayAssertions(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("replay", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dsnFile := flags.String("dsn-file", "", "absolute PostgreSQL DSN file")
	phaseStateFile := flags.String("phase-state-file", "", "absolute full-stack phase state file")
	spoolRoot := flags.String("spool-root", "", "absolute stopped Agent spool root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !filepath.IsAbs(*dsnFile) || !filepath.IsAbs(*phaseStateFile) || !filepath.IsAbs(*spoolRoot) {
		return 2
	}
	dsnBody, err := readBoundedRegularFile(*dsnFile, 8<<10, true)
	if err != nil || len(dsnBody) == 0 {
		fmt.Fprintln(stderr, "database credential is unavailable")
		return 2
	}
	dsn := string(dsnBody)
	defer zeroBytes(dsnBody)
	var state AssertionOptions
	if err := decodeJSONFile(*phaseStateFile, 64<<10, &state); err != nil {
		fmt.Fprintln(stderr, "replay phase state is unavailable or invalid")
		return 2
	}
	database, err := sql.Open("postgres", dsn)
	if err != nil {
		fmt.Fprintln(stderr, "replay assertion connection failed")
		return 1
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	evidence, err := AssertReplay(ctx, database, *spoolRoot, ReplayAssertion{
		TenantID: state.TenantID, ProjectID: state.ProjectID, AgentID: state.OnlineAgentID,
		ControlplaneStoppedAt: state.ControlplaneStoppedAt, ControlplaneRestartedAt: state.ControlplaneRestartedAt,
	})
	if err != nil {
		fmt.Fprintln(stderr, redactAssertionError(err, []string{dsn}))
		return 1
	}
	state, err = WithReplayEvidence(state, evidence)
	if err != nil || writeJSONFileAtomic(*phaseStateFile, state) != nil {
		fmt.Fprintln(stderr, "replay evidence persistence failed")
		return 1
	}
	return 0
}

func writeJSONFileAtomic(path string, value any) (resultErr error) {
	if !filepath.IsAbs(path) || value == nil {
		return errors.New("JSON output is invalid")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".phase-state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if resultErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	encoder := json.NewEncoder(temporary)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func runBootstrap(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "absolute bootstrap output root")
	issuer := flags.String("issuer", "https://oidc:9444", "OIDC issuer")
	audience := flags.String("audience", "dbpilot-control-plane", "OIDC audience")
	tenantID := flags.String("tenant-id", "tenant-acceptance", "acceptance tenant ID")
	projectID := flags.String("project-id", "project-acceptance", "acceptance project ID")
	onlineAgentID := flags.String("online-agent-id", "agent-online", "online Agent ID")
	offlineAgentID := flags.String("offline-agent-id", "agent-offline", "offline Agent ID")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return 2
	}
	manifest, err := GenerateBootstrap(context.Background(), BootstrapOptions{
		Root: *root, Issuer: *issuer, Audience: *audience, TenantID: *tenantID, ProjectID: *projectID,
		OnlineAgentID: *onlineAgentID, OfflineAgentID: *offlineAgentID, Now: time.Now().UTC(), Random: rand.Reader,
	})
	if err != nil {
		fmt.Fprintln(stderr, "bootstrap generation failed")
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		fmt.Fprintln(stderr, "bootstrap manifest output failed")
		return 1
	}
	return 0
}

func runOIDC(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("oidc", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "absolute OIDC configuration path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !filepath.IsAbs(*configPath) {
		return 2
	}
	var config OIDCConfig
	if err := decodeJSONFile(*configPath, 64<<10, &config); err != nil {
		fmt.Fprintln(stderr, "OIDC configuration is unavailable or invalid")
		return 2
	}
	server, err := NewOIDCServer(config)
	if err != nil {
		fmt.Fprintln(stderr, "OIDC server configuration failed")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownContext)
	}()
	serveErr := server.ListenAndServeTLS("", "")
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "OIDC HTTPS server failed")
		cancel()
		<-shutdownDone
		return 1
	}
	cancel()
	<-shutdownDone
	return 0
}

func runDatabaseAssertions(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("database", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dsnFile := flags.String("dsn-file", "", "absolute PostgreSQL DSN file")
	assertionsFile := flags.String("assertions-file", "", "absolute assertion options file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !filepath.IsAbs(*dsnFile) || !filepath.IsAbs(*assertionsFile) {
		return 2
	}
	dsnBody, err := readBoundedRegularFile(*dsnFile, 8<<10, true)
	if err != nil || len(dsnBody) == 0 {
		fmt.Fprintln(stderr, "database credential is unavailable")
		return 2
	}
	dsn := string(dsnBody)
	defer zeroBytes(dsnBody)
	var options AssertionOptions
	if err := decodeJSONFile(*assertionsFile, 64<<10, &options); err != nil {
		fmt.Fprintln(stderr, "database assertion options are unavailable or invalid")
		return 2
	}
	options.SensitiveValues = append(options.SensitiveValues, dsn)
	database, err := sql.Open("postgres", dsn)
	if err != nil {
		fmt.Fprintln(stderr, "database assertion connection failed")
		return 1
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := AssertDatabase(ctx, database, options); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func runJournalAssertions(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("journal", flag.ContinueOnError)
	flags.SetOutput(stderr)
	journalPath := flags.String("path", "", "absolute Agent journal path")
	assertionsFile := flags.String("assertions-file", "", "absolute journal assertion options file")
	phaseStateFile := flags.String("phase-state-file", "", "absolute full-stack phase state file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !filepath.IsAbs(*journalPath) || (filepath.IsAbs(*assertionsFile) == filepath.IsAbs(*phaseStateFile)) {
		return 2
	}
	var assertion JournalAssertion
	if filepath.IsAbs(*phaseStateFile) {
		var phase AssertionOptions
		if err := decodeJSONFile(*phaseStateFile, 64<<10, &phase); err != nil || phase.JournalCommandID == "" {
			fmt.Fprintln(stderr, "journal phase state is unavailable or invalid")
			return 2
		}
		assertion.CommandID = phase.JournalCommandID
	} else {
		if err := decodeJSONFile(*assertionsFile, 64<<10, &assertion); err != nil {
			fmt.Fprintln(stderr, "journal assertion options are unavailable or invalid")
			return 2
		}
	}
	if err := AssertJournal(*journalPath, assertion); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func decodeJSONFile(path string, limit int64, destination any) error {
	if !filepath.IsAbs(path) || destination == nil {
		return errors.New("JSON file input is invalid")
	}
	body, err := readBoundedRegularFile(path, limit, false)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
