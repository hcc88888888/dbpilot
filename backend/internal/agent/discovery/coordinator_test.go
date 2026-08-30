package discovery

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	domain "dbpilot.local/platform/internal/discovery"
	"github.com/stretchr/testify/require"
)

func TestCoordinatorEnrollmentTickerAndCommandUseOneScanPath(t *testing.T) {
	detector := &recordingDetector{candidate: domain.CandidateObservation{ObservationID: "native-1", Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: 0.9, Evidence: []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: "mysqld"}}}}
	reports := make(chan *agentv1.DiscoveryReport, 3)
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: detector, RuleSet: domain.RuleSet{Revision: 4, ScanInterval: time.Minute, DisappearanceGrace: time.Minute, IssuedAt: time.Now().Add(-time.Minute).UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(), Rules: []domain.Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}, DefaultPorts: []uint16{3306}}}}, Reporter: func(_ context.Context, report *agentv1.DiscoveryReport) error { reports <- report; return nil }, Now: func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }})
	require.NoError(t, err)

	require.NoError(t, coordinator.Scan(context.Background(), ScanEnrollment))
	result, err := coordinator.Execute(context.Background(), &agentv1.CommandEnvelope{CommandId: "discover-1", Command: &agentv1.CommandEnvelope_DiscoverDatabases{DiscoverDatabases: &agentv1.DiscoverDatabases{HostId: "host-1", RuleRevision: 4, IncludeNative: true}}}, nil)
	require.NoError(t, err)
	require.Equal(t, agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, result.State)
	require.Equal(t, 2, detector.calls)
	first, second := <-reports, <-reports
	require.Equal(t, uint64(1), first.ObservationRevision)
	require.Equal(t, uint64(2), second.ObservationRevision)
	require.Equal(t, first.Candidates[0].Fingerprint, second.Candidates[0].Fingerprint)
}

func TestCoordinatorRetriesEnrollmentReportUntilControlStreamConnects(t *testing.T) {
	detector := &recordingDetector{candidate: domain.CandidateObservation{ObservationID: "native-1", Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: .9, Evidence: []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: "mysqld"}}}}
	attempts := 0
	delivered := make(chan struct{}, 1)
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: detector, RuleSet: domain.RuleSet{Revision: 4, ScanInterval: time.Minute, DisappearanceGrace: time.Minute, IssuedAt: time.Now().Add(-time.Minute).UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(), Rules: []domain.Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}, DefaultPorts: []uint16{3306}}}}, RetryBackoff: time.Millisecond, Reporter: func(context.Context, *agentv1.DiscoveryReport) error {
		attempts++
		if attempts == 1 {
			return errors.New("stream disconnected")
		}
		delivered <- struct{}{}
		return nil
	}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- coordinator.Run(ctx) }()
	<-delivered
	cancel()
	require.NoError(t, <-done)
	require.Equal(t, 2, attempts)
}

func TestFileRevisionStoreSurvivesAgentRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "discovery-revision")
	first, err := NewFileRevisionStore(path)
	require.NoError(t, err)
	revision, err := first.Next(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(1), revision)
	second, err := NewFileRevisionStore(path)
	require.NoError(t, err)
	revision, err = second.Next(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(2), revision)
}

func TestFileRevisionStoreRecoversFromOneTornSlot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "discovery-revision")
	store, err := NewFileRevisionStore(path)
	require.NoError(t, err)
	_, err = store.Next(context.Background())
	require.NoError(t, err)
	_, err = store.Next(context.Background())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path+".a", []byte("torn"), 0o600))
	recovered, err := NewFileRevisionStore(path)
	require.NoError(t, err)
	revision, err := recovered.Next(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(3), revision)
}

type recordingDetector struct {
	calls     int
	candidate domain.CandidateObservation
}

func (detector *recordingDetector) Discover(context.Context, []domain.Rule) ([]domain.CandidateObservation, error) {
	detector.calls++
	return []domain.CandidateObservation{detector.candidate}, nil
}
