package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	domain "dbpilot.local/platform/internal/discovery"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCoordinatorEnrollmentTickerAndCommandUseOneScanPath(t *testing.T) {
	detector := &recordingDetector{candidate: domain.CandidateObservation{ObservationID: "native-1", Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: 0.9, Evidence: []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: "mysqld"}}}}
	reports := make(chan *agentv1.DiscoveryReport, 3)
	rules, attestation := testRules(t)
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: detector, RuleSet: rules, Attestation: attestation, Reporter: func(_ context.Context, report *agentv1.DiscoveryReport) error { reports <- report; return nil }, Now: func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }})
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
	rules, attestation := testRules(t)
	var digests [][32]byte
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: detector, RuleSet: rules, Attestation: attestation, RetryBackoff: time.Millisecond, Now: func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }, Reporter: func(_ context.Context, report *agentv1.DiscoveryReport) error {
		attempts++
		digest, _ := ReportDigest(report)
		digests = append(digests, digest)
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
	require.Equal(t, digests[0], digests[1])
	require.Equal(t, 1, detector.calls, "unknown delivery outcome must replay without rescanning")
}

func TestCoordinatorStopsNewScansAndCommandsWhenRulesExpire(t *testing.T) {
	detector := &recordingDetector{candidate: domain.CandidateObservation{ObservationID: "native-1", Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: .9, Evidence: []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: "mysqld"}}}}
	rules, attestation := testRules(t)
	current := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: detector, RuleSet: rules, Attestation: attestation, Now: func() time.Time { return current }, Reporter: func(context.Context, *agentv1.DiscoveryReport) error { return nil }})
	require.NoError(t, err)
	require.NoError(t, coordinator.Scan(context.Background(), ScanEnrollment))
	require.Equal(t, 1, detector.calls)
	current = time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	require.Error(t, coordinator.Scan(context.Background(), ScanPeriodic))
	_, err = coordinator.Execute(context.Background(), &agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_DiscoverDatabases{DiscoverDatabases: &agentv1.DiscoverDatabases{HostId: "host-1", RuleRevision: 4, IncludeNative: true}}}, nil)
	require.Error(t, err)
	require.Equal(t, 1, detector.calls)
}

func TestCoordinatorRetiresExactTerminallyRejectedPendingReportAndAdvances(t *testing.T) {
	detector := &recordingDetector{candidate: domain.CandidateObservation{ObservationID: "native-1", Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: .9, Evidence: []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: "mysqld"}}}}
	rules, attestation := testRules(t)
	attempts := 0
	var revisions []uint64
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: detector, RuleSet: rules, Attestation: attestation, Now: func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }, Reporter: func(_ context.Context, report *agentv1.DiscoveryReport) error {
		attempts++
		revisions = append(revisions, report.GetObservationRevision())
		if attempts == 1 {
			return terminalReportError{}
		}
		return nil
	}})
	require.NoError(t, err)
	require.Error(t, coordinator.Scan(context.Background(), ScanEnrollment))
	require.NoError(t, coordinator.Scan(context.Background(), ScanPeriodic))
	require.Equal(t, []uint64{1, 2}, revisions)
	require.Equal(t, 2, detector.calls)
}

type terminalReportError struct{}

func (terminalReportError) Error() string               { return "terminal" }
func (terminalReportError) NonRetryableDiscovery() bool { return true }

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

func TestRuleStateRejectsRollbackAndConflictingSameRevisionAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rule-state")
	store, err := NewRuleStateStore(path)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("revision-9"))
	require.NoError(t, store.Accept(context.Background(), 9, digest))
	restarted, err := NewRuleStateStore(path)
	require.NoError(t, err)
	require.Error(t, restarted.Accept(context.Background(), 8, sha256.Sum256([]byte("revision-8"))))
	require.Error(t, restarted.Accept(context.Background(), 9, sha256.Sum256([]byte("different"))))
	require.NoError(t, restarted.Accept(context.Background(), 9, digest))
}

func TestFileReportStoreReplaysByteIdenticalUnknownOutcome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pending.pb")
	store, err := NewFileReportStore(path)
	require.NoError(t, err)
	report := validPendingReportFixture()
	require.NoError(t, store.Save(context.Background(), report))
	restarted, err := NewFileReportStore(path)
	require.NoError(t, err)
	loaded, err := restarted.Load(context.Background())
	require.NoError(t, err)
	left, _ := ReportDigest(report)
	right, _ := ReportDigest(loaded)
	require.Equal(t, left, right)
	require.NoError(t, restarted.Clear(context.Background(), loaded))
	empty, err := restarted.Load(context.Background())
	require.NoError(t, err)
	require.Nil(t, empty)
}

func TestFileReportStoreRecoversValidOrphanTempAndDeletesTornTemp(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "pending.pb")
	report := validPendingReportFixture()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path+".tmp", encoded, 0o600))
	store, err := NewFileReportStore(path)
	require.NoError(t, err)
	loaded, err := store.Load(context.Background())
	require.NoError(t, err)
	left, _ := ReportDigest(report)
	right, _ := ReportDigest(loaded)
	require.Equal(t, left, right)
	require.NoError(t, store.Clear(context.Background(), loaded))
	require.NoError(t, os.WriteFile(path+".tmp", []byte("torn"), 0o600))
	store, err = NewFileReportStore(path)
	require.NoError(t, err)
	require.NoError(t, store.Save(context.Background(), report), "torn orphan must not permanently block later publication")
}

func TestRuleStateSameParityJumpPreservesPreviousGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules")
	store, err := NewRuleStateStore(path)
	require.NoError(t, err)
	one := sha256.Sum256([]byte("one"))
	three := sha256.Sum256([]byte("three"))
	require.NoError(t, store.Accept(context.Background(), 1, one))
	require.NoError(t, store.Accept(context.Background(), 3, three))
	restarted, err := NewRuleStateStore(path)
	require.NoError(t, err)
	require.Error(t, restarted.Accept(context.Background(), 2, sha256.Sum256([]byte("two"))))
	require.NoError(t, restarted.Accept(context.Background(), 3, three))
}

func TestRuleStateRecoversValidTempAndRejectsConflictingSlots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules")
	one := sha256.Sum256([]byte("one"))
	store, err := NewRuleStateStore(path)
	require.NoError(t, err)
	require.NoError(t, store.Accept(context.Background(), 1, one))
	two := sha256.Sum256([]byte("two"))
	encoded, err := json.Marshal(AcceptedRuleState{Revision: 2, Digest: hex.EncodeToString(two[:])})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path+".b.tmp", encoded, 0o600))
	recovered, err := NewRuleStateStore(path)
	require.NoError(t, err)
	require.Error(t, recovered.Accept(context.Background(), 1, one))
	conflict, err := json.Marshal(AcceptedRuleState{Revision: 2, Digest: hex.EncodeToString(one[:])})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path+".a", conflict, 0o600))
	_, err = NewRuleStateStore(path)
	require.Error(t, err)
}

func TestCoordinatorRejectsOversizedReportBeforeAllocatingRevision(t *testing.T) {
	rules, attestation := testRules(t)
	candidates := make([]domain.CandidateObservation, 1024)
	for index := range candidates {
		evidence := make([]domain.Evidence, 32)
		for item := range evidence {
			evidence[item] = domain.Evidence{Kind: domain.EvidenceVersionHint, Value: fmt.Sprintf("%03d-%02d-%s", index, item, strings.Repeat("x", 245))}
		}
		candidates[index] = domain.CandidateObservation{ObservationID: fmt.Sprintf("obs-%d", index), Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: fmt.Sprintf("127.0.0.1:%d", 10000+index), ProcessIdentity: "mysqld", Confidence: .9, Evidence: evidence}
	}
	revisions := &countingRevisionStore{}
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: staticCandidatesDetector(candidates), RuleSet: rules, Attestation: attestation, RevisionStore: revisions, Now: func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }, Reporter: func(context.Context, *agentv1.DiscoveryReport) error { return nil }})
	require.NoError(t, err)
	require.Error(t, coordinator.Scan(context.Background(), ScanEnrollment))
	require.Zero(t, revisions.calls)
}

type staticCandidatesDetector []domain.CandidateObservation

func (detector staticCandidatesDetector) Discover(context.Context, []domain.Rule) ([]domain.CandidateObservation, error) {
	return detector, nil
}

type countingRevisionStore struct{ calls int }

func (store *countingRevisionStore) Next(context.Context) (uint64, error) {
	store.calls++
	return uint64(store.calls), nil
}

func validPendingReportFixture() *agentv1.DiscoveryReport {
	now := timestamppb.New(time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC))
	return &agentv1.DiscoveryReport{HostId: "host-1", AgentId: "agent-1", ObservationRevision: 7, RuleRevision: 4, ObservedAt: now, RuleSetDigest: make([]byte, 32), DisappearanceGraceSeconds: 60, RuleIssuedAt: now, RuleExpiresAt: timestamppb.New(now.AsTime().Add(time.Hour)), RuleAttestationSignature: make([]byte, 64), RuleAttestationVersion: 1, RuleAttestationAlgorithm: "ed25519-sha256", RuleAttestationKeyId: "test"}
}

type recordingDetector struct {
	calls     int
	candidate domain.CandidateObservation
}

func testRules(t *testing.T) (domain.RuleSet, domain.RuleAttestation) {
	t.Helper()
	rules := domain.RuleSet{Revision: 4, ScanInterval: time.Minute, DisappearanceGrace: time.Minute, IssuedAt: time.Date(2026, 8, 30, 7, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC), Rules: []domain.Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}, DefaultPorts: []uint16{3306}}}}
	digest, err := domain.CanonicalRuleSetDigest(rules)
	require.NoError(t, err)
	return rules, domain.RuleAttestation{Version: domain.RuleAttestationVersion, Algorithm: domain.RuleAttestationAlgorithm, KeyID: "test", Revision: rules.Revision, Digest: digest, IssuedAt: rules.IssuedAt, ExpiresAt: rules.ExpiresAt, DisappearanceGrace: rules.DisappearanceGrace, Signature: make([]byte, 64)}
}

func (detector *recordingDetector) Discover(context.Context, []domain.Rule) ([]domain.CandidateObservation, error) {
	detector.calls++
	return []domain.CandidateObservation{detector.candidate}, nil
}
