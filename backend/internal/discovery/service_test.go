package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestServiceResolvesAgentBindingAndPreservesReportScope(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	repository := &recordingRepository{binding: AgentBinding{Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, HostID: "host-1", AgentID: "agent-1"}}
	service := NewService(repository)
	service.Now = func() time.Time { return now }
	attestation, key := signedTestAttestation(t, now, 4, 10*time.Minute)
	service.RuleKeys = map[string]ed25519.PublicKey{"test": key}
	report := Report{HostID: "host-1", AgentID: "agent-1", ObservationRevision: 1, RuleRevision: 4, ObservedAt: now, RuleAttestation: attestation}
	_, err := service.RecordReport(context.Background(), report)
	require.NoError(t, err)
	require.Equal(t, repository.binding.Scope, repository.recorded.Scope)
	require.Equal(t, 10*time.Minute, repository.grace)

	report.HostID = "host-2"
	_, err = service.RecordReport(context.Background(), report)
	require.ErrorIs(t, err, ErrConflict)
}

func TestServiceIgnoreIsIdempotentForSameReason(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	candidate := candidateFixture(scope)
	repository := &recordingRepository{candidate: candidate}
	service := NewService(repository)
	first, err := service.Ignore(context.Background(), scope, candidate.ID, "not_managed")
	require.NoError(t, err)
	second, err := service.Ignore(context.Background(), scope, candidate.ID, "not_managed")
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestServiceRejectsAgentSuppliedFingerprintThatDoesNotMatchHostFacts(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	repository := &recordingRepository{binding: AgentBinding{Scope: scope, HostID: "host-1", AgentID: "agent-1"}}
	service := NewService(repository)
	attestation, key := signedTestAttestation(t, now, 4, 10*time.Minute)
	service.RuleKeys = map[string]ed25519.PublicKey{"test": key}
	service.Now = func() time.Time { return now }
	candidate := candidateFixture(scope).CandidateObservation
	candidate.Fingerprint[0] ^= 0xff
	_, err := service.RecordReport(context.Background(), Report{HostID: "host-1", AgentID: "agent-1", ObservationRevision: 1, RuleRevision: 4, ObservedAt: now, Candidates: []CandidateObservation{candidate}, RuleAttestation: attestation})
	require.ErrorIs(t, err, ErrConflict)
}

func TestServiceRejectsTamperedRuleGraceBeforeRepositoryWrite(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	repository := &recordingRepository{binding: AgentBinding{Scope: scope, HostID: "host-1", AgentID: "agent-1"}}
	service := NewService(repository)
	service.Now = func() time.Time { return now }
	attestation, key := signedTestAttestation(t, now, 4, 10*time.Minute)
	service.RuleKeys = map[string]ed25519.PublicKey{"test": key}
	attestation.DisappearanceGrace = time.Minute
	_, err := service.RecordReport(context.Background(), Report{HostID: "host-1", AgentID: "agent-1", ObservationRevision: 1, RuleRevision: 4, ObservedAt: now, RuleAttestation: attestation})
	require.ErrorIs(t, err, ErrInvalidSignature)
	require.Equal(t, uint64(0), repository.recorded.ObservationRevision)
}

func signedTestAttestation(t *testing.T, now time.Time, revision uint64, grace time.Duration) (RuleAttestation, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rules := RuleSet{Revision: revision, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), ScanInterval: time.Minute, DisappearanceGrace: grace, Rules: []Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}, DefaultPorts: []uint16{3306}}}}
	envelope, err := SignRuleSetWithKey(private, "test", rules)
	require.NoError(t, err)
	attestation, err := AttestationFor(envelope)
	require.NoError(t, err)
	return attestation, public
}

func candidateFixture(scope platformscope.Scope) Candidate {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	observation := CandidateObservation{ObservationID: "obs-1", Source: SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: 0.9, Evidence: []Evidence{{Kind: EvidenceProcessName, Value: "mysqld"}}, ObservedAt: now}
	fingerprint, _ := Fingerprint("host-1", observation)
	observation.Fingerprint = fingerprint
	return Candidate{ID: "candidate-1", Scope: scope, HostID: "host-1", AgentID: "agent-1", CandidateObservation: observation, RuleRevision: 4, ObservationRevision: 1, FirstSeenAt: now, LastSeenAt: now, Status: StatusAwaitingConfirmation}
}

type recordingRepository struct {
	binding   AgentBinding
	recorded  Report
	grace     time.Duration
	candidate Candidate
}

func (repository *recordingRepository) ResolveAgentBinding(context.Context, string) (AgentBinding, error) {
	return repository.binding, nil
}
func (repository *recordingRepository) RecordReport(_ context.Context, report Report, _ time.Time, grace time.Duration) ([]Candidate, error) {
	repository.recorded, repository.grace = report, grace
	return []Candidate{}, nil
}
func (repository *recordingRepository) List(context.Context, platformscope.Scope, Filter) (Page, error) {
	return Page{}, nil
}
func (repository *recordingRepository) Get(context.Context, platformscope.Scope, string) (Candidate, error) {
	return repository.candidate, nil
}
func (repository *recordingRepository) Ignore(_ context.Context, _ platformscope.Scope, _ string, reason string, _ time.Time) (Candidate, error) {
	repository.candidate.Status, repository.candidate.IgnoreReason = StatusIgnored, reason
	return repository.candidate, nil
}
