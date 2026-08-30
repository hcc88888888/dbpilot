package discovery

import (
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestCandidateObservationRejectsUnboundedOrSecretEvidence(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	base := CandidateObservation{
		ObservationID: "obs-1", Source: SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql",
		NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: 0.9,
		Evidence: []Evidence{{Kind: EvidenceProcessName, Value: "mysqld"}}, ObservedAt: now,
	}
	require.NoError(t, base.Validate())

	secret := base
	secret.Evidence = []Evidence{{Kind: EvidenceProcessName, Value: "mysqld --password=hunter2"}}
	require.ErrorIs(t, secret.Validate(), ErrSecretEvidence)

	tooMany := base
	tooMany.Evidence = make([]Evidence, MaximumEvidenceItems+1)
	for index := range tooMany.Evidence {
		tooMany.Evidence[index] = Evidence{Kind: EvidenceProcessName, Value: "mysqld"}
	}
	require.ErrorIs(t, tooMany.Validate(), ErrInvalid)
}

func TestReportRequiresExactScopedMonotonicIdentity(t *testing.T) {
	report := Report{
		Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, HostID: "host-1", AgentID: "agent-1",
		ObservationRevision: 2, RuleRevision: 7, ObservedAt: time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC),
	}
	require.NoError(t, report.Validate())
	report.ObservationRevision = 0
	require.ErrorIs(t, report.Validate(), ErrInvalid)
}
