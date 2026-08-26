package alert_test

import (
	"math"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"github.com/stretchr/testify/require"
)

func TestRuleValidateRejectsUnsafeOrIncompleteDefinition(t *testing.T) {
	rule := alert.AlertRule{
		Scope:           alert.Scope{TenantID: "t1", ProjectID: "p1"},
		Name:            "cpu",
		Metric:          "host.cpu",
		Aggregation:     "avg",
		Operator:        ">",
		Threshold:       80,
		EvaluationEvery: time.Minute,
		For:             time.Minute,
		MissingData:     "ignore",
		Severity:        "critical",
	}
	require.NoError(t, rule.Validate())

	rule.Aggregation = "promql"
	require.Error(t, rule.Validate())
}

func TestRuleValidateRejectsNonFiniteThreshold(t *testing.T) {
	rule := alert.AlertRule{
		Scope:           alert.Scope{TenantID: "t1", ProjectID: "p1"},
		Name:            "cpu",
		Metric:          "host.cpu",
		Aggregation:     "avg",
		Operator:        ">",
		Threshold:       math.NaN(),
		EvaluationEvery: time.Minute,
		For:             time.Minute,
		MissingData:     "ignore",
		Severity:        "critical",
	}
	require.Error(t, rule.Validate())
}

func TestFingerprintIgnoresLabelOrder(t *testing.T) {
	require.Equal(t,
		alert.EventFingerprint(alert.Scope{"t1", "p1"}, "r1", map[string]string{"host": "a", "role": "db"}),
		alert.EventFingerprint(alert.Scope{"t1", "p1"}, "r1", map[string]string{"role": "db", "host": "a"}),
	)
}

func TestPrincipalAllowsOnlyAssignedProjectsUnlessPlatformAdmin(t *testing.T) {
	projectScope := alert.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	require.True(t, (alert.Principal{Subject: "user", Projects: map[string]struct{}{"project-a": {}}}).Allows(projectScope))
	require.False(t, (alert.Principal{Subject: "user", Projects: map[string]struct{}{"project-b": {}}}).Allows(projectScope))
	require.True(t, (alert.Principal{Subject: "admin", PlatformAdmin: true}).Allows(projectScope))
}

func TestEventTransitionPreservesFirstSeenAndRecordsStateTimes(t *testing.T) {
	firstSeen := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	firedAt := firstSeen.Add(time.Minute)
	event := alert.AlertEvent{State: alert.EventPending, FirstSeen: firstSeen}

	transitioned, err := event.Transition(alert.EventFiring, firedAt, "operator")
	require.NoError(t, err)
	require.Equal(t, firstSeen, transitioned.FirstSeen)
	require.Equal(t, firedAt, transitioned.FiringAt)
	require.Equal(t, firedAt, transitioned.LastSeen)
	require.Equal(t, alert.EventFiring, transitioned.State)
	require.Equal(t, "operator", transitioned.LastActor)

	_, err = transitioned.Transition(alert.EventPending, firedAt.Add(time.Minute), "operator")
	require.Error(t, err)
}
