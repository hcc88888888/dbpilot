package inspection

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestEstimateReportBudgetAcceptsAndRejectsAtPersistedRenderLimit(t *testing.T) {
	// Break caught: Run validation must include repeated recommendation and HTML
	// escaping cost before any durable Run, Job, command, or outbox side effect.
	accepted := reportBudgetItem(strings.Repeat("a", 160_000))
	budget, err := estimateReportBudget([]Item{accepted}, []TargetRun{reportBudgetTarget("agent-a")})
	require.NoError(t, err)
	require.Equal(t, 1, budget.Findings)
	require.LessOrEqual(t, budget.MaximumRenderedBytes, maximumReportBytes)

	rejected := reportBudgetItem(strings.Repeat("a", 180_000))
	_, err = estimateReportBudget([]Item{rejected}, []TargetRun{reportBudgetTarget("agent-a")})
	require.ErrorIs(t, err, ErrReportBudgetExceeded)
}

func TestEstimateReportBudgetChecksFindingMultiplicationAndOverflow(t *testing.T) {
	items := make([]Item, 101)
	for index := range items {
		items[index] = reportBudgetItem("review")
		items[index].ID = "custom.item." + string(rune('a'+index%26)) + strings.Repeat("x", index/26)
	}
	targets := make([]TargetRun, 100)
	for index := range targets {
		targets[index] = reportBudgetTarget("agent-" + strings.Repeat("a", index/26) + string(rune('a'+index%26)))
	}

	_, err := estimateReportBudget(items, targets)
	require.ErrorIs(t, err, ErrReportBudgetExceeded)
	require.ErrorIs(t, checkedReportProduct(math.MaxInt, 2, nil), ErrReportBudgetOverflow)
}

func TestEstimateReportBudgetAcceptsLongAndHTTPSRecommendation(t *testing.T) {
	item := reportBudgetItem("See https://docs.example.test/host/filesystems?view=inspection - " + strings.Repeat("review capacity; ", 200))

	budget, err := estimateReportBudget([]Item{item}, []TargetRun{reportBudgetTarget("agent-a")})

	require.NoError(t, err)
	require.Equal(t, 1, budget.Findings)
}

func TestCreateRunRejectsReportBudgetBeforeIDsAndPersistence(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.repository.items = []Item{reportBudgetItem(strings.Repeat("a", 180_000))}
	fixture.service.NewID = func() (string, error) {
		t.Fatal("report budget rejection must happen before allocating persisted identities")
		return "", nil
	}

	_, err := fixture.service.CreateRun(context.Background(), CreateRunRequest{
		Scope: fixture.scope, Selector: TargetSelector{AgentIDs: []string{"agent-a"}},
		Items: []PolicyItem{{ItemID: "custom.report.budget", Version: 1}}, TargetTimeout: time.Minute, MaxConcurrency: 1,
		IdempotencyKey: "budget-rejected", InitiatedBy: "operator-1", RequestID: "request-budget",
	})

	require.ErrorIs(t, err, ErrReportBudgetExceeded)
	require.Empty(t, fixture.repository.run.ID)
	require.Empty(t, fixture.repository.messages)
}

func reportBudgetItem(recommendation string) Item {
	return Item{
		Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, ID: "custom.report.budget", Version: 1,
		Name: "Capacity & filesystem", Category: "capacity", ScopeType: ScopeHost, SourceType: SourceMetric,
		MetricRule:       &MetricRule{MetricName: "custom.filesystem.metric", Labels: map[string]string{}, Window: 5 * time.Minute, Aggregation: AggregationLatest, Operator: OperatorGTE, WarningThreshold: 80, CriticalThreshold: 90},
		EvidenceSelector: []string{"value"}, RecommendationTemplate: recommendation, DocumentationURL: "https://docs.example.test/inspection", Enabled: true,
	}
}

func reportBudgetTarget(id string) TargetRun {
	return TargetRun{TargetID: id, AgentID: id, DisplayName: "Database <primary>", Host: "db.example.test", Status: TargetPending, AdvertisedSources: []SourceType{SourceMetric}}
}
