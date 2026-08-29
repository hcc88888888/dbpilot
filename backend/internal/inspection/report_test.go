package inspection

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRenderJSONIsDeterministicSortedAndContainsVersionedReferences(t *testing.T) {
	// Break caught: map/row iteration order must not change immutable artifact
	// bytes or omit the versions and operational correlations used for audit.
	snapshot := reportRendererFixture()
	first, err := RenderJSON(snapshot)
	require.NoError(t, err)
	second, err := RenderJSON(snapshot)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.True(t, bytes.HasSuffix(first, []byte("\n")))

	var document ReportDocument
	require.NoError(t, json.Unmarshal(first, &document))
	require.Equal(t, int64(7), document.Policy.Version)
	require.Equal(t, []string{"cpu.utilization", "disk.utilization"}, []string{document.Items[0].ID, document.Items[1].ID})
	require.Equal(t, []int{3, 2}, []int{document.Items[0].Version, document.Items[1].Version})
	require.Equal(t, []string{"agent-a", "agent-b"}, []string{document.Targets[0].TargetID, document.Targets[1].TargetID})
	require.Equal(t, "job-a", document.References.JobID)
	require.Equal(t, "inspection-run:run-a", document.References.AuditCorrelation)
	require.Equal(t, []string{"command-agent-a", "command-agent-b"}, []string{document.References.Commands[0].CommandID, document.References.Commands[1].CommandID})
	require.Less(t, bytes.Index(first, []byte(`"report_id"`)), bytes.Index(first, []byte(`"run_id"`)), "top-level key order is part of the stable format")
}

func TestRenderHTMLEscapesEveryExternalStringAndOmitsScopeInternals(t *testing.T) {
	// Break caught: names, host labels, summaries, and recommendations are all
	// externally supplied strings and must never become executable HTML.
	snapshot := reportRendererFixture()
	html, err := RenderHTML(snapshot)
	require.NoError(t, err)
	text := string(html)
	for _, unsafe := range []string{"<script>", "<img", `onerror="alert(1)"`} {
		require.NotContains(t, text, unsafe)
	}
	for _, escaped := range []string{"&lt;script&gt;", "&lt;img", "CPU &lt;utilization&gt;"} {
		require.Contains(t, text, escaped)
	}
	for _, required := range []string{"policy-a", "version 7", "cpu.utilization", "version 3", "job-a", "command-agent-a", "inspection-run:run-a", "Warning threshold", "Critical threshold", "system.disk.utilization", "82"} {
		require.Contains(t, text, required)
	}
	for _, forbidden := range []string{"tenant-a", "project-a", `"scope"`, "raw_log", "connection_string"} {
		require.NotContains(t, text, forbidden)
	}
}

func TestRenderersRejectCredentialConnectionAndRawLogMaterial(t *testing.T) {
	// Break caught: escaping makes dangerous HTML inert but does not make
	// credentials or raw logs acceptable report content.
	tests := []string{
		"password=hunter2",
		"postgres://user:secret@db.internal/app",
		"mongodb://db.internal/app",
		"jdbc:oracle:thin:@db.internal:1521/service",
		"Authorization: Bearer abc",
		"-----BEGIN PRIVATE KEY-----",
	}
	for _, unsafe := range tests {
		t.Run(unsafe[:minInt(len(unsafe), 12)], func(t *testing.T) {
			snapshot := reportRendererFixture()
			snapshot.Document.Findings[0].Evidence["value"] = unsafe
			_, jsonErr := RenderJSON(snapshot)
			_, htmlErr := RenderHTML(snapshot)
			require.ErrorIs(t, jsonErr, ErrUnsafeReport)
			require.ErrorIs(t, htmlErr, ErrUnsafeReport)
		})
	}
}

func TestRenderersAllowHTTPSDocumentationAndLongRecommendationText(t *testing.T) {
	snapshot := reportRendererFixture()
	recommendation := "See https://docs.example.test/inspection/filesystems?view=host&lang=en - " + strings.Repeat("review capacity; ", 200)
	snapshot.Document.Findings[0].Recommendation = recommendation

	jsonReport, jsonErr := RenderJSON(snapshot)
	htmlReport, htmlErr := RenderHTML(snapshot)

	require.NoError(t, jsonErr)
	require.NoError(t, htmlErr)
	require.Contains(t, string(jsonReport), "https://docs.example.test/inspection/filesystems")
	require.Contains(t, string(htmlReport), "https://docs.example.test/inspection/filesystems")
}

func TestRenderersBoundReportOutput(t *testing.T) {
	// Break caught: persisted snapshots and renderer output need a hard bound so
	// a pathological external display string cannot exhaust worker memory/disk.
	snapshot := reportRendererFixture()
	snapshot.Document.Targets[0].DisplayName = strings.Repeat("x", maximumReportBytes+1)
	_, jsonErr := RenderJSON(snapshot)
	_, htmlErr := RenderHTML(snapshot)
	require.ErrorIs(t, jsonErr, ErrReportTooLarge)
	require.ErrorIs(t, htmlErr, ErrReportTooLarge)
}

func TestRenderersRejectSnapshotIdentityMismatch(t *testing.T) {
	// Break caught: a row-level report ID must bind the embedded immutable
	// document so content from another Run cannot be served under this report.
	snapshot := reportRendererFixture()
	snapshot.ID = "inspection-report-other"
	_, jsonErr := RenderJSON(snapshot)
	_, htmlErr := RenderHTML(snapshot)
	require.ErrorIs(t, jsonErr, ErrInvalidReport)
	require.ErrorIs(t, htmlErr, ErrInvalidReport)
}

func TestRenderersAcceptStableReportIDForMaximumLengthRunID(t *testing.T) {
	// Break caught: the required inspection-report-<run-id> identity is longer
	// than the generic 128-byte ID bound when the Run itself uses that bound.
	snapshot := reportRendererFixture()
	runID := "r" + strings.Repeat("a", 127)
	snapshot.RunID = runID
	snapshot.ID = "inspection-report-" + runID
	snapshot.Document.RunID = runID
	snapshot.Document.ReportID = snapshot.ID

	jsonReport, err := RenderJSON(snapshot)

	require.NoError(t, err)
	require.Contains(t, string(jsonReport), snapshot.ID)
}

func reportRendererFixture() ReportSnapshot {
	generated := time.Date(2026, 8, 29, 10, 2, 0, 0, time.UTC)
	document := &ReportDocument{
		ReportID: "inspection-report-run-a", RunID: "run-a", Status: RunPartial, GeneratedAt: generated,
		Summary: "mixed <script>alert(1)</script>",
		Policy:  ReportPolicy{ID: "policy-a", Version: 7, Name: "Nightly <inspection>"},
		Items: []ReportItem{
			{ID: "disk.utilization", Version: 2, Name: "Disk", Category: "capacity"},
			{ID: "cpu.utilization", Version: 3, Name: "CPU <utilization>", Category: "capacity"},
		},
		Targets: []ReportTarget{
			{TargetID: "agent-b", DisplayName: `<img src=x onerror="alert(1)">`, Host: "b.internal", Status: TargetSucceeded, CommandID: "command-agent-b"},
			{TargetID: "agent-a", DisplayName: "Host A", Host: "a.internal", Status: TargetFailed, ErrorCode: "collection_failed", CommandID: "command-agent-a"},
		},
		Findings: []ReportFinding{
			{ID: "finding-disk", TargetID: "agent-b", ItemID: "disk.utilization", ItemVersion: 2, Level: LevelWarning, ObservedAt: generated.Add(-time.Minute), WarningThreshold: floatPointer(80), CriticalThreshold: floatPointer(90), Evidence: map[string]string{"metric": "system.disk.utilization", "value": "82"}, Summary: "Disk <warning>", Recommendation: "Review <mount>"},
			{TargetID: "agent-b", ItemID: "cpu.utilization", ItemVersion: 3, Level: LevelHealthy, ObservedAt: generated.Add(-time.Minute), Evidence: map[string]string{"metric": "system.cpu.utilization", "value": "12"}},
		},
		References: ReportReferences{
			JobID: "job-a", AuditCorrelation: "inspection-run:run-a",
			Commands: []ReportCommandReference{{TargetID: "agent-b", CommandID: "command-agent-b"}, {TargetID: "agent-a", CommandID: "command-agent-a"}},
		},
	}
	return ReportSnapshot{ID: document.ReportID, RunID: document.RunID, PolicyID: document.Policy.ID, Status: ReportCompleted, Document: document, GeneratedAt: generated}
}

func floatPointer(value float64) *float64 { return &value }

func minInt(first, second int) int {
	if first < second {
		return first
	}
	return second
}
