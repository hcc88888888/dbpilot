package inspection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
)

const (
	hostSnapshotSourceID  = "inspection-host-snapshot"
	defaultRunWorkerLease = 30 * time.Second
	maximumWorkerClaims   = 100
)

type ArtifactWriter interface {
	Put(context.Context, artifact.Artifact, []byte) (artifact.Artifact, error)
}

type JobReader interface {
	Get(context.Context, platformscope.Scope, string) (job.Job, error)
}

type AuditRecorder interface {
	RecordOnce(context.Context, audit.Event) (audit.Event, error)
}

type RunClaim struct {
	Detail            RunDetail
	Token             string
	LeaseExpiresAt    time.Time
	ReportGeneratedAt time.Time
}

type ReportAuditClaim struct {
	Scope          platformscope.Scope
	RunID          string
	Token          string
	LeaseExpiresAt time.Time
	Event          audit.Event
}

type RunWorkerRepository interface {
	ClaimRuns(context.Context, time.Time, int, time.Duration) ([]RunClaim, error)
	MarkCollecting(context.Context, RunClaim, time.Time) (RunClaim, error)
	BeginEvaluation(context.Context, RunClaim) (RunClaim, error)
	FreshSnapshotAt(context.Context, platformscope.Scope, string, string, time.Time, time.Time) (time.Time, bool, error)
	SaveEvaluation(context.Context, RunClaim, []TargetRun, []Finding, time.Time) (RunClaim, error)
	ReleaseRun(context.Context, RunClaim) error
	FinalizeReport(context.Context, RunClaim, ReportSnapshot, RunStatus, audit.Event, time.Time) (ReportAuditClaim, error)
	ClaimPendingReportAudits(context.Context, time.Time, int, time.Duration) ([]ReportAuditClaim, error)
	MarkReportAuditRecorded(context.Context, ReportAuditClaim, time.Time) error
	ReleaseReportAudit(context.Context, ReportAuditClaim) error
}

type Worker struct {
	Runs      RunWorkerRepository
	Jobs      JobReader
	Evaluator *Evaluator
	Artifacts ArtifactWriter
	Audit     AuditRecorder
}

func (worker *Worker) Process(ctx context.Context, now time.Time, limit int) (int, error) {
	if worker == nil || worker.Runs == nil || worker.Jobs == nil || worker.Evaluator == nil || worker.Artifacts == nil || ctx == nil || now.IsZero() || limit < 1 || limit > maximumWorkerClaims {
		return 0, ErrInvalid
	}
	now = now.UTC()
	processed := 0
	var processErrors []error

	claims, err := worker.Runs.ClaimRuns(ctx, now, limit, defaultRunWorkerLease)
	if err != nil {
		return 0, fmt.Errorf("claim inspection runs: %w", err)
	}
	for _, claim := range claims {
		processed++
		if err := worker.processRun(ctx, claim, now); err != nil {
			_ = worker.Runs.ReleaseRun(ctx, claim)
			processErrors = append(processErrors, fmt.Errorf("process inspection run %s: %w", claim.Detail.Run.ID, err))
		}
	}
	if processed >= limit {
		return processed, errors.Join(processErrors...)
	}

	auditClaims, err := worker.Runs.ClaimPendingReportAudits(ctx, now, limit-processed, defaultRunWorkerLease)
	if err != nil {
		return processed, fmt.Errorf("claim inspection report audits: %w", err)
	}
	for _, claim := range auditClaims {
		processed++
		if err := worker.repairAudit(ctx, claim, now); err != nil {
			processErrors = append(processErrors, err)
		}
	}
	return processed, errors.Join(processErrors...)
}

func (worker *Worker) processRun(ctx context.Context, claim RunClaim, now time.Time) error {
	run := claim.Detail.Run
	if run.Scope.Validate() != nil || !validID(run.ID) || !validID(run.JobID) || !canonicalText(claim.Token) {
		return ErrInvalid
	}
	value, err := worker.Jobs.Get(ctx, run.Scope, run.JobID)
	if err != nil {
		return err
	}
	if value.ID != run.JobID || value.Scope != run.Scope || value.TimeoutAt == nil || value.TimeoutAt.IsZero() {
		return ErrInvalid
	}
	deadline := value.TimeoutAt.UTC()
	if run.Status == RunQueued {
		claim, err = worker.Runs.MarkCollecting(ctx, claim, now)
		if err != nil {
			return err
		}
		run = claim.Detail.Run
	}
	if run.Status == RunGeneratingReport {
		return worker.generateReport(ctx, claim, now)
	}
	if run.Status != RunCollecting && run.Status != RunEvaluating {
		return ErrInvalidRunTransition
	}
	if !terminalJobStatus(value.Status) {
		return worker.Runs.ReleaseRun(ctx, claim)
	}
	results := jobResultsByTarget(value.TargetResults)
	for _, target := range claim.Detail.Targets {
		result, ok := results[target.TargetID]
		if ok && result.Status == job.TargetSucceeded {
			_, fresh, err := worker.Runs.FreshSnapshotAt(ctx, run.Scope, target.AgentID, hostSnapshotSourceID, run.CreatedAt.UTC(), deadline)
			if err != nil {
				return err
			}
			if !fresh && now.Before(deadline) {
				return worker.Runs.ReleaseRun(ctx, claim)
			}
		}
	}
	if run.Status == RunCollecting {
		claim, err = worker.Runs.BeginEvaluation(ctx, claim)
		if err != nil {
			return err
		}
	}
	targets, findings, err := worker.evaluateTargets(ctx, claim, value, results, deadline, now)
	if err != nil {
		return err
	}
	claim, err = worker.Runs.SaveEvaluation(ctx, claim, targets, findings, now)
	if err != nil {
		return err
	}
	return worker.generateReport(ctx, claim, now)
}

func (worker *Worker) evaluateTargets(ctx context.Context, claim RunClaim, value job.Job, results map[string]job.TargetResult, deadline, now time.Time) ([]TargetRun, []Finding, error) {
	run := claim.Detail.Run
	evaluationAt := now.UTC()
	if deadline.Before(evaluationAt) {
		evaluationAt = deadline.UTC()
	}
	evaluator := *worker.Evaluator
	evaluator.Now = func() time.Time { return evaluationAt }
	targets := append([]TargetRun(nil), claim.Detail.Targets...)
	for index := range targets {
		targets[index].Status = TargetEvaluating
		targets[index].ErrorCode = ""
	}
	snapshot := RunSnapshot{ID: run.ID, Scope: run.Scope, CreatedAt: run.CreatedAt.UTC(), Items: cloneItems(run.ItemSnapshot), Targets: targets}
	findings := make([]Finding, 0, len(targets)*len(run.ItemSnapshot))
	for index := range targets {
		target := targets[index]
		result, ok := results[target.TargetID]
		if !ok {
			mapMissingJobTarget(&targets[index], value.Status)
			continue
		}
		switch result.Status {
		case job.TargetSucceeded:
			freshAt, fresh, err := worker.Runs.FreshSnapshotAt(ctx, run.Scope, target.AgentID, hostSnapshotSourceID, run.CreatedAt.UTC(), deadline)
			if err != nil {
				return nil, nil, err
			}
			var evaluated []Finding
			if !fresh {
				evaluated = missingSnapshotFindings(snapshot, target, evaluationAt)
			} else {
				evaluated, err = evaluator.EvaluateTarget(ctx, snapshot, target)
				if err != nil {
					return nil, nil, err
				}
				if targets[index].ObservedAt.IsZero() || freshAt.After(targets[index].ObservedAt) {
					targets[index].ObservedAt = freshAt.UTC()
				}
			}
			for findingIndex := range evaluated {
				prepareFinding(&evaluated[findingIndex], snapshot.Items)
			}
			findings = append(findings, evaluated...)
			applyFindingOutcome(&targets[index], evaluated)
		case job.TargetCancelled:
			targets[index].Status, targets[index].ErrorCode = TargetCancelled, "collection_cancelled"
		case job.TargetTimedOut:
			targets[index].Status, targets[index].ErrorCode = TargetFailed, "collection_timed_out"
		case job.TargetSkipped:
			targets[index].Status, targets[index].ErrorCode = TargetUnsupported, "collection_unsupported"
		case job.TargetFailed:
			targets[index].Status, targets[index].ErrorCode = TargetFailed, "collection_failed"
		default:
			return nil, nil, ErrInvalid
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].TargetID < targets[j].TargetID })
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].TargetID != findings[j].TargetID {
			return findings[i].TargetID < findings[j].TargetID
		}
		if findings[i].ItemID != findings[j].ItemID {
			return findings[i].ItemID < findings[j].ItemID
		}
		return findings[i].ItemVersion < findings[j].ItemVersion
	})
	return targets, findings, nil
}

func (worker *Worker) generateReport(ctx context.Context, claim RunClaim, now time.Time) error {
	if claim.Detail.Run.Status != RunGeneratingReport || claim.ReportGeneratedAt.IsZero() {
		return ErrInvalid
	}
	terminal := AggregateRunStatus(targetStatuses(claim.Detail.Targets))
	document := buildReportDocument(claim.Detail, terminal, claim.ReportGeneratedAt.UTC())
	report := ReportSnapshot{
		Scope: claim.Detail.Run.Scope, ID: document.ReportID, RunID: claim.Detail.Run.ID, PolicyID: claim.Detail.Run.PolicyID,
		Status: ReportCompleted, Summary: document.Summary, Document: &document, GeneratedAt: claim.ReportGeneratedAt.UTC(), CreatedAt: claim.ReportGeneratedAt.UTC(),
	}
	jsonBytes, err := RenderJSON(report)
	if err != nil {
		return err
	}
	htmlBytes, err := RenderHTML(report)
	if err != nil {
		return err
	}
	jsonArtifact, err := worker.Artifacts.Put(ctx, reportArtifact(claim.Detail.Run, report, "json", "application/json", jsonBytes), jsonBytes)
	if err != nil {
		return err
	}
	htmlArtifact, err := worker.Artifacts.Put(ctx, reportArtifact(claim.Detail.Run, report, "html", "text/html; charset=utf-8", htmlBytes), htmlBytes)
	if err != nil {
		return err
	}
	report.Snapshot = append([]byte(nil), jsonBytes...)
	report.Document = nil
	report.Artifacts = []job.ArtifactReference{{ArtifactID: jsonArtifact.ID, Kind: jsonArtifact.Kind}, {ArtifactID: htmlArtifact.ID, Kind: htmlArtifact.Kind}}
	event := reportAuditEvent(claim.Detail.Run, report, terminal)
	auditClaim, err := worker.Runs.FinalizeReport(ctx, claim, report, terminal, event, now)
	if err != nil {
		return err
	}
	if worker.Audit == nil {
		return nil
	}
	if _, err := worker.Audit.RecordOnce(ctx, event); err != nil {
		_ = worker.Runs.ReleaseReportAudit(ctx, auditClaim)
		return nil
	}
	return worker.Runs.MarkReportAuditRecorded(ctx, auditClaim, now)
}

func (worker *Worker) repairAudit(ctx context.Context, claim ReportAuditClaim, now time.Time) error {
	if claim.Scope.Validate() != nil || !validID(claim.RunID) || !canonicalText(claim.Event.DedupeKey) {
		return ErrInvalid
	}
	if worker.Audit == nil {
		return worker.Runs.ReleaseReportAudit(ctx, claim)
	}
	if _, err := worker.Audit.RecordOnce(ctx, claim.Event); err != nil {
		_ = worker.Runs.ReleaseReportAudit(ctx, claim)
		return fmt.Errorf("record inspection report Audit %s: %w", claim.RunID, err)
	}
	return worker.Runs.MarkReportAuditRecorded(ctx, claim, now)
}

func missingSnapshotFindings(snapshot RunSnapshot, target TargetRun, now time.Time) []Finding {
	items := cloneItems(snapshot.Items)
	sort.Slice(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		return items[i].Version < items[j].Version
	})
	result := make([]Finding, 0, len(items))
	for _, item := range items {
		result = append(result, baseFinding(snapshot, target, item, LevelMissingData, now, map[string]string{"reason": "snapshot_not_ingested_by_deadline", "samples": "0"}))
	}
	return result
}

func prepareFinding(finding *Finding, items []Item) {
	key := finding.RunID + "\x00" + finding.TargetID + "\x00" + finding.ItemID + "\x00" + strconv.Itoa(finding.ItemVersion)
	digest := sha256.Sum256([]byte(key))
	finding.ID = "inspection-finding-" + hex.EncodeToString(digest[:16])
	for _, item := range items {
		if item.ID == finding.ItemID && item.Version == finding.ItemVersion {
			if finding.Summary == "" {
				finding.Summary = string(finding.Level)
			}
			finding.Recommendation = item.RecommendationTemplate
			return
		}
	}
}

func applyFindingOutcome(target *TargetRun, findings []Finding) {
	valid, unsupported, missing := false, false, false
	for _, finding := range findings {
		if target.ObservedAt.IsZero() || finding.ObservedAt.After(target.ObservedAt) {
			target.ObservedAt = finding.ObservedAt.UTC()
		}
		switch finding.Level {
		case LevelHealthy, LevelWarning, LevelCritical:
			valid = true
		case LevelUnsupported:
			unsupported = true
		case LevelMissingData:
			missing = true
		}
	}
	switch {
	case valid:
		target.Status = TargetSucceeded
	case missing:
		target.Status, target.ErrorCode = TargetFailed, "missing_data"
	case unsupported:
		target.Status, target.ErrorCode = TargetUnsupported, "unsupported"
	default:
		target.Status, target.ErrorCode = TargetFailed, "missing_data"
	}
}

func buildReportDocument(detail RunDetail, terminal RunStatus, generatedAt time.Time) ReportDocument {
	run := detail.Run
	reportID := "inspection-report-" + run.ID
	document := ReportDocument{
		ReportID: reportID, RunID: run.ID, Status: terminal, Summary: reportSummary(detail.Targets, detail.Findings), GeneratedAt: generatedAt.UTC(),
		Policy:     ReportPolicy{ID: run.PolicyID, Version: run.PolicyVersion},
		References: ReportReferences{JobID: run.JobID, AuditCorrelation: run.AuditCorrelation},
	}
	if run.PolicySnapshot != nil {
		document.Policy.Name = run.PolicySnapshot.Name
	}
	for _, item := range run.ItemSnapshot {
		document.Items = append(document.Items, ReportItem{ID: item.ID, Version: item.Version, Name: item.Name, Category: item.Category})
	}
	for _, target := range detail.Targets {
		document.Targets = append(document.Targets, ReportTarget{TargetID: target.TargetID, DisplayName: target.DisplayName, Host: target.Host, Status: target.Status, ErrorCode: target.ErrorCode, CommandID: target.CommandID})
		document.References.Commands = append(document.References.Commands, ReportCommandReference{TargetID: target.TargetID, CommandID: target.CommandID})
	}
	for _, finding := range detail.Findings {
		document.Findings = append(document.Findings, ReportFinding{
			TargetID: finding.TargetID, ItemID: finding.ItemID, ItemVersion: finding.ItemVersion, Level: finding.Level, ObservedAt: finding.ObservedAt.UTC(),
			WarningThreshold: finding.WarningThreshold, CriticalThreshold: finding.CriticalThreshold, Evidence: cloneEvidence(finding.Evidence), Summary: finding.Summary, Recommendation: finding.Recommendation,
		})
	}
	return document
}

func reportSummary(targets []TargetRun, findings []Finding) string {
	levels := map[FindingLevel]int{}
	for _, finding := range findings {
		levels[finding.Level]++
	}
	failed := 0
	for _, target := range targets {
		if target.Status != TargetSucceeded {
			failed++
		}
	}
	return fmt.Sprintf("targets=%d failed=%d healthy=%d warning=%d critical=%d unsupported=%d missing_data=%d", len(targets), failed, levels[LevelHealthy], levels[LevelWarning], levels[LevelCritical], levels[LevelUnsupported], levels[LevelMissingData])
}

func reportArtifact(run Run, report ReportSnapshot, extension, contentType string, contents []byte) artifact.Artifact {
	digest := sha256.Sum256(contents)
	return artifact.Artifact{
		ID: report.ID + "." + extension, Scope: run.Scope, Kind: "inspection-report", ContentType: contentType,
		SizeBytes: int64(len(contents)), Checksum: "sha256:" + hex.EncodeToString(digest[:]),
		SourceResource: artifact.ResourceReference{ResourceType: "inspection_report", ResourceID: report.ID},
		JobID:          run.JobID, CreatedBy: "inspection-worker", CreatedAt: report.GeneratedAt.UTC(),
	}
}

func reportAuditEvent(run Run, report ReportSnapshot, terminal RunStatus) audit.Event {
	artifactIDs := make([]any, len(report.Artifacts))
	for index := range report.Artifacts {
		artifactIDs[index] = report.Artifacts[index].ArtifactID
	}
	return audit.Event{
		Scope: run.Scope, OccurredAt: report.GeneratedAt.UTC(), Action: "inspection.report.completed",
		Actor: audit.Actor{Type: "system", ID: "inspection-worker"}, Resource: audit.Resource{Type: "inspection_report", ID: report.ID},
		Result: string(terminal), RequestID: run.RequestID, TraceID: run.TraceID, JobID: run.JobID, DedupeKey: run.AuditCorrelation + ":report",
		Detail: map[string]any{"run_id": run.ID, "report_id": report.ID, "status": string(terminal), "artifact_ids": artifactIDs},
	}
}

func mapMissingJobTarget(target *TargetRun, status job.Status) {
	if status == job.StatusCancelled {
		target.Status, target.ErrorCode = TargetCancelled, "collection_cancelled"
		return
	}
	target.Status, target.ErrorCode = TargetFailed, "collection_result_missing"
}

func terminalJobStatus(status job.Status) bool {
	return status == job.StatusSucceeded || status == job.StatusFailed || status == job.StatusCancelled || status == job.StatusTimedOut
}

func jobResultsByTarget(results []job.TargetResult) map[string]job.TargetResult {
	result := make(map[string]job.TargetResult, len(results))
	for _, value := range results {
		result[value.TargetID] = value
	}
	return result
}

func targetStatuses(targets []TargetRun) []TargetStatus {
	result := make([]TargetStatus, len(targets))
	for index := range targets {
		result[index] = targets[index].Status
	}
	return result
}

func cloneEvidence(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
