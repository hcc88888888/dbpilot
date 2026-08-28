package inspection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/robfig/cron/v3"
	"google.golang.org/protobuf/proto"
)

var (
	ErrInvalidSchedule = errors.New("inspection schedule requires five cron fields and an explicit IANA timezone")
	ErrRunNotRetryable = errors.New("inspection run is not retryable")
)

type CreateRunRequest struct {
	Scope          platformscope.Scope
	PolicyID       string
	PolicyVersion  int64
	RetryOfRunID   string
	Selector       TargetSelector
	Items          []PolicyItem
	TargetTimeout  time.Duration
	MaxConcurrency int
	IdempotencyKey string
	InitiatedBy    string
	RequestID      string
	TraceID        string
	Trigger        RunTrigger
	ScheduledFor   *time.Time
	OccurrenceKey  string
	PolicySnapshot *Policy
}

type Service struct {
	Repository Repository
	Targets    TargetResolver
	Now        func() time.Time
	NewID      func() (string, error)
	ClaimLimit int
	ClaimLease time.Duration
}

func (service *Service) CreateRun(ctx context.Context, request CreateRunRequest) (Run, error) {
	return service.createRun(ctx, request, nil)
}

func (service *Service) RetryRun(ctx context.Context, scope platformscope.Scope, runID, idempotencyKey, actor string) (Run, error) {
	if service == nil || service.Repository == nil || scope.Validate() != nil || !validID(runID) || !canonicalText(idempotencyKey) || !canonicalText(actor) {
		return Run{}, ErrInvalid
	}
	detail, err := service.Repository.GetRun(ctx, scope, runID)
	if err != nil {
		return Run{}, err
	}
	if detail.Run.Status != RunFailed && detail.Run.Status != RunPartial {
		return Run{}, ErrRunNotRetryable
	}
	items := make([]PolicyItem, len(detail.Run.ItemSnapshot))
	for index, item := range detail.Run.ItemSnapshot {
		items[index] = PolicyItem{ItemID: item.ID, Version: item.Version}
	}
	agentIDs := make([]string, len(detail.Targets))
	for index, target := range detail.Targets {
		agentIDs[index] = target.AgentID
	}
	timeout := time.Minute
	maxConcurrency := 1
	if detail.Run.PolicySnapshot != nil {
		timeout = detail.Run.PolicySnapshot.TargetTimeout
		maxConcurrency = detail.Run.PolicySnapshot.MaxConcurrency
	}
	return service.createRun(ctx, CreateRunRequest{
		Scope: scope, PolicyID: detail.Run.PolicyID, PolicyVersion: detail.Run.PolicyVersion,
		RetryOfRunID: runID, Selector: TargetSelector{AgentIDs: agentIDs}, Items: items,
		TargetTimeout: timeout, MaxConcurrency: maxConcurrency, IdempotencyKey: idempotencyKey,
		InitiatedBy: actor, RequestID: "retry-" + idempotencyKey, Trigger: RunTriggerRetry,
	}, nil)
}

func (service *Service) ScheduleDue(ctx context.Context, now time.Time) (int, error) {
	if service == nil || service.Repository == nil || service.Targets == nil || ctx == nil || now.Location() != time.UTC {
		return 0, ErrInvalid
	}
	limit := service.ClaimLimit
	if limit == 0 {
		limit = 10
	}
	lease := service.ClaimLease
	if lease == 0 {
		lease = time.Minute
	}
	policies, err := service.Repository.ClaimDuePolicies(ctx, now, limit, lease)
	if err != nil {
		return 0, err
	}
	created := 0
	for _, policy := range policies {
		if policy.Claim == nil || policy.NextRunAt == nil || !policy.Claim.Occurrence.Equal(*policy.NextRunAt) {
			return created, ErrConflict
		}
		occurrence := policy.Claim.Occurrence.UTC()
		key := scheduledOccurrenceKey(policy, occurrence)
		_, err := service.createRun(ctx, CreateRunRequest{
			Scope: policy.Scope, PolicyID: policy.ID, PolicyVersion: policy.Version,
			Selector: policy.Selector, Items: policy.Items, TargetTimeout: policy.TargetTimeout, MaxConcurrency: policy.MaxConcurrency,
			IdempotencyKey: key, InitiatedBy: "inspection-scheduler", RequestID: key, Trigger: RunTriggerScheduled,
			ScheduledFor: &occurrence, OccurrenceKey: key, PolicySnapshot: clonePolicy(&policy),
		}, &policy)
		if err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}

func (service *Service) createRun(ctx context.Context, request CreateRunRequest, claimed *Policy) (Run, error) {
	if err := service.validateCreateRequest(ctx, request); err != nil {
		return Run{}, err
	}
	targets, err := service.Targets.Resolve(ctx, request.Scope, request.Selector)
	if err != nil {
		return Run{}, err
	}
	items, err := service.snapshotItems(ctx, request.Scope, request.Items)
	if err != nil {
		return Run{}, err
	}
	now := service.now().UTC()
	runID, err := service.newID()
	if err != nil {
		return Run{}, err
	}
	jobID, err := service.newID()
	if err != nil {
		return Run{}, err
	}
	trigger := request.Trigger
	if trigger == "" {
		trigger = RunTriggerManual
	}
	targetRuns := make([]TargetRun, len(targets))
	jobTargets := make([]string, len(targets))
	messages := make([]job.OutboxMessage, len(targets))
	for index, target := range targets {
		commandID, err := service.newID()
		if err != nil {
			return Run{}, err
		}
		targetRuns[index] = TargetRun{
			TargetID: target.AgentID, AgentID: target.AgentID, CommandID: commandID,
			DisplayName: target.DisplayName, Host: target.Host, Labels: cloneLabels(target.Labels), Status: TargetPending,
			AdvertisedSources: append([]SourceType(nil), target.AdvertisedSources...), Capabilities: append([]string(nil), target.Capabilities...), TrustedProcessAllowlist: target.TrustedProcessAllowlist,
		}
		jobTargets[index] = target.AgentID
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.CommandEnvelope{
			AgentId: target.AgentID, LeaseSeconds: 60,
			Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"host"}}},
		})
		if err != nil {
			return Run{}, fmt.Errorf("marshal inspection CollectNow: %w", err)
		}
		messages[index] = job.OutboxMessage{ID: commandID, Scope: request.Scope, JobID: jobID, TargetID: target.AgentID, Type: "agent.command", Payload: payload, AvailableAt: now, CreatedAt: now}
	}
	run := Run{
		Scope: request.Scope, ID: runID, PolicyID: request.PolicyID, PolicyVersion: request.PolicyVersion,
		RetryOfRunID: request.RetryOfRunID, JobID: jobID, Status: RunQueued, Trigger: trigger,
		OccurrenceKey: request.OccurrenceKey, ScheduledFor: utcCopy(request.ScheduledFor), PolicySnapshot: clonePolicy(request.PolicySnapshot),
		ItemSnapshot: cloneItems(items), TargetCount: len(targetRuns), AuditCorrelation: "inspection-run:" + runID,
		IdempotencyKey: request.IdempotencyKey, InitiatedBy: request.InitiatedBy, RequestID: request.RequestID, TraceID: request.TraceID, CreatedAt: now,
	}
	timeoutAt := now.Add(request.TargetTimeout)
	value := job.Job{
		ID: jobID, Type: "inspection.collect", Scope: request.Scope, Status: job.StatusQueued, Outcome: job.OutcomeNone,
		TargetResourceIDs: jobTargets, InitiatedBy: request.InitiatedBy,
		SourceResource: job.ResourceReference{ResourceType: "inspection_run", ResourceID: runID},
		IdempotencyKey: request.IdempotencyKey, Version: 1, Progress: job.Progress{TotalTargets: len(jobTargets)}, Artifacts: []job.ArtifactReference{},
		CreatedAt: now, TimeoutAt: &timeoutAt, RequestID: request.RequestID, TraceID: request.TraceID,
	}
	if claimed != nil {
		return service.Repository.CreateClaimedRunWithJob(ctx, *claimed, run, targetRuns, value, messages)
	}
	err = service.Repository.CreateRunWithJob(ctx, run, targetRuns, value, messages)
	if errors.Is(err, ErrDuplicate) {
		return service.Repository.GetRunByIdempotencyKey(ctx, request.Scope, request.IdempotencyKey)
	}
	if err != nil {
		return Run{}, err
	}
	return run, nil
}

func (service *Service) validateCreateRequest(ctx context.Context, request CreateRunRequest) error {
	if service == nil || service.Repository == nil || service.Targets == nil || ctx == nil || request.Scope.Validate() != nil || len(request.Items) < 1 || len(request.Items) > maxSnapshotItems || request.TargetTimeout < time.Second || request.TargetTimeout > time.Hour || request.MaxConcurrency < 1 || request.MaxConcurrency > 1000 || !canonicalText(request.IdempotencyKey) || !canonicalText(request.InitiatedBy) || !canonicalText(request.RequestID) {
		return ErrInvalid
	}
	if request.Trigger == RunTriggerRetry {
		if !validID(request.RetryOfRunID) {
			return ErrInvalid
		}
	} else if request.RetryOfRunID != "" {
		return ErrInvalid
	}
	if request.Trigger == "" || request.Trigger == RunTriggerManual || request.Trigger == RunTriggerRetry {
		if request.ScheduledFor != nil || request.OccurrenceKey != "" || (request.Trigger == RunTriggerManual && request.RetryOfRunID != "") {
			return ErrInvalid
		}
		return nil
	}
	if request.Trigger != RunTriggerScheduled || request.PolicySnapshot == nil || request.ScheduledFor == nil || !isUTC(*request.ScheduledFor) || !canonicalText(request.OccurrenceKey) {
		return ErrInvalid
	}
	return nil
}

func (service *Service) snapshotItems(ctx context.Context, scope platformscope.Scope, requested []PolicyItem) ([]Item, error) {
	page, err := service.Repository.ListItems(ctx, scope, ItemFilter{CursorFilter: CursorFilter{Limit: len(requested) + 1}, Versions: append([]PolicyItem(nil), requested...)})
	if err != nil {
		return nil, err
	}
	wanted := make(map[string]struct{}, len(requested))
	for _, item := range requested {
		if !validID(item.ItemID) || item.Version < 1 {
			return nil, ErrInvalid
		}
		wanted[fmt.Sprintf("%s\x00%d", item.ItemID, item.Version)] = struct{}{}
	}
	found := make(map[string]Item, len(page.Items))
	for _, item := range page.Items {
		key := fmt.Sprintf("%s\x00%d", item.ID, item.Version)
		if _, requested := wanted[key]; requested && item.Validate() == nil {
			found[key] = item
		}
	}
	if len(found) != len(wanted) {
		return nil, ErrNotFound
	}
	items := make([]Item, 0, len(found))
	for _, item := range found {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ID == items[j].ID {
			return items[i].Version < items[j].Version
		}
		return items[i].ID < items[j].ID
	})
	return items, nil
}

func NextScheduledOccurrence(schedule Schedule, after time.Time) (time.Time, error) {
	if len(strings.Fields(schedule.Cron)) != 5 || strings.TrimSpace(schedule.Timezone) == "" || after.IsZero() {
		return time.Time{}, ErrInvalidSchedule
	}
	location, err := time.LoadLocation(schedule.Timezone)
	if err != nil {
		return time.Time{}, ErrInvalidSchedule
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	parsed, err := parser.Parse(schedule.Cron)
	if err != nil {
		return time.Time{}, ErrInvalidSchedule
	}
	return parsed.Next(after.In(location)).UTC(), nil
}

func scheduledOccurrenceKey(policy Policy, occurrence time.Time) string {
	return fmt.Sprintf("%s:v%d:%s", policy.ID, policy.Version, occurrence.UTC().Format(time.RFC3339Nano))
}

func (service *Service) now() time.Time {
	if service.Now != nil {
		return service.Now()
	}
	return time.Now()
}

func (service *Service) newID() (string, error) {
	if service.NewID != nil {
		return service.NewID()
	}
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "inspection-" + hex.EncodeToString(buffer), nil
}

func canonicalText(value string) bool {
	return strings.TrimSpace(value) != "" && value == strings.TrimSpace(value)
}

func cloneLabels(labels map[string]string) map[string]string {
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}

func clonePolicy(value *Policy) *Policy {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Claim = nil
	cloned.Items = append([]PolicyItem(nil), value.Items...)
	cloned.Selector.AgentIDs = append([]string(nil), value.Selector.AgentIDs...)
	cloned.Selector.Labels = cloneLabels(value.Selector.Labels)
	cloned.NextRunAt = utcCopy(value.NextRunAt)
	return &cloned
}

func utcCopy(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	at := value.UTC()
	return &at
}
