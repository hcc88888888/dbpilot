package discovery

import (
	"context"
	"crypto/ed25519"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

const DefaultDisappearanceGrace = 10 * time.Minute

type ApplicationService struct {
	Repository         Repository
	Now                func() time.Time
	DisappearanceGrace time.Duration
	RuleKeys           map[string]ed25519.PublicKey
}

func NewService(repository Repository) *ApplicationService {
	return &ApplicationService{Repository: repository}
}

func (service ApplicationService) RecordReport(ctx context.Context, report Report) ([]Candidate, error) {
	if ctx == nil || service.Repository == nil || !identifierPattern.MatchString(report.AgentID) || !identifierPattern.MatchString(report.HostID) {
		return nil, ErrInvalid
	}
	binding, err := service.Repository.ResolveAgentBinding(ctx, report.AgentID)
	if err != nil {
		return nil, err
	}
	if binding.Validate() != nil || binding.AgentID != report.AgentID || binding.HostID != report.HostID {
		return nil, ErrConflict
	}
	report.Scope = binding.Scope
	if report.Validate() != nil {
		return nil, ErrInvalid
	}
	publicKey := service.RuleKeys[report.RuleAttestation.KeyID]
	if VerifyRuleAttestation(publicKey, report.RuleAttestation, serviceTime(service.Now)) != nil {
		return nil, ErrInvalidSignature
	}
	for _, candidate := range report.Candidates {
		expected, fingerprintErr := Fingerprint(binding.HostID, candidate)
		if fingerprintErr != nil {
			return nil, ErrInvalid
		}
		if expected != candidate.Fingerprint || !candidate.ObservedAt.Equal(report.ObservedAt) {
			return nil, ErrConflict
		}
	}
	now, _, err := service.settings()
	if err != nil {
		return nil, err
	}
	if report.ObservedAt.Before(now.Add(-5*time.Minute)) || report.ObservedAt.After(now.Add(5*time.Minute)) {
		return nil, ErrConflict
	}
	values, err := service.Repository.RecordReport(ctx, report, now, report.RuleAttestation.DisappearanceGrace)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		if value.Validate() != nil || value.Scope != binding.Scope || value.HostID != binding.HostID || value.AgentID != binding.AgentID {
			return nil, ErrInvalid
		}
	}
	if values == nil {
		values = []Candidate{}
	}
	return values, nil
}

func serviceTime(now func() time.Time) time.Time {
	value := time.Now().UTC()
	if now != nil {
		value = now().UTC()
	}
	return value
}

func (service ApplicationService) List(ctx context.Context, scope platformscope.Scope, filter Filter) (Page, error) {
	if ctx == nil || service.Repository == nil || scope.Validate() != nil || filter.Validate() != nil {
		return Page{}, ErrInvalid
	}
	page, err := service.Repository.List(ctx, scope, filter)
	if err != nil {
		return Page{}, err
	}
	for _, value := range page.Items {
		if value.Validate() != nil || value.Scope != scope {
			return Page{}, ErrInvalid
		}
	}
	if page.Items == nil {
		page.Items = []Candidate{}
	}
	return page, nil
}

func (service ApplicationService) Get(ctx context.Context, scope platformscope.Scope, candidateID string) (Candidate, error) {
	if ctx == nil || service.Repository == nil || scope.Validate() != nil || !identifierPattern.MatchString(candidateID) {
		return Candidate{}, ErrInvalid
	}
	value, err := service.Repository.Get(ctx, scope, candidateID)
	if err != nil {
		return Candidate{}, err
	}
	if value.Validate() != nil || value.Scope != scope || value.ID != candidateID {
		return Candidate{}, ErrInvalid
	}
	return value, nil
}

func (service ApplicationService) Ignore(ctx context.Context, scope platformscope.Scope, candidateID, reason string) (Candidate, error) {
	if ctx == nil || service.Repository == nil || scope.Validate() != nil || !identifierPattern.MatchString(candidateID) || !familyPattern.MatchString(reason) {
		return Candidate{}, ErrInvalid
	}
	now, _, err := service.settings()
	if err != nil {
		return Candidate{}, err
	}
	value, err := service.Repository.Ignore(ctx, scope, candidateID, reason, now)
	if err != nil {
		return Candidate{}, err
	}
	if value.Validate() != nil || value.Scope != scope || value.ID != candidateID || value.Status != StatusIgnored || value.IgnoreReason != reason {
		return Candidate{}, ErrInvalid
	}
	return value, nil
}

func (service ApplicationService) settings() (time.Time, time.Duration, error) {
	now := time.Now().UTC()
	if service.Now != nil {
		now = service.Now()
	}
	grace := service.DisappearanceGrace
	if grace == 0 {
		grace = DefaultDisappearanceGrace
	}
	if !validUTC(now) || grace < time.Minute || grace > 24*time.Hour {
		return time.Time{}, 0, ErrInvalid
	}
	return now, grace, nil
}
