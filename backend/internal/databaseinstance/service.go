package databaseinstance

import (
	"context"

	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
)

type ApplicationService struct{ Repository Repository }

func NewService(repository Repository) *ApplicationService {
	return &ApplicationService{Repository: repository}
}

func (service ApplicationService) AcceptCandidate(ctx context.Context, scope platformscope.Scope, candidateID string, request AcceptCandidateRequest) (Instance, error) {
	if ctx == nil || service.Repository == nil || scope.Validate() != nil || !identifierPattern.MatchString(candidateID) || request.Validate() != nil {
		return Instance{}, ErrInvalid
	}
	value, err := service.Repository.AcceptCandidate(ctx, scope, candidateID, request)
	return checkedInstance(value, err, scope, "")
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
		page.Items = []Instance{}
	}
	return page, nil
}

func (service ApplicationService) Get(ctx context.Context, scope platformscope.Scope, instanceID string) (Instance, error) {
	if ctx == nil || service.Repository == nil || scope.Validate() != nil || !identifierPattern.MatchString(instanceID) {
		return Instance{}, ErrInvalid
	}
	value, err := service.Repository.Get(ctx, scope, instanceID)
	return checkedInstance(value, err, scope, instanceID)
}

func (service ApplicationService) Update(ctx context.Context, scope platformscope.Scope, instanceID string, revision uint64, update Update) (Instance, error) {
	if ctx == nil || service.Repository == nil || scope.Validate() != nil || !identifierPattern.MatchString(instanceID) || revision == 0 || update.Validate() != nil || update.Audit.Validate() != nil {
		return Instance{}, ErrInvalid
	}
	value, err := service.Repository.Update(ctx, scope, instanceID, revision, update)
	return checkedInstance(value, err, scope, instanceID)
}

func (service ApplicationService) Retire(ctx context.Context, scope platformscope.Scope, instanceID string, revision uint64, audit MutationAudit) (Instance, error) {
	if ctx == nil || service.Repository == nil || scope.Validate() != nil || !identifierPattern.MatchString(instanceID) || revision == 0 || audit.Validate() != nil {
		return Instance{}, ErrInvalid
	}
	value, err := service.Repository.Retire(ctx, scope, instanceID, revision, audit)
	return checkedInstance(value, err, scope, instanceID)
}

func (service ApplicationService) StartValidation(ctx context.Context, scope platformscope.Scope, instanceID string, request ValidationRequest) (job.Job, error) {
	if ctx == nil || service.Repository == nil || scope.Validate() != nil || !identifierPattern.MatchString(instanceID) || request.Validate() != nil {
		return job.Job{}, ErrInvalid
	}
	value, err := service.Repository.StartValidation(ctx, scope, instanceID, request)
	if err != nil {
		return job.Job{}, err
	}
	if value.Scope != scope || value.InstanceID != instanceID || value.Type != "database_instance.validate" || value.SourceResource != (job.ResourceReference{ResourceType: "database_instance", ResourceID: instanceID}) || value.Version < 1 {
		return job.Job{}, ErrInvalid
	}
	return value, nil
}

func checkedInstance(value Instance, err error, scope platformscope.Scope, expectedID string) (Instance, error) {
	if err != nil {
		return Instance{}, err
	}
	if value.Validate() != nil || value.Scope != scope || expectedID != "" && value.ID != expectedID {
		return Instance{}, ErrInvalid
	}
	return value, nil
}

var _ Service = (*ApplicationService)(nil)
