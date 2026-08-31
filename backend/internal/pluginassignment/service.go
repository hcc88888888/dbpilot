package pluginassignment

import (
	"context"

	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/platformscope"
)

type Repository interface {
	EnsureForInstance(context.Context, databaseinstance.Instance) (Assignment, error)
	List(context.Context, platformscope.Scope, Filter) (Page, error)
	Get(context.Context, platformscope.Scope, string) (Assignment, error)
	SetDesiredState(context.Context, platformscope.Scope, string, uint64, DesiredUpdate) (Assignment, error)
	RecordObservation(context.Context, ObservationReport) error
	ForceReconcile(context.Context, platformscope.Scope, string, MutationAudit) (Assignment, error)
}

type Service interface {
	EnsureForInstance(context.Context, databaseinstance.Instance) (Assignment, error)
	List(context.Context, platformscope.Scope, Filter) (Page, error)
	Get(context.Context, platformscope.Scope, string) (Assignment, error)
	SetDesiredState(context.Context, platformscope.Scope, string, uint64, DesiredUpdate) (Assignment, error)
	RecordObservation(context.Context, ObservationReport) error
	ForceReconcile(context.Context, platformscope.Scope, string, MutationAudit) (Assignment, error)
}

type ApplicationService struct{ repository Repository }

func NewService(repository Repository) *ApplicationService {
	return &ApplicationService{repository: repository}
}

func (service *ApplicationService) EnsureForInstance(ctx context.Context, instance databaseinstance.Instance) (Assignment, error) {
	if ctx == nil || service == nil || service.repository == nil || instance.Scope.Validate() != nil || !idPattern.MatchString(instance.ID) || !idPattern.MatchString(instance.HostID) || !idPattern.MatchString(instance.AgentID) || !familyPattern.MatchString(instance.DatabaseFamily) {
		return Assignment{}, ErrInvalid
	}
	value, err := service.repository.EnsureForInstance(ctx, instance)
	return checkedAssignment(value, err, instance.Scope, "")
}

func (service *ApplicationService) List(ctx context.Context, scope platformscope.Scope, filter Filter) (Page, error) {
	if ctx == nil || service == nil || service.repository == nil || scope.Validate() != nil || filter.Validate() != nil {
		return Page{}, ErrInvalid
	}
	page, err := service.repository.List(ctx, scope, filter)
	if err != nil {
		return Page{}, err
	}
	for _, value := range page.Items {
		if value.Scope != scope || value.Validate() != nil {
			return Page{}, ErrConflict
		}
	}
	if page.Items == nil {
		page.Items = []Assignment{}
	}
	return page, nil
}

func (service *ApplicationService) Get(ctx context.Context, scope platformscope.Scope, assignmentID string) (Assignment, error) {
	if ctx == nil || service == nil || service.repository == nil || scope.Validate() != nil || !idPattern.MatchString(assignmentID) {
		return Assignment{}, ErrInvalid
	}
	value, err := service.repository.Get(ctx, scope, assignmentID)
	return checkedAssignment(value, err, scope, assignmentID)
}

func (service *ApplicationService) SetDesiredState(ctx context.Context, scope platformscope.Scope, assignmentID string, revision uint64, update DesiredUpdate) (Assignment, error) {
	if ctx == nil || service == nil || service.repository == nil || scope.Validate() != nil || !idPattern.MatchString(assignmentID) || revision == 0 || update.Validate() != nil {
		return Assignment{}, ErrInvalid
	}
	value, err := service.repository.SetDesiredState(ctx, scope, assignmentID, revision, update)
	return checkedAssignment(value, err, scope, assignmentID)
}

func (service *ApplicationService) RecordObservation(ctx context.Context, report ObservationReport) error {
	if ctx == nil || service == nil || service.repository == nil || report.Validate() != nil {
		return ErrInvalid
	}
	return service.repository.RecordObservation(ctx, report)
}

func (service *ApplicationService) ForceReconcile(ctx context.Context, scope platformscope.Scope, assignmentID string, audit MutationAudit) (Assignment, error) {
	if ctx == nil || service == nil || service.repository == nil || scope.Validate() != nil || !idPattern.MatchString(assignmentID) || audit.Validate() != nil {
		return Assignment{}, ErrInvalid
	}
	value, err := service.repository.ForceReconcile(ctx, scope, assignmentID, audit)
	return checkedAssignment(value, err, scope, assignmentID)
}

func checkedAssignment(value Assignment, err error, scope platformscope.Scope, expectedID string) (Assignment, error) {
	if err != nil {
		return Assignment{}, err
	}
	if value.Scope != scope || expectedID != "" && value.ID != expectedID || value.Validate() != nil {
		return Assignment{}, ErrConflict
	}
	return value, nil
}

var _ Service = (*ApplicationService)(nil)
