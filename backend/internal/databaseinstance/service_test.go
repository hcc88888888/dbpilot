package databaseinstance

import (
	"context"
	"testing"

	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestAcceptCandidateRequiresRepositoryResultToRemainInExactScope(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	repository := &stubRepository{accept: validInstance()}
	repository.accept.Scope = platformscope.Scope{TenantID: "tenant-other", ProjectID: "project-1"}
	service := NewService(repository)

	_, err := service.AcceptCandidate(context.Background(), scope, "candidate-1", validAcceptRequest())

	require.ErrorIs(t, err, ErrInvalid)
}

func TestListRejectsOutOfScopeRepositoryRows(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	wrong := validInstance()
	wrong.Scope.ProjectID = "project-other"
	service := NewService(&stubRepository{page: Page{Items: []Instance{wrong}}})

	_, err := service.List(context.Background(), scope, Filter{Limit: 10})

	require.ErrorIs(t, err, ErrInvalid)
}

type stubRepository struct {
	accept Instance
	page   Page
}

func (repository *stubRepository) AcceptCandidate(context.Context, platformscope.Scope, string, AcceptCandidateRequest) (Instance, error) {
	return repository.accept, nil
}
func (repository *stubRepository) List(context.Context, platformscope.Scope, Filter) (Page, error) {
	return repository.page, nil
}
func (repository *stubRepository) Get(context.Context, platformscope.Scope, string) (Instance, error) {
	return validInstance(), nil
}
func (repository *stubRepository) Update(context.Context, platformscope.Scope, string, uint64, Update) (Instance, error) {
	return validInstance(), nil
}
func (repository *stubRepository) Retire(context.Context, platformscope.Scope, string, uint64, MutationAudit) (Instance, error) {
	return validInstance(), nil
}
func (repository *stubRepository) StartValidation(context.Context, platformscope.Scope, string, ValidationRequest) (job.Job, error) {
	return job.Job{}, ErrPluginUnavailable
}

var _ Repository = (*stubRepository)(nil)
