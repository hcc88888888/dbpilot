package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestDiscoveryAPIListsOnlyScopedRedactedCandidates(t *testing.T) {
	service := &discoveryAPIService{candidate: discoveryAPICandidate(platformTestScope)}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/discovery-candidates?limit=10", nil)
	response := servePlatformRequest(Services{Discovery: service}, principalWith(platformTestScope, openapi.PermissionListDiscoveryCandidates), request)
	require.Equal(t, http.StatusOK, response.Code)
	var page openapi.DiscoveryCandidatePage
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &page))
	require.Len(t, page.Items, 1)
	require.Equal(t, "127.0.0.1:3306", *page.Items[0].NormalizedEndpoint)
	require.NotContains(t, response.Body.String(), "hunter2")
}

func TestDiscoveryAPIKeepsInternalContainerIDEvidenceOutOfCanonicalDTO(t *testing.T) {
	candidate := discoveryAPICandidate(platformTestScope)
	candidate.Source = discovery.SourceDocker
	candidate.ContainerIdentity = "mysql-primary"
	candidate.Evidence = append(candidate.Evidence, discovery.Evidence{Kind: discovery.EvidenceContainerID, Value: strings.Repeat("a", 64)})
	service := &discoveryAPIService{candidate: candidate}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/discovery-candidates", nil)
	response := servePlatformRequest(Services{Discovery: service}, principalWith(platformTestScope, openapi.PermissionListDiscoveryCandidates), request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var page openapi.DiscoveryCandidatePage
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &page))
	require.Len(t, page.Items, 1)
	require.Equal(t, "mysql-primary", *page.Items[0].ContainerIdentity)
	for _, evidence := range page.Items[0].EvidenceSummary {
		require.NotEqual(t, discovery.EvidenceContainerID, discovery.EvidenceKind(evidence.Kind))
	}
	require.NotContains(t, response.Body.String(), strings.Repeat("a", 64))
}

func TestDiscoveryAPIIgnoreRequiresPermissionAndIsIdempotent(t *testing.T) {
	service := &discoveryAPIService{candidate: discoveryAPICandidate(platformTestScope)}
	services := Services{Discovery: service, Idempotency: idempotency.NewService(newHTTPIdempotencyStore()), Audit: &recordingAuditService{}}
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/discovery-candidates/candidate-1/actions/ignore", strings.NewReader(`{"reason_code":"not_managed"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "ignore-1")
	denied := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionListDiscoveryCandidates), request)
	require.Equal(t, http.StatusForbidden, denied.Code)
	request = httptest.NewRequest(http.MethodPost, platformBasePath+"/discovery-candidates/candidate-1/actions/ignore", strings.NewReader(`{"reason_code":"not_managed"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "ignore-1")
	first := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionIgnoreDiscoveryCandidate), request)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	request = httptest.NewRequest(http.MethodPost, platformBasePath+"/discovery-candidates/candidate-1/actions/ignore", strings.NewReader(`{"reason_code":"not_managed"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "ignore-1")
	second := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionIgnoreDiscoveryCandidate), request)
	require.Equal(t, first.Body.String(), second.Body.String())
	require.Equal(t, 1, service.ignoreCalls)
}

type discoveryAPIService struct {
	candidate     discovery.Candidate
	ignoreCalls   int
	sourceResults []discovery.SourceResult
}

func (service *discoveryAPIService) RecordReport(context.Context, discovery.Report) ([]discovery.Candidate, error) {
	return nil, nil
}
func (service *discoveryAPIService) List(_ context.Context, scope platformscope.Scope, _ discovery.Filter) (discovery.Page, error) {
	value := service.candidate
	value.Scope = scope
	return discovery.Page{Items: []discovery.Candidate{value}}, nil
}
func (service *discoveryAPIService) Get(_ context.Context, scope platformscope.Scope, id string) (discovery.Candidate, error) {
	value := service.candidate
	value.Scope = scope
	value.ID = id
	return value, nil
}
func (service *discoveryAPIService) Ignore(_ context.Context, scope platformscope.Scope, id, reason string) (discovery.Candidate, error) {
	service.ignoreCalls++
	value := service.candidate
	value.Scope = scope
	value.ID = id
	value.Status = discovery.StatusIgnored
	value.IgnoreReason = reason
	service.candidate = value
	return value, nil
}
func (service *discoveryAPIService) SourceResults(context.Context, platformscope.Scope, string) ([]discovery.SourceResult, error) {
	return append([]discovery.SourceResult(nil), service.sourceResults...), nil
}

func discoveryAPICandidate(scope platformscope.Scope) discovery.Candidate {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	observation := discovery.CandidateObservation{ObservationID: "obs-1", Source: discovery.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: .9, Evidence: []discovery.Evidence{{Kind: discovery.EvidenceProcessName, Value: "mysqld"}}, ObservedAt: now}
	fingerprint, _ := discovery.Fingerprint("host-1", observation)
	observation.Fingerprint = fingerprint
	return discovery.Candidate{ID: "candidate-1", Scope: scope, HostID: "host-1", AgentID: "agent-1", CandidateObservation: observation, RuleRevision: 4, ObservationRevision: 1, FirstSeenAt: now, LastSeenAt: now, Status: discovery.StatusAwaitingConfirmation}
}
