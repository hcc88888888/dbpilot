package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestBearerPrincipalResolverRejectsMissingMultipleAndMalformedAuthorization(t *testing.T) {
	tests := map[string]func(*http.Request){
		"missing": func(*http.Request) {},
		"multiple": func(request *http.Request) {
			request.Header.Add("Authorization", "Bearer first")
			request.Header.Add("Authorization", "Bearer second")
		},
		"basic": func(request *http.Request) {
			request.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		},
		"empty bearer": func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer ")
		},
		"extra token": func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer one two")
		},
		"non canonical": func(request *http.Request) {
			request.Header.Set("Authorization", " bearer token")
		},
	}

	for name, configure := range tests {
		t.Run(name, func(t *testing.T) {
			verifier := &recordingTokenVerifier{}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			configure(request)

			_, err := (BearerPrincipalResolver{Verifier: verifier}).ResolvePrincipal(request)

			require.ErrorIs(t, err, ErrUnauthenticated)
			require.Empty(t, verifier.tokens, "malformed credentials must not reach token verification")
		})
	}
}

func TestBearerPrincipalResolverRejectsVerifierFailures(t *testing.T) {
	for _, name := range []string{"expired", "wrong issuer", "wrong audience"} {
		t.Run(name, func(t *testing.T) {
			verifier := &recordingTokenVerifier{err: errors.New(name)}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("Authorization", "Bearer short-lived-token")

			_, err := (BearerPrincipalResolver{Verifier: verifier}).ResolvePrincipal(request)

			require.ErrorIs(t, err, ErrUnauthenticated)
			require.Equal(t, []string{"short-lived-token"}, verifier.tokens)
		})
	}
}

func TestBearerPrincipalResolverMapsValidatedScopedPermissionGrants(t *testing.T) {
	scopeA := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	scopeB := platformscope.Scope{TenantID: "tenant-b", ProjectID: "project-b"}
	verifier := &recordingTokenVerifier{claims: OIDCClaims{
		Subject: "user-42",
		Grants: []OIDCGrant{
			{TenantID: scopeA.TenantID, ProjectID: scopeA.ProjectID, Permissions: []string{"platform.jobs.read", "platform.jobs.read", "platform.jobs.cancel"}},
			{TenantID: scopeB.TenantID, ProjectID: scopeB.ProjectID, Permissions: []string{"platform.audit.read"}},
		},
	}}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer valid-token")

	principal, err := (BearerPrincipalResolver{Verifier: verifier}).ResolvePrincipal(request)

	require.NoError(t, err)
	require.Equal(t, "user-42", principal.Subject)
	require.False(t, principal.PlatformAdmin)
	require.Equal(t, map[string]struct{}{scopeA.Key(): {}, scopeB.Key(): {}}, principal.Projects)
	require.Equal(t, map[string]map[string]struct{}{
		scopeA.Key(): {"platform.jobs.read": {}, "platform.jobs.cancel": {}},
		scopeB.Key(): {"platform.audit.read": {}},
	}, principal.Grants)
	require.Equal(t, []string{"valid-token"}, verifier.tokens)
}

func TestBearerPrincipalResolverMapsPlatformAdminWithoutGrants(t *testing.T) {
	verifier := &recordingTokenVerifier{claims: OIDCClaims{Subject: "operator", PlatformAdmin: true}}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer admin-token")

	principal, err := (BearerPrincipalResolver{Verifier: verifier}).ResolvePrincipal(request)

	require.NoError(t, err)
	require.True(t, principal.PlatformAdmin)
	require.Empty(t, principal.Projects)
	require.Empty(t, principal.Grants)
}

func TestBearerPrincipalResolverRejectsInvalidClaimGrants(t *testing.T) {
	tests := map[string]OIDCClaims{
		"missing subject":   {Grants: []OIDCGrant{{TenantID: "tenant-a", ProjectID: "project-a", Permissions: []string{"platform.jobs.read"}}}},
		"blank subject":     {Subject: " ", Grants: []OIDCGrant{{TenantID: "tenant-a", ProjectID: "project-a", Permissions: []string{"platform.jobs.read"}}}},
		"empty tenant":      {Subject: "user", Grants: []OIDCGrant{{ProjectID: "project-a", Permissions: []string{"platform.jobs.read"}}}},
		"invalid tenant":    {Subject: "user", Grants: []OIDCGrant{{TenantID: "tenant/a", ProjectID: "project-a", Permissions: []string{"platform.jobs.read"}}}},
		"empty project":     {Subject: "user", Grants: []OIDCGrant{{TenantID: "tenant-a", Permissions: []string{"platform.jobs.read"}}}},
		"invalid project":   {Subject: "user", Grants: []OIDCGrant{{TenantID: "tenant-a", ProjectID: "project a", Permissions: []string{"platform.jobs.read"}}}},
		"blank permission":  {Subject: "user", Grants: []OIDCGrant{{TenantID: "tenant-a", ProjectID: "project-a", Permissions: []string{""}}}},
		"spaced permission": {Subject: "user", Grants: []OIDCGrant{{TenantID: "tenant-a", ProjectID: "project-a", Permissions: []string{" platform.jobs.read"}}}},
		"duplicate scope": {Subject: "user", Grants: []OIDCGrant{
			{TenantID: "tenant-a", ProjectID: "project-a", Permissions: []string{"platform.jobs.read"}},
			{TenantID: "tenant-a", ProjectID: "project-a", Permissions: []string{"platform.jobs.cancel"}},
		}},
	}

	for name, claims := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set("Authorization", "Bearer token")

			_, err := (BearerPrincipalResolver{Verifier: &recordingTokenVerifier{claims: claims}}).ResolvePrincipal(request)

			require.ErrorIs(t, err, ErrUnauthenticated)
		})
	}
}

func TestPrincipalAlertAdapterDoesNotCarryActionGrants(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	principal := Principal{
		Subject: "user", Projects: map[string]struct{}{scope.Key(): {}},
		Grants: map[string]map[string]struct{}{scope.Key(): {"platform.jobs.read": {}}},
	}

	legacy := principal.AlertPrincipal()

	require.Equal(t, "user", legacy.Subject)
	require.False(t, legacy.PlatformAdmin)
	require.True(t, legacy.Allows(alert.Scope{TenantID: scope.TenantID, ProjectID: scope.ProjectID}))
}

type recordingTokenVerifier struct {
	claims OIDCClaims
	err    error
	tokens []string
}

func (verifier *recordingTokenVerifier) Verify(_ context.Context, token string) (OIDCClaims, error) {
	verifier.tokens = append(verifier.tokens, token)
	return verifier.claims, verifier.err
}
