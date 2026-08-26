package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"dbpilot.local/platform/internal/alert"
	"github.com/stretchr/testify/require"
)

func TestHeaderPrincipalResolverAcceptsExplicitScopedProjects(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(HeaderSubject, "actor-1")
	request.Header.Set(HeaderPlatformAdmin, "false")
	request.Header.Set(HeaderProjects, "t1/p1,t2/p2")

	principal, err := (HeaderPrincipalResolver{}).ResolvePrincipal(request)
	require.NoError(t, err)
	require.Equal(t, "actor-1", principal.Subject)
	require.True(t, principal.Allows(alert.Scope{TenantID: "t1", ProjectID: "p1"}))
	require.False(t, principal.Allows(alert.Scope{TenantID: "t1", ProjectID: "p2"}))
}

func TestHeaderPrincipalResolverRejectsMissingMalformedAndMultiValueIdentity(t *testing.T) {
	tests := map[string]func(*http.Request){
		"missing subject": func(request *http.Request) {
			request.Header.Set(HeaderPlatformAdmin, "false")
		},
		"blank subject": func(request *http.Request) {
			request.Header.Set(HeaderSubject, " ")
		},
		"multi subject": func(request *http.Request) {
			request.Header.Add(HeaderSubject, "actor-1")
			request.Header.Add(HeaderSubject, "actor-2")
		},
		"malformed admin": func(request *http.Request) {
			request.Header.Set(HeaderSubject, "actor-1")
			request.Header.Set(HeaderPlatformAdmin, "yes")
		},
		"multi admin": func(request *http.Request) {
			request.Header.Set(HeaderSubject, "actor-1")
			request.Header.Add(HeaderPlatformAdmin, "false")
			request.Header.Add(HeaderPlatformAdmin, "true")
		},
		"malformed project": func(request *http.Request) {
			request.Header.Set(HeaderSubject, "actor-1")
			request.Header.Set(HeaderPlatformAdmin, "false")
			request.Header.Set(HeaderProjects, "p1")
		},
		"multi projects": func(request *http.Request) {
			request.Header.Set(HeaderSubject, "actor-1")
			request.Header.Set(HeaderPlatformAdmin, "false")
			request.Header.Add(HeaderProjects, "t1/p1")
			request.Header.Add(HeaderProjects, "t2/p2")
		},
	}

	for name, configure := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			configure(request)
			_, err := (HeaderPrincipalResolver{}).ResolvePrincipal(request)
			require.ErrorIs(t, err, ErrUnauthenticated)
		})
	}
}

func TestHeaderPrincipalResolverAllowsAdminWithoutProjectHeader(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(HeaderSubject, "platform-operator")
	request.Header.Set(HeaderPlatformAdmin, "true")

	principal, err := (HeaderPrincipalResolver{}).ResolvePrincipal(request)
	require.NoError(t, err)
	require.True(t, principal.PlatformAdmin)
	require.True(t, principal.Allows(alert.Scope{TenantID: "any", ProjectID: "project"}))
}
