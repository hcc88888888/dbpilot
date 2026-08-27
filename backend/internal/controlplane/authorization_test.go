package controlplane

import (
	"testing"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestAuthorizerRequiresExactScopeAndPermission(t *testing.T) {
	allowed := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	wrongTenant := platformscope.Scope{TenantID: "tenant-b", ProjectID: "project-a"}
	wrongProject := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-b"}
	tests := []struct {
		name       string
		principal  Principal
		scope      platformscope.Scope
		permission string
		allowed    bool
	}{
		{name: "platform admin", principal: Principal{Subject: "admin", PlatformAdmin: true}, scope: wrongTenant, permission: openapi.PermissionCancelJob, allowed: true},
		{name: "exact project grant", principal: Principal{Subject: "user", Grants: scopedGrants(allowed, openapi.PermissionGetJob)}, scope: allowed, permission: openapi.PermissionGetJob, allowed: true},
		{name: "wrong tenant", principal: Principal{Subject: "user", Grants: scopedGrants(allowed, openapi.PermissionGetJob)}, scope: wrongTenant, permission: openapi.PermissionGetJob},
		{name: "wrong project", principal: Principal{Subject: "user", Grants: scopedGrants(allowed, openapi.PermissionGetJob)}, scope: wrongProject, permission: openapi.PermissionGetJob},
		{name: "missing action", principal: Principal{Subject: "user", Grants: scopedGrants(allowed, openapi.PermissionGetJob)}, scope: allowed, permission: openapi.PermissionCancelJob},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := (Authorizer{}).Require(test.principal, test.scope, test.permission)
			if test.allowed {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrForbidden)
		})
	}
}

func TestPrincipalAllowsScopeFromMembershipOrGrantWithoutGrantingActions(t *testing.T) {
	membership := platformscope.Scope{TenantID: "tenant-a", ProjectID: "membership"}
	grant := platformscope.Scope{TenantID: "tenant-a", ProjectID: "grant"}
	principal := Principal{
		Subject:  "user",
		Projects: map[string]struct{}{membership.Key(): {}},
		Grants:   scopedGrants(grant, openapi.PermissionGetJob),
	}

	require.True(t, principal.AllowsScope(membership))
	require.False(t, principal.Allows(membership, openapi.PermissionGetJob), "scope membership alone must never become an action grant")
	require.True(t, principal.AllowsScope(grant))
	require.True(t, principal.Allows(grant, openapi.PermissionGetJob))
}

func TestGeneratedOperationPermissionsUseGeneratedConstants(t *testing.T) {
	want := map[string]string{
		"GetArtifact":            openapi.PermissionGetArtifact,
		"CreateArtifactDownload": openapi.PermissionCreateArtifactDownload,
		"ListAuditEvents":        openapi.PermissionListAuditEvents,
		"GetCapabilities":        openapi.PermissionGetCapabilities,
		"GetJob":                 openapi.PermissionGetJob,
		"CancelJob":              openapi.PermissionCancelJob,
	}
	for operationID, permission := range want {
		got, ok := permissionForStrictOperation(operationID)
		require.True(t, ok, operationID)
		require.Equal(t, permission, got, operationID)
	}
	_, ok := permissionForStrictOperation("UnknownOperation")
	require.False(t, ok, "unknown generated operations must fail closed")
}

func scopedGrants(scope platformscope.Scope, permissions ...string) map[string]map[string]struct{} {
	values := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		values[permission] = struct{}{}
	}
	return map[string]map[string]struct{}{scope.Key(): values}
}
