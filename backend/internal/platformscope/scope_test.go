package platformscope

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScopeValidateAndKey(t *testing.T) {
	scope := Scope{TenantID: "tenant:one", ProjectID: "project:two"}
	require.NoError(t, scope.Validate())
	require.Equal(t, "10:tenant:one11:project:two", scope.Key())
	require.NotEqual(t,
		Scope{TenantID: "tenant", ProjectID: "one:project:two"}.Key(),
		Scope{TenantID: "tenant:one", ProjectID: "project:two"}.Key(),
	)
}

func TestScopeValidateRejectsBlankComponents(t *testing.T) {
	for _, scope := range []Scope{
		{},
		{TenantID: "tenant-1"},
		{ProjectID: "project-1"},
		{TenantID: " tenant-1 ", ProjectID: "project-1"},
	} {
		require.ErrorIs(t, scope.Validate(), ErrInvalid)
	}
}
