package credentiallease

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryProviderReturnsCopiesAndEnvironmentProviderUsesExplicitBinding(t *testing.T) {
	memory, err := NewMemoryProvider(map[string]Credential{"secret://database/one": {Username: "monitor", SecretBytes: []byte("fixture-password"), Revision: 3}})
	require.NoError(t, err)
	first, err := memory.Resolve(context.Background(), "secret://database/one")
	require.NoError(t, err)
	first.SecretBytes[0] = 'X'
	second, err := memory.Resolve(context.Background(), "secret://database/one")
	require.NoError(t, err)
	require.Equal(t, []byte("fixture-password"), second.SecretBytes)

	environment, err := NewEnvironmentProvider(map[string]EnvironmentBinding{"secret://database/one": {Username: "monitor", Variable: "DBPILOT_DEV_DB_ONE", Revision: 4}}, func(name string) (string, bool) {
		return map[string]string{"DBPILOT_DEV_DB_ONE": "environment-password"}[name], name == "DBPILOT_DEV_DB_ONE"
	})
	require.NoError(t, err)
	credential, err := environment.Resolve(context.Background(), "secret://database/one")
	require.NoError(t, err)
	require.Equal(t, []byte("environment-password"), credential.SecretBytes)
	_, err = environment.Resolve(context.Background(), "secret://database/other")
	require.ErrorIs(t, err, ErrLeaseRejected)
}
