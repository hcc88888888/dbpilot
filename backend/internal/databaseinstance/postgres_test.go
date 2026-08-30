package databaseinstance

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSourceIdentityUsesStableServiceOrContainerIdentity(t *testing.T) {
	require.Equal(t, "native-service:mysqld.service", sourceIdentity(candidateState{source: "native", serviceName: "mysqld.service", processIdentity: "/usr/sbin/mysqld", fingerprint: "fallback"}))
	require.Equal(t, "native-process:/usr/sbin/mysqld", sourceIdentity(candidateState{source: "native", processIdentity: "/usr/sbin/mysqld", fingerprint: "fallback"}))
	require.Equal(t, "docker:orders-mysql", sourceIdentity(candidateState{source: "docker", containerIdentity: "orders-mysql", fingerprint: "fallback"}))
}

func TestCanonicalConnectionKeepsTransportIdentityExplicit(t *testing.T) {
	require.Equal(t, "tcp:db.internal:3306", canonicalConnection("db.internal:3306", ""))
	require.Equal(t, "unix:/run/mysqld/mysqld.sock", canonicalConnection("", "/run/mysqld/mysqld.sock"))
}
