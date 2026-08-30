package databaseinstance

import (
	"strings"
	"testing"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestSourceIdentityUsesStableServiceOrContainerIdentity(t *testing.T) {
	require.Equal(t, "native-service:mysqld.service", sourceIdentity(candidateState{source: "native", serviceName: "mysqld.service", processIdentity: "/usr/sbin/mysqld", fingerprint: "fallback"}))
	require.Equal(t, "native-fingerprint:fallback", sourceIdentity(candidateState{source: "native", processIdentity: "/usr/sbin/mysqld", fingerprint: "fallback"}), "an executable path is not instance-unique")
	require.Equal(t, "docker:orders-mysql", sourceIdentity(candidateState{source: "docker", containerIdentity: "orders-mysql", fingerprint: "fallback"}))
}

func TestInstanceCursorIsOpaqueAndBoundToScopeAndFilters(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	filter := Filter{HostID: "host-a", DatabaseFamily: "mysql", Status: StatusAccepted, Limit: 10}
	cursor, err := encodeInstanceCursor(scope, filter, "instance-1")
	require.NoError(t, err)
	require.False(t, strings.Contains(cursor, "instance-1"))
	filter.Cursor = cursor
	after, err := decodeInstanceCursor(scope, filter)
	require.NoError(t, err)
	require.Equal(t, "instance-1", after)
	_, err = decodeInstanceCursor(platformscope.Scope{TenantID: "tenant-b", ProjectID: "project-a"}, filter)
	require.ErrorIs(t, err, ErrInvalid)
	filter.Status = StatusManaged
	_, err = decodeInstanceCursor(scope, filter)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestCanonicalConnectionKeepsTransportIdentityExplicit(t *testing.T) {
	require.Equal(t, "tcp:db.internal:3306", canonicalConnection("db.internal:3306", ""))
	require.Equal(t, "unix:/run/mysqld/mysqld.sock", canonicalConnection("", "/run/mysqld/mysqld.sock"))
}
