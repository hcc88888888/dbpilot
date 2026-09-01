package metrictemplatelease

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCacheKeepsLeaseOnlyInMemoryAndBuildsGatewayConfiguration(t *testing.T) {
	now := time.Date(2026, 9, 1, 6, 0, 0, 0, time.UTC)
	cache := NewCache(func() time.Time { return now })
	lease := Material{LeaseID: "lease-a", AssignmentID: "assignment-a", InstanceID: "instance-a", TemplateID: "template-a", RevisionID: "revision-a", Revision: 3, ConfigurationRevision: 7, OperationRevision: 9, QueryDigest: statementDigest([]byte("SELECT value FROM metrics")), ExpiresAt: now.Add(time.Minute), StatementBytes: []byte("SELECT value FROM metrics"), TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2, CardinalityLimit: 10, CollectionIntervalSeconds: 60, ValueMappings: []ValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: "gauge", Unit: "1"}}}
	require.NoError(t, cache.Store(lease))
	configuration, err := cache.PluginConfiguration("assignment-a", 7, "instance-a", "mysql", "127.0.0.1:3306", "", "revision-a")
	require.NoError(t, err)
	require.Equal(t, "template-a", configuration.Instances[0].Templates[0].TemplateId)
	require.Equal(t, "SELECT value FROM metrics", configuration.Instances[0].Templates[0].ReadOnlyStatement)
	ReleasePluginConfiguration(&configuration)
	require.Empty(t, configuration.Instances[0].Templates[0].ReadOnlyStatement)
	lease.StatementBytes[0] = 'X'
	configuration, err = cache.PluginConfiguration("assignment-a", 7, "instance-a", "mysql", "127.0.0.1:3306", "", "revision-a")
	require.NoError(t, err)
	require.Equal(t, "SELECT value FROM metrics", configuration.Instances[0].Templates[0].ReadOnlyStatement, "cache owns an isolated memory copy")
	cache.Close()
	_, err = cache.PluginConfiguration("assignment-a", 7, "instance-a", "mysql", "127.0.0.1:3306", "", "revision-a")
	require.ErrorIs(t, err, ErrUnavailable)
}

func TestCacheRejectsUnboundedLeaseMaterial(t *testing.T) {
	now := time.Date(2026, 9, 1, 6, 0, 0, 0, time.UTC)
	cache := NewCache(func() time.Time { return now })
	defer cache.Close()
	valid := Material{LeaseID: "lease-a", AssignmentID: "assignment-a", InstanceID: "instance-a", TemplateID: "template-a", RevisionID: "revision-a", Revision: 1, ConfigurationRevision: 7, OperationRevision: 9, QueryDigest: statementDigest([]byte("SELECT 1")), ExpiresAt: now.Add(time.Minute), StatementBytes: []byte("SELECT 1"), CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, CardinalityLimit: 1, ValueMappings: []ValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: "gauge", Unit: "1"}}}
	invalid := valid
	invalid.CollectionIntervalSeconds = 9
	require.ErrorIs(t, cache.Store(invalid), ErrUnavailable)
	invalid = valid
	invalid.CardinalityLimit = 10001
	require.ErrorIs(t, cache.Store(invalid), ErrUnavailable)
}
