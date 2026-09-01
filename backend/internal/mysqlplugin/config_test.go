package mysqlplugin

import (
	"crypto/sha256"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDecodeConfigurationAcceptsTwoIndependentInstancesAndCopiesSecrets(t *testing.T) {
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	secretA := []byte("secret-a")
	secretB := []byte("secret-b")
	request := &pluginv1.ApplyPluginConfigurationRequest{AssignmentId: "assignment-a", ConfigurationRevision: 7, Instances: []*pluginv1.PluginInstanceConfiguration{
		fixtureInstance("mysql-a", "127.0.0.1:33061", "monitor-a", secretA, now.Add(time.Minute)),
		fixtureInstance("mysql-b", "127.0.0.1:33062", "monitor-b", secretB, now.Add(time.Minute)),
	}}

	configuration, err := DecodeConfiguration(request, now, NewMySQLStatementParser())
	require.NoError(t, err)
	require.Equal(t, uint64(7), configuration.Revision)
	require.Len(t, configuration.Instances, 2)
	request.Instances[0].CredentialLease.SecretBytes[0] = 'X'
	require.Equal(t, []byte("secret-a"), configuration.Instances[0].Credential.Secret)
	configuration.Release()
	require.Equal(t, make([]byte, len("secret-a")), configuration.Instances[0].Credential.Secret)
}

func TestDecodeConfigurationRejectsDuplicateInstancesExpiredCredentialsAndUnsafeTemplates(t *testing.T) {
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		edit func(*pluginv1.ApplyPluginConfigurationRequest)
	}{
		{name: "duplicate instance", edit: func(request *pluginv1.ApplyPluginConfigurationRequest) {
			request.Instances = append(request.Instances, fixtureInstance("mysql-a", "127.0.0.1:33062", "monitor", []byte("secret"), now.Add(time.Minute)))
		}},
		{name: "expired credential", edit: func(request *pluginv1.ApplyPluginConfigurationRequest) {
			request.Instances[0].CredentialLease.ExpiresAt = timestamppb.New(now)
		}},
		{name: "unsafe template", edit: func(request *pluginv1.ApplyPluginConfigurationRequest) {
			request.Instances[0].Templates = []*pluginv1.MetricTemplateConfiguration{fixtureTemplate("custom-a", 2, "DELETE FROM orders")}
		}},
		{name: "duplicate template revision", edit: func(request *pluginv1.ApplyPluginConfigurationRequest) {
			template := fixtureTemplate("custom-a", 2, "SELECT 1 AS value")
			request.Instances[0].Templates = []*pluginv1.MetricTemplateConfiguration{template, fixtureTemplate("custom-a", 2, "SELECT 2 AS value")}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := &pluginv1.ApplyPluginConfigurationRequest{AssignmentId: "assignment-a", ConfigurationRevision: 1, Instances: []*pluginv1.PluginInstanceConfiguration{fixtureInstance("mysql-a", "127.0.0.1:33061", "monitor", []byte("secret"), now.Add(time.Minute))}}
			test.edit(request)
			_, err := DecodeConfiguration(request, now, NewMySQLStatementParser())
			require.ErrorIs(t, err, ErrConfigurationRejected)
		})
	}
}

func fixtureInstance(id, endpoint, username string, secret []byte, expires time.Time) *pluginv1.PluginInstanceConfiguration {
	return &pluginv1.PluginInstanceConfiguration{InstanceId: id, DatabaseVariant: "mysql", Endpoint: endpoint, CredentialLease: &pluginv1.CredentialLease{LeaseId: "lease-" + id, CredentialRevision: 1, Username: username, SecretBytes: append([]byte(nil), secret...), ExpiresAt: timestamppb.New(expires)}}
}

func fixtureTemplate(id string, revision uint64, statement string) *pluginv1.MetricTemplateConfiguration {
	digest := sha256.Sum256([]byte(statement))
	return &pluginv1.MetricTemplateConfiguration{TemplateId: id, Revision: revision, QueryDigest: digest[:], QueryKind: "sql", ReadOnlyStatement: statement, CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 10, MaxColumns: 4, CardinalityLimit: 10, ValueMappings: []*pluginv1.MetricValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: "gauge", Unit: "1"}}}
}
