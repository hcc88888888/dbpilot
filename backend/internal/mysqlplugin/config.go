package mysqlplugin

import (
	"net"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"google.golang.org/protobuf/proto"
)

func DecodeConfiguration(request *pluginv1.ApplyPluginConfigurationRequest, now time.Time, parser StatementParser) (Config, error) {
	if request == nil || request.GetAssignmentId() == "" || request.GetConfigurationRevision() == 0 || len(request.GetInstances()) == 0 || len(request.GetInstances()) > MaxInstances || parser == nil {
		return Config{}, ErrConfigurationRejected
	}
	result := Config{AssignmentID: request.GetAssignmentId(), Revision: request.GetConfigurationRevision(), Instances: make([]InstanceConfig, 0, len(request.GetInstances()))}
	failed := true
	defer func() {
		if failed {
			result.Release()
		}
	}()
	seen := map[string]struct{}{}
	for _, source := range request.GetInstances() {
		if source == nil || source.GetInstanceId() == "" || source.GetDatabaseVariant() != "mysql" || (source.GetEndpoint() == "") == (source.GetUnixSocket() == "") || len(source.GetTemplates()) > MaxTemplates {
			return Config{}, ErrConfigurationRejected
		}
		if _, duplicate := seen[source.GetInstanceId()]; duplicate {
			return Config{}, ErrConfigurationRejected
		}
		seen[source.GetInstanceId()] = struct{}{}
		if source.GetEndpoint() != "" {
			host, port, err := net.SplitHostPort(source.GetEndpoint())
			if err != nil || host == "" || port == "" {
				return Config{}, ErrConfigurationRejected
			}
		}
		instance := InstanceConfig{ID: source.GetInstanceId(), Variant: source.GetDatabaseVariant(), Endpoint: source.GetEndpoint(), UnixSocket: source.GetUnixSocket(), Templates: map[string]TemplateConfig{}}
		if lease := source.GetCredentialLease(); lease != nil {
			if lease.GetLeaseId() == "" || lease.GetCredentialRevision() == 0 || lease.GetUsername() == "" || len(lease.GetSecretBytes()) == 0 || lease.GetExpiresAt() == nil || !lease.GetExpiresAt().IsValid() || !lease.GetExpiresAt().AsTime().After(now) {
				return Config{}, ErrConfigurationRejected
			}
			instance.Credential = Credential{LeaseID: lease.GetLeaseId(), Revision: lease.GetCredentialRevision(), Username: lease.GetUsername(), Secret: append([]byte(nil), lease.GetSecretBytes()...), ExpiresAt: lease.GetExpiresAt().AsTime().UTC()}
		}
		for _, template := range source.GetTemplates() {
			if ValidateTemplate(template, parser) != nil {
				return Config{}, ErrConfigurationRejected
			}
			key := template.GetTemplateId()
			if _, duplicate := instance.Templates[key]; duplicate {
				return Config{}, ErrConfigurationRejected
			}
			copyValue := proto.Clone(template).(*pluginv1.MetricTemplateConfiguration)
			instance.Templates[key] = TemplateConfig{ID: copyValue.GetTemplateId(), Revision: copyValue.GetRevision(), Digest: append([]byte(nil), copyValue.GetQueryDigest()...), Statement: copyValue.GetReadOnlyStatement(), Interval: time.Duration(copyValue.GetCollectionIntervalSeconds()) * time.Second, Timeout: time.Duration(copyValue.GetTimeoutSeconds()) * time.Second, MaxRows: copyValue.GetMaxRows(), MaxColumns: copyValue.GetMaxColumns(), Cardinality: copyValue.GetCardinalityLimit(), ValueMappings: copyValue.GetValueMappings(), LabelMappings: copyValue.GetLabelMappings()}
		}
		result.Instances = append(result.Instances, instance)
	}
	failed = false
	return result, nil
}

func clearApplyRequest(request *pluginv1.ApplyPluginConfigurationRequest) {
	if request == nil {
		return
	}
	for _, instance := range request.GetInstances() {
		if lease := instance.GetCredentialLease(); lease != nil {
			clear(lease.SecretBytes)
			lease.Username = ""
		}
		for _, template := range instance.GetTemplates() {
			if template != nil {
				template.ReadOnlyStatement = ""
				template.ValueMappings = nil
				template.LabelMappings = nil
			}
		}
	}
}
