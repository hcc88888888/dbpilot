// Package plugingateway is the Agent's only client for a supervised database
// plugin. It intentionally supports Unix-domain sockets only; plugins never
// receive a Control Plane endpoint or transport credential.
package plugingateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/plugincontract"
	"dbpilot.local/platform/internal/spool"
	"google.golang.org/protobuf/proto"
)

const (
	maxRPCMessageBytes = 4 << 20
	maxGatewayMembers  = 128
	maxConfiguredPairs = maxGatewayMembers * maxGatewayMembers
)

var (
	resourceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	familyID   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	errGateway = errors.New("PLUGIN_GATEWAY_REJECTED")
)

type Spool interface {
	AppendWithCursor(context.Context, spool.DataClass, spool.Batch, spool.CursorReceipt) (spool.CursorAppendResult, error)
	Cursor(context.Context, string) (spool.CursorReceipt, bool, error)
	MarkCursorAcknowledged(context.Context, string, uint64) error
}

type ClientConfig struct {
	RuntimeRoot string
	Scope       MetricScope
	Store       Spool
	Timeout     time.Duration
	Now         func() time.Time
}

type Client struct {
	config ClientConfig
}

// MetricSink returns the Agent-owned durable spool configured for this
// client. It is deliberately exposed only as the narrow append interface so
// Supervisor can own the stream lifetime without exposing spool internals.
func (client *Client) MetricSink() MetricSink {
	if client == nil {
		return nil
	}
	return client.config.Store
}

// ExpectedPlugin comes only from the Supervisor's launch result, never from a
// plugin response or control-plane supplied socket address.
type ExpectedPlugin struct {
	PID                            int
	ExpectedUserID                 uint32
	ExpectedGroupID                uint32
	RuntimeDirectory               string
	AssignmentID                   string
	PluginID                       string
	DatabaseFamily                 string
	Version                        string
	ProtocolVersion                string
	ExecutablePath                 string
	ExecutableSHA256               []byte
	LaunchNonce                    []byte
	ConfigurationRevision          uint64
	OperationRevision              uint64
	InstanceIDs                    []string
	TemplateIDs                    []string
	SupportedVariants              []string
	SignedCapabilities             []string
	MetricTemplateSchemaVersion    uint32
	TemplateConfigurations         []*pluginv1.MetricTemplateConfiguration
	InstanceTemplateConfigurations map[string][]*pluginv1.MetricTemplateConfiguration
}

type Capabilities struct {
	SupportedVariants           []string
	DatabaseVersionRange        string
	Capabilities                []string
	MetricTemplateSchemaVersion uint32
	BuiltinTemplateIDs          []string
}

type PluginConfiguration struct {
	AssignmentID          string
	ConfigurationRevision uint64
	Instances             []*pluginv1.PluginInstanceConfiguration
}

func (configuration *PluginConfiguration) Release() {
	if configuration == nil {
		return
	}
	for _, instance := range configuration.Instances {
		clearInstanceCredential(instance)
		for _, template := range instance.GetTemplates() {
			if template != nil {
				template.ReadOnlyStatement = ""
				template.ValueMappings = nil
				template.LabelMappings = nil
			}
		}
	}
}

type ValidationResult struct {
	InstanceID      string
	Valid           bool
	DatabaseVersion string
	DatabaseEdition string
	Capabilities    []string
	ErrorCode       string
}

type TrialMetric struct {
	Name       string
	Value      float64
	Unit       string
	MetricType string
	Labels     map[string]string
}

type TrialResult struct {
	Succeeded      bool
	Metrics        []TrialMetric
	RowCount       uint32
	ColumnCount    uint32
	MetricCount    uint32
	DurationMillis uint32
	ErrorCode      string
}

type MetricSink interface {
	AppendWithCursor(context.Context, spool.DataClass, spool.Batch, spool.CursorReceipt) (spool.CursorAppendResult, error)
	Cursor(context.Context, string) (spool.CursorReceipt, bool, error)
	MarkCursorAcknowledged(context.Context, string, uint64) error
}

type cursorKey struct {
	AssignmentID          string
	ConfigurationRevision uint64
	TemplateID            string
	InstanceID            string
}

func (key cursorKey) string() string {
	return key.AssignmentID + "\x00" + stringRevision(key.ConfigurationRevision) + "\x00" + key.TemplateID + "\x00" + key.InstanceID
}

func stringRevision(value uint64) string {
	return fmt.Sprintf("%d", value)
}

type Session struct {
	client                  *Client
	expected                ExpectedPlugin
	launchOperationRevision uint64
	mu                      sync.Mutex
	lanesMu                 sync.Mutex
	lanes                   map[cursorKey]*sync.Mutex
	handshaken              bool
	configurationRevision   uint64
	instances               map[string]*pluginv1.PluginInstanceConfiguration
	builtinTemplates        map[string]*pluginv1.BuiltinMetricTemplateDescriptor
	pendingRollback         *sessionConfigurationSnapshot
}

type sessionConfigurationSnapshot struct {
	expected              ExpectedPlugin
	configurationRevision uint64
	instances             map[string]*pluginv1.PluginInstanceConfiguration
}

func NewClient(config ClientConfig) (*Client, error) {
	if !filepath.IsAbs(config.RuntimeRoot) || filepath.Clean(config.RuntimeRoot) != config.RuntimeRoot || config.Scope.validateAgent() != nil || config.Timeout < 0 || config.Timeout > time.Minute {
		return nil, errGateway
	}
	if config.Timeout == 0 {
		config.Timeout = 15 * time.Second
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Client{config: config}, nil
}

func (client *Client) Open(expected ExpectedPlugin) (*Session, error) {
	if client == nil || client.config.Scope.validateAgent() != nil || validateExpected(client.config.RuntimeRoot, expected) != nil {
		return nil, errGateway
	}
	return &Session{client: client, expected: cloneExpected(expected), launchOperationRevision: expected.OperationRevision}, nil
}

func (session *Session) Handshake(ctx context.Context, expected ExpectedPlugin) (Capabilities, error) {
	if session == nil || ctx == nil || ctx.Err() != nil || !sameExpected(session.expected, expected) {
		return Capabilities{}, errGateway
	}
	var result Capabilities
	var builtinTemplates map[string]*pluginv1.BuiltinMetricTemplateDescriptor
	err := session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		challenge := make([]byte, sha256.Size)
		if _, err := rand.Read(challenge); err != nil {
			return errGateway
		}
		response, err := client.Handshake(callContext, &pluginv1.PluginHandshakeRequest{ExpectedPluginId: session.expected.PluginID, ExpectedDatabaseFamily: session.expected.DatabaseFamily, ExpectedVersion: session.expected.Version, ExpectedProtocolVersion: session.expected.ProtocolVersion, LaunchNonceChallenge: challenge})
		if err != nil || !validHandshake(response, session.expected, challenge) || !matchesSignedManifest(response, session.expected) {
			return errGateway
		}
		variants, capabilities, versionRange := boundedSorted(response.GetSupportedVariants(), 64), boundedSorted(response.GetCapabilities(), 64), boundedText(response.GetDatabaseVersionRange(), 128)
		if len(response.GetSupportedVariants()) > 0 && variants == nil || len(response.GetCapabilities()) > 0 && capabilities == nil || response.GetDatabaseVersionRange() != "" && versionRange == "" {
			return errGateway
		}
		var valid bool
		builtinTemplates, valid = plugincontract.ValidateBuiltinDescriptors(response.GetBuiltinTemplates(), session.expected.TemplateIDs)
		if !valid {
			return errGateway
		}
		builtinIDs := mapKeysBuiltin(builtinTemplates)
		sort.Strings(builtinIDs)
		result = Capabilities{SupportedVariants: variants, DatabaseVersionRange: versionRange, Capabilities: capabilities, MetricTemplateSchemaVersion: response.GetMetricTemplateSchemaVersion(), BuiltinTemplateIDs: builtinIDs}
		return nil
	})
	if err != nil {
		return Capabilities{}, err
	}
	session.mu.Lock()
	session.handshaken = true
	session.builtinTemplates = builtinTemplates
	session.mu.Unlock()
	return result, nil
}

func (session *Session) ApplyConfiguration(ctx context.Context, configuration PluginConfiguration) error {
	if session == nil || ctx == nil || ctx.Err() != nil || configuration.validate(session.expected) != nil || !session.isHandshaken() {
		return errGateway
	}
	if err := session.applyConfigurationRPC(ctx, configuration); err != nil {
		return err
	}
	session.mu.Lock()
	session.configurationRevision = configuration.ConfigurationRevision
	session.instances = make(map[string]*pluginv1.PluginInstanceConfiguration, len(configuration.Instances))
	for _, instance := range configuration.Instances {
		session.instances[instance.GetInstanceId()] = cloneInstanceWithoutCredential(instance)
	}
	session.mu.Unlock()
	return nil
}

func (session *Session) applyConfigurationRPC(ctx context.Context, configuration PluginConfiguration) error {
	request := canonicalApplyRequest(configuration)
	defer clearConfigurationSecrets(request)
	return session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		response, err := client.ApplyConfiguration(callContext, request)
		if err != nil || !validApplyResponse(response, configuration) {
			return errGateway
		}
		return nil
	})
}

func (session *Session) AssignmentID() string {
	if session == nil {
		return ""
	}
	return session.expected.AssignmentID
}

func (session *Session) ConfiguredTemplateIDs(instanceID string) ([]string, error) {
	if session == nil || !session.isConfigured() {
		return nil, errGateway
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	instance := session.instances[instanceID]
	if instance == nil {
		return nil, errGateway
	}
	return session.configuredTemplateIDs(instance), nil
}

func (session *Session) SetExpectedTemplateConfigurations(values []*pluginv1.MetricTemplateConfiguration) error {
	if session == nil || len(values) == 0 {
		return errGateway
	}
	ids := make([]string, 0, len(values))
	for _, value := range values {
		if !validTemplateConfiguration(value) {
			return errGateway
		}
		ids = append(ids, value.GetTemplateId())
	}
	if !sameSet(ids, session.expected.TemplateIDs) {
		return errGateway
	}
	session.mu.Lock()
	session.expected.TemplateConfigurations = cloneTemplateConfigurations(values)
	session.mu.Unlock()
	return nil
}

func (session *Session) SetExpectedInstanceTemplateConfigurations(values map[string][]*pluginv1.MetricTemplateConfiguration) error {
	if session == nil || len(values) != len(session.expected.InstanceIDs) {
		return errGateway
	}
	aggregateByID := map[string]*pluginv1.MetricTemplateConfiguration{}
	conflictingAggregate := false
	cloned := make(map[string][]*pluginv1.MetricTemplateConfiguration, len(values))
	for _, instanceID := range session.expected.InstanceIDs {
		templates, ok := values[instanceID]
		if !ok {
			return errGateway
		}
		seen := map[string]struct{}{}
		for _, template := range templates {
			if !validTemplateConfiguration(template) {
				return errGateway
			}
			if _, duplicate := seen[template.GetTemplateId()]; duplicate {
				return errGateway
			}
			seen[template.GetTemplateId()] = struct{}{}
			if existing := aggregateByID[template.GetTemplateId()]; existing != nil && !proto.Equal(existing, template) {
				conflictingAggregate = true
			} else if existing == nil {
				aggregateByID[template.GetTemplateId()] = template
			}
		}
		cloned[instanceID] = cloneTemplateConfigurations(templates)
	}
	var aggregate []*pluginv1.MetricTemplateConfiguration
	for _, templateID := range session.expected.TemplateIDs {
		template := aggregateByID[templateID]
		if template == nil {
			return errGateway
		}
		if !conflictingAggregate {
			aggregate = append(aggregate, proto.Clone(template).(*pluginv1.MetricTemplateConfiguration))
		}
	}
	session.mu.Lock()
	session.expected.TemplateConfigurations = aggregate
	session.expected.InstanceTemplateConfigurations = cloned
	session.mu.Unlock()
	return nil
}

// RemoveCredentials applies the current routing and templates without a lease,
// requiring the plugin to close its database pools before shutdown or expiry.
func (session *Session) RemoveCredentials(ctx context.Context) error {
	if session == nil || ctx == nil || ctx.Err() != nil || !session.isConfigured() {
		return errGateway
	}
	session.mu.Lock()
	instances := make([]*pluginv1.PluginInstanceConfiguration, 0, len(session.instances))
	for _, instance := range session.instances {
		instances = append(instances, cloneInstanceWithoutCredential(instance))
	}
	revision := session.configurationRevision
	session.mu.Unlock()
	configuration := PluginConfiguration{AssignmentID: session.expected.AssignmentID, ConfigurationRevision: revision, Instances: instances}
	return session.ApplyConfiguration(ctx, configuration)
}

// CheckHealth is used by the Supervisor activation gate after the nonce-backed
// handshake. It verifies the plugin cannot claim a different assignment,
// revision, or instance set than the launched process was given.
func (session *Session) CheckHealth(ctx context.Context) error {
	if session == nil || ctx == nil || ctx.Err() != nil || !session.isHandshaken() {
		return errGateway
	}
	return session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		response, err := client.GetHealth(callContext, &pluginv1.GetPluginHealthRequest{AssignmentId: session.expected.AssignmentID})
		if err != nil || response.GetAssignmentId() != session.expected.AssignmentID || response.GetState() != pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY || response.GetActiveConfigurationRevision() != session.expected.ConfigurationRevision || int(response.GetBoundInstanceCount()) != len(session.expected.InstanceIDs) || len(response.GetInstances()) != len(session.expected.InstanceIDs) || response.GetObservedAt() == nil || !response.GetObservedAt().IsValid() {
			return errGateway
		}
		seen := map[string]struct{}{}
		for _, instance := range response.GetInstances() {
			if instance == nil || !contains(session.expected.InstanceIDs, instance.GetInstanceId()) || instance.GetState() != pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY || instance.GetErrorCode() != "" {
				return errGateway
			}
			if _, duplicate := seen[instance.GetInstanceId()]; duplicate {
				return errGateway
			}
			seen[instance.GetInstanceId()] = struct{}{}
		}
		return nil
	})
}

func (session *Session) ValidateInstance(ctx context.Context, instanceID string) (ValidationResult, error) {
	if session == nil || ctx == nil || ctx.Err() != nil || !session.readyForInstance(instanceID) {
		return ValidationResult{}, errGateway
	}
	var result ValidationResult
	err := session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		response, err := client.ValidateInstance(callContext, &pluginv1.ValidatePluginInstanceRequest{AssignmentId: session.expected.AssignmentID, InstanceId: instanceID, ConfigurationRevision: session.currentRevision()})
		if err != nil || !validValidationResponse(response, instanceID, session.expected.SignedCapabilities) {
			return errGateway
		}
		result = ValidationResult{InstanceID: response.GetInstanceId(), Valid: response.GetValid(), DatabaseVersion: response.GetDatabaseVersion(), DatabaseEdition: response.GetDatabaseEdition(), Capabilities: boundedSorted(response.GetCapabilities(), 64), ErrorCode: fixedPluginCode(response.GetErrorCode())}
		return nil
	})
	return result, err
}

func (session *Session) TrialMetricTemplate(ctx context.Context, configurationRevision, operationRevision uint64, instanceID string, template *pluginv1.TrialMetricTemplateDefinition) (TrialResult, error) {
	if session == nil || ctx == nil || ctx.Err() != nil {
		return TrialResult{}, errGateway
	}
	session.mu.Lock()
	assignmentID, currentOperation, launchOperation := session.expected.AssignmentID, session.expected.OperationRevision, session.launchOperationRevision
	session.mu.Unlock()
	if launchOperation == 0 {
		launchOperation = currentOperation
	}
	if configurationRevision == 0 || operationRevision == 0 || configurationRevision != session.currentRevision() || operationRevision != currentOperation || launchOperation == 0 || !session.readyForInstance(instanceID) || !validTrialTemplateDefinition(template) {
		return TrialResult{}, errGateway
	}
	request := &pluginv1.TrialMetricTemplateRequest{AssignmentId: assignmentID, ConfigurationRevision: session.currentRevision(), OperationRevision: launchOperation, InstanceId: instanceID, Template: proto.Clone(template).(*pluginv1.TrialMetricTemplateDefinition)}
	var result TrialResult
	err := session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		var trialErr error
		result, trialErr = trialMetricTemplateWithClient(callContext, client, request)
		return trialErr
	})
	return result, err
}

func (session *Session) ConfigurationRevision() uint64 {
	if session == nil {
		return 0
	}
	return session.currentRevision()
}
func (session *Session) OperationRevision() uint64 {
	if session == nil {
		return 0
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.expected.OperationRevision
}

func trialMetricTemplateWithClient(ctx context.Context, client pluginv1.PluginRuntimeClient, request *pluginv1.TrialMetricTemplateRequest) (TrialResult, error) {
	if ctx == nil || client == nil || request == nil || request.GetTemplate() == nil || !validTrialTemplateDefinition(request.GetTemplate()) {
		return TrialResult{}, errGateway
	}
	defer clearTrialMetricTemplateRequest(request)
	response, err := client.TrialMetricTemplate(ctx, request)
	if err != nil || !validTrialMetricTemplateResponse(response, request.GetTemplate()) {
		return TrialResult{}, errGateway
	}
	result := TrialResult{Succeeded: response.GetSucceeded(), RowCount: response.GetRowCount(), ColumnCount: response.GetColumnCount(), MetricCount: response.GetMetricCount(), DurationMillis: response.GetDurationMillis(), ErrorCode: fixedPluginCode(response.GetErrorCode()), Metrics: make([]TrialMetric, len(response.GetCandidateMetrics()))}
	for index, metric := range response.GetCandidateMetrics() {
		labels := make(map[string]string, len(metric.GetLabels()))
		for name, value := range metric.GetLabels() {
			labels[name] = value
		}
		result.Metrics[index] = TrialMetric{Name: metric.GetMetricName(), Value: metric.GetValue(), Unit: metric.GetUnit(), MetricType: metricTypeName(metric.GetMetricType()), Labels: labels}
	}
	return result, nil
}

func validTrialTemplateDefinition(value *pluginv1.TrialMetricTemplateDefinition) bool {
	if value == nil || !identifier(value.GetTemplateId()) || value.GetRevision() == 0 || len(value.GetQueryDigest()) != sha256.Size || value.GetQueryKind() != "sql" || len(value.GetReadOnlyStatement()) == 0 || len(value.GetReadOnlyStatement()) > 32768 || value.GetCollectionIntervalSeconds() < 10 || value.GetCollectionIntervalSeconds() > 86400 || value.GetTimeoutSeconds() == 0 || value.GetTimeoutSeconds() > 30 || value.GetMaxRows() == 0 || value.GetMaxRows() > 100 || value.GetMaxColumns() == 0 || value.GetMaxColumns() > 32 || value.GetCardinalityLimit() == 0 || value.GetCardinalityLimit() > 10000 || !validTemplateMappings(value.GetValueMappings(), value.GetLabelMappings()) {
		return false
	}
	digest := sha256.Sum256(value.GetReadOnlyStatement())
	return subtle.ConstantTimeCompare(digest[:], value.GetQueryDigest()) == 1
}

func validTrialMetricTemplateResponse(value *pluginv1.TrialMetricTemplateResponse, definition *pluginv1.TrialMetricTemplateDefinition) bool {
	maximumMetrics := uint64(definition.GetMaxRows()) * uint64(len(definition.GetValueMappings()))
	if maximumMetrics > uint64(definition.GetCardinalityLimit()) {
		maximumMetrics = uint64(definition.GetCardinalityLimit())
	}
	if value == nil || definition == nil || value.GetMetricCount() != uint32(len(value.GetCandidateMetrics())) || value.GetRowCount() > definition.GetMaxRows() || value.GetColumnCount() > definition.GetMaxColumns() || uint64(value.GetMetricCount()) > maximumMetrics || value.GetDurationMillis() > definition.GetTimeoutSeconds()*1000 || value.GetSucceeded() == (value.GetErrorCode() != "") || fixedPluginCode(value.GetErrorCode()) != value.GetErrorCode() {
		return false
	}
	type metricIdentity struct {
		unit       string
		metricType pluginv1.PluginMetricType
	}
	allowed := make(map[string]metricIdentity, len(definition.GetValueMappings()))
	for _, mapping := range definition.GetValueMappings() {
		if mapping == nil {
			return false
		}
		allowed[mapping.GetMetricName()] = metricIdentity{unit: mapping.GetUnit(), metricType: metricTypeFromName(mapping.GetMetricType())}
	}
	allowedLabels := make(map[string]struct{}, len(definition.GetLabelMappings()))
	for _, mapping := range definition.GetLabelMappings() {
		allowedLabels[mapping.GetLabel()] = struct{}{}
	}
	series := make(map[string]struct{}, len(value.GetCandidateMetrics()))
	for _, metric := range value.GetCandidateMetrics() {
		identity, exists := allowed[metric.GetMetricName()]
		if metric == nil || !exists || identity.unit != metric.GetUnit() || identity.metricType != metric.GetMetricType() || !finite(metric.GetValue()) || len(metric.GetLabels()) > 16 {
			return false
		}
		key := metric.GetMetricName()
		names := make([]string, 0, len(metric.GetLabels()))
		for name := range metric.GetLabels() {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			label := metric.GetLabels()[name]
			if _, ok := allowedLabels[name]; !ok || !pluginLabelName.MatchString(name) || !utf8.ValidString(label) || len([]byte(label)) > 128 || strings.ContainsAny(label, "\x00\r\n") {
				return false
			}
			key += "\x00" + name + "=" + label
		}
		series[key] = struct{}{}
	}
	return len(series) <= int(definition.GetCardinalityLimit())
}

func clearTrialMetricTemplateRequest(request *pluginv1.TrialMetricTemplateRequest) {
	if request == nil || request.Template == nil {
		return
	}
	for index := range request.Template.ReadOnlyStatement {
		request.Template.ReadOnlyStatement[index] = 0
	}
	request.Template.ReadOnlyStatement = nil
}

func (session *Session) CollectNow(ctx context.Context, instanceIDs, templateIDs []string) error {
	if session == nil || ctx == nil || ctx.Err() != nil || !session.readyForCollect(instanceIDs, templateIDs) {
		return errGateway
	}
	request := canonicalCollectRequest(session.expected.AssignmentID, session.currentRevision(), instanceIDs, templateIDs)
	instances, templates := request.GetInstanceIds(), request.GetTemplateIds()
	if len(instances) > 0 && len(templates) > maxConfiguredPairs/len(instances) || proto.Size(request) > maxRPCMessageBytes {
		return errGateway
	}
	return session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		response, err := client.CollectNow(callContext, request)
		if err != nil || !validCollectResponseEnvelope(response, len(instances)*len(templates)) {
			return errGateway
		}
		batches := append([]*pluginv1.PluginMetricBatch(nil), response.GetBatches()...)
		sort.Slice(batches, func(left, right int) bool {
			if batches[left].GetInstanceId() != batches[right].GetInstanceId() {
				return batches[left].GetInstanceId() < batches[right].GetInstanceId()
			}
			if batches[left].GetTemplateId() != batches[right].GetTemplateId() {
				return batches[left].GetTemplateId() < batches[right].GetTemplateId()
			}
			return batches[left].GetSequence() < batches[right].GetSequence()
		})
		seen := make(map[string]struct{}, len(batches))
		for _, batch := range batches {
			if batch == nil || !contains(instances, batch.GetInstanceId()) || !contains(templates, batch.GetTemplateId()) || !session.isBatchConfigured(batch) {
				return errGateway
			}
			key := batch.GetInstanceId() + "\x00" + batch.GetTemplateId()
			if _, duplicate := seen[key]; duplicate {
				return errGateway
			}
			seen[key] = struct{}{}
		}
		for _, batch := range batches {
			if err := session.appendAndAcknowledge(callContext, batch, session.client.config.Store, client); err != nil {
				return err
			}
		}
		return nil
	})
}

func (session *Session) RunMetricStream(ctx context.Context, sink MetricSink) error {
	return session.runMetricStream(ctx, sink, nil, false)
}

// RunMetricStreamReady reports readiness only after the verified stream has
// received server headers. Dial/header setup is bounded by the unary timeout;
// the receive loop is owned solely by the Supervisor lifetime context.
func (session *Session) RunMetricStreamReady(ctx context.Context, sink MetricSink, ready chan<- error) error {
	return session.runMetricStream(ctx, sink, ready, false)
}

// RunMetricStreamCommitted reports readiness only after the first batch in
// the current configuration namespace has been durably spooled and ACKed.
// Live Apply uses this stronger boundary before committing its transaction.
func (session *Session) RunMetricStreamCommitted(ctx context.Context, sink MetricSink, ready chan<- error) error {
	return session.runMetricStream(ctx, sink, ready, true)
}

// ApplyConfigurationUpdate stages a same-process configuration transaction.
// It leaves the previous session projection intact until the plugin has
// accepted the candidate and every configured instance has passed validation
// and an initial collection. The caller must then reopen the metric stream and
// either FinalizeConfigurationUpdate after its first durable ACK or invoke
// RollbackConfigurationUpdate with the exact previous configuration.
func (session *Session) ApplyConfigurationUpdate(ctx context.Context, expected ExpectedPlugin, configuration, previous PluginConfiguration) error {
	if session == nil || ctx == nil || ctx.Err() != nil || validateExpected(filepath.Dir(expected.RuntimeDirectory), expected) != nil || configuration.validate(expected) != nil {
		return errGateway
	}
	session.mu.Lock()
	snapshot := sessionConfigurationSnapshot{expected: cloneExpected(session.expected), configurationRevision: session.configurationRevision, instances: cloneInstanceMap(session.instances)}
	handshaken, pending := session.handshaken, session.pendingRollback
	session.mu.Unlock()
	if !handshaken || pending != nil || previous.validate(snapshot.expected) != nil || previous.ConfigurationRevision != snapshot.configurationRevision || !sameVerifiedRuntime(snapshot.expected, expected) || expected.ConfigurationRevision <= snapshot.expected.ConfigurationRevision || expected.OperationRevision <= snapshot.expected.OperationRevision {
		return errGateway
	}
	if err := session.applyConfigurationRPC(ctx, configuration); err != nil {
		if session.restoreConfigurationRPC(previous) != nil {
			session.mu.Lock()
			session.handshaken = false
			session.mu.Unlock()
		}
		return errGateway
	}
	if err := session.probeConfiguration(ctx, expected, configuration); err != nil {
		if rollbackErr := session.restoreConfigurationRPC(previous); rollbackErr != nil {
			session.mu.Lock()
			session.handshaken = false
			session.mu.Unlock()
		}
		return errGateway
	}
	session.mu.Lock()
	if !session.handshaken || session.pendingRollback != nil || !sameExpected(session.expected, snapshot.expected) || session.configurationRevision != snapshot.configurationRevision {
		session.mu.Unlock()
		_ = session.restoreConfigurationRPC(previous)
		return errGateway
	}
	session.expected = cloneExpected(expected)
	session.configurationRevision = configuration.ConfigurationRevision
	session.instances = instanceMapWithoutCredentials(configuration.Instances)
	session.pendingRollback = &snapshot
	session.mu.Unlock()
	return nil
}

func (session *Session) restoreConfigurationRPC(previous PluginConfiguration) error {
	if session == nil || session.client == nil {
		return errGateway
	}
	restoreContext, cancel := context.WithTimeout(context.Background(), session.client.config.Timeout)
	defer cancel()
	return session.applyConfigurationRPC(restoreContext, previous)
}

// FinalizeConfigurationUpdate commits a staged configuration after the new
// cursor namespace has produced its first durable spool receipt and ACK.
func (session *Session) FinalizeConfigurationUpdate() error {
	if session == nil {
		return errGateway
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.pendingRollback == nil || !session.handshaken {
		return errGateway
	}
	session.pendingRollback = nil
	return nil
}

// RollbackConfigurationUpdate restores the exact pre-update projection while
// retaining the already verified process and handshake identity.
func (session *Session) RollbackConfigurationUpdate(ctx context.Context, previous PluginConfiguration) error {
	if session == nil || ctx == nil || ctx.Err() != nil {
		return errGateway
	}
	session.mu.Lock()
	snapshot := session.pendingRollback
	session.mu.Unlock()
	if snapshot == nil || previous.validate(snapshot.expected) != nil || previous.ConfigurationRevision != snapshot.configurationRevision {
		return errGateway
	}
	if err := session.applyConfigurationRPC(ctx, previous); err != nil {
		return errGateway
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.pendingRollback != snapshot {
		return errGateway
	}
	session.expected = cloneExpected(snapshot.expected)
	session.configurationRevision = snapshot.configurationRevision
	session.instances = cloneInstanceMap(snapshot.instances)
	session.pendingRollback = nil
	return nil
}

func (session *Session) probeConfiguration(ctx context.Context, expected ExpectedPlugin, configuration PluginConfiguration) error {
	instances := instanceMapWithoutCredentials(configuration.Instances)
	instanceIDs := append([]string(nil), expected.InstanceIDs...)
	sort.Strings(instanceIDs)
	for _, instanceID := range instanceIDs {
		if err := session.validateConfigurationInstance(ctx, expected, instanceID); err != nil {
			return err
		}
	}
	for _, instanceID := range instanceIDs {
		instance := instances[instanceID]
		if instance == nil {
			return errGateway
		}
		templateIDs := session.configuredTemplateIDs(instance)
		if len(templateIDs) == 0 || session.collectConfigurationInstance(ctx, expected, instances, instanceID, templateIDs) != nil {
			return errGateway
		}
	}
	return nil
}

func (session *Session) validateConfigurationInstance(ctx context.Context, expected ExpectedPlugin, instanceID string) error {
	return session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		response, err := client.ValidateInstance(callContext, &pluginv1.ValidatePluginInstanceRequest{AssignmentId: expected.AssignmentID, InstanceId: instanceID, ConfigurationRevision: expected.ConfigurationRevision})
		if err != nil || !validValidationResponse(response, instanceID, expected.SignedCapabilities) || !response.GetValid() {
			return errGateway
		}
		return nil
	})
}

func (session *Session) collectConfigurationInstance(ctx context.Context, expected ExpectedPlugin, instances map[string]*pluginv1.PluginInstanceConfiguration, instanceID string, templateIDs []string) error {
	request := canonicalCollectRequest(expected.AssignmentID, expected.ConfigurationRevision, []string{instanceID}, templateIDs)
	if proto.Size(request) > maxRPCMessageBytes {
		return errGateway
	}
	return session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		response, err := client.CollectNow(callContext, request)
		if err != nil || !validCollectResponseEnvelope(response, len(templateIDs)) {
			return errGateway
		}
		seen := make(map[string]struct{}, len(response.GetBatches()))
		for _, batch := range response.GetBatches() {
			if !batchConfiguredFor(batch, expected, expected.ConfigurationRevision, instances, session.builtinTemplates) {
				return errGateway
			}
			key := batch.GetInstanceId() + "\x00" + batch.GetTemplateId()
			if _, duplicate := seen[key]; duplicate {
				return errGateway
			}
			seen[key] = struct{}{}
			scope := metricScopeFor(session.client.config.Scope, batch, expected, expected.ConfigurationRevision, instances, session.builtinTemplates)
			if _, _, normalizeErr := normalizeBatch(batch, scope, session.client.config.Now().UTC()); normalizeErr != nil {
				return errGateway
			}
		}
		return nil
	})
}

func sameVerifiedRuntime(left, right ExpectedPlugin) bool {
	return left.PID == right.PID && left.ExpectedUserID == right.ExpectedUserID && left.ExpectedGroupID == right.ExpectedGroupID && left.RuntimeDirectory == right.RuntimeDirectory && left.AssignmentID == right.AssignmentID && left.PluginID == right.PluginID && left.DatabaseFamily == right.DatabaseFamily && left.Version == right.Version && left.ProtocolVersion == right.ProtocolVersion && left.ExecutablePath == right.ExecutablePath && bytes.Equal(left.ExecutableSHA256, right.ExecutableSHA256) && bytes.Equal(left.LaunchNonce, right.LaunchNonce) && sameSet(left.SupportedVariants, right.SupportedVariants) && sameSet(left.SignedCapabilities, right.SignedCapabilities) && left.MetricTemplateSchemaVersion == right.MetricTemplateSchemaVersion
}

// HasResumeCursors reports whether the exact assignment/configuration has
// durable metric receipts. A fresh process with receipts must resume its
// stream before producing another sequence; a first deployment may perform
// its activation CollectNow before opening the stream.
func (session *Session) HasResumeCursors(ctx context.Context, sink MetricSink) (bool, error) {
	values, err := session.resumeCursors(ctx, sink)
	return len(values) > 0, err
}

func (session *Session) runMetricStream(ctx context.Context, sink MetricSink, ready chan<- error, readyAfterCommit bool) error {
	if session == nil || ctx == nil || ctx.Err() != nil || sink == nil || !session.isConfigured() {
		reportStreamReady(ready, errGateway)
		return errGateway
	}
	commitPairs := make(map[string]struct{})
	if readyAfterCommit {
		session.mu.Lock()
		for _, instanceID := range session.expected.InstanceIDs {
			instance := session.instances[instanceID]
			if instance != nil {
				for _, templateID := range session.configuredTemplateIDs(instance) {
					commitPairs[instanceID+"\x00"+templateID] = struct{}{}
				}
			}
		}
		session.mu.Unlock()
		if len(commitPairs) == 0 {
			reportStreamReady(ready, errGateway)
			return errGateway
		}
	}
	dialContext, dialCancel := context.WithTimeout(ctx, session.client.config.Timeout)
	connection, err := dialVerifiedPlugin(dialContext, session.client.config.RuntimeRoot, session.expected)
	dialCancel()
	if err != nil {
		reportStreamReady(ready, errGateway)
		return errGateway
	}
	defer connection.Close()
	streamContext, streamCancel := context.WithCancel(ctx)
	defer streamCancel()
	resume, err := session.resumeCursors(streamContext, sink)
	if err != nil {
		reportStreamReady(ready, errGateway)
		return errGateway
	}
	runtimeClient := pluginv1.NewPluginRuntimeClient(connection)
	stream, err := runtimeClient.StreamMetrics(streamContext, &pluginv1.StreamPluginMetricsRequest{AssignmentId: session.expected.AssignmentID, ConfigurationRevision: session.currentRevision(), ResumeCursors: resume})
	if err != nil {
		reportStreamReady(ready, errGateway)
		return errGateway
	}
	headerResult := make(chan error, 1)
	go func() {
		_, headerErr := stream.Header()
		headerResult <- headerErr
	}()
	headerTimer := time.NewTimer(session.client.config.Timeout)
	defer headerTimer.Stop()
	select {
	case headerErr := <-headerResult:
		if headerErr != nil {
			reportStreamReady(ready, errGateway)
			return errGateway
		}
	case <-headerTimer.C:
		reportStreamReady(ready, errGateway)
		return errGateway
	case <-ctx.Done():
		reportStreamReady(ready, errGateway)
		return errGateway
	}
	readyReported := false
	if !readyAfterCommit {
		reportStreamReady(ready, nil)
		readyReported = true
	}
	for {
		batch, receiveErr := stream.Recv()
		if errors.Is(receiveErr, io.EOF) || receiveErr != nil {
			if !readyReported {
				reportStreamReady(ready, errGateway)
			}
			return errGateway
		}
		if err := session.appendAndAcknowledge(streamContext, batch, sink, runtimeClient); err != nil {
			if !readyReported {
				reportStreamReady(ready, errGateway)
			}
			return err
		}
		delete(commitPairs, batch.GetInstanceId()+"\x00"+batch.GetTemplateId())
		if !readyReported && len(commitPairs) == 0 {
			reportStreamReady(ready, nil)
			readyReported = true
		}
	}
}

func reportStreamReady(ready chan<- error, err error) {
	if ready != nil {
		ready <- err
	}
}

func (session *Session) resumeCursors(ctx context.Context, sink MetricSink) ([]*pluginv1.PluginMetricCursor, error) {
	if session == nil || ctx == nil || sink == nil {
		return nil, errGateway
	}
	instanceIDs := append([]string(nil), session.expected.InstanceIDs...)
	sort.Strings(instanceIDs)
	result := make([]*pluginv1.PluginMetricCursor, 0)
	for _, instanceID := range instanceIDs {
		configured := session.instances[instanceID]
		if configured == nil {
			return nil, errGateway
		}
		templateIDs := session.configuredTemplateIDs(configured)
		sort.Strings(templateIDs)
		for _, templateID := range templateIDs {
			key := cursorKey{AssignmentID: session.expected.AssignmentID, ConfigurationRevision: session.currentRevision(), TemplateID: templateID, InstanceID: instanceID}
			receipt, found, err := sink.Cursor(ctx, key.string())
			if err != nil {
				return nil, errGateway
			}
			if found {
				result = append(result, &pluginv1.PluginMetricCursor{InstanceId: instanceID, TemplateId: templateID, Sequence: receipt.Sequence})
			}
		}
	}
	request := &pluginv1.StreamPluginMetricsRequest{AssignmentId: session.expected.AssignmentID, ConfigurationRevision: session.currentRevision(), ResumeCursors: result}
	if len(result) > maxConfiguredPairs || proto.Size(request) > maxRPCMessageBytes {
		return nil, errGateway
	}
	return result, nil
}

func acknowledgeBatch(ctx context.Context, client pluginv1.PluginRuntimeClient, assignmentID string, revision uint64, batch *pluginv1.PluginMetricBatch) error {
	return acknowledgeCursor(ctx, client, assignmentID, revision, &pluginv1.PluginMetricCursor{InstanceId: batch.GetInstanceId(), TemplateId: batch.GetTemplateId(), Sequence: batch.GetSequence()})
}

func acknowledgeCursor(ctx context.Context, client pluginv1.PluginRuntimeClient, assignmentID string, revision uint64, cursor *pluginv1.PluginMetricCursor) error {
	cursors := []*pluginv1.PluginMetricCursor{cursor}
	request := &pluginv1.AcknowledgePluginMetricsRequest{AssignmentId: assignmentID, ConfigurationRevision: revision, Cursors: cursors}
	if proto.Size(request) > maxRPCMessageBytes {
		return errGateway
	}
	response, err := client.AcknowledgeMetrics(ctx, request)
	if err != nil || !validAckResponse(response, cursors) {
		return errGateway
	}
	return nil
}

func canonicalCollectRequest(assignmentID string, revision uint64, instanceIDs, templateIDs []string) *pluginv1.CollectPluginMetricsRequest {
	instances, templates := append([]string(nil), instanceIDs...), append([]string(nil), templateIDs...)
	sort.Strings(instances)
	sort.Strings(templates)
	return &pluginv1.CollectPluginMetricsRequest{AssignmentId: assignmentID, ConfigurationRevision: revision, InstanceIds: instances, TemplateIds: templates}
}

func validCollectResponseEnvelope(response *pluginv1.CollectPluginMetricsResponse, expectedPairs int) bool {
	return response != nil && expectedPairs >= 0 && expectedPairs <= maxConfiguredPairs && len(response.GetBatches()) == expectedPairs && proto.Size(response) <= maxRPCMessageBytes
}

func validAckResponse(response *pluginv1.AcknowledgePluginMetricsResponse, expected []*pluginv1.PluginMetricCursor) bool {
	if response == nil || response.GetErrorCode() != "" || len(response.GetAcceptedCursors()) != len(expected) || len(expected) == 0 || len(expected) > maxConfiguredPairs || proto.Size(response) > maxRPCMessageBytes {
		return false
	}
	for index, cursor := range expected {
		accepted := response.GetAcceptedCursors()[index]
		if cursor == nil || accepted == nil || accepted.GetInstanceId() != cursor.GetInstanceId() || accepted.GetTemplateId() != cursor.GetTemplateId() || accepted.GetSequence() != cursor.GetSequence() || accepted.GetSequence() == 0 {
			return false
		}
	}
	return true
}

func (session *Session) Shutdown(ctx context.Context, timeout time.Duration) error {
	if session == nil || ctx == nil || ctx.Err() != nil || timeout <= 0 || timeout > time.Minute || !session.isHandshaken() {
		return errGateway
	}
	return session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		response, err := client.Shutdown(callContext, &pluginv1.ShutdownPluginRequest{AssignmentId: session.expected.AssignmentID, DrainTimeoutSeconds: uint32(timeout / time.Second)})
		if err != nil || !response.GetDrained() || response.GetErrorCode() != "" {
			return errGateway
		}
		return nil
	})
}

func (session *Session) appendBatch(ctx context.Context, batch *pluginv1.PluginMetricBatch, sink MetricSink) error {
	if session == nil || ctx == nil || ctx.Err() != nil || sink == nil || session.client == nil {
		return errGateway
	}
	lane, err := session.batchLane(batch)
	if err != nil {
		return err
	}
	lane.Lock()
	defer lane.Unlock()
	return session.appendBatchInLane(ctx, batch, sink)
}

func (session *Session) appendAndAcknowledge(ctx context.Context, batch *pluginv1.PluginMetricBatch, sink MetricSink, client pluginv1.PluginRuntimeClient) error {
	if client == nil {
		return errGateway
	}
	lane, err := session.batchLane(batch)
	if err != nil {
		return err
	}
	lane.Lock()
	defer lane.Unlock()
	key := cursorKey{AssignmentID: session.expected.AssignmentID, ConfigurationRevision: batch.GetConfigurationRevision(), TemplateID: batch.GetTemplateId(), InstanceID: batch.GetInstanceId()}
	current, found, err := sink.Cursor(ctx, key.string())
	if err != nil {
		return errGateway
	}
	if found && current.ACKPending {
		if batch.GetSequence() < current.Sequence {
			return errGateway
		}
		if batch.GetSequence() == current.Sequence {
			if err := session.appendBatchInLane(ctx, batch, sink); err != nil {
				return err
			}
			return session.acknowledgeReceipt(ctx, sink, client, current)
		}
		if err := session.validateBatchInLane(batch); err != nil {
			return err
		}
		if err := session.acknowledgeReceipt(ctx, sink, client, current); err != nil {
			return err
		}
	}
	if err := session.appendBatchInLane(ctx, batch, sink); err != nil {
		return err
	}
	ackContext, cancel := context.WithTimeout(ctx, session.client.config.Timeout)
	defer cancel()
	if err := acknowledgeBatch(ackContext, client, session.expected.AssignmentID, batch.GetConfigurationRevision(), batch); err != nil {
		return err
	}
	return sink.MarkCursorAcknowledged(ctx, key.string(), batch.GetSequence())
}

func (session *Session) acknowledgeReceipt(ctx context.Context, sink MetricSink, client pluginv1.PluginRuntimeClient, receipt spool.CursorReceipt) error {
	ackContext, cancel := context.WithTimeout(ctx, session.client.config.Timeout)
	defer cancel()
	if err := acknowledgeCursor(ackContext, client, receipt.AssignmentID, receipt.ConfigurationRevision, &pluginv1.PluginMetricCursor{InstanceId: receipt.InstanceID, TemplateId: receipt.TemplateID, Sequence: receipt.Sequence}); err != nil {
		return err
	}
	return sink.MarkCursorAcknowledged(ctx, receipt.Key, receipt.Sequence)
}

func (session *Session) validateBatchInLane(batch *pluginv1.PluginMetricBatch) error {
	session.mu.Lock()
	if !session.isBatchConfigured(batch) {
		session.mu.Unlock()
		return errGateway
	}
	scope := session.metricScope(batch)
	session.mu.Unlock()
	if _, _, err := normalizeBatch(batch, scope, session.client.config.Now().UTC()); err != nil {
		return errGateway
	}
	return nil
}

func (session *Session) batchLane(batch *pluginv1.PluginMetricBatch) (*sync.Mutex, error) {
	if session == nil || batch == nil || batch.GetConfigurationRevision() != session.expected.ConfigurationRevision || !contains(session.expected.InstanceIDs, batch.GetInstanceId()) || !session.hasTemplate(batch.GetTemplateId()) {
		return nil, errGateway
	}
	key := cursorKey{AssignmentID: session.expected.AssignmentID, ConfigurationRevision: batch.GetConfigurationRevision(), TemplateID: batch.GetTemplateId(), InstanceID: batch.GetInstanceId()}
	session.lanesMu.Lock()
	defer session.lanesMu.Unlock()
	if session.lanes == nil {
		session.lanes = make(map[cursorKey]*sync.Mutex)
	}
	lane := session.lanes[key]
	if lane == nil {
		lane = &sync.Mutex{}
		session.lanes[key] = lane
	}
	return lane, nil
}

func (session *Session) appendBatchInLane(ctx context.Context, batch *pluginv1.PluginMetricBatch, sink MetricSink) error {
	if session == nil || ctx == nil || ctx.Err() != nil || sink == nil || session.client == nil {
		return errGateway
	}
	session.mu.Lock()
	if !session.isBatchConfigured(batch) {
		session.mu.Unlock()
		return errGateway
	}
	key := cursorKey{AssignmentID: session.expected.AssignmentID, ConfigurationRevision: session.configurationRevision, TemplateID: batch.GetTemplateId(), InstanceID: batch.GetInstanceId()}
	scope := session.metricScope(batch)
	session.mu.Unlock()
	now := session.client.config.Now().UTC()
	payload, id, err := normalizeBatch(batch, scope, now)
	if err != nil {
		return errGateway
	}
	digest := sha256.Sum256(payload)
	receipt := spool.CursorReceipt{Key: key.string(), AssignmentID: session.expected.AssignmentID, ConfigurationRevision: session.configurationRevision, TemplateID: batch.GetTemplateId(), InstanceID: batch.GetInstanceId(), Sequence: batch.GetSequence(), Digest: digest[:], CollectedAt: batch.GetCollectedAt().AsTime().UTC()}
	if _, err := sink.AppendWithCursor(ctx, spool.Metric, spool.Batch{ID: id, SourceID: pluginMetricSourceID + ":" + session.expected.AssignmentID + ":" + batch.GetInstanceId(), CreatedAt: now, Priority: 1, Payload: payload}, receipt); err != nil {
		return err
	}
	return nil
}

func (session *Session) isBatchConfigured(batch *pluginv1.PluginMetricBatch) bool {
	return batchConfiguredFor(batch, session.expected, session.configurationRevision, session.instances, session.builtinTemplates)
}

func batchConfiguredFor(batch *pluginv1.PluginMetricBatch, expected ExpectedPlugin, revision uint64, instances map[string]*pluginv1.PluginInstanceConfiguration, builtins map[string]*pluginv1.BuiltinMetricTemplateDescriptor) bool {
	if batch == nil || batch.GetPluginId() != expected.PluginID || batch.GetPluginVersion() != expected.Version || batch.GetDatabaseFamily() != expected.DatabaseFamily || batch.GetConfigurationRevision() != revision || (!contains(expected.TemplateIDs, batch.GetTemplateId()) && builtins[batch.GetTemplateId()] == nil) {
		return false
	}
	configured := instances[batch.GetInstanceId()]
	if configured == nil || batch.GetDatabaseVariant() != configured.GetDatabaseVariant() {
		return false
	}
	for _, template := range configured.GetTemplates() {
		if template != nil && template.GetTemplateId() == batch.GetTemplateId() && template.GetRevision() == batch.GetTemplateRevision() {
			return validateBatchAgainstTemplate(batch, template)
		}
	}
	if builtin := builtins[batch.GetTemplateId()]; builtin != nil && builtin.GetRevision() == batch.GetTemplateRevision() {
		return validateBatchAgainstBuiltin(batch, builtin)
	}
	return false
}

func (session *Session) metricScope(batch *pluginv1.PluginMetricBatch) MetricScope {
	return metricScopeFor(session.client.config.Scope, batch, session.expected, session.configurationRevision, session.instances, session.builtinTemplates)
}

func metricScopeFor(scope MetricScope, batch *pluginv1.PluginMetricBatch, expected ExpectedPlugin, revision uint64, instances map[string]*pluginv1.PluginInstanceConfiguration, builtins map[string]*pluginv1.BuiltinMetricTemplateDescriptor) MetricScope {
	scope.AssignmentID = expected.AssignmentID
	scope.InstanceIDs = append([]string(nil), expected.InstanceIDs...)
	scope.TemplateIDs = append([]string(nil), expected.TemplateIDs...)
	for id := range builtins {
		scope.TemplateIDs = append(scope.TemplateIDs, id)
	}
	sort.Strings(scope.TemplateIDs)
	scope.DatabaseFamily = expected.DatabaseFamily
	scope.PluginID = expected.PluginID
	scope.PluginVersion = expected.Version
	scope.ConfigurationRevision = revision
	scope.DatabaseVariant = instances[batch.GetInstanceId()].GetDatabaseVariant()
	scope.TemplateRevision = batch.GetTemplateRevision()
	return scope
}
func (session *Session) isHandshaken() bool {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.handshaken
}
func (session *Session) isConfigured() bool {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.handshaken && session.configurationRevision == session.expected.ConfigurationRevision
}
func (session *Session) currentRevision() uint64 {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.configurationRevision
}
func (session *Session) readyForInstance(id string) bool {
	return session.isConfigured() && contains(session.expected.InstanceIDs, id)
}
func (session *Session) readyForCollect(instances, templates []string) bool {
	if !session.isConfigured() || len(instances) == 0 || len(templates) == 0 || !unique(instances) || !unique(templates) {
		return false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	for _, instanceID := range instances {
		instance := session.instances[instanceID]
		if instance == nil {
			return false
		}
		configured := session.configuredTemplateIDs(instance)
		for _, templateID := range templates {
			if !contains(configured, templateID) {
				return false
			}
		}
	}
	return true
}

func (session *Session) invoke(ctx context.Context, invoke func(pluginv1.PluginRuntimeClient, context.Context) error) error {
	if ctx == nil || ctx.Err() != nil {
		return errGateway
	}
	callContext, cancel := context.WithTimeout(ctx, session.client.config.Timeout)
	defer cancel()
	connection, err := dialVerifiedPlugin(callContext, session.client.config.RuntimeRoot, session.expected)
	if err != nil {
		return errGateway
	}
	defer connection.Close()
	return invoke(pluginv1.NewPluginRuntimeClient(connection), callContext)
}

func (configuration PluginConfiguration) validate(expected ExpectedPlugin) error {
	if configuration.AssignmentID != expected.AssignmentID || configuration.ConfigurationRevision != expected.ConfigurationRevision || len(configuration.Instances) != len(expected.InstanceIDs) || len(configuration.Instances) == 0 {
		return errGateway
	}
	seen := map[string]struct{}{}
	pairs := 0
	for _, instance := range configuration.Instances {
		if instance == nil || !contains(expected.InstanceIDs, instance.GetInstanceId()) || instance.GetInstanceId() == "" || !family(instance.GetDatabaseVariant()) || (instance.GetEndpoint() == "" && instance.GetUnixSocket() == "") || (instance.GetEndpoint() != "" && instance.GetUnixSocket() != "") || len(instance.GetTemplates()) > maxGatewayMembers {
			return errGateway
		}
		if instance.GetCredentialLease() != nil && !validCredentialLease(instance.GetCredentialLease()) {
			return errGateway
		}
		templates := map[string]struct{}{}
		expectedTemplates := expected.TemplateConfigurations
		expectedIDs := expected.TemplateIDs
		if expected.InstanceTemplateConfigurations != nil {
			expectedTemplates = expected.InstanceTemplateConfigurations[instance.GetInstanceId()]
			expectedIDs = make([]string, len(expectedTemplates))
			for index, template := range expectedTemplates {
				expectedIDs[index] = template.GetTemplateId()
			}
		}
		for _, template := range instance.GetTemplates() {
			if template == nil || !contains(expectedIDs, template.GetTemplateId()) || !validTemplateConfiguration(template) || !matchesExpectedTemplate(template, expectedTemplates) {
				return errGateway
			}
			if _, duplicate := templates[template.GetTemplateId()]; duplicate {
				return errGateway
			}
			templates[template.GetTemplateId()] = struct{}{}
		}
		if _, duplicate := seen[instance.GetInstanceId()]; duplicate {
			return errGateway
		}
		seen[instance.GetInstanceId()] = struct{}{}
		pairs += len(instance.GetTemplates())
		if pairs > maxConfiguredPairs {
			return errGateway
		}
		if !sameSet(mapKeys(templates), expectedIDs) {
			return errGateway
		}
	}
	if proto.Size(canonicalApplyRequest(configuration)) > maxRPCMessageBytes {
		return errGateway
	}
	return nil
}

func validCredentialLease(value *pluginv1.CredentialLease) bool {
	return value != nil && resourceID.MatchString(value.GetLeaseId()) && value.GetCredentialRevision() > 0 && len(value.GetUsername()) <= 256 && strings.TrimSpace(value.GetUsername()) == value.GetUsername() && !strings.ContainsAny(value.GetUsername(), "\x00\r\n") && len(value.GetSecretBytes()) > 0 && len(value.GetSecretBytes()) <= 64<<10 && value.GetExpiresAt() != nil && value.GetExpiresAt().IsValid()
}

func validApplyResponse(response *pluginv1.ApplyPluginConfigurationResponse, configuration PluginConfiguration) bool {
	if response == nil || response.GetErrorCode() != "" || response.GetActiveConfigurationRevision() != configuration.ConfigurationRevision || len(response.GetResults()) != len(configuration.Instances) {
		return false
	}
	seen := map[string]struct{}{}
	for _, result := range response.GetResults() {
		if result == nil || !result.GetApplied() || result.GetErrorCode() != "" || !containsInstance(configuration.Instances, result.GetInstanceId()) {
			return false
		}
		if _, duplicate := seen[result.GetInstanceId()]; duplicate {
			return false
		}
		seen[result.GetInstanceId()] = struct{}{}
	}
	return true
}

func validHandshake(response *pluginv1.PluginHandshakeResponse, expected ExpectedPlugin, challenge []byte) bool {
	proof := launchProof(expected.LaunchNonce, challenge, expected.AssignmentID, expected.Version, expected.ConfigurationRevision, expected.OperationRevision, expected.InstanceIDs)
	return response != nil && response.GetPluginId() == expected.PluginID && response.GetDatabaseFamily() == expected.DatabaseFamily && response.GetVersion() == expected.Version && response.GetProtocolVersion() == expected.ProtocolVersion && bytes.Equal(response.GetExecutableDigest(), expected.ExecutableSHA256) && len(proof) == len(response.GetLaunchNonceProof()) && subtle.ConstantTimeCompare(proof, response.GetLaunchNonceProof()) == 1
}

func matchesSignedManifest(response *pluginv1.PluginHandshakeResponse, expected ExpectedPlugin) bool {
	if response == nil {
		return false
	}
	return sameSet(response.GetSupportedVariants(), expected.SupportedVariants) && sameSet(response.GetCapabilities(), expected.SignedCapabilities) && response.GetMetricTemplateSchemaVersion() == expected.MetricTemplateSchemaVersion
}

func validValidationResponse(response *pluginv1.ValidatePluginInstanceResponse, instanceID string, signedCapabilities []string) bool {
	if response == nil || response.GetInstanceId() != instanceID {
		return false
	}
	capabilities := boundedSorted(response.GetCapabilities(), 64)
	if len(response.GetCapabilities()) > 0 && capabilities == nil || !subset(capabilities, signedCapabilities) {
		return false
	}
	if response.GetDatabaseVersion() != "" && !canonicalDatabaseText(response.GetDatabaseVersion()) || response.GetDatabaseEdition() != "" && !canonicalDatabaseText(response.GetDatabaseEdition()) {
		return false
	}
	if response.GetValid() {
		return response.GetErrorCode() == "" && response.GetDatabaseVersion() != ""
	}
	return response.GetErrorCode() != ""
}

func canonicalDatabaseText(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.Contains(value, "  ") || strings.ContainsAny(value, "\x00\r\n\t/:\\=@") {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"password", "passwd", "secret", "token", "credential", "dsn"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune(" ._()+-", character) {
			continue
		}
		return false
	}
	return true
}

func validTemplateConfiguration(value *pluginv1.MetricTemplateConfiguration) bool {
	if value == nil || !identifier(value.GetTemplateId()) || value.GetRevision() == 0 || len(value.GetQueryDigest()) != sha256.Size || value.GetQueryKind() != "sql" || value.GetReadOnlyStatement() == "" || len(value.GetReadOnlyStatement()) > 32<<10 || value.GetCollectionIntervalSeconds() < 10 || value.GetCollectionIntervalSeconds() > 86400 || value.GetTimeoutSeconds() == 0 || value.GetTimeoutSeconds() > 30 || value.GetMaxRows() == 0 || value.GetMaxRows() > 100 || value.GetMaxColumns() == 0 || value.GetMaxColumns() > 32 || value.GetCardinalityLimit() == 0 || value.GetCardinalityLimit() > 10000 || !validTemplateMappings(value.GetValueMappings(), value.GetLabelMappings()) {
		return false
	}
	return true
}

func mapKeysBuiltin(values map[string]*pluginv1.BuiltinMetricTemplateDescriptor) []string {
	result := make([]string, 0, len(values))
	for id := range values {
		result = append(result, id)
	}
	return result
}
func (session *Session) allTemplateIDs() []string {
	result := append([]string(nil), session.expected.TemplateIDs...)
	for id := range session.builtinTemplates {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}
func (session *Session) configuredTemplateIDs(instance *pluginv1.PluginInstanceConfiguration) []string {
	result := make([]string, 0, len(instance.GetTemplates())+len(session.builtinTemplates))
	for _, template := range instance.GetTemplates() {
		if template != nil {
			result = append(result, template.GetTemplateId())
		}
	}
	for id := range session.builtinTemplates {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}
func (session *Session) hasTemplate(id string) bool {
	return contains(session.expected.TemplateIDs, id) || session.builtinTemplates[id] != nil
}

func validateBatchAgainstBuiltin(batch *pluginv1.PluginMetricBatch, descriptor *pluginv1.BuiltinMetricTemplateDescriptor) bool {
	if batch == nil || descriptor == nil || batch.GetTemplateId() != descriptor.GetTemplateId() || batch.GetTemplateRevision() != descriptor.GetRevision() || len(batch.GetSamples()) > len(descriptor.GetMetrics()) {
		return false
	}
	allowed := make(map[string]*pluginv1.BuiltinMetricDescriptor, len(descriptor.GetMetrics()))
	for _, metric := range descriptor.GetMetrics() {
		allowed[metric.GetMetricName()] = metric
	}
	seen := map[string]struct{}{}
	for _, sample := range batch.GetSamples() {
		metric := allowed[sample.GetMetricName()]
		if sample == nil || metric == nil || sample.GetMetricType() != metric.GetMetricType() || sample.GetUnit() != metric.GetUnit() || len(sample.GetLabels()) != 0 || metric.GetMetricType() == pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_COUNTER && sample.GetStartTime() == nil {
			return false
		}
		if _, duplicate := seen[sample.GetMetricName()]; duplicate {
			return false
		}
		seen[sample.GetMetricName()] = struct{}{}
	}
	return batch.GetCollectionStatus() != pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED || len(seen) == len(allowed)
}

func validTemplateMappings(valueMappings []*pluginv1.MetricValueMapping, labelMappings []*pluginv1.MetricLabelMapping) bool {
	if len(valueMappings) == 0 || len(valueMappings) > 32 || len(labelMappings) > 16 {
		return false
	}
	metrics, labels := map[string]struct{}{}, map[string]struct{}{}
	sources := map[string]struct{}{}
	for _, mapping := range valueMappings {
		if mapping == nil || !identifier(mapping.GetSourceColumn()) || !pluginMetricName.MatchString(mapping.GetMetricName()) || !pluginUnit.MatchString(mapping.GetUnit()) || metricTypeFromName(mapping.GetMetricType()) == pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_UNSPECIFIED {
			return false
		}
		if _, duplicate := metrics[mapping.GetMetricName()]; duplicate {
			return false
		}
		if _, duplicate := sources[mapping.GetSourceColumn()]; duplicate {
			return false
		}
		metrics[mapping.GetMetricName()] = struct{}{}
		sources[mapping.GetSourceColumn()] = struct{}{}
	}
	for _, mapping := range labelMappings {
		if mapping == nil {
			return false
		}
		normalized := normalizeMetricLabelKey(mapping.GetLabel())
		_, reserved := reservedNormalizedLabels[normalized]
		if !identifier(mapping.GetSourceColumn()) || !pluginLabelName.MatchString(mapping.GetLabel()) || normalized == "" || reserved || strings.HasSuffix(normalized, "_tenant_id") || strings.HasSuffix(normalized, "_project_id") || strings.HasSuffix(normalized, "_agent_id") || strings.HasPrefix(normalized, "dbpilot_") {
			return false
		}
		if _, duplicate := labels[mapping.GetLabel()]; duplicate {
			return false
		}
		labels[mapping.GetLabel()] = struct{}{}
	}
	return true
}

func validateBatchAgainstTemplate(batch *pluginv1.PluginMetricBatch, template *pluginv1.MetricTemplateConfiguration) bool {
	if !validTemplateConfiguration(template) {
		return false
	}
	allowedMetrics, allowedLabels := map[string]struct{}{}, map[string]struct{}{}
	for _, mapping := range template.GetValueMappings() {
		key := mapping.GetMetricName() + "\x00" + fmt.Sprint(metricTypeFromName(mapping.GetMetricType())) + "\x00" + mapping.GetUnit()
		allowedMetrics[key] = struct{}{}
	}
	for _, mapping := range template.GetLabelMappings() {
		allowedLabels[mapping.GetLabel()] = struct{}{}
	}
	for _, sample := range batch.GetSamples() {
		key := sample.GetMetricName() + "\x00" + fmt.Sprint(sample.GetMetricType()) + "\x00" + sample.GetUnit()
		if _, ok := allowedMetrics[key]; !ok {
			return false
		}
		for label := range sample.GetLabels() {
			if _, ok := allowedLabels[label]; !ok {
				return false
			}
		}
	}
	return true
}

func metricTypeFromName(value string) pluginv1.PluginMetricType {
	switch value {
	case "gauge":
		return pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE
	case "monotonic_gauge":
		return pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_GAUGE
	case "counter":
		return pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_COUNTER
	case "monotonic_counter":
		return pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_COUNTER
	default:
		return pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_UNSPECIFIED
	}
}

func metricTypeName(value pluginv1.PluginMetricType) string {
	switch value {
	case pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE:
		return "gauge"
	case pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_GAUGE:
		return "monotonic_gauge"
	case pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_COUNTER:
		return "counter"
	case pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_COUNTER:
		return "monotonic_counter"
	default:
		return ""
	}
}

func subset(values, allowed []string) bool {
	for _, value := range values {
		if !contains(allowed, value) {
			return false
		}
	}
	return true
}

func mapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	return result
}

func launchProof(nonce, challenge []byte, assignment, version string, configurationRevision, operationRevision uint64, instances []string) []byte {
	if len(nonce) != sha256.Size || len(challenge) != sha256.Size {
		return nil
	}
	instances = append([]string(nil), instances...)
	sort.Strings(instances)
	values := []string{hex.EncodeToString(challenge), assignment, version, fmt.Sprintf("%d", configurationRevision), fmt.Sprintf("%d", operationRevision)}
	values = append(values, instances...)
	mac := hmac.New(sha256.New, nonce)
	_, _ = mac.Write([]byte("dbpilot-plugin-launch-proof-v1\n"))
	for _, value := range values {
		_, _ = mac.Write([]byte(fmt.Sprintf("%d:%s", len(value), value)))
	}
	return mac.Sum(nil)
}

func validateExpected(root string, expected ExpectedPlugin) error {
	expectedSocket := filepath.Join(root, expected.DatabaseFamily, "plugin.sock")
	if expected.PID <= 0 || expected.ExpectedUserID == 0 || expected.ExpectedGroupID == 0 || !resourceID.MatchString(expected.AssignmentID) || !family(expected.PluginID) || !family(expected.DatabaseFamily) || !version(expected.Version) || expected.ProtocolVersion != "v1" || len(expected.ExecutableSHA256) != sha256.Size || !filepath.IsAbs(expected.ExecutablePath) || filepath.Clean(expected.ExecutablePath) != expected.ExecutablePath || len(expected.LaunchNonce) != sha256.Size || expected.ConfigurationRevision == 0 || expected.OperationRevision == 0 || len(expected.InstanceIDs) == 0 || len(expected.InstanceIDs) > maxGatewayMembers || !unique(expected.InstanceIDs) || len(expected.TemplateIDs) > maxGatewayMembers || !unique(expected.TemplateIDs) || len(expected.SupportedVariants) == 0 || len(expected.SupportedVariants) > 16 || !unique(expected.SupportedVariants) || len(expected.SignedCapabilities) == 0 || len(expected.SignedCapabilities) > 64 || !unique(expected.SignedCapabilities) || expected.MetricTemplateSchemaVersion == 0 || expected.MetricTemplateSchemaVersion > 65535 || expected.RuntimeDirectory != filepath.Join(root, expected.DatabaseFamily) || filepath.Join(expected.RuntimeDirectory, "plugin.sock") != expectedSocket {
		return errGateway
	}
	if len(expected.TemplateConfigurations) > 0 {
		ids := make([]string, 0, len(expected.TemplateConfigurations))
		for _, template := range expected.TemplateConfigurations {
			if !validTemplateConfiguration(template) {
				return errGateway
			}
			ids = append(ids, template.GetTemplateId())
		}
		if !sameSet(ids, expected.TemplateIDs) {
			return errGateway
		}
	}
	return nil
}

func cloneExpected(value ExpectedPlugin) ExpectedPlugin {
	value.ExecutableSHA256 = append([]byte(nil), value.ExecutableSHA256...)
	value.LaunchNonce = append([]byte(nil), value.LaunchNonce...)
	value.InstanceIDs = append([]string(nil), value.InstanceIDs...)
	value.TemplateIDs = append([]string(nil), value.TemplateIDs...)
	value.SupportedVariants = append([]string(nil), value.SupportedVariants...)
	value.SignedCapabilities = append([]string(nil), value.SignedCapabilities...)
	value.TemplateConfigurations = cloneTemplateConfigurations(value.TemplateConfigurations)
	value.InstanceTemplateConfigurations = cloneInstanceTemplateConfigurationMap(value.InstanceTemplateConfigurations)
	return value
}
func sameExpected(left, right ExpectedPlugin) bool {
	return left.PID == right.PID && left.ExpectedUserID == right.ExpectedUserID && left.ExpectedGroupID == right.ExpectedGroupID && left.RuntimeDirectory == right.RuntimeDirectory && left.AssignmentID == right.AssignmentID && left.PluginID == right.PluginID && left.DatabaseFamily == right.DatabaseFamily && left.Version == right.Version && left.ProtocolVersion == right.ProtocolVersion && left.ExecutablePath == right.ExecutablePath && bytes.Equal(left.ExecutableSHA256, right.ExecutableSHA256) && bytes.Equal(left.LaunchNonce, right.LaunchNonce) && left.ConfigurationRevision == right.ConfigurationRevision && left.OperationRevision == right.OperationRevision && sameSet(left.InstanceIDs, right.InstanceIDs) && sameSet(left.TemplateIDs, right.TemplateIDs) && sameSet(left.SupportedVariants, right.SupportedVariants) && sameSet(left.SignedCapabilities, right.SignedCapabilities) && left.MetricTemplateSchemaVersion == right.MetricTemplateSchemaVersion && sameTemplateConfigurations(left.TemplateConfigurations, right.TemplateConfigurations) && sameInstanceTemplateConfigurationMap(left.InstanceTemplateConfigurations, right.InstanceTemplateConfigurations)
}

func cloneInstanceTemplateConfigurationMap(values map[string][]*pluginv1.MetricTemplateConfiguration) map[string][]*pluginv1.MetricTemplateConfiguration {
	if values == nil {
		return nil
	}
	result := make(map[string][]*pluginv1.MetricTemplateConfiguration, len(values))
	for id, templates := range values {
		result[id] = cloneTemplateConfigurations(templates)
	}
	return result
}
func sameInstanceTemplateConfigurationMap(left, right map[string][]*pluginv1.MetricTemplateConfiguration) bool {
	if len(left) != len(right) {
		return false
	}
	for id, templates := range left {
		if !sameTemplateConfigurations(templates, right[id]) {
			return false
		}
	}
	return true
}

func cloneTemplateConfigurations(values []*pluginv1.MetricTemplateConfiguration) []*pluginv1.MetricTemplateConfiguration {
	result := make([]*pluginv1.MetricTemplateConfiguration, len(values))
	for index, value := range values {
		if value != nil {
			result[index] = proto.Clone(value).(*pluginv1.MetricTemplateConfiguration)
		}
	}
	return result
}

func sameTemplateConfigurations(left, right []*pluginv1.MetricTemplateConfiguration) bool {
	if len(left) != len(right) {
		return false
	}
	for _, value := range left {
		if value == nil || !matchesExpectedTemplate(value, right) {
			return false
		}
	}
	return true
}

func matchesExpectedTemplate(value *pluginv1.MetricTemplateConfiguration, expected []*pluginv1.MetricTemplateConfiguration) bool {
	for _, candidate := range expected {
		if candidate != nil && candidate.GetTemplateId() == value.GetTemplateId() {
			return proto.Equal(candidate, value)
		}
	}
	return false
}
func cloneInstances(values []*pluginv1.PluginInstanceConfiguration) []*pluginv1.PluginInstanceConfiguration {
	result := make([]*pluginv1.PluginInstanceConfiguration, len(values))
	for index, value := range values {
		result[index] = proto.Clone(value).(*pluginv1.PluginInstanceConfiguration)
	}
	return result
}

func cloneInstancesWithoutCredentials(values []*pluginv1.PluginInstanceConfiguration) []*pluginv1.PluginInstanceConfiguration {
	result := make([]*pluginv1.PluginInstanceConfiguration, len(values))
	for index, value := range values {
		result[index] = cloneInstanceWithoutCredential(value)
	}
	return result
}

func instanceMapWithoutCredentials(values []*pluginv1.PluginInstanceConfiguration) map[string]*pluginv1.PluginInstanceConfiguration {
	result := make(map[string]*pluginv1.PluginInstanceConfiguration, len(values))
	for _, value := range values {
		if value != nil {
			result[value.GetInstanceId()] = cloneInstanceWithoutCredential(value)
		}
	}
	return result
}

func cloneInstanceMap(values map[string]*pluginv1.PluginInstanceConfiguration) map[string]*pluginv1.PluginInstanceConfiguration {
	result := make(map[string]*pluginv1.PluginInstanceConfiguration, len(values))
	for id, value := range values {
		if value != nil {
			result[id] = cloneInstanceWithoutCredential(value)
		}
	}
	return result
}

func cloneInstanceWithoutCredential(value *pluginv1.PluginInstanceConfiguration) *pluginv1.PluginInstanceConfiguration {
	cloned := proto.Clone(value).(*pluginv1.PluginInstanceConfiguration)
	clearInstanceCredential(cloned)
	cloned.CredentialLease = nil
	return cloned
}

func clearConfigurationSecrets(request *pluginv1.ApplyPluginConfigurationRequest) {
	if request == nil {
		return
	}
	for _, instance := range request.Instances {
		clearInstanceCredential(instance)
		for _, template := range instance.GetTemplates() {
			if template != nil {
				template.ReadOnlyStatement = ""
			}
		}
	}
}

func clearInstanceCredential(instance *pluginv1.PluginInstanceConfiguration) {
	if instance == nil || instance.CredentialLease == nil {
		return
	}
	for index := range instance.CredentialLease.SecretBytes {
		instance.CredentialLease.SecretBytes[index] = 0
	}
	instance.CredentialLease.SecretBytes = nil
	instance.CredentialLease.Username = ""
}

func canonicalApplyRequest(configuration PluginConfiguration) *pluginv1.ApplyPluginConfigurationRequest {
	instances := cloneInstances(configuration.Instances)
	for _, instance := range instances {
		sort.Slice(instance.Templates, func(left, right int) bool {
			return instance.Templates[left].GetTemplateId() < instance.Templates[right].GetTemplateId()
		})
		for _, template := range instance.Templates {
			sort.Slice(template.ValueMappings, func(left, right int) bool {
				leftValue, rightValue := template.ValueMappings[left], template.ValueMappings[right]
				if leftValue.GetSourceColumn() != rightValue.GetSourceColumn() {
					return leftValue.GetSourceColumn() < rightValue.GetSourceColumn()
				}
				if leftValue.GetMetricName() != rightValue.GetMetricName() {
					return leftValue.GetMetricName() < rightValue.GetMetricName()
				}
				if leftValue.GetMetricType() != rightValue.GetMetricType() {
					return leftValue.GetMetricType() < rightValue.GetMetricType()
				}
				return leftValue.GetUnit() < rightValue.GetUnit()
			})
			sort.Slice(template.LabelMappings, func(left, right int) bool {
				leftValue, rightValue := template.LabelMappings[left], template.LabelMappings[right]
				if leftValue.GetSourceColumn() != rightValue.GetSourceColumn() {
					return leftValue.GetSourceColumn() < rightValue.GetSourceColumn()
				}
				return leftValue.GetLabel() < rightValue.GetLabel()
			})
		}
	}
	sort.Slice(instances, func(left, right int) bool { return instances[left].GetInstanceId() < instances[right].GetInstanceId() })
	return &pluginv1.ApplyPluginConfigurationRequest{AssignmentId: configuration.AssignmentID, ConfigurationRevision: configuration.ConfigurationRevision, Instances: instances}
}
func containsInstance(values []*pluginv1.PluginInstanceConfiguration, instanceID string) bool {
	for _, value := range values {
		if value.GetInstanceId() == instanceID {
			return true
		}
	}
	return false
}
func boundedSorted(values []string, max int) []string {
	if len(values) > max {
		return nil
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index, value := range result {
		if value == "" || len(value) > 128 || (index > 0 && result[index-1] == value) {
			return nil
		}
	}
	return result
}
func boundedText(value string, max int) string {
	if len(value) > max || strings.ContainsAny(value, "\x00\r\n") {
		return ""
	}
	return value
}
func identifier(value string) bool { return resourceID.MatchString(value) }
func family(value string) bool     { return familyID.MatchString(value) }
func version(value string) bool {
	return value != "" && len(value) <= 64 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t/\\:")
}
func unique(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if !identifier(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func sameSet(left, right []string) bool {
	if len(left) != len(right) || !unique(left) || !unique(right) {
		return false
	}
	for _, value := range left {
		if !contains(right, value) {
			return false
		}
	}
	return true
}

var _ = fmt.Sprintf
