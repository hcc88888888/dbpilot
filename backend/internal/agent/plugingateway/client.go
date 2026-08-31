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

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/spool"
	"google.golang.org/protobuf/proto"
)

const (
	maxRPCMessageBytes   = 1 << 20
	maxAssignedInstances = 1024
	maxAssignedTemplates = 1024
)

var (
	resourceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	familyID   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	errGateway = errors.New("PLUGIN_GATEWAY_REJECTED")
)

type Spool interface {
	Append(context.Context, spool.DataClass, spool.Batch) error
}

type ClientConfig struct {
	RuntimeRoot string
	Scope       MetricScope
	Store       Spool
	Timeout     time.Duration
	Now         func() time.Time
}

type Client struct{ config ClientConfig }

// ExpectedPlugin comes only from the Supervisor's launch result, never from a
// plugin response or control-plane supplied socket address.
type ExpectedPlugin struct {
	PID                   int
	ExpectedUserID        uint32
	ExpectedGroupID       uint32
	RuntimeDirectory      string
	AssignmentID          string
	PluginID              string
	DatabaseFamily        string
	Version               string
	ProtocolVersion       string
	ExecutablePath        string
	ExecutableSHA256      []byte
	LaunchNonce           []byte
	ConfigurationRevision uint64
	OperationRevision     uint64
	InstanceIDs           []string
	TemplateIDs           []string
}

type Capabilities struct {
	SupportedVariants           []string
	DatabaseVersionRange        string
	Capabilities                []string
	MetricTemplateSchemaVersion uint32
}

type PluginConfiguration struct {
	AssignmentID          string
	ConfigurationRevision uint64
	Instances             []*pluginv1.PluginInstanceConfiguration
}

type ValidationResult struct {
	InstanceID      string
	Valid           bool
	DatabaseVersion string
	DatabaseEdition string
	Capabilities    []string
	ErrorCode       string
}

type MetricSink interface {
	Append(context.Context, spool.DataClass, spool.Batch) error
}

type Session struct {
	client                *Client
	expected              ExpectedPlugin
	mu                    sync.Mutex
	handshaken            bool
	configurationRevision uint64
	instances             map[string]*pluginv1.PluginInstanceConfiguration
	lastSequence          map[string]uint64
	lastTimestamp         map[string]time.Time
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
	return &Session{client: client, expected: cloneExpected(expected), lastSequence: map[string]uint64{}, lastTimestamp: map[string]time.Time{}}, nil
}

func (session *Session) Handshake(ctx context.Context, expected ExpectedPlugin) (Capabilities, error) {
	if session == nil || ctx == nil || ctx.Err() != nil || !sameExpected(session.expected, expected) {
		return Capabilities{}, errGateway
	}
	var result Capabilities
	err := session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		challenge := make([]byte, sha256.Size)
		if _, err := rand.Read(challenge); err != nil {
			return errGateway
		}
		response, err := client.Handshake(callContext, &pluginv1.PluginHandshakeRequest{ExpectedPluginId: session.expected.PluginID, ExpectedDatabaseFamily: session.expected.DatabaseFamily, ExpectedVersion: session.expected.Version, ExpectedProtocolVersion: session.expected.ProtocolVersion, LaunchNonceChallenge: challenge})
		if err != nil || !validHandshake(response, session.expected, challenge) {
			return errGateway
		}
		result = Capabilities{SupportedVariants: boundedSorted(response.GetSupportedVariants(), 64), DatabaseVersionRange: boundedText(response.GetDatabaseVersionRange(), 128), Capabilities: boundedSorted(response.GetCapabilities(), 64), MetricTemplateSchemaVersion: response.GetMetricTemplateSchemaVersion()}
		return nil
	})
	if err != nil {
		return Capabilities{}, err
	}
	session.mu.Lock()
	session.handshaken = true
	session.mu.Unlock()
	return result, nil
}

func (session *Session) ApplyConfiguration(ctx context.Context, configuration PluginConfiguration) error {
	if session == nil || ctx == nil || ctx.Err() != nil || configuration.validate(session.expected) != nil || !session.isHandshaken() {
		return errGateway
	}
	responseErr := session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		response, err := client.ApplyConfiguration(callContext, &pluginv1.ApplyPluginConfigurationRequest{AssignmentId: configuration.AssignmentID, ConfigurationRevision: configuration.ConfigurationRevision, Instances: cloneInstances(configuration.Instances)})
		if err != nil || !validApplyResponse(response, configuration) {
			return errGateway
		}
		return nil
	})
	if responseErr != nil {
		return responseErr
	}
	session.mu.Lock()
	session.configurationRevision = configuration.ConfigurationRevision
	session.instances = make(map[string]*pluginv1.PluginInstanceConfiguration, len(configuration.Instances))
	for _, instance := range configuration.Instances {
		session.instances[instance.GetInstanceId()] = proto.Clone(instance).(*pluginv1.PluginInstanceConfiguration)
	}
	session.lastSequence = map[string]uint64{}
	session.lastTimestamp = map[string]time.Time{}
	session.mu.Unlock()
	return nil
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
		if err != nil || response.GetInstanceId() != instanceID || len(response.GetDatabaseVersion()) > 128 || len(response.GetDatabaseEdition()) > 128 || len(response.GetErrorCode()) > 64 {
			return errGateway
		}
		result = ValidationResult{InstanceID: response.GetInstanceId(), Valid: response.GetValid(), DatabaseVersion: response.GetDatabaseVersion(), DatabaseEdition: response.GetDatabaseEdition(), Capabilities: boundedSorted(response.GetCapabilities(), 64), ErrorCode: response.GetErrorCode()}
		return nil
	})
	return result, err
}

func (session *Session) CollectNow(ctx context.Context, instanceIDs, templateIDs []string) error {
	if session == nil || ctx == nil || ctx.Err() != nil || !session.readyForCollect(instanceIDs, templateIDs) {
		return errGateway
	}
	return session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		response, err := client.CollectNow(callContext, &pluginv1.CollectPluginMetricsRequest{AssignmentId: session.expected.AssignmentID, ConfigurationRevision: session.currentRevision(), InstanceIds: append([]string(nil), instanceIDs...), TemplateIds: append([]string(nil), templateIDs...)})
		if err != nil || len(response.GetBatches()) > maxAssignedInstances {
			return errGateway
		}
		for _, batch := range response.GetBatches() {
			if err := session.appendBatch(callContext, batch, session.client.config.Store); err != nil {
				return err
			}
		}
		return nil
	})
}

func (session *Session) RunMetricStream(ctx context.Context, sink MetricSink) error {
	if session == nil || ctx == nil || ctx.Err() != nil || sink == nil || !session.isConfigured() {
		return errGateway
	}
	return session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		stream, err := client.StreamMetrics(callContext, &pluginv1.StreamPluginMetricsRequest{AssignmentId: session.expected.AssignmentID, ConfigurationRevision: session.currentRevision()})
		if err != nil {
			return errGateway
		}
		for {
			batch, receiveErr := stream.Recv()
			if errors.Is(receiveErr, io.EOF) {
				return nil
			}
			if receiveErr != nil {
				return receiveErr
			}
			if err := session.appendBatch(callContext, batch, sink); err != nil {
				return err
			}
		}
	})
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
	if sink == nil {
		return errGateway
	}
	now := session.client.config.Now().UTC()
	payload, id, err := normalizeBatch(batch, session.metricScope(), now)
	if err != nil {
		return errGateway
	}
	session.mu.Lock()
	configured := session.instances[batch.GetInstanceId()]
	if configured == nil || configured.GetDatabaseVariant() != batch.GetDatabaseVariant() || batch.GetConfigurationRevision() != session.configurationRevision {
		session.mu.Unlock()
		return errGateway
	}
	if batch.GetSequence() <= session.lastSequence[batch.GetInstanceId()] || (!session.lastTimestamp[batch.GetInstanceId()].IsZero() && batch.GetCollectedAt().AsTime().UTC().Before(session.lastTimestamp[batch.GetInstanceId()])) {
		session.mu.Unlock()
		return errGateway
	}
	session.mu.Unlock()
	if err := sink.Append(ctx, spool.Metric, spool.Batch{ID: id, SourceID: pluginMetricSourceID + ":" + session.expected.AssignmentID + ":" + batch.GetInstanceId(), CreatedAt: now, Priority: 1, Payload: payload}); err != nil {
		return err
	}
	session.mu.Lock()
	session.lastSequence[batch.GetInstanceId()] = batch.GetSequence()
	session.lastTimestamp[batch.GetInstanceId()] = batch.GetCollectedAt().AsTime().UTC()
	session.mu.Unlock()
	return nil
}

func (session *Session) metricScope() MetricScope {
	scope := session.client.config.Scope
	scope.AssignmentID = session.expected.AssignmentID
	scope.InstanceIDs = append([]string(nil), session.expected.InstanceIDs...)
	scope.DatabaseFamily = session.expected.DatabaseFamily
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
	return session.isConfigured() && sameSet(instances, session.expected.InstanceIDs) && sameSet(templates, session.expected.TemplateIDs)
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
	for _, instance := range configuration.Instances {
		if instance == nil || !contains(expected.InstanceIDs, instance.GetInstanceId()) || instance.GetInstanceId() == "" || !family(instance.GetDatabaseVariant()) || (instance.GetEndpoint() == "" && instance.GetUnixSocket() == "") || (instance.GetEndpoint() != "" && instance.GetUnixSocket() != "") || len(instance.GetTemplates()) > maxAssignedTemplates {
			return errGateway
		}
		if _, duplicate := seen[instance.GetInstanceId()]; duplicate {
			return errGateway
		}
		seen[instance.GetInstanceId()] = struct{}{}
	}
	return nil
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
	if expected.PID <= 0 || expected.ExpectedUserID == 0 || expected.ExpectedGroupID == 0 || !resourceID.MatchString(expected.AssignmentID) || !family(expected.PluginID) || !family(expected.DatabaseFamily) || !version(expected.Version) || expected.ProtocolVersion != "v1" || len(expected.ExecutableSHA256) != sha256.Size || !filepath.IsAbs(expected.ExecutablePath) || filepath.Clean(expected.ExecutablePath) != expected.ExecutablePath || len(expected.LaunchNonce) != sha256.Size || expected.ConfigurationRevision == 0 || expected.OperationRevision == 0 || len(expected.InstanceIDs) == 0 || len(expected.InstanceIDs) > maxAssignedInstances || !unique(expected.InstanceIDs) || len(expected.TemplateIDs) > maxAssignedTemplates || !unique(expected.TemplateIDs) || expected.RuntimeDirectory != filepath.Join(root, expected.DatabaseFamily) || filepath.Join(expected.RuntimeDirectory, "plugin.sock") != expectedSocket {
		return errGateway
	}
	return nil
}

func cloneExpected(value ExpectedPlugin) ExpectedPlugin {
	value.ExecutableSHA256 = append([]byte(nil), value.ExecutableSHA256...)
	value.LaunchNonce = append([]byte(nil), value.LaunchNonce...)
	value.InstanceIDs = append([]string(nil), value.InstanceIDs...)
	value.TemplateIDs = append([]string(nil), value.TemplateIDs...)
	return value
}
func sameExpected(left, right ExpectedPlugin) bool {
	return left.PID == right.PID && left.ExpectedUserID == right.ExpectedUserID && left.ExpectedGroupID == right.ExpectedGroupID && left.RuntimeDirectory == right.RuntimeDirectory && left.AssignmentID == right.AssignmentID && left.PluginID == right.PluginID && left.DatabaseFamily == right.DatabaseFamily && left.Version == right.Version && left.ProtocolVersion == right.ProtocolVersion && left.ExecutablePath == right.ExecutablePath && bytes.Equal(left.ExecutableSHA256, right.ExecutableSHA256) && bytes.Equal(left.LaunchNonce, right.LaunchNonce) && left.ConfigurationRevision == right.ConfigurationRevision && left.OperationRevision == right.OperationRevision && sameSet(left.InstanceIDs, right.InstanceIDs) && sameSet(left.TemplateIDs, right.TemplateIDs)
}
func cloneInstances(values []*pluginv1.PluginInstanceConfiguration) []*pluginv1.PluginInstanceConfiguration {
	result := make([]*pluginv1.PluginInstanceConfiguration, len(values))
	for index, value := range values {
		result[index] = proto.Clone(value).(*pluginv1.PluginInstanceConfiguration)
	}
	return result
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
