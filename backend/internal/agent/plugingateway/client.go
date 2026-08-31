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
	PID                         int
	ExpectedUserID              uint32
	ExpectedGroupID             uint32
	RuntimeDirectory            string
	AssignmentID                string
	PluginID                    string
	DatabaseFamily              string
	Version                     string
	ProtocolVersion             string
	ExecutablePath              string
	ExecutableSHA256            []byte
	LaunchNonce                 []byte
	ConfigurationRevision       uint64
	OperationRevision           uint64
	InstanceIDs                 []string
	TemplateIDs                 []string
	SupportedVariants           []string
	SignedCapabilities          []string
	MetricTemplateSchemaVersion uint32
	TemplateConfigurations      []*pluginv1.MetricTemplateConfiguration
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

func (configuration *PluginConfiguration) Release() {
	if configuration == nil {
		return
	}
	for _, instance := range configuration.Instances {
		clearInstanceCredential(instance)
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
	client                *Client
	expected              ExpectedPlugin
	mu                    sync.Mutex
	lanesMu               sync.Mutex
	lanes                 map[cursorKey]*sync.Mutex
	handshaken            bool
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
	return &Session{client: client, expected: cloneExpected(expected)}, nil
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
		if err != nil || !validHandshake(response, session.expected, challenge) || !matchesSignedManifest(response, session.expected) {
			return errGateway
		}
		variants, capabilities, versionRange := boundedSorted(response.GetSupportedVariants(), 64), boundedSorted(response.GetCapabilities(), 64), boundedText(response.GetDatabaseVersionRange(), 128)
		if len(response.GetSupportedVariants()) > 0 && variants == nil || len(response.GetCapabilities()) > 0 && capabilities == nil || response.GetDatabaseVersionRange() != "" && versionRange == "" {
			return errGateway
		}
		result = Capabilities{SupportedVariants: variants, DatabaseVersionRange: versionRange, Capabilities: capabilities, MetricTemplateSchemaVersion: response.GetMetricTemplateSchemaVersion()}
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
	request := canonicalApplyRequest(configuration)
	defer clearConfigurationSecrets(request)
	responseErr := session.invoke(ctx, func(client pluginv1.PluginRuntimeClient, callContext context.Context) error {
		response, err := client.ApplyConfiguration(callContext, request)
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
		session.instances[instance.GetInstanceId()] = cloneInstanceWithoutCredential(instance)
	}
	session.mu.Unlock()
	return nil
}

func (session *Session) AssignmentID() string {
	if session == nil {
		return ""
	}
	return session.expected.AssignmentID
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
	return session.runMetricStream(ctx, sink, nil)
}

// RunMetricStreamReady reports readiness only after the verified stream has
// received server headers. Dial/header setup is bounded by the unary timeout;
// the receive loop is owned solely by the Supervisor lifetime context.
func (session *Session) RunMetricStreamReady(ctx context.Context, sink MetricSink, ready chan<- error) error {
	return session.runMetricStream(ctx, sink, ready)
}

func (session *Session) runMetricStream(ctx context.Context, sink MetricSink, ready chan<- error) error {
	if session == nil || ctx == nil || ctx.Err() != nil || sink == nil || !session.isConfigured() {
		reportStreamReady(ready, errGateway)
		return errGateway
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
	reportStreamReady(ready, nil)
	for {
		batch, receiveErr := stream.Recv()
		if errors.Is(receiveErr, io.EOF) || receiveErr != nil {
			return errGateway
		}
		if err := session.appendAndAcknowledge(streamContext, batch, sink, runtimeClient); err != nil {
			return err
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
		templateIDs := make([]string, 0, len(configured.GetTemplates()))
		for _, template := range configured.GetTemplates() {
			templateIDs = append(templateIDs, template.GetTemplateId())
		}
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
	if session == nil || batch == nil || batch.GetConfigurationRevision() != session.expected.ConfigurationRevision || !contains(session.expected.InstanceIDs, batch.GetInstanceId()) || !contains(session.expected.TemplateIDs, batch.GetTemplateId()) {
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
	if batch == nil || batch.GetPluginId() != session.expected.PluginID || batch.GetPluginVersion() != session.expected.Version || batch.GetDatabaseFamily() != session.expected.DatabaseFamily || batch.GetConfigurationRevision() != session.configurationRevision || !contains(session.expected.TemplateIDs, batch.GetTemplateId()) {
		return false
	}
	configured := session.instances[batch.GetInstanceId()]
	if configured == nil || batch.GetDatabaseVariant() != configured.GetDatabaseVariant() {
		return false
	}
	for _, template := range configured.GetTemplates() {
		if template != nil && template.GetTemplateId() == batch.GetTemplateId() && template.GetRevision() == batch.GetTemplateRevision() {
			return validateBatchAgainstTemplate(batch, template)
		}
	}
	return false
}

func (session *Session) metricScope(batch *pluginv1.PluginMetricBatch) MetricScope {
	scope := session.client.config.Scope
	scope.AssignmentID = session.expected.AssignmentID
	scope.InstanceIDs = append([]string(nil), session.expected.InstanceIDs...)
	scope.TemplateIDs = append([]string(nil), session.expected.TemplateIDs...)
	scope.DatabaseFamily = session.expected.DatabaseFamily
	scope.PluginID = session.expected.PluginID
	scope.PluginVersion = session.expected.Version
	scope.ConfigurationRevision = session.configurationRevision
	scope.DatabaseVariant = session.instances[batch.GetInstanceId()].GetDatabaseVariant()
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
	pairs := 0
	for _, instance := range configuration.Instances {
		if instance == nil || !contains(expected.InstanceIDs, instance.GetInstanceId()) || instance.GetInstanceId() == "" || !family(instance.GetDatabaseVariant()) || (instance.GetEndpoint() == "" && instance.GetUnixSocket() == "") || (instance.GetEndpoint() != "" && instance.GetUnixSocket() != "") || len(instance.GetTemplates()) > maxGatewayMembers {
			return errGateway
		}
		if instance.GetCredentialLease() != nil && !validCredentialLease(instance.GetCredentialLease()) {
			return errGateway
		}
		templates := map[string]struct{}{}
		for _, template := range instance.GetTemplates() {
			if template == nil || !contains(expected.TemplateIDs, template.GetTemplateId()) || !validTemplateConfiguration(template) || !matchesExpectedTemplate(template, expected.TemplateConfigurations) {
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
		if !sameSet(mapKeys(templates), expected.TemplateIDs) {
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
	if value == nil || !identifier(value.GetTemplateId()) || value.GetRevision() == 0 || len(value.GetQueryDigest()) != sha256.Size || value.GetQueryKind() != "sql" || value.GetReadOnlyStatement() == "" || len(value.GetReadOnlyStatement()) > 64<<10 || value.GetCollectionIntervalSeconds() < 10 || value.GetTimeoutSeconds() == 0 || value.GetTimeoutSeconds() > 30 || value.GetMaxRows() == 0 || value.GetMaxRows() > 100 || value.GetMaxColumns() == 0 || value.GetMaxColumns() > 32 || len(value.GetValueMappings()) == 0 || len(value.GetValueMappings()) > 32 || len(value.GetLabelMappings()) > 16 {
		return false
	}
	metrics, labels := map[string]struct{}{}, map[string]struct{}{}
	for _, mapping := range value.GetValueMappings() {
		if mapping == nil || !identifier(mapping.GetSourceColumn()) || !pluginMetricName.MatchString(mapping.GetMetricName()) || !pluginUnit.MatchString(mapping.GetUnit()) || metricTypeFromName(mapping.GetMetricType()) == pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_UNSPECIFIED {
			return false
		}
		key := mapping.GetMetricName() + "\x00" + mapping.GetMetricType() + "\x00" + mapping.GetUnit()
		if _, duplicate := metrics[key]; duplicate {
			return false
		}
		metrics[key] = struct{}{}
	}
	for _, mapping := range value.GetLabelMappings() {
		normalized := normalizeMetricLabelKey(mapping.GetLabel())
		_, reserved := reservedNormalizedLabels[normalized]
		if mapping == nil || !identifier(mapping.GetSourceColumn()) || !pluginLabelName.MatchString(mapping.GetLabel()) || normalized == "" || reserved || strings.HasSuffix(normalized, "_tenant_id") || strings.HasSuffix(normalized, "_project_id") || strings.HasSuffix(normalized, "_agent_id") || strings.HasPrefix(normalized, "dbpilot_") {
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
	return value
}
func sameExpected(left, right ExpectedPlugin) bool {
	return left.PID == right.PID && left.ExpectedUserID == right.ExpectedUserID && left.ExpectedGroupID == right.ExpectedGroupID && left.RuntimeDirectory == right.RuntimeDirectory && left.AssignmentID == right.AssignmentID && left.PluginID == right.PluginID && left.DatabaseFamily == right.DatabaseFamily && left.Version == right.Version && left.ProtocolVersion == right.ProtocolVersion && left.ExecutablePath == right.ExecutablePath && bytes.Equal(left.ExecutableSHA256, right.ExecutableSHA256) && bytes.Equal(left.LaunchNonce, right.LaunchNonce) && left.ConfigurationRevision == right.ConfigurationRevision && left.OperationRevision == right.OperationRevision && sameSet(left.InstanceIDs, right.InstanceIDs) && sameSet(left.TemplateIDs, right.TemplateIDs) && sameSet(left.SupportedVariants, right.SupportedVariants) && sameSet(left.SignedCapabilities, right.SignedCapabilities) && left.MetricTemplateSchemaVersion == right.MetricTemplateSchemaVersion && sameTemplateConfigurations(left.TemplateConfigurations, right.TemplateConfigurations)
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
