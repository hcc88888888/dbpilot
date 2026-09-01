package mysqlplugin

import (
	"context"
	"crypto/sha256"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maxPluginRPCMessageBytes   = 4 << 20
	maxPluginBatchBytes        = 3 << 20
	maxPendingBytes            = 64 << 20
	pendingFailureReserveBytes = 1 << 10
)

type ServerConfig struct {
	AssignmentID          string
	OperationRevision     uint64
	ConfigurationRevision uint64
	PluginID              string
	Version               string
	ExecutableDigest      []byte
	LaunchNonce           []byte
	ExpectedInstanceIDs   []string
	Runtime               *Runtime
	Collector             *Collector
	Parser                StatementParser
	Now                   func() time.Time
	StreamInterval        time.Duration
}

type Server struct {
	pluginv1.UnimplementedPluginRuntimeServer
	config        ServerConfig
	runtime       *Runtime
	collector     *Collector
	parser        StatementParser
	mu            sync.Mutex
	instanceLanes map[string]*sync.Mutex
	sequences     map[string]uint64
	acknowledged  map[string]uint64
	shuttingDown  bool
	shutdown      chan struct{}
	shutdownOnce  sync.Once
	streams       sync.WaitGroup
	nextDue       map[string]time.Time
	pending       map[string]*pluginv1.PluginMetricBatch
	pendingBytes  int
}

func NewServer(config ServerConfig) *Server {
	if config.PluginID == "" {
		config.PluginID = PluginID
	}
	if config.Version == "" {
		config.Version = PluginVersion
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Parser == nil {
		parser := NewMySQLStatementParser()
		config.Parser = parser
	}
	if config.Runtime == nil {
		config.Runtime = NewRuntime(MySQLPoolFactory{}, RuntimeOptions{})
	}
	if config.Collector == nil {
		config.Collector = NewCollector(config.Runtime, CollectorOptions{Now: config.Now})
	}
	if config.StreamInterval <= 0 {
		config.StreamInterval = time.Second
	}
	return &Server{config: config, runtime: config.Runtime, collector: config.Collector, parser: config.Parser, sequences: map[string]uint64{}, acknowledged: map[string]uint64{}, shutdown: make(chan struct{}), nextDue: map[string]time.Time{}, pending: map[string]*pluginv1.PluginMetricBatch{}, instanceLanes: map[string]*sync.Mutex{}}
}

func (server *Server) Handshake(_ context.Context, request *pluginv1.PluginHandshakeRequest) (*pluginv1.PluginHandshakeResponse, error) {
	if request == nil || request.GetExpectedPluginId() != server.config.PluginID || request.GetExpectedDatabaseFamily() != DatabaseFamily || request.GetExpectedVersion() != server.config.Version || request.GetExpectedProtocolVersion() != ProtocolVersion || len(request.GetLaunchNonceChallenge()) != sha256.Size {
		return nil, errors.New("handshake_rejected")
	}
	proof := pluginsupervisor.LaunchProof(server.config.LaunchNonce, request.GetLaunchNonceChallenge(), server.config.AssignmentID, server.config.Version, server.config.ConfigurationRevision, server.config.OperationRevision, server.config.ExpectedInstanceIDs)
	if len(proof) != sha256.Size || len(server.config.ExecutableDigest) != sha256.Size {
		return nil, errors.New("handshake_rejected")
	}
	return &pluginv1.PluginHandshakeResponse{PluginId: server.config.PluginID, DatabaseFamily: DatabaseFamily, Version: server.config.Version, ProtocolVersion: ProtocolVersion, SupportedVariants: []string{"mysql"}, DatabaseVersionRange: ">=8.0.0 <9.0.0", Capabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: TemplateSchemaVersion, ExecutableDigest: append([]byte(nil), server.config.ExecutableDigest...), LaunchNonceProof: proof, BuiltinTemplates: BuiltinDescriptors()}, nil
}

func (server *Server) ApplyConfiguration(ctx context.Context, request *pluginv1.ApplyPluginConfigurationRequest) (*pluginv1.ApplyPluginConfigurationResponse, error) {
	defer clearApplyRequest(request)
	if request == nil || request.GetAssignmentId() != server.config.AssignmentID || server.isShuttingDown() {
		return nil, errors.New("configuration_rejected")
	}
	configuration, err := DecodeConfiguration(request, server.config.Now().UTC(), server.parser)
	if err != nil {
		return &pluginv1.ApplyPluginConfigurationResponse{ErrorCode: "configuration_rejected"}, nil
	}
	previousRevision := server.runtime.Revision()
	targetRevision := request.GetConfigurationRevision()
	if err = server.runtime.ApplyWithSwap(ctx, configuration, func() {
		if previousRevision != 0 && previousRevision != targetRevision {
			server.mu.Lock()
			server.nextDue = map[string]time.Time{}
			server.pending = map[string]*pluginv1.PluginMetricBatch{}
			server.pendingBytes = 0
			server.mu.Unlock()
		}
	}); err != nil {
		code := "connection_rejected"
		if errors.Is(err, ErrConfigurationRejected) {
			code = "configuration_rejected"
		}
		return &pluginv1.ApplyPluginConfigurationResponse{ErrorCode: code}, nil
	}
	server.pruneCursors()
	results := make([]*pluginv1.PluginInstanceConfigurationResult, 0, len(request.GetInstances()))
	for _, instance := range request.GetInstances() {
		results = append(results, &pluginv1.PluginInstanceConfigurationResult{InstanceId: instance.GetInstanceId(), Applied: true})
	}
	return &pluginv1.ApplyPluginConfigurationResponse{ActiveConfigurationRevision: request.GetConfigurationRevision(), Results: results}, nil
}

func (server *Server) ValidateInstance(ctx context.Context, request *pluginv1.ValidatePluginInstanceRequest) (*pluginv1.ValidatePluginInstanceResponse, error) {
	if request == nil || request.GetAssignmentId() != server.config.AssignmentID || request.GetConfigurationRevision() != server.runtime.Revision() {
		return nil, errors.New("validation_rejected")
	}
	instance, ok := server.runtime.Instance(request.GetInstanceId())
	if !ok {
		return nil, errors.New("validation_rejected")
	}
	if instance.Pool == nil {
		return &pluginv1.ValidatePluginInstanceResponse{InstanceId: request.GetInstanceId(), Valid: false, ErrorCode: "waiting_credentials"}, nil
	}
	callContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := instance.Pool.QueryContext(callContext, "SELECT VERSION(), @@version_comment")
	if err != nil {
		return &pluginv1.ValidatePluginInstanceResponse{InstanceId: request.GetInstanceId(), Valid: false, ErrorCode: "connection_unavailable"}, nil
	}
	defer rows.Close()
	var version, edition string
	if !rows.Next() || rows.Scan(&version, &edition) != nil || rows.Err() != nil {
		return &pluginv1.ValidatePluginInstanceResponse{InstanceId: request.GetInstanceId(), Valid: false, ErrorCode: "result_rejected"}, nil
	}
	lower := strings.ToLower(version + " " + edition)
	if !strings.HasPrefix(version, "8.") || strings.Contains(lower, "mariadb") || strings.Contains(lower, "tidb") || strings.Contains(lower, "oceanbase") {
		return &pluginv1.ValidatePluginInstanceResponse{InstanceId: request.GetInstanceId(), Valid: false, ErrorCode: "unsupported_database"}, nil
	}
	return &pluginv1.ValidatePluginInstanceResponse{InstanceId: request.GetInstanceId(), Valid: true, DatabaseVersion: version, DatabaseEdition: boundedText(edition, 128), Capabilities: []string{"metrics.collect"}}, nil
}

func (server *Server) CollectNow(ctx context.Context, request *pluginv1.CollectPluginMetricsRequest) (*pluginv1.CollectPluginMetricsResponse, error) {
	if request == nil || request.GetAssignmentId() != server.config.AssignmentID || request.GetConfigurationRevision() != server.runtime.Revision() || len(request.GetInstanceIds()) == 0 || len(request.GetInstanceIds()) > MaxInstances || len(request.GetTemplateIds()) == 0 || len(request.GetTemplateIds()) > MaxTemplates || !uniqueStrings(request.GetInstanceIds()) || !uniqueStrings(request.GetTemplateIds()) {
		return nil, errors.New("collection_rejected")
	}
	type instanceResult struct {
		index   int
		batches []*pluginv1.PluginMetricBatch
		err     error
	}
	results := make(chan instanceResult, len(request.GetInstanceIds()))
	for index, instanceID := range request.GetInstanceIds() {
		go func(index int, instanceID string) {
			batches, err := server.collectInstance(ctx, request.GetConfigurationRevision(), instanceID, request.GetTemplateIds())
			results <- instanceResult{index: index, batches: batches, err: err}
		}(index, instanceID)
	}
	ordered := make([][]*pluginv1.PluginMetricBatch, len(request.GetInstanceIds()))
	var firstErr error
	for range request.GetInstanceIds() {
		result := <-results
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
		ordered[result.index] = result.batches
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if request.GetConfigurationRevision() != server.runtime.Revision() {
		return nil, errors.New("collection_rejected")
	}
	batches := make([]*pluginv1.PluginMetricBatch, 0, len(request.GetInstanceIds())*len(request.GetTemplateIds()))
	for _, group := range ordered {
		batches = append(batches, group...)
	}
	response := &pluginv1.CollectPluginMetricsResponse{Batches: batches}
	if proto.Size(response) > maxPluginRPCMessageBytes {
		return nil, errors.New("collection_response_too_large")
	}
	return response, nil
}

func (server *Server) collectInstance(ctx context.Context, revision uint64, instanceID string, templateIDs []string) ([]*pluginv1.PluginMetricBatch, error) {
	instance, exists := server.runtime.Instance(instanceID)
	if !exists {
		return nil, errors.New("collection_rejected")
	}
	lane := server.instanceLane(instanceID)
	lane.Lock()
	defer lane.Unlock()
	if revision != server.runtime.Revision() {
		return nil, errors.New("collection_rejected")
	}
	instance, exists = server.runtime.Instance(instanceID)
	if !exists {
		return nil, errors.New("collection_rejected")
	}
	for _, templateID := range templateIDs {
		if _, builtin := builtinCatalog[templateID]; builtin {
			continue
		}
		if _, custom := instance.Config.Templates[templateID]; !custom {
			return nil, errors.New("collection_rejected")
		}
	}
	pending := make(map[string]*pluginv1.PluginMetricBatch, len(templateIDs))
	builtins := make([]string, 0)
	for _, templateID := range templateIDs {
		if batch := server.pendingBatch(instanceID, templateID); batch != nil {
			if batch.GetConfigurationRevision() != revision {
				return nil, errors.New("collection_rejected")
			}
			pending[templateID] = batch
			continue
		}
		if _, builtin := builtinCatalog[templateID]; builtin {
			builtins = append(builtins, templateID)
		}
	}
	var builtin Batch
	if len(builtins) > 0 {
		builtin = server.collector.Collect(ctx, instanceID, builtins)
	}
	batches := make([]*pluginv1.PluginMetricBatch, 0, len(templateIDs))
	for _, templateID := range templateIDs {
		if revision != server.runtime.Revision() {
			return nil, errors.New("collection_rejected")
		}
		if batch := pending[templateID]; batch != nil {
			batches = append(batches, batch)
			continue
		}
		if _, isBuiltin := builtinCatalog[templateID]; isBuiltin {
			filtered := filterSample(builtin, templateID)
			status, errorCode := builtin.Status, builtin.ErrorCode
			if templateID == "mysql.up" && len(filtered.Samples) == 1 && filtered.Samples[0].Value == 1 {
				status, errorCode = CollectionSucceeded, ""
			}
			batch := server.wireBatchAtRevision(revision, instance, templateID, 1, filtered, status, errorCode)
			if batch == nil {
				return nil, errors.New("collection_rejected")
			}
			batches = append(batches, batch)
			continue
		}
		template := instance.Config.Templates[templateID]
		collected := server.collector.CollectTemplate(ctx, instanceID, template)
		batch := server.wireBatchAtRevision(revision, instance, templateID, template.Revision, collected, collected.Status, collected.ErrorCode)
		if batch == nil {
			return nil, errors.New("collection_rejected")
		}
		batches = append(batches, batch)
	}
	if revision != server.runtime.Revision() {
		return nil, errors.New("collection_rejected")
	}
	return batches, nil
}

func (server *Server) instanceLane(instanceID string) *sync.Mutex {
	server.mu.Lock()
	defer server.mu.Unlock()
	lane := server.instanceLanes[instanceID]
	if lane == nil {
		lane = &sync.Mutex{}
		server.instanceLanes[instanceID] = lane
	}
	return lane
}

func (server *Server) TrialMetricTemplate(ctx context.Context, request *pluginv1.TrialMetricTemplateRequest) (*pluginv1.TrialMetricTemplateResponse, error) {
	started := server.config.Now().UTC()
	defer clearTrialRequest(request)
	if request == nil || request.GetAssignmentId() != server.config.AssignmentID || request.GetConfigurationRevision() != server.runtime.Revision() || request.GetOperationRevision() != server.config.OperationRevision || request.GetTemplate() == nil {
		return nil, errors.New("trial_rejected")
	}
	definition := request.GetTemplate()
	if definition.GetCardinalityLimit() == 0 || definition.GetCardinalityLimit() > 10000 {
		return &pluginv1.TrialMetricTemplateResponse{ErrorCode: "template_rejected"}, nil
	}
	wire := &pluginv1.MetricTemplateConfiguration{TemplateId: definition.GetTemplateId(), Revision: definition.GetRevision(), QueryDigest: append([]byte(nil), definition.GetQueryDigest()...), QueryKind: definition.GetQueryKind(), ReadOnlyStatement: string(definition.GetReadOnlyStatement()), CollectionIntervalSeconds: definition.GetCollectionIntervalSeconds(), TimeoutSeconds: definition.GetTimeoutSeconds(), MaxRows: definition.GetMaxRows(), MaxColumns: definition.GetMaxColumns(), CardinalityLimit: definition.GetCardinalityLimit(), ValueMappings: definition.GetValueMappings(), LabelMappings: definition.GetLabelMappings()}
	if ValidateTemplate(wire, server.parser) != nil {
		return &pluginv1.TrialMetricTemplateResponse{ErrorCode: "template_rejected"}, nil
	}
	template := TemplateConfig{ID: wire.GetTemplateId(), Revision: wire.GetRevision(), Digest: append([]byte(nil), wire.GetQueryDigest()...), Statement: wire.GetReadOnlyStatement(), Interval: time.Duration(wire.GetCollectionIntervalSeconds()) * time.Second, Timeout: time.Duration(wire.GetTimeoutSeconds()) * time.Second, MaxRows: wire.GetMaxRows(), MaxColumns: wire.GetMaxColumns(), Cardinality: definition.GetCardinalityLimit(), ValueMappings: wire.GetValueMappings(), LabelMappings: wire.GetLabelMappings()}
	defer template.Release()
	result := server.collector.CollectTemplate(ctx, request.GetInstanceId(), template)
	duration := server.config.Now().UTC().Sub(started)
	if duration < 0 {
		duration = 0
	}
	millis := duration.Milliseconds()
	if millis > int64(^uint32(0)) {
		millis = int64(^uint32(0))
	}
	response := &pluginv1.TrialMetricTemplateResponse{Succeeded: result.Status == CollectionSucceeded, RowCount: result.RowCount, ColumnCount: result.ColumnCount, MetricCount: uint32(len(result.Samples)), DurationMillis: uint32(millis), ErrorCode: result.ErrorCode}
	for _, sample := range result.Samples {
		response.CandidateMetrics = append(response.CandidateMetrics, wireSample(sample))
	}
	return response, nil
}

func (server *Server) StreamMetrics(request *pluginv1.StreamPluginMetricsRequest, stream pluginv1.PluginRuntime_StreamMetricsServer) error {
	if request == nil || request.GetAssignmentId() != server.config.AssignmentID || request.GetConfigurationRevision() != server.runtime.Revision() {
		return errors.New("stream_rejected")
	}
	replays, err := server.prepareResume(request.GetResumeCursors())
	if err != nil {
		return err
	}
	server.mu.Lock()
	if server.shuttingDown {
		server.mu.Unlock()
		return errors.New("stream_rejected")
	}
	server.streams.Add(1)
	server.mu.Unlock()
	defer server.streams.Done()
	if err := stream.SendHeader(nil); err != nil {
		return err
	}
	for _, batch := range replays {
		if err := stream.Send(batch); err != nil {
			return err
		}
	}
	streamContext, cancel := context.WithCancel(stream.Context())
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		select {
		case <-server.shutdown:
			cancel()
		case <-stopped:
		}
	}()
	defer close(stopped)
	ticker := time.NewTicker(server.config.StreamInterval)
	defer ticker.Stop()
	type streamCollection struct {
		instanceID string
		response   *pluginv1.CollectPluginMetricsResponse
		err        error
	}
	completed := make(chan streamCollection, MaxInstances)
	inFlight := map[string]struct{}{}
	for {
		select {
		case <-streamContext.Done():
			select {
			case <-server.shutdown:
				return nil
			default:
				return streamContext.Err()
			}
		case result := <-completed:
			delete(inFlight, result.instanceID)
			if result.err != nil {
				return result.err
			}
			for _, batch := range result.response.GetBatches() {
				if err := stream.Send(batch); err != nil {
					return err
				}
			}
		case <-ticker.C:
			instances := server.runtime.Instances()
			sort.Slice(instances, func(i, j int) bool { return instances[i].Config.ID < instances[j].Config.ID })
			revision := server.runtime.Revision()
			for _, instance := range instances {
				if _, running := inFlight[instance.Config.ID]; running {
					continue
				}
				ids := server.dueTemplateIDs(instance.Config, server.config.Now().UTC())
				if len(ids) == 0 {
					continue
				}
				inFlight[instance.Config.ID] = struct{}{}
				go func(instanceID string, templateIDs []string) {
					response, err := server.CollectNow(streamContext, &pluginv1.CollectPluginMetricsRequest{AssignmentId: server.config.AssignmentID, ConfigurationRevision: revision, InstanceIds: []string{instanceID}, TemplateIds: templateIDs})
					completed <- streamCollection{instanceID: instanceID, response: response, err: err}
				}(instance.Config.ID, append([]string(nil), ids...))
			}
		}
	}
}

func (server *Server) AcknowledgeMetrics(_ context.Context, request *pluginv1.AcknowledgePluginMetricsRequest) (*pluginv1.AcknowledgePluginMetricsResponse, error) {
	if request == nil || request.GetAssignmentId() != server.config.AssignmentID || request.GetConfigurationRevision() != server.runtime.Revision() || len(request.GetCursors()) == 0 || len(request.GetCursors()) > MaxInstances*MaxTemplates {
		return nil, errors.New("ack_rejected")
	}
	bound := server.boundPairs()
	proposed := make(map[string]uint64, len(request.GetCursors()))
	accepted := make([]*pluginv1.PluginMetricCursor, 0, len(request.GetCursors()))
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, cursor := range request.GetCursors() {
		key := cursorKey(cursor.GetInstanceId(), cursor.GetTemplateId())
		if _, ok := bound[key]; !ok {
			return &pluginv1.AcknowledgePluginMetricsResponse{ErrorCode: "cursor_rejected"}, nil
		}
		if _, duplicate := proposed[key]; duplicate {
			return &pluginv1.AcknowledgePluginMetricsResponse{ErrorCode: "cursor_rejected"}, nil
		}
		sequence := cursor.GetSequence()
		pending := server.pending[key]
		if sequence == 0 || sequence != server.acknowledged[key] && (pending == nil || pending.GetSequence() != sequence || server.sequences[key] != sequence) {
			return &pluginv1.AcknowledgePluginMetricsResponse{ErrorCode: "cursor_rejected"}, nil
		}
		proposed[key] = cursor.GetSequence()
		accepted = append(accepted, &pluginv1.PluginMetricCursor{InstanceId: cursor.GetInstanceId(), TemplateId: cursor.GetTemplateId(), Sequence: cursor.GetSequence()})
	}
	for key, sequence := range proposed {
		server.acknowledged[key] = sequence
		if pending := server.pending[key]; pending != nil && pending.GetSequence() == sequence {
			server.removePendingLocked(key)
		}
	}
	return &pluginv1.AcknowledgePluginMetricsResponse{AcceptedCursors: accepted}, nil
}

func (server *Server) GetHealth(_ context.Context, request *pluginv1.GetPluginHealthRequest) (*pluginv1.PluginHealth, error) {
	if request == nil || request.GetAssignmentId() != server.config.AssignmentID {
		return nil, errors.New("health_rejected")
	}
	instances := server.runtime.Instances()
	sort.Slice(instances, func(i, j int) bool { return instances[i].Config.ID < instances[j].Config.ID })
	health := &pluginv1.PluginHealth{AssignmentId: server.config.AssignmentID, ActiveConfigurationRevision: server.runtime.Revision(), BoundInstanceCount: uint32(len(instances)), State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY, ObservedAt: timestamppb.New(server.config.Now().UTC())}
	for _, instance := range instances {
		state := pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY
		code := ""
		if instance.Pool == nil {
			state = pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_DEGRADED
			code = "waiting_credentials"
			health.State = pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_DEGRADED
		} else {
			collectionState, collectionCode := server.collector.Health(instance.Config.ID, server.config.Now().UTC())
			switch collectionState {
			case HealthDegraded:
				state, code = pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_DEGRADED, collectionCode
				if health.State == pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY {
					health.State = state
				}
			case HealthUnhealthy:
				state, code = pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_UNHEALTHY, collectionCode
				health.State = state
			}
		}
		health.Instances = append(health.Instances, &pluginv1.PluginInstanceHealth{InstanceId: instance.Config.ID, State: state, ErrorCode: code})
	}
	return health, nil
}

func (server *Server) Shutdown(ctx context.Context, request *pluginv1.ShutdownPluginRequest) (*pluginv1.ShutdownPluginResponse, error) {
	if request == nil || request.GetAssignmentId() != server.config.AssignmentID {
		return nil, errors.New("shutdown_rejected")
	}
	server.mu.Lock()
	server.shuttingDown = true
	server.mu.Unlock()
	server.shutdownOnce.Do(func() { close(server.shutdown) })
	done := make(chan struct{})
	go func() { server.streams.Wait(); close(done) }()
	timeout := time.Duration(request.GetDrainTimeoutSeconds()) * time.Second
	if timeout <= 0 {
		timeout = time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return &pluginv1.ShutdownPluginResponse{Drained: false, ErrorCode: "drain_timeout"}, nil
	case <-timer.C:
		return &pluginv1.ShutdownPluginResponse{Drained: false, ErrorCode: "drain_timeout"}, nil
	case <-done:
		server.runtime.Close()
		return &pluginv1.ShutdownPluginResponse{Drained: true}, nil
	}
}
func (server *Server) isShuttingDown() bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.shuttingDown
}

func (server *Server) wireBatch(instance InstanceRuntime, templateID string, revision uint64, batch Batch, status CollectionStatus, errorCode string) *pluginv1.PluginMetricBatch {
	return server.wireBatchAtRevision(server.runtime.Revision(), instance, templateID, revision, batch, status, errorCode)
}

func (server *Server) wireBatchAtRevision(configurationRevision uint64, instance InstanceRuntime, templateID string, revision uint64, batch Batch, status CollectionStatus, errorCode string) *pluginv1.PluginMetricBatch {
	key := cursorKey(instance.Config.ID, templateID)
	boundCount := len(server.boundPairs())
	collectedAt := batch.CollectedAt
	if collectedAt.IsZero() {
		collectedAt = server.config.Now().UTC()
	}
	result := &pluginv1.PluginMetricBatch{PluginId: server.config.PluginID, PluginVersion: server.config.Version, DatabaseFamily: DatabaseFamily, DatabaseVariant: instance.Config.Variant, InstanceId: instance.Config.ID, ConfigurationRevision: configurationRevision, TemplateId: templateID, TemplateRevision: revision, CollectedAt: timestamppb.New(collectedAt), CollectionStatus: wireStatus(status), ErrorCode: errorCode}
	for _, sample := range batch.Samples {
		result.Samples = append(result.Samples, wireSample(sample))
	}
	interval := 10 * time.Second
	if template, ok := instance.Config.Templates[templateID]; ok && template.Interval > 0 {
		interval = template.Interval
	}
	var output *pluginv1.PluginMetricBatch
	if !server.runtime.withRevision(configurationRevision, func() {
		server.mu.Lock()
		defer server.mu.Unlock()
		if existing := server.pending[key]; existing != nil {
			output = proto.Clone(existing).(*pluginv1.PluginMetricBatch)
			return
		}
		server.sequences[key]++
		result.Sequence = server.sequences[key]
		if proto.Size(result) >= maxPluginBatchBytes {
			result = smallFailureBatch(result)
		}
		size := proto.Size(result)
		unoccupied := boundCount - (len(server.pending) + 1)
		if unoccupied < 0 {
			unoccupied = 0
		}
		budget := maxPendingBytes - unoccupied*pendingFailureReserveBytes
		if server.pendingBytes+size > budget {
			result = smallFailureBatch(result)
			size = proto.Size(result)
		}
		if size >= maxPluginBatchBytes || server.pendingBytes+size > maxPendingBytes {
			server.sequences[key]--
			output = smallFailureBatch(result)
			return
		}
		server.pending[key] = proto.Clone(result).(*pluginv1.PluginMetricBatch)
		server.pendingBytes += size
		server.nextDue[key] = collectedAt.Add(interval)
		output = result
	}) {
		return nil
	}
	return output
}

func smallFailureBatch(source *pluginv1.PluginMetricBatch) *pluginv1.PluginMetricBatch {
	return &pluginv1.PluginMetricBatch{PluginId: source.GetPluginId(), PluginVersion: source.GetPluginVersion(), DatabaseFamily: source.GetDatabaseFamily(), DatabaseVariant: source.GetDatabaseVariant(), InstanceId: source.GetInstanceId(), ConfigurationRevision: source.GetConfigurationRevision(), TemplateId: source.GetTemplateId(), TemplateRevision: source.GetTemplateRevision(), CollectedAt: source.GetCollectedAt(), Sequence: source.GetSequence(), CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_FAILED, ErrorCode: "result_limit_exceeded"}
}

func (server *Server) removePendingLocked(key string) {
	if pending := server.pending[key]; pending != nil {
		server.pendingBytes -= proto.Size(pending)
		if server.pendingBytes < 0 {
			server.pendingBytes = 0
		}
		delete(server.pending, key)
	}
}

func (server *Server) pendingBatch(instanceID, templateID string) *pluginv1.PluginMetricBatch {
	server.mu.Lock()
	defer server.mu.Unlock()
	if batch := server.pending[cursorKey(instanceID, templateID)]; batch != nil {
		return proto.Clone(batch).(*pluginv1.PluginMetricBatch)
	}
	return nil
}

func (server *Server) prepareResume(cursors []*pluginv1.PluginMetricCursor) ([]*pluginv1.PluginMetricBatch, error) {
	bound := server.boundPairs()
	if len(cursors) != len(bound) || len(bound) == 0 || len(bound) > MaxInstances*MaxTemplates {
		return nil, errors.New("stream_rejected")
	}
	resume := make(map[string]uint64, len(bound))
	for _, cursor := range cursors {
		key := cursorKey(cursor.GetInstanceId(), cursor.GetTemplateId())
		if _, ok := bound[key]; !ok {
			return nil, errors.New("stream_rejected")
		}
		if _, duplicate := resume[key]; duplicate {
			return nil, errors.New("stream_rejected")
		}
		resume[key] = cursor.GetSequence()
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	replayKeys := make([]string, 0)
	for key, sequence := range resume {
		current, acknowledged, pending := server.sequences[key], server.acknowledged[key], server.pending[key]
		if current == 0 {
			continue
		}
		if sequence < acknowledged {
			return nil, errors.New("stream_rejected")
		}
		if sequence == current {
			continue
		}
		if pending != nil && pending.GetSequence() == current && sequence == current-1 {
			replayKeys = append(replayKeys, key)
			continue
		}
		return nil, errors.New("stream_rejected")
	}
	for key, sequence := range resume {
		current := server.sequences[key]
		if current == 0 {
			server.sequences[key] = sequence
			server.acknowledged[key] = sequence
			server.removePendingLocked(key)
		} else if sequence == current {
			server.acknowledged[key] = sequence
			server.removePendingLocked(key)
		}
	}
	sort.Strings(replayKeys)
	result := make([]*pluginv1.PluginMetricBatch, 0, len(replayKeys))
	for _, key := range replayKeys {
		result = append(result, proto.Clone(server.pending[key]).(*pluginv1.PluginMetricBatch))
	}
	return result, nil
}
func filterSample(batch Batch, name string) Batch {
	result := batch
	result.Samples = nil
	for _, sample := range batch.Samples {
		if sample.Name == name {
			result.Samples = append(result.Samples, sample)
		}
	}
	return result
}
func wireSample(sample Sample) *pluginv1.PluginMetricSample {
	result := &pluginv1.PluginMetricSample{MetricName: sample.Name, Value: sample.Value, Unit: sample.Unit, MetricType: sample.MetricType, Labels: cloneLabels(sample.Labels), SampledAt: timestamppb.New(sample.SampledAt)}
	if !sample.StartTime.IsZero() {
		result.StartTime = timestamppb.New(sample.StartTime)
	}
	return result
}
func wireStatus(value CollectionStatus) pluginv1.PluginCollectionStatus {
	switch value {
	case CollectionSucceeded:
		return pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED
	case CollectionPartial:
		return pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_PARTIAL
	default:
		return pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_FAILED
	}
}
func cursorKey(instanceID, templateID string) string { return instanceID + "\x00" + templateID }
func uniqueStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
func boundedText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
func clearTrialRequest(request *pluginv1.TrialMetricTemplateRequest) {
	if request == nil || request.Template == nil {
		return
	}
	clear(request.Template.ReadOnlyStatement)
	request.Template.ValueMappings = nil
	request.Template.LabelMappings = nil
}

func (server *Server) boundPairs() map[string]struct{} {
	result := map[string]struct{}{}
	for _, instance := range server.runtime.Instances() {
		for id := range builtinCatalog {
			result[cursorKey(instance.Config.ID, id)] = struct{}{}
		}
		for id := range instance.Config.Templates {
			result[cursorKey(instance.Config.ID, id)] = struct{}{}
		}
	}
	return result
}
func (server *Server) pruneCursors() {
	bound := server.boundPairs()
	activeInstances := map[string]struct{}{}
	for _, instance := range server.runtime.Instances() {
		activeInstances[instance.Config.ID] = struct{}{}
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	for key := range server.sequences {
		if _, ok := bound[key]; !ok {
			delete(server.sequences, key)
			delete(server.acknowledged, key)
			delete(server.nextDue, key)
			server.removePendingLocked(key)
		}
	}
	for instanceID := range server.instanceLanes {
		if _, active := activeInstances[instanceID]; !active {
			delete(server.instanceLanes, instanceID)
		}
	}
}

func (server *Server) dueTemplateIDs(instance InstanceConfig, now time.Time) []string {
	ids := SortedBuiltinTemplateIDs(BuiltinCatalog())
	for id := range instance.Templates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	server.mu.Lock()
	defer server.mu.Unlock()
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		if server.pending[cursorKey(instance.ID, id)] != nil {
			continue
		}
		due := server.nextDue[cursorKey(instance.ID, id)]
		if due.IsZero() || !now.Before(due) {
			result = append(result, id)
		}
	}
	return result
}

func (server *Server) markScheduled(instance InstanceConfig, ids []string, at time.Time) {
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, id := range ids {
		interval := 10 * time.Second
		if template, ok := instance.Templates[id]; ok && template.Interval > 0 {
			interval = template.Interval
		}
		server.nextDue[cursorKey(instance.ID, id)] = at.Add(interval)
	}
}

var _ pluginv1.PluginRuntimeServer = (*Server)(nil)
