package agentcontrol

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/commandvalidation"
	"dbpilot.local/platform/internal/credentiallease"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const ProtocolVersion = "1"
const CapabilityDiscoveryReportACKV1 = "discovery_report_ack_v1"
const CapabilityDiscoveryPolicyAttestationV1 = "discovery_policy_attestation_v1"
const CapabilityDiscoverySourceResultsV1 = "discovery_source_results_v1"

type Observer interface {
	Connected(context.Context, SessionInfo)
	Heartbeat(context.Context, string, *agentv1.Heartbeat)
	Acknowledged(context.Context, string, *agentv1.CommandAcknowledgement)
	Progress(context.Context, string, *agentv1.CommandProgress)
	Result(context.Context, string, *agentv1.CommandResult) (ResultPersistence, error)
}

type ResultPersistence struct {
	CommandID    string
	ResultDigest []byte
	Persisted    bool
	Retryable    bool
	ReasonCode   string
}

type PreparedObserver interface {
	Prepared(context.Context, string, *agentv1.CommandPrepared) (*agentv1.CommandStart, error)
}

// NoopObserver is the safe pre-integration default for command business events.
type NoopObserver struct{}

func (NoopObserver) Connected(context.Context, SessionInfo)                                {}
func (NoopObserver) Heartbeat(context.Context, string, *agentv1.Heartbeat)                 {}
func (NoopObserver) Acknowledged(context.Context, string, *agentv1.CommandAcknowledgement) {}
func (NoopObserver) Prepared(context.Context, string, *agentv1.CommandPrepared) (*agentv1.CommandStart, error) {
	return nil, nil
}
func (NoopObserver) Progress(context.Context, string, *agentv1.CommandProgress) {}
func (NoopObserver) Result(_ context.Context, _ string, result *agentv1.CommandResult) (ResultPersistence, error) {
	return ResultPersistence{CommandID: result.GetCommandId(), ReasonCode: "OBSERVER_UNAVAILABLE"}, nil
}

type Server struct {
	agentv1.UnimplementedAgentControlServer
	registry              *Registry
	observer              Observer
	hosts                 HostObserver
	discovery             DiscoveryObserver
	plugins               PluginObserver
	pluginArtifacts       PluginArtifactLeaseIssueService
	credentials           CredentialLeaseIssueService
	metricTemplates       MetricTemplateLeaseIssueService
	credentialsAuthorizer AgentCredentialAuthorizer
	now                   func() time.Time
}

type AgentCredentialAuthorizer interface {
	AuthorizeAgentCredential(context.Context, string, [sha256.Size]byte, string) error
}

type PluginArtifactLeaseIssueService interface {
	Issue(context.Context, string, *agentv1.PluginArtifactLeaseRequest) (*agentv1.PluginArtifactLeaseResponse, error)
}

type CredentialLeaseIssueService interface {
	Issue(context.Context, credentiallease.AuthenticatedAgent, *agentv1.CredentialLeaseRequest) (*agentv1.CredentialLeaseResponse, error)
}

type MetricTemplateLeaseIssueService interface {
	Issue(context.Context, credentiallease.AuthenticatedAgent, *agentv1.MetricTemplateLeaseRequest) (*agentv1.MetricTemplateLeaseResponse, error)
}

type noopCredentialLeaseIssuer struct{}

func (noopCredentialLeaseIssuer) Issue(context.Context, credentiallease.AuthenticatedAgent, *agentv1.CredentialLeaseRequest) (*agentv1.CredentialLeaseResponse, error) {
	return nil, credentiallease.ErrLeaseRejected
}

type noopPluginArtifactLeaseIssuer struct{}

type noopMetricTemplateLeaseIssuer struct{}

func (noopMetricTemplateLeaseIssuer) Issue(context.Context, credentiallease.AuthenticatedAgent, *agentv1.MetricTemplateLeaseRequest) (*agentv1.MetricTemplateLeaseResponse, error) {
	return nil, errors.New("metric template lease is unavailable")
}

func (noopPluginArtifactLeaseIssuer) Issue(context.Context, string, *agentv1.PluginArtifactLeaseRequest) (*agentv1.PluginArtifactLeaseResponse, error) {
	return nil, ErrPluginArtifactLeaseRejected
}

type PluginObserver interface {
	SubmitPlugin(string, *agentv1.PluginObservation) error
}
type noopPluginObserver struct{}

func (noopPluginObserver) SubmitPlugin(string, *agentv1.PluginObservation) error { return nil }

type ServerOption func(*Server)

func WithHostObserver(observer HostObserver) ServerOption {
	return func(server *Server) {
		if observer != nil {
			server.hosts = observer
		}
	}
}

func WithDiscoveryObserver(observer DiscoveryObserver) ServerOption {
	return func(server *Server) {
		if observer != nil {
			server.discovery = observer
		}
	}
}

func WithPluginObserver(observer PluginObserver) ServerOption {
	return func(server *Server) {
		if observer != nil {
			server.plugins = observer
		}
	}
}

func WithPluginArtifactLeaseIssuer(issuer PluginArtifactLeaseIssueService) ServerOption {
	return func(server *Server) {
		if issuer != nil {
			server.pluginArtifacts = issuer
		}
	}
}

func WithCredentialLeaseIssuer(issuer CredentialLeaseIssueService) ServerOption {
	return func(server *Server) {
		if issuer != nil {
			server.credentials = issuer
		}
	}
}

func WithMetricTemplateLeaseIssuer(issuer MetricTemplateLeaseIssueService) ServerOption {
	return func(server *Server) {
		if issuer != nil {
			server.metricTemplates = issuer
		}
	}
}

func WithAgentCredentialAuthorizer(authorizer AgentCredentialAuthorizer) ServerOption {
	return func(server *Server) { server.credentialsAuthorizer = authorizer }
}

func NewServer(registry *Registry, observer Observer, options ...ServerOption) *Server {
	if registry == nil {
		registry = NewRegistry(64)
	}
	if observer == nil {
		observer = NoopObserver{}
	}
	server := &Server{registry: registry, observer: observer, hosts: noopHostObserver{}, discovery: noopDiscoveryObserver{}, plugins: noopPluginObserver{}, pluginArtifacts: noopPluginArtifactLeaseIssuer{}, credentials: noopCredentialLeaseIssuer{}, metricTemplates: noopMetricTemplateLeaseIssuer{}, now: time.Now}
	for _, option := range options {
		if option != nil {
			option(server)
		}
	}
	return server
}

func (s *Server) Connect(stream agentv1.AgentControl_ConnectServer) error {
	agentID, err := verifiedAgentID(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	var credentialFingerprint [sha256.Size]byte
	var credentialSerial string
	if s.credentialsAuthorizer != nil {
		credentialFingerprint, credentialSerial, err = verifiedAgentCredential(stream.Context(), agentID)
		if err != nil || s.credentialsAuthorizer.AuthorizeAgentCredential(stream.Context(), agentID, credentialFingerprint, credentialSerial) != nil {
			return status.Error(codes.Unauthenticated, "Agent credential is not active")
		}
	}
	first, err := stream.Recv()
	if err != nil {
		return status.Error(codes.InvalidArgument, "Hello must be the first Agent message")
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "Hello must be the first Agent message")
	}
	if hello.GetAgentId() == "" {
		return status.Error(codes.InvalidArgument, "Hello Agent ID is required")
	}
	if subtle.ConstantTimeCompare([]byte(agentID), []byte(hello.GetAgentId())) != 1 {
		return status.Error(codes.PermissionDenied, "Hello Agent ID does not match the verified SPIFFE identity")
	}
	if hello.GetProtocolVersion() != ProtocolVersion {
		return status.Errorf(codes.FailedPrecondition, "unsupported Agent protocol version %q", hello.GetProtocolVersion())
	}

	sessionContext, cancel := context.WithCancel(stream.Context())
	if err := s.registry.registerCredential(agentID, hello.GetCapabilities(), hello.GetActiveCommands(), credentialFingerprint, credentialSerial, cancel); err != nil {
		cancel()
		if errors.Is(err, ErrDuplicateSession) {
			return status.Error(codes.AlreadyExists, err.Error())
		}
		return status.Error(codes.Internal, err.Error())
	}
	current, _ := s.registry.liveSession(agentID)
	defer func() {
		cancel()
		s.registry.unregister(agentID, current)
	}()

	ack := &agentv1.ServerMessage{
		MessageId: fmt.Sprintf("hello-ack-%d", s.now().UnixNano()), SentAt: timestamppb.New(s.now()),
		Message: &agentv1.ServerMessage_HelloAck{HelloAck: &agentv1.HelloAck{ProtocolVersion: ProtocolVersion, Capabilities: []string{CapabilityDiscoveryPolicyAttestationV1, CapabilityDiscoveryReportACKV1, CapabilityDiscoverySourceResultsV1}, ServerTime: timestamppb.New(s.now())}},
	}
	if err := stream.Send(ack); err != nil {
		return err
	}
	_ = s.hosts.SubmitHello(agentID, s.now().UTC())
	type receiveResult struct {
		message *agentv1.AgentMessage
		err     error
	}
	received := make(chan receiveResult, 1)
	go func() {
		for {
			message, receiveErr := stream.Recv()
			if receiveErr != nil {
				select {
				case received <- receiveResult{err: receiveErr}:
				case <-sessionContext.Done():
				}
				return
			}
			if heartbeat := message.GetHeartbeat(); heartbeat != nil {
				if heartbeatErr := s.recordHeartbeat(agentID, heartbeat); heartbeatErr != nil {
					select {
					case received <- receiveResult{err: heartbeatErr}:
					case <-sessionContext.Done():
					}
					return
				}
			}
			select {
			case received <- receiveResult{message: message}:
			case <-sessionContext.Done():
				return
			}
		}
	}()
	if snapshot, ok := s.registry.snapshot(agentID, current); ok {
		s.observer.Connected(sessionContext, snapshot)
	}

	for {
		select {
		case message := <-current.send:
			message.SentAt = timestamppb.New(s.now())
			if err := stream.Send(message); err != nil {
				clearCredentialLeaseResponse(message.GetCredentialLeaseResponse())
				clearMetricTemplateLeaseResponse(message.GetMetricTemplateLeaseResponse())
				return err
			}
			clearCredentialLeaseResponse(message.GetCredentialLeaseResponse())
			clearMetricTemplateLeaseResponse(message.GetMetricTemplateLeaseResponse())
		case item := <-received:
			if errors.Is(item.err, io.EOF) {
				return nil
			}
			if item.err != nil {
				return item.err
			}
			if err := s.handleAgentMessage(sessionContext, agentID, item.message); err != nil {
				return err
			}
		case <-sessionContext.Done():
			return sessionContext.Err()
		}
	}
}

func (s *Server) recordHeartbeat(agentID string, heartbeat *agentv1.Heartbeat) error {
	if heartbeat == nil || subtle.ConstantTimeCompare([]byte(agentID), []byte(heartbeat.GetAgentId())) != 1 {
		return status.Error(codes.PermissionDenied, "heartbeat Agent ID does not match the session identity")
	}
	at := s.now().UTC()
	s.registry.renew(agentID, heartbeat, at)
	_ = s.hosts.SubmitHeartbeat(agentID, at)
	return nil
}

func (s *Server) handleAgentMessage(ctx context.Context, agentID string, message *agentv1.AgentMessage) error {
	if message == nil {
		return status.Error(codes.InvalidArgument, "Agent message is required")
	}
	switch typed := message.GetMessage().(type) {
	case *agentv1.AgentMessage_Heartbeat:
		s.observer.Heartbeat(ctx, agentID, typed.Heartbeat)
	case *agentv1.AgentMessage_CommandAcknowledgement:
		if typed.CommandAcknowledgement == nil {
			return status.Error(codes.InvalidArgument, "command acknowledgement is required")
		}
		s.observer.Acknowledged(ctx, agentID, typed.CommandAcknowledgement)
	case *agentv1.AgentMessage_CommandPrepared:
		if err := commandvalidation.ValidatePrepared(typed.CommandPrepared); err != nil {
			return status.Error(codes.InvalidArgument, "command prepared message is invalid")
		}
		preparedObserver, ok := s.observer.(PreparedObserver)
		if !ok {
			return status.Error(codes.FailedPrecondition, "command prepared observer is unavailable")
		}
		start, err := preparedObserver.Prepared(ctx, agentID, typed.CommandPrepared)
		if err != nil {
			return status.Error(codes.Unavailable, err.Error())
		}
		if start == nil {
			break
		}
		if start.GetCommandId() != typed.CommandPrepared.GetCommandId() {
			return status.Error(codes.Internal, "prepared command start did not match command")
		}
		if err := s.registry.Start(ctx, agentID, start); err != nil {
			return status.Error(codes.Unavailable, err.Error())
		}
	case *agentv1.AgentMessage_CommandProgress:
		if err := commandvalidation.ValidateProgress(typed.CommandProgress); err != nil {
			return status.Error(codes.InvalidArgument, "command progress is invalid")
		}
		s.observer.Progress(ctx, agentID, typed.CommandProgress)
	case *agentv1.AgentMessage_CommandResult:
		if err := commandvalidation.ValidateResult(typed.CommandResult); err != nil {
			return status.Error(codes.InvalidArgument, "command result is invalid")
		}
		encodedResult, err := proto.MarshalOptions{Deterministic: true}.Marshal(typed.CommandResult)
		if err != nil {
			return status.Error(codes.Internal, "command result digest failed")
		}
		resultDigest := sha256.Sum256(encodedResult)
		outcome, err := s.observer.Result(ctx, agentID, typed.CommandResult)
		if err != nil {
			outcome = ResultPersistence{CommandID: typed.CommandResult.GetCommandId(), ResultDigest: resultDigest[:], Retryable: true, ReasonCode: "PERSISTENCE_RETRY"}
		}
		if outcome.CommandID != typed.CommandResult.GetCommandId() {
			return status.Error(codes.Internal, "result persistence outcome did not match command")
		}
		digestMatches := len(outcome.ResultDigest) == sha256.Size && subtle.ConstantTimeCompare(outcome.ResultDigest, resultDigest[:]) == 1
		persisted := outcome.Persisted && digestMatches
		retryable := outcome.Retryable && !persisted
		reasonCode := outcome.ReasonCode
		if !digestMatches {
			retryable = false
			reasonCode = "RESULT_DIGEST_MISMATCH"
		}
		ack := &agentv1.CommandResultAcknowledgement{CommandId: outcome.CommandID, ResultDigest: resultDigest[:], Persisted: persisted, Retryable: retryable, ReasonCode: reasonCode}
		if err := s.registry.enqueue(agentID, &agentv1.ServerMessage{MessageId: "result-ack-" + outcome.CommandID, Message: &agentv1.ServerMessage_CommandResultAcknowledgement{CommandResultAcknowledgement: ack}}); err != nil {
			return status.Error(codes.Unavailable, err.Error())
		}
	case *agentv1.AgentMessage_Inventory:
		// Inventory is authenticated by this stream and consumed by the inventory service in a later task.
	case *agentv1.AgentMessage_HostObservation:
		if typed.HostObservation == nil || subtle.ConstantTimeCompare([]byte(agentID), []byte(typed.HostObservation.GetAgentId())) != 1 {
			return status.Error(codes.PermissionDenied, "Host observation Agent ID does not match the session identity")
		}
		if err := s.hosts.SubmitObservation(agentID, typed.HostObservation); errors.Is(err, ErrHostObservationInvalid) {
			return status.Error(codes.InvalidArgument, "Host observation is invalid")
		}
	case *agentv1.AgentMessage_DiscoveryReport:
		if !s.registry.Supports(agentID, CapabilityDiscoveryReportACKV1, CapabilityDiscoveryPolicyAttestationV1) {
			return nil
		}
		if typed.DiscoveryReport == nil || subtle.ConstantTimeCompare([]byte(agentID), []byte(typed.DiscoveryReport.GetAgentId())) != 1 {
			s.rejectDiscoveryReport(agentID, typed.DiscoveryReport, "REPORT_IDENTITY_REJECTED")
			return nil
		}
		if err := s.discovery.SubmitDiscovery(agentID, typed.DiscoveryReport); err != nil {
			switch {
			case errors.Is(err, ErrDiscoveryObservationInvalid):
				s.rejectDiscoveryReport(agentID, typed.DiscoveryReport, "REPORT_INVALID")
				return nil
			case errors.Is(err, ErrDiscoveryObservationCapacity):
				return status.Error(codes.ResourceExhausted, "Discovery report delivery capacity is exhausted")
			default:
				return status.Error(codes.Unavailable, "Discovery report delivery is unavailable")
			}
		}
	case *agentv1.AgentMessage_PluginObservation:
		if typed.PluginObservation == nil || subtle.ConstantTimeCompare([]byte(agentID), []byte(typed.PluginObservation.GetAgentId())) != 1 {
			return status.Error(codes.PermissionDenied, "Plugin observation Agent ID does not match the session identity")
		}
		if err := s.plugins.SubmitPlugin(agentID, typed.PluginObservation); err != nil {
			if errors.Is(err, ErrPluginObservationInvalid) {
				return status.Error(codes.InvalidArgument, "Plugin observation is invalid")
			}
			return nil
		}
	case *agentv1.AgentMessage_PluginArtifactLeaseRequest:
		request := typed.PluginArtifactLeaseRequest
		if request == nil || len(request.GetRequestNonce()) != sha256.Size || !s.registry.Supports(agentID, "plugin.reconcile.v1", "plugin_reconcile.instance_descriptors.v1") {
			return status.Error(codes.InvalidArgument, "plugin artifact lease request is invalid")
		}
		response, issueErr := s.pluginArtifacts.Issue(ctx, agentID, request)
		if issueErr != nil || response == nil {
			response = &agentv1.PluginArtifactLeaseResponse{RequestNonce: append([]byte(nil), request.GetRequestNonce()...)}
		}
		if subtle.ConstantTimeCompare(response.GetRequestNonce(), request.GetRequestNonce()) != 1 {
			return status.Error(codes.Internal, "plugin artifact lease correlation failed")
		}
		if err := s.registry.enqueue(agentID, &agentv1.ServerMessage{MessageId: "plugin-artifact-lease", Message: &agentv1.ServerMessage_PluginArtifactLeaseResponse{PluginArtifactLeaseResponse: response}}); err != nil {
			return status.Error(codes.Unavailable, "plugin artifact lease delivery is unavailable")
		}
	case *agentv1.AgentMessage_CredentialLeaseRequest:
		request := typed.CredentialLeaseRequest
		if request == nil || len(request.GetRequestNonce()) != credentiallease.RequestNonceBytes || request.GetDatabaseFamily() == "" || request.GetOperationRevision() == 0 || !s.registry.Supports(agentID, "plugin.reconcile.v1", "plugin_reconcile.instance_descriptors.v1", "credential_lease.v1") {
			return status.Error(codes.InvalidArgument, "credential lease request is invalid")
		}
		session, ok := s.registry.Session(agentID)
		if !ok || session.SessionID == "" {
			return status.Error(codes.Unauthenticated, "Agent session is unavailable")
		}
		response, issueErr := s.credentials.Issue(ctx, credentiallease.AuthenticatedAgent{AgentID: agentID, SessionID: session.SessionID}, request)
		if issueErr != nil || !validCredentialLeaseResponse(response, request, s.now()) {
			clearCredentialLeaseResponse(response)
			response = &agentv1.CredentialLeaseResponse{RequestNonce: append([]byte(nil), request.GetRequestNonce()...), InstanceId: request.GetInstanceId(), AssignmentId: request.GetAssignmentId()}
		}
		if err := s.registry.enqueue(agentID, &agentv1.ServerMessage{MessageId: "credential-lease", Message: &agentv1.ServerMessage_CredentialLeaseResponse{CredentialLeaseResponse: response}}); err != nil {
			clearCredentialLeaseResponse(response)
			return status.Error(codes.Unavailable, "credential lease delivery is unavailable")
		}
	case *agentv1.AgentMessage_MetricTemplateLeaseRequest:
		request := typed.MetricTemplateLeaseRequest
		if request == nil || len(request.GetRequestNonce()) != sha256.Size || len(request.GetQueryDigest()) != sha256.Size || request.GetCommandId() == "" || request.GetAssignmentId() == "" || request.GetInstanceId() == "" || request.GetConfigurationRevision() == 0 || request.GetOperationRevision() == 0 || request.GetTemplateId() == "" || request.GetRevisionId() == "" || !s.registry.Supports(agentID, "metric_template_lease.v1") {
			return status.Error(codes.InvalidArgument, "metric template lease request is invalid")
		}
		session, ok := s.registry.Session(agentID)
		if !ok || session.SessionID == "" {
			return status.Error(codes.Unauthenticated, "Agent session is unavailable")
		}
		response, issueErr := s.metricTemplates.Issue(ctx, credentiallease.AuthenticatedAgent{AgentID: agentID, SessionID: session.SessionID}, request)
		if issueErr != nil || !validMetricTemplateLeaseResponse(response, request, s.now()) {
			clearMetricTemplateLeaseResponse(response)
			response = &agentv1.MetricTemplateLeaseResponse{RequestNonce: append([]byte(nil), request.GetRequestNonce()...), CommandId: request.GetCommandId(), AssignmentId: request.GetAssignmentId(), InstanceId: request.GetInstanceId(), TemplateId: request.GetTemplateId(), RevisionId: request.GetRevisionId(), QueryDigest: append([]byte(nil), request.GetQueryDigest()...)}
		}
		if err := s.registry.enqueue(agentID, &agentv1.ServerMessage{MessageId: "metric-template-lease", Message: &agentv1.ServerMessage_MetricTemplateLeaseResponse{MetricTemplateLeaseResponse: response}}); err != nil {
			clearMetricTemplateLeaseResponse(response)
			return status.Error(codes.Unavailable, "metric template lease delivery is unavailable")
		}
	default:
		return status.Error(codes.InvalidArgument, "unsupported Agent message for an established session")
	}
	return nil
}

func validCredentialLeaseResponse(response *agentv1.CredentialLeaseResponse, request *agentv1.CredentialLeaseRequest, now time.Time) bool {
	if response == nil || request == nil || len(response.GetRequestNonce()) != credentiallease.RequestNonceBytes || subtle.ConstantTimeCompare(response.GetRequestNonce(), request.GetRequestNonce()) != 1 || response.GetLeaseId() == "" || len(response.GetLeaseId()) > 128 || response.GetInstanceId() != request.GetInstanceId() || response.GetAssignmentId() != request.GetAssignmentId() || response.GetDatabaseFamily() != request.GetDatabaseFamily() || response.GetConfigurationRevision() != request.GetConfigurationRevision() || response.GetOperationRevision() != request.GetOperationRevision() || response.GetValidForSeconds() < uint32(credentiallease.MinimumLeaseTTL/time.Second) || response.GetValidForSeconds() > uint32(credentiallease.MaximumLeaseTTL/time.Second) || response.GetCredentialRevision() == 0 || response.GetExpiresAt() == nil || !response.GetExpiresAt().IsValid() || response.GetCredential() == nil || len(response.GetCredential().GetUsername()) > credentiallease.MaximumUsernameBytes || len(response.GetCredential().GetSecretBytes()) == 0 || len(response.GetCredential().GetSecretBytes()) > credentiallease.MaximumSecretBytes || proto.Size(response) > credentiallease.MaximumSecretBytes+(4<<10) {
		return false
	}
	return true
}

func clearCredentialLeaseResponse(response *agentv1.CredentialLeaseResponse) {
	if response == nil || response.Credential == nil {
		return
	}
	for index := range response.Credential.SecretBytes {
		response.Credential.SecretBytes[index] = 0
	}
	response.Credential.SecretBytes = nil
	response.Credential.Username = ""
}

func validMetricTemplateLeaseResponse(response *agentv1.MetricTemplateLeaseResponse, request *agentv1.MetricTemplateLeaseRequest, now time.Time) bool {
	if response == nil || request == nil || len(response.GetRequestNonce()) != sha256.Size || subtle.ConstantTimeCompare(response.GetRequestNonce(), request.GetRequestNonce()) != 1 || response.GetLeaseId() == "" || len(response.GetLeaseId()) > 128 || response.GetCommandId() != request.GetCommandId() || response.GetAssignmentId() != request.GetAssignmentId() || response.GetInstanceId() != request.GetInstanceId() || response.GetConfigurationRevision() != request.GetConfigurationRevision() || response.GetOperationRevision() != request.GetOperationRevision() || response.GetTemplateId() != request.GetTemplateId() || response.GetRevisionId() != request.GetRevisionId() || subtle.ConstantTimeCompare(response.GetQueryDigest(), request.GetQueryDigest()) != 1 || response.GetValidForSeconds() < 5 || response.GetValidForSeconds() > 60 || response.GetExpiresAt() == nil || !response.GetExpiresAt().IsValid() || !response.GetExpiresAt().AsTime().After(now.UTC()) || response.GetExpiresAt().AsTime().After(now.UTC().Add(time.Duration(response.GetValidForSeconds())*time.Second+2*time.Second)) || !validMetricTemplateDefinition(response.GetDefinition()) || proto.Size(response) > 40<<10 {
		return false
	}
	return true
}

func validMetricTemplateDefinition(value *agentv1.MetricTemplateDefinition) bool {
	return value != nil && value.GetRevision() > 0 && value.GetQueryKind() == "sql" && len(value.GetReadOnlyStatement()) > 0 && len(value.GetReadOnlyStatement()) <= 32768 && value.GetCollectionIntervalSeconds() >= 10 && value.GetCollectionIntervalSeconds() <= 86400 && value.GetTimeoutSeconds() > 0 && value.GetTimeoutSeconds() <= 30 && value.GetMaxRows() > 0 && value.GetMaxRows() <= 100 && value.GetMaxColumns() > 0 && value.GetMaxColumns() <= 32 && value.GetCardinalityLimit() > 0 && value.GetCardinalityLimit() <= 10000 && len(value.GetValueMappings()) > 0 && len(value.GetValueMappings()) <= 32 && len(value.GetLabelMappings()) <= 16
}

func clearMetricTemplateLeaseResponse(response *agentv1.MetricTemplateLeaseResponse) {
	if response == nil || response.Definition == nil {
		return
	}
	for index := range response.Definition.ReadOnlyStatement {
		response.Definition.ReadOnlyStatement[index] = 0
	}
	response.Definition.ReadOnlyStatement = nil
}

func (s *Server) rejectDiscoveryReport(agentID string, report *agentv1.DiscoveryReport, reason string) {
	if report == nil || report.GetObservationRevision() == 0 || report.GetHostId() == "" {
		return
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil {
		return
	}
	digest := sha256.Sum256(encoded)
	_ = s.registry.AcknowledgeDiscovery(agentID, &agentv1.DiscoveryReportAcknowledgement{HostId: report.GetHostId(), AgentId: agentID, ObservationRevision: report.GetObservationRevision(), ReportDigest: digest[:], Persisted: false, Retryable: false, ReasonCode: reason})
}

var _ agentv1.AgentControlServer = (*Server)(nil)
