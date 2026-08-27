package agentcontrol

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const ProtocolVersion = "1"

type Observer interface {
	Connected(context.Context, SessionInfo)
	Heartbeat(context.Context, string, *agentv1.Heartbeat)
	Acknowledged(context.Context, string, *agentv1.CommandAcknowledgement)
	Progress(context.Context, string, *agentv1.CommandProgress)
	Result(context.Context, string, *agentv1.CommandResult)
}

type noopObserver struct{}

func (noopObserver) Connected(context.Context, SessionInfo)                                {}
func (noopObserver) Heartbeat(context.Context, string, *agentv1.Heartbeat)                 {}
func (noopObserver) Acknowledged(context.Context, string, *agentv1.CommandAcknowledgement) {}
func (noopObserver) Progress(context.Context, string, *agentv1.CommandProgress)            {}
func (noopObserver) Result(context.Context, string, *agentv1.CommandResult)                {}

type Server struct {
	agentv1.UnimplementedAgentControlServer
	registry *Registry
	observer Observer
	now      func() time.Time
}

func NewServer(registry *Registry, observer Observer) *Server {
	if registry == nil {
		registry = NewRegistry(64)
	}
	if observer == nil {
		observer = noopObserver{}
	}
	return &Server{registry: registry, observer: observer, now: time.Now}
}

func (s *Server) Connect(stream agentv1.AgentControl_ConnectServer) error {
	agentID, err := verifiedAgentID(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
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
	if err := s.registry.register(agentID, hello.GetCapabilities(), hello.GetActiveCommands(), cancel); err != nil {
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
		Message: &agentv1.ServerMessage_HelloAck{HelloAck: &agentv1.HelloAck{ProtocolVersion: ProtocolVersion, Capabilities: append([]string(nil), current.capabilityList...), ServerTime: timestamppb.New(s.now())}},
	}
	if err := stream.Send(ack); err != nil {
		return err
	}
	s.observer.Connected(sessionContext, sessionSnapshot(current))

	receiveErrors := make(chan error, 1)
	go func() {
		for {
			message, receiveErr := stream.Recv()
			if receiveErr != nil {
				receiveErrors <- receiveErr
				return
			}
			if handleErr := s.handleAgentMessage(sessionContext, agentID, message); handleErr != nil {
				receiveErrors <- handleErr
				return
			}
		}
	}()

	for {
		select {
		case message := <-current.send:
			message.SentAt = timestamppb.New(s.now())
			if err := stream.Send(message); err != nil {
				return err
			}
		case receiveErr := <-receiveErrors:
			if errors.Is(receiveErr, io.EOF) {
				return nil
			}
			return receiveErr
		case <-sessionContext.Done():
			return sessionContext.Err()
		}
	}
}

func (s *Server) handleAgentMessage(ctx context.Context, agentID string, message *agentv1.AgentMessage) error {
	if message == nil {
		return status.Error(codes.InvalidArgument, "Agent message is required")
	}
	switch typed := message.GetMessage().(type) {
	case *agentv1.AgentMessage_Heartbeat:
		if typed.Heartbeat == nil || subtle.ConstantTimeCompare([]byte(agentID), []byte(typed.Heartbeat.GetAgentId())) != 1 {
			return status.Error(codes.PermissionDenied, "heartbeat Agent ID does not match the session identity")
		}
		s.registry.renew(agentID, typed.Heartbeat, s.now())
		s.observer.Heartbeat(ctx, agentID, typed.Heartbeat)
	case *agentv1.AgentMessage_CommandAcknowledgement:
		if typed.CommandAcknowledgement == nil {
			return status.Error(codes.InvalidArgument, "command acknowledgement is required")
		}
		s.observer.Acknowledged(ctx, agentID, typed.CommandAcknowledgement)
	case *agentv1.AgentMessage_CommandProgress:
		if typed.CommandProgress == nil {
			return status.Error(codes.InvalidArgument, "command progress is required")
		}
		s.observer.Progress(ctx, agentID, typed.CommandProgress)
	case *agentv1.AgentMessage_CommandResult:
		if typed.CommandResult == nil {
			return status.Error(codes.InvalidArgument, "command result is required")
		}
		s.observer.Result(ctx, agentID, typed.CommandResult)
	case *agentv1.AgentMessage_Inventory:
		// Inventory is authenticated by this stream and consumed by the inventory service in a later task.
	default:
		return status.Error(codes.InvalidArgument, "unsupported Agent message for an established session")
	}
	return nil
}

func sessionSnapshot(current *session) SessionInfo {
	leasing := make(map[string]time.Time, len(current.leases))
	for commandID, deadline := range current.leases {
		leasing[commandID] = deadline
	}
	return SessionInfo{AgentID: current.agentID, Capabilities: append([]string(nil), current.capabilityList...), ActiveCommands: cloneRecoveryStates(current.active), LastHeartbeat: current.lastHeartbeat, Leases: leasing}
}

var _ agentv1.AgentControlServer = (*Server)(nil)
