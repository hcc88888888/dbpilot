package metrictemplate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

const (
	LeaseNonceBytes      = 32
	DefaultLeaseTTL      = 30 * time.Second
	MaximumLeaseTTL      = time.Minute
	DefaultMaximumLeases = 4096
)

type AuthenticatedAgent struct{ AgentID, SessionID string }

type LeaseRequest struct {
	Nonce                 []byte
	CommandID             string
	AssignmentID          string
	InstanceID            string
	ConfigurationRevision uint64
	OperationRevision     uint64
	TemplateID            string
	RevisionID            string
	QueryDigest           string
}

type LeaseDefinition struct {
	Revision                  uint64
	StatementBytes            []byte
	CollectionIntervalSeconds int
	TimeoutSeconds            int
	MaxRows                   int
	MaxColumns                int
	CardinalityLimit          int
	ValueMappings             []ValueMapping
	LabelMappings             []LabelMapping
}

func (value LeaseDefinition) Clone() LeaseDefinition {
	value.StatementBytes = append([]byte(nil), value.StatementBytes...)
	value.ValueMappings = append([]ValueMapping(nil), value.ValueMappings...)
	value.LabelMappings = append([]LabelMapping(nil), value.LabelMappings...)
	return value
}
func (value *LeaseDefinition) Release() {
	if value == nil {
		return
	}
	zeroBytes(value.StatementBytes)
	value.StatementBytes = nil
	value.ValueMappings = nil
	value.LabelMappings = nil
}

type LeaseAuthorization struct {
	Scope                 platformscope.Scope
	HostID                string
	AgentID               string
	AssignmentID          string
	InstanceID            string
	ConfigurationRevision uint64
	OperationRevision     uint64
	TemplateID            string
	RevisionID            string
	QueryDigest           string
	Definition            LeaseDefinition
	Trial                 bool
	AuthorizedAt          time.Time
}

type MetricTemplateLeaseAuthorizer interface {
	AuthorizeMetricTemplateLease(context.Context, AuthenticatedAgent, LeaseRequest) (LeaseAuthorization, error)
}

type LeaseResult string

const (
	LeaseIssued   LeaseResult = "issued"
	LeaseRejected LeaseResult = "rejected"
)

type LeaseAudit struct {
	Scope                                                                                     platformscope.Scope
	AgentID, HostID, AssignmentID, InstanceID, CommandID, TemplateID, RevisionID, QueryDigest string
	ConfigurationRevision, OperationRevision                                                  uint64
	Trial                                                                                     bool
	Result                                                                                    LeaseResult
	OccurredAt                                                                                time.Time
}

func (value LeaseAudit) Validate() error {
	if value.Scope.Validate() != nil || !idPattern.MatchString(value.AgentID) || !idPattern.MatchString(value.HostID) || !idPattern.MatchString(value.AssignmentID) || !idPattern.MatchString(value.InstanceID) || !idPattern.MatchString(value.CommandID) || !templateIDPattern.MatchString(value.TemplateID) || !idPattern.MatchString(value.RevisionID) || !digestPattern.MatchString(value.QueryDigest) || value.ConfigurationRevision == 0 || value.OperationRevision == 0 || (value.Result != LeaseIssued && value.Result != LeaseRejected) || !validUTC(value.OccurredAt) {
		return ErrInvalid
	}
	return nil
}

type LeaseAuditRecorder interface {
	Record(context.Context, LeaseAudit) error
}

type LeaseConfig struct {
	Authorizer  MetricTemplateLeaseAuthorizer
	Audit       LeaseAuditRecorder
	Now         func() time.Time
	TTL         time.Duration
	MaximumLive int
}
type MetricTemplateLease struct {
	ID                                                            string
	AssignmentID, InstanceID, TemplateID, RevisionID, QueryDigest string
	ConfigurationRevision, OperationRevision                      uint64
	ExpiresAt                                                     time.Time
	ValidFor                                                      time.Duration
	Trial                                                         bool
	Definition                                                    LeaseDefinition
}

func (value MetricTemplateLease) Clone() MetricTemplateLease {
	value.Definition = value.Definition.Clone()
	return value
}
func (value *MetricTemplateLease) Release() {
	if value == nil {
		return
	}
	value.Definition.Release()
}

type liveTemplateLease struct {
	fingerprint [sha256.Size]byte
	lease       MetricTemplateLease
	timer       *time.Timer
}
type LeaseService struct {
	authorizer MetricTemplateLeaseAuthorizer
	audit      LeaseAuditRecorder
	now        func() time.Time
	ttl        time.Duration
	maximum    int
	mu         sync.Mutex
	live       map[string]*liveTemplateLease
	closed     bool
}

func NewLeaseService(config LeaseConfig) (*LeaseService, error) {
	if config.Authorizer == nil || config.Audit == nil {
		return nil, ErrLeaseRejected
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	ttl := config.TTL
	if ttl == 0 {
		ttl = DefaultLeaseTTL
	}
	if ttl < 5*time.Second || ttl > MaximumLeaseTTL {
		return nil, ErrLeaseRejected
	}
	maximum := config.MaximumLive
	if maximum == 0 {
		maximum = DefaultMaximumLeases
	}
	if maximum < 1 || maximum > DefaultMaximumLeases {
		return nil, ErrLeaseRejected
	}
	return &LeaseService{authorizer: config.Authorizer, audit: config.Audit, now: config.Now, ttl: ttl, maximum: maximum, live: map[string]*liveTemplateLease{}}, nil
}

func (service *LeaseService) Issue(ctx context.Context, agent AuthenticatedAgent, request LeaseRequest) (MetricTemplateLease, error) {
	if ctx == nil || ctx.Err() != nil || service == nil || !validLeaseAgent(agent) || !validTemplateLeaseRequest(request) {
		return MetricTemplateLease{}, ErrLeaseRejected
	}
	authorization, err := service.authorizer.AuthorizeMetricTemplateLease(ctx, agent, request)
	now := service.now().UTC()
	if err != nil || !validLeaseAuthorization(authorization, agent, request) || DefinitionDigest(string(authorization.Definition.StatementBytes)) != request.QueryDigest {
		authorization.Definition.Release()
		service.record(ctx, authorization, agent, request, LeaseRejected, now)
		return MetricTemplateLease{}, ErrLeaseRejected
	}
	key := agent.SessionID + "\x00" + hex.EncodeToString(request.Nonce)
	fingerprint := templateLeaseFingerprint(agent, request)
	service.mu.Lock()
	if service.closed {
		service.mu.Unlock()
		authorization.Definition.Release()
		return MetricTemplateLease{}, ErrLeaseRejected
	}
	if existing := service.live[key]; existing != nil {
		if subtle.ConstantTimeCompare(existing.fingerprint[:], fingerprint[:]) != 1 || !existing.lease.ExpiresAt.After(now) {
			service.mu.Unlock()
			authorization.Definition.Release()
			service.record(ctx, authorization, agent, request, LeaseRejected, now)
			return MetricTemplateLease{}, ErrLeaseRejected
		}
		lease := existing.lease.Clone()
		service.mu.Unlock()
		authorization.Definition.Release()
		return lease, nil
	}
	if len(service.live) >= service.maximum {
		service.mu.Unlock()
		authorization.Definition.Release()
		service.record(ctx, authorization, agent, request, LeaseRejected, now)
		return MetricTemplateLease{}, ErrLeaseRejected
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		service.mu.Unlock()
		authorization.Definition.Release()
		return MetricTemplateLease{}, ErrLeaseRejected
	}
	lease := MetricTemplateLease{ID: hex.EncodeToString(idBytes), AssignmentID: request.AssignmentID, InstanceID: request.InstanceID, TemplateID: request.TemplateID, RevisionID: request.RevisionID, QueryDigest: request.QueryDigest, ConfigurationRevision: request.ConfigurationRevision, OperationRevision: request.OperationRevision, ExpiresAt: now.Add(service.ttl), ValidFor: service.ttl, Trial: authorization.Trial, Definition: authorization.Definition.Clone()}
	record := &liveTemplateLease{fingerprint: fingerprint, lease: lease.Clone()}
	service.live[key] = record
	service.mu.Unlock()
	authorization.Definition.Release()
	audit := leaseAudit(authorization, agent, request, LeaseIssued, now)
	if audit.Validate() != nil || service.audit.Record(ctx, audit) != nil {
		service.mu.Lock()
		if service.live[key] == record {
			delete(service.live, key)
			record.lease.Release()
		}
		service.mu.Unlock()
		lease.Release()
		return MetricTemplateLease{}, ErrLeaseRejected
	}
	record.timer = time.AfterFunc(service.ttl, func() {
		service.mu.Lock()
		if service.live[key] == record {
			delete(service.live, key)
			record.lease.Release()
		}
		service.mu.Unlock()
	})
	return lease, nil
}

func (service *LeaseService) record(ctx context.Context, authorization LeaseAuthorization, agent AuthenticatedAgent, request LeaseRequest, result LeaseResult, at time.Time) {
	audit := leaseAudit(authorization, agent, request, result, at)
	if audit.Validate() == nil {
		_ = service.audit.Record(ctx, audit)
	}
}
func leaseAudit(authorization LeaseAuthorization, agent AuthenticatedAgent, request LeaseRequest, result LeaseResult, at time.Time) LeaseAudit {
	return LeaseAudit{Scope: authorization.Scope, AgentID: agent.AgentID, HostID: authorization.HostID, AssignmentID: request.AssignmentID, InstanceID: request.InstanceID, CommandID: request.CommandID, TemplateID: request.TemplateID, RevisionID: request.RevisionID, QueryDigest: request.QueryDigest, ConfigurationRevision: request.ConfigurationRevision, OperationRevision: request.OperationRevision, Trial: authorization.Trial, Result: result, OccurredAt: at}
}
func (service *LeaseService) Close() {
	if service == nil {
		return
	}
	service.mu.Lock()
	if service.closed {
		service.mu.Unlock()
		return
	}
	service.closed = true
	for key, record := range service.live {
		if record.timer != nil {
			record.timer.Stop()
		}
		record.lease.Release()
		delete(service.live, key)
	}
	service.mu.Unlock()
}

func validLeaseAgent(value AuthenticatedAgent) bool {
	return idPattern.MatchString(value.AgentID) && idPattern.MatchString(value.SessionID)
}
func validTemplateLeaseRequest(value LeaseRequest) bool {
	return len(value.Nonce) == LeaseNonceBytes && idPattern.MatchString(value.CommandID) && idPattern.MatchString(value.AssignmentID) && idPattern.MatchString(value.InstanceID) && value.ConfigurationRevision > 0 && value.OperationRevision > 0 && templateIDPattern.MatchString(value.TemplateID) && idPattern.MatchString(value.RevisionID) && digestPattern.MatchString(value.QueryDigest)
}
func validLeaseAuthorization(value LeaseAuthorization, agent AuthenticatedAgent, request LeaseRequest) bool {
	return value.Scope.Validate() == nil && idPattern.MatchString(value.HostID) && value.AgentID == agent.AgentID && value.AssignmentID == request.AssignmentID && value.InstanceID == request.InstanceID && value.ConfigurationRevision == request.ConfigurationRevision && value.OperationRevision == request.OperationRevision && value.TemplateID == request.TemplateID && value.RevisionID == request.RevisionID && value.QueryDigest == request.QueryDigest && validUTC(value.AuthorizedAt) && value.Definition.Revision > 0 && len(value.Definition.StatementBytes) > 0 && len(value.Definition.StatementBytes) <= MaximumStatementBytes && value.Definition.CollectionIntervalSeconds >= 10 && value.Definition.CollectionIntervalSeconds <= 86400 && value.Definition.TimeoutSeconds >= 1 && value.Definition.TimeoutSeconds <= 30 && value.Definition.MaxRows >= 1 && value.Definition.MaxRows <= 100 && value.Definition.MaxColumns >= 1 && value.Definition.MaxColumns <= 32 && value.Definition.CardinalityLimit >= 1 && value.Definition.CardinalityLimit <= 10000 && len(value.Definition.ValueMappings) > 0 && len(value.Definition.ValueMappings) <= MaximumValueMappings && len(value.Definition.LabelMappings) <= MaximumLabelMappings
}
func templateLeaseFingerprint(agent AuthenticatedAgent, request LeaseRequest) [sha256.Size]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%s\x00%s\x00%s", agent.AgentID, agent.SessionID, request.CommandID, request.AssignmentID, request.ConfigurationRevision, request.OperationRevision, request.InstanceID, request.TemplateID, request.RevisionID) + "\x00" + request.QueryDigest))
}
func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
