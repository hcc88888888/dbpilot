package credentiallease

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Authorizer  Authorizer
	Provider    SecretProvider
	Clock       DatabaseClock
	Audit       AuditRecorder
	TTL         time.Duration
	MaximumLive int
	Random      io.Reader
}

type ApplicationService struct {
	authorizer  Authorizer
	provider    SecretProvider
	clock       DatabaseClock
	audit       AuditRecorder
	ttl         time.Duration
	maximumLive int
	random      io.Reader
	mu          sync.Mutex
	leases      map[string]*liveLease
}

type liveLease struct {
	fingerprint [sha256.Size]byte
	ready       chan struct{}
	lease       Lease
	err         error
	timer       *time.Timer
}

func NewService(config Config) (*ApplicationService, error) {
	if config.Authorizer == nil || config.Provider == nil || config.Clock == nil || config.Audit == nil || config.Random == nil {
		return nil, ErrLeaseRejected
	}
	ttl := config.TTL
	if ttl == 0 {
		ttl = DefaultLeaseTTL
	}
	if ttl < MinimumLeaseTTL {
		ttl = MinimumLeaseTTL
	}
	if ttl > MaximumLeaseTTL {
		ttl = MaximumLeaseTTL
	}
	maximum := config.MaximumLive
	if maximum == 0 {
		maximum = DefaultMaximumLive
	}
	if maximum < 1 || maximum > DefaultMaximumLive {
		return nil, ErrLeaseRejected
	}
	return &ApplicationService{authorizer: config.Authorizer, provider: config.Provider, clock: config.Clock, audit: config.Audit, ttl: ttl, maximumLive: maximum, random: config.Random, leases: make(map[string]*liveLease)}, nil
}

func (service *ApplicationService) Lease(ctx context.Context, agent AuthenticatedAgent, request LeaseRequest) (Lease, error) {
	if ctx == nil || ctx.Err() != nil || service == nil || !validAgent(agent) || !validLeaseRequest(request) {
		return Lease{}, ErrLeaseRejected
	}
	authorization, err := service.authorizer.Authorize(ctx, agent, request)
	if err != nil || !validAuthorization(authorization, agent, request) || !strictSecretReference(authorization.CredentialRef) || authorization.TLSRef != "" && !strictSecretReference(authorization.TLSRef) {
		service.recordRejected(ctx, authorization, agent, request, time.Time{})
		return Lease{}, ErrLeaseRejected
	}
	now, err := service.clock.Now(ctx)
	if err != nil || now.IsZero() {
		service.recordRejected(ctx, authorization, agent, request, time.Time{})
		return Lease{}, ErrLeaseRejected
	}
	now = now.UTC()
	fingerprint := leaseFingerprint(agent, request, authorization)
	key := agent.SessionID + "\x00" + string(request.Nonce)

	service.mu.Lock()
	service.pruneLocked(now)
	if existing := service.leases[key]; existing != nil {
		if existing.fingerprint != fingerprint {
			if existing.timer != nil {
				existing.timer.Stop()
			}
			existing.lease.Release()
			delete(service.leases, key)
			service.mu.Unlock()
			service.recordRejected(ctx, authorization, agent, request, now)
			return Lease{}, ErrLeaseRejected
		}
		ready := existing.ready
		service.mu.Unlock()
		select {
		case <-ready:
			service.mu.Lock()
			if existing.err != nil || !existing.lease.ExpiresAt.After(now) || service.leases[key] != existing {
				service.mu.Unlock()
				return Lease{}, ErrLeaseRejected
			}
			lease := existing.lease.Clone()
			service.mu.Unlock()
			return lease, nil
		case <-ctx.Done():
			return Lease{}, ErrLeaseRejected
		}
	}
	if len(service.leases) >= service.maximumLive {
		service.mu.Unlock()
		service.recordRejected(ctx, authorization, agent, request, now)
		return Lease{}, ErrLeaseRejected
	}
	record := &liveLease{fingerprint: fingerprint, ready: make(chan struct{})}
	service.leases[key] = record
	service.mu.Unlock()

	credential, resolveErr := service.provider.Resolve(ctx, authorization.CredentialRef)
	if resolveErr != nil || !validCredential(credential) {
		credential.Release()
		service.failRecord(key, record)
		service.recordRejected(ctx, authorization, agent, request, now)
		return Lease{}, ErrLeaseRejected
	}
	leaseIDBytes := make([]byte, 16)
	if _, err = io.ReadFull(service.random, leaseIDBytes); err != nil {
		credential.Release()
		service.failRecord(key, record)
		service.recordRejected(ctx, authorization, agent, request, now)
		return Lease{}, ErrLeaseRejected
	}
	lease := Lease{ID: hex.EncodeToString(leaseIDBytes), InstanceID: request.InstanceID, AssignmentID: request.AssignmentID, DatabaseFamily: authorization.DatabaseFamily, ConfigurationRevision: authorization.ConfigurationRevision, OperationRevision: authorization.OperationRevision, CredentialRevision: credential.Revision, ExpiresAt: now.Add(service.ttl), Username: credential.Username, SecretBytes: append([]byte(nil), credential.SecretBytes...)}
	credential.Release()
	audit := auditFor(authorization, agent, request, now, AuditResultIssued, lease.CredentialRevision)
	if audit.Validate() != nil || service.audit.Record(ctx, audit) != nil {
		lease.Release()
		service.failRecord(key, record)
		return Lease{}, ErrLeaseRejected
	}
	service.mu.Lock()
	if service.leases[key] != record {
		record.err = ErrLeaseRejected
		close(record.ready)
		service.mu.Unlock()
		lease.Release()
		return Lease{}, ErrLeaseRejected
	}
	record.lease = lease.Clone()
	record.timer = time.AfterFunc(service.ttl, func() {
		service.mu.Lock()
		if service.leases[key] == record {
			record.lease.Release()
			delete(service.leases, key)
		}
		service.mu.Unlock()
	})
	close(record.ready)
	service.mu.Unlock()
	return lease, nil
}

func (service *ApplicationService) failRecord(key string, record *liveLease) {
	service.mu.Lock()
	record.err = ErrLeaseRejected
	if record.timer != nil {
		record.timer.Stop()
	}
	if service.leases[key] == record {
		delete(service.leases, key)
	}
	close(record.ready)
	service.mu.Unlock()
}

func (service *ApplicationService) pruneLocked(now time.Time) {
	for key, record := range service.leases {
		select {
		case <-record.ready:
			if record.err != nil || !record.lease.ExpiresAt.After(now) {
				if record.timer != nil {
					record.timer.Stop()
				}
				record.lease.Release()
				delete(service.leases, key)
			}
		default:
		}
	}
}

func (service *ApplicationService) recordRejected(ctx context.Context, authorization Authorization, agent AuthenticatedAgent, request LeaseRequest, now time.Time) {
	if now.IsZero() {
		clockNow, err := service.clock.Now(ctx)
		if err != nil {
			return
		}
		now = clockNow.UTC()
	}
	record := auditFor(authorization, agent, request, now, AuditResultRejected, 0)
	if record.Validate() == nil {
		_ = service.audit.Record(ctx, record)
	}
}

func auditFor(authorization Authorization, agent AuthenticatedAgent, request LeaseRequest, now time.Time, result AuditResult, credentialRevision uint64) AuditRecord {
	return AuditRecord{TenantID: authorization.Scope.TenantID, ProjectID: authorization.Scope.ProjectID, AgentID: agent.AgentID, HostID: authorization.HostID, AssignmentID: request.AssignmentID, InstanceID: request.InstanceID, ConfigurationRevision: authorization.ConfigurationRevision, OperationRevision: authorization.OperationRevision, InstanceRevision: authorization.InstanceRevision, CredentialRevision: credentialRevision, Result: result, ExpiryClass: ExpiryClassShort, OccurredAt: now.UTC()}
}

func validAgent(value AuthenticatedAgent) bool {
	return identifier.MatchString(value.AgentID) && identifier.MatchString(value.SessionID)
}

func validLeaseRequest(value LeaseRequest) bool {
	return len(value.Nonce) == RequestNonceBytes && identifier.MatchString(value.InstanceID) && identifier.MatchString(value.AssignmentID) && value.ConfigurationRevision > 0
}

func validAuthorization(value Authorization, agent AuthenticatedAgent, request LeaseRequest) bool {
	return value.Scope.Validate() == nil && identifier.MatchString(value.HostID) && value.AgentID == agent.AgentID && value.AssignmentID == request.AssignmentID && familyIdentifier.MatchString(value.DatabaseFamily) && value.ConfigurationRevision == request.ConfigurationRevision && value.OperationRevision > 0 && value.InstanceID == request.InstanceID && value.InstanceRevision > 0 && value.ManagementStatus != "" && value.ManagementStatus != "retired" && !value.AuthorizedAt.IsZero()
}

func validCredential(value Credential) bool {
	return value.Revision > 0 && len(value.Username) <= MaximumUsernameBytes && strings.TrimSpace(value.Username) == value.Username && !strings.ContainsAny(value.Username, "\x00\r\n") && len(value.SecretBytes) > 0 && len(value.SecretBytes) <= MaximumSecretBytes
}

func strictSecretReference(value string) bool {
	if value == "" || len(value) > 512 || strings.Contains(value, "\\") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "secret" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Opaque == "" && parsed.Path != "" && parsed.Path != "/" && !strings.Contains(parsed.Host, ":") && path.Clean(parsed.Path) == parsed.Path && !strings.Contains(parsed.Path, "..")
}

func leaseFingerprint(agent AuthenticatedAgent, request LeaseRequest, authorization Authorization) [sha256.Size]byte {
	hash := sha256.New()
	writeFingerprint := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	writeRevision := func(value uint64) {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value)
		_, _ = hash.Write(encoded[:])
	}
	for _, value := range []string{agent.AgentID, agent.SessionID, request.InstanceID, request.AssignmentID, authorization.Scope.TenantID, authorization.Scope.ProjectID, authorization.HostID, authorization.DatabaseFamily, authorization.CredentialRef, authorization.TLSRef, authorization.ManagementStatus} {
		writeFingerprint(value)
	}
	for _, value := range []uint64{request.ConfigurationRevision, authorization.OperationRevision, authorization.InstanceRevision} {
		writeRevision(value)
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

var _ Service = (*ApplicationService)(nil)
