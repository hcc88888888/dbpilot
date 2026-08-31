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
	Renewals    RenewalAuthorizer
	Provider    SecretProvider
	Clock       DatabaseClock
	Audit       AuditRecorder
	TTL         time.Duration
	MaximumLive int
	Random      io.Reader
}

type ApplicationService struct {
	authorizer          Authorizer
	renewals            RenewalAuthorizer
	provider            SecretProvider
	clock               DatabaseClock
	audit               AuditRecorder
	ttl                 time.Duration
	maximumLive         int
	random              io.Reader
	mu                  sync.Mutex
	leases              map[string]*liveLease
	issued              map[string]bool
	tombstones          map[string]nonceTombstone
	tombstoneOrder      []tombstoneOrderEntry
	tombstoneGeneration uint64
	closed              bool
}

type nonceTombstone struct {
	until      time.Time
	generation uint64
}
type tombstoneOrderEntry struct {
	key        string
	generation uint64
}

type liveLease struct {
	fingerprint    [sha256.Size]byte
	ready          chan struct{}
	lease          Lease
	err            error
	timer          *time.Timer
	expired        bool
	completed      bool
	tombstoneUntil time.Time
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
	return &ApplicationService{authorizer: config.Authorizer, renewals: config.Renewals, provider: config.Provider, clock: config.Clock, audit: config.Audit, ttl: ttl, maximumLive: maximum, random: config.Random, leases: make(map[string]*liveLease), issued: make(map[string]bool), tombstones: make(map[string]nonceTombstone)}, nil
}

func (service *ApplicationService) Lease(ctx context.Context, agent AuthenticatedAgent, request LeaseRequest) (Lease, error) {
	if ctx == nil || ctx.Err() != nil || service == nil || !validAgent(agent) || !validLeaseRequest(request) {
		return Lease{}, ErrLeaseRejected
	}
	service.mu.Lock()
	closed := service.closed
	service.mu.Unlock()
	if closed {
		return Lease{}, ErrLeaseRejected
	}
	renewalKey := agent.SessionID + "\x00" + request.AssignmentID + "\x00" + request.InstanceID
	service.mu.Lock()
	isRenewal := service.issued[renewalKey]
	service.mu.Unlock()
	authorization, err := service.authorize(ctx, agent, request, isRenewal)
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
	if service.closed {
		service.mu.Unlock()
		return Lease{}, ErrLeaseRejected
	}
	if existing := service.leases[key]; existing != nil {
		if existing.fingerprint != fingerprint {
			service.mu.Unlock()
			service.recordRejected(ctx, authorization, agent, request, now)
			return Lease{}, ErrLeaseRejected
		}
		ready := existing.ready
		service.mu.Unlock()
		select {
		case <-ready:
			service.mu.Lock()
			if existing.err != nil || existing.expired || !existing.lease.ExpiresAt.After(now) || service.leases[key] != existing {
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
	if tombstone, reused := service.tombstones[key]; reused && tombstone.until.After(now) {
		service.mu.Unlock()
		service.recordRejected(ctx, authorization, agent, request, now)
		return Lease{}, ErrLeaseRejected
	}
	if len(service.leases) >= service.maximumLive {
		service.mu.Unlock()
		service.recordRejected(ctx, authorization, agent, request, now)
		return Lease{}, ErrLeaseRejected
	}
	record := &liveLease{fingerprint: fingerprint, ready: make(chan struct{}), tombstoneUntil: now.Add(service.ttl * 3)}
	service.leases[key] = record
	service.mu.Unlock()

	credential, resolveErr := service.provider.Resolve(ctx, authorization.CredentialRef)
	if resolveErr != nil || !validCredential(credential) {
		credential.Release()
		service.failRecord(key, record)
		service.recordRejected(ctx, authorization, agent, request, now)
		return Lease{}, ErrLeaseRejected
	}
	freshAuthorization, authorizeErr := service.authorize(ctx, agent, request, isRenewal)
	finalNow, clockErr := service.clock.Now(ctx)
	if authorizeErr != nil || clockErr != nil || finalNow.IsZero() || !validAuthorization(freshAuthorization, agent, request) || leaseFingerprint(agent, request, freshAuthorization) != fingerprint {
		credential.Release()
		service.failRecord(key, record)
		service.recordRejected(ctx, freshAuthorization, agent, request, finalNow)
		return Lease{}, ErrLeaseRejected
	}
	authorization = freshAuthorization
	finalNow = finalNow.UTC()
	record.tombstoneUntil = finalNow.Add(service.ttl * 3)
	leaseIDBytes := make([]byte, 16)
	if _, err = io.ReadFull(service.random, leaseIDBytes); err != nil {
		credential.Release()
		service.failRecord(key, record)
		service.recordRejected(ctx, authorization, agent, request, now)
		return Lease{}, ErrLeaseRejected
	}
	lease := Lease{ID: hex.EncodeToString(leaseIDBytes), InstanceID: request.InstanceID, AssignmentID: request.AssignmentID, DatabaseFamily: authorization.DatabaseFamily, ConfigurationRevision: authorization.ConfigurationRevision, OperationRevision: authorization.OperationRevision, CredentialRevision: credential.Revision, ExpiresAt: finalNow.Add(service.ttl), ValidFor: service.ttl, Username: credential.Username, SecretBytes: append([]byte(nil), credential.SecretBytes...)}
	credential.Release()
	remaining := lease.ExpiresAt.Sub(finalNow)
	if remaining <= 0 {
		lease.Release()
		service.failRecord(key, record)
		service.recordRejected(ctx, authorization, agent, request, finalNow)
		return Lease{}, ErrLeaseRejected
	}
	audit := auditFor(authorization, agent, request, finalNow, AuditResultIssued, lease.CredentialRevision, LeaseIDAuditHash(lease.ID))
	if audit.Validate() != nil || service.audit.Record(ctx, audit) != nil {
		lease.Release()
		service.failRecord(key, record)
		return Lease{}, ErrLeaseRejected
	}
	service.mu.Lock()
	if service.closed || service.leases[key] != record || record.completed {
		record.err = ErrLeaseRejected
		if !record.completed {
			record.completed = true
			close(record.ready)
		}
		service.mu.Unlock()
		lease.Release()
		return Lease{}, ErrLeaseRejected
	}
	record.lease = lease.Clone()
	service.issued[renewalKey] = true
	record.completed = true
	record.timer = time.AfterFunc(remaining, func() {
		service.mu.Lock()
		if service.leases[key] == record {
			record.lease.Release()
			record.expired = true
			delete(service.leases, key)
			service.addTombstoneLocked(key, finalNow.Add(service.ttl*3))
		}
		service.mu.Unlock()
	})
	close(record.ready)
	service.mu.Unlock()
	return lease, nil
}

func (service *ApplicationService) failRecord(key string, record *liveLease) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if record.completed {
		return
	}
	record.err = ErrLeaseRejected
	if record.timer != nil {
		record.timer.Stop()
	}
	record.completed = true
	close(record.ready)
	if service.leases[key] == record {
		delete(service.leases, key)
		service.addTombstoneLocked(key, record.tombstoneUntil)
	}
}

func (service *ApplicationService) pruneLocked(now time.Time) {
	for key, tombstone := range service.tombstones {
		if !tombstone.until.After(now) {
			delete(service.tombstones, key)
		}
	}
	for key, record := range service.leases {
		select {
		case <-record.ready:
			if record.err != nil || !record.lease.ExpiresAt.After(now) {
				if record.timer != nil {
					record.timer.Stop()
				}
				record.lease.Release()
				record.expired = true
				delete(service.leases, key)
				service.addTombstoneLocked(key, now.Add(service.ttl*3))
			}
		default:
		}
	}
}

func (service *ApplicationService) Close() {
	if service == nil {
		return
	}
	service.mu.Lock()
	if service.closed {
		service.mu.Unlock()
		return
	}
	service.closed = true
	for key, record := range service.leases {
		if record.timer != nil {
			record.timer.Stop()
		}
		record.lease.Release()
		record.err = ErrLeaseRejected
		record.expired = true
		if !record.completed {
			record.completed = true
			close(record.ready)
		}
		delete(service.leases, key)
	}
	clear(service.issued)
	clear(service.tombstones)
	service.tombstoneOrder = nil
	service.mu.Unlock()
}

func (service *ApplicationService) addTombstoneLocked(key string, until time.Time) {
	service.tombstoneGeneration++
	generation := service.tombstoneGeneration
	service.tombstones[key] = nonceTombstone{until: until, generation: generation}
	service.tombstoneOrder = append(service.tombstoneOrder, tombstoneOrderEntry{key: key, generation: generation})
	for len(service.tombstoneOrder) > service.maximumLive*4 {
		oldest := service.tombstoneOrder[0]
		service.tombstoneOrder = service.tombstoneOrder[1:]
		if current, exists := service.tombstones[oldest.key]; exists && current.generation == oldest.generation {
			delete(service.tombstones, oldest.key)
		}
	}
}

func (service *ApplicationService) authorize(ctx context.Context, agent AuthenticatedAgent, request LeaseRequest, renewal bool) (Authorization, error) {
	if renewal && service.renewals != nil {
		return service.renewals.AuthorizeRenewal(ctx, agent, request)
	}
	return service.authorizer.Authorize(ctx, agent, request)
}

func (service *ApplicationService) recordRejected(ctx context.Context, authorization Authorization, agent AuthenticatedAgent, request LeaseRequest, now time.Time) {
	if now.IsZero() {
		clockNow, err := service.clock.Now(ctx)
		if err != nil {
			return
		}
		now = clockNow.UTC()
	}
	record := auditFor(authorization, agent, request, now, AuditResultRejected, 0, "")
	if record.Validate() == nil {
		_ = service.audit.Record(ctx, record)
	}
}

func auditFor(authorization Authorization, agent AuthenticatedAgent, request LeaseRequest, now time.Time, result AuditResult, credentialRevision uint64, leaseIDHash string) AuditRecord {
	return AuditRecord{TenantID: authorization.Scope.TenantID, ProjectID: authorization.Scope.ProjectID, AgentID: agent.AgentID, HostID: authorization.HostID, AssignmentID: request.AssignmentID, InstanceID: request.InstanceID, ConfigurationRevision: authorization.ConfigurationRevision, OperationRevision: authorization.OperationRevision, InstanceRevision: authorization.InstanceRevision, CredentialRevision: credentialRevision, LeaseIDHash: leaseIDHash, Result: result, ExpiryClass: ExpiryClassShort, OccurredAt: now.UTC()}
}

func validAgent(value AuthenticatedAgent) bool {
	return identifier.MatchString(value.AgentID) && identifier.MatchString(value.SessionID)
}

func validLeaseRequest(value LeaseRequest) bool {
	return len(value.Nonce) == RequestNonceBytes && identifier.MatchString(value.InstanceID) && identifier.MatchString(value.AssignmentID) && familyIdentifier.MatchString(value.DatabaseFamily) && value.ConfigurationRevision > 0 && value.OperationRevision > 0
}

func validAuthorization(value Authorization, agent AuthenticatedAgent, request LeaseRequest) bool {
	return value.Scope.Validate() == nil && identifier.MatchString(value.HostID) && value.AgentID == agent.AgentID && value.AssignmentID == request.AssignmentID && value.DatabaseFamily == request.DatabaseFamily && value.ConfigurationRevision == request.ConfigurationRevision && value.OperationRevision == request.OperationRevision && value.InstanceID == request.InstanceID && value.InstanceRevision > 0 && value.ManagementStatus != "" && value.ManagementStatus != "retired" && !value.AuthorizedAt.IsZero()
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
	for _, value := range []string{agent.AgentID, agent.SessionID, request.InstanceID, request.AssignmentID, request.DatabaseFamily, authorization.Scope.TenantID, authorization.Scope.ProjectID, authorization.HostID, authorization.DatabaseFamily, authorization.CredentialRef, authorization.TLSRef, authorization.ManagementStatus} {
		writeFingerprint(value)
	}
	for _, value := range []uint64{request.ConfigurationRevision, request.OperationRevision, authorization.OperationRevision, authorization.InstanceRevision} {
		writeRevision(value)
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

var _ Service = (*ApplicationService)(nil)
