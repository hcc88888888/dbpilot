// Package idempotency provides the durable claim/complete boundary for scoped
// HTTP write operations.
package idempotency

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

const DefaultTTL = 24 * time.Hour
const maximumReconciliationBytes = 64 << 10

var (
	ErrInvalid           = errors.New("invalid idempotency request")
	ErrKeyConflict       = errors.New("idempotency key reused with a different request")
	ErrInProgress        = errors.New("idempotent request is already processing")
	ErrNotClaimed        = errors.New("idempotency claim is unavailable")
	ErrOwnershipConflict = errors.New("idempotency claim owner does not match")
)

var fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var ownerPattern = regexp.MustCompile(`^owner-[0-9a-f]{64}$`)

type State string

const (
	StateProcessing          State = "processing"
	StateSideEffectCommitted State = "side_effect_committed"
	StateAudited             State = "audited"
	StateCompleted           State = "completed"
)

type Key struct {
	Scope          platformscope.Scope
	Actor          string
	OperationID    string
	IdempotencyKey string
}

type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

type Claim struct {
	Claimed        bool
	OwnerToken     string
	State          State
	CreatedAt      time.Time
	Response       *Response
	Reconciliation []byte
}

type ReconcileFunc func(context.Context, Response, []byte) error

// ProcessingClaim is the immutable fence exposed only to an operation-specific
// recovery callback. Possessing it does not reclaim or replace an unknown
// processing owner.
type ProcessingClaim struct {
	OwnerToken     string
	CreatedAt      time.Time
	Reconciliation []byte
	Response       *Response
}

type RecoverProcessingFunc func(context.Context, ProcessingClaim) (Response, error)

type ClaimRequest struct {
	Key               Key
	Fingerprint       string
	OwnerToken        string
	Reconciliation    []byte
	RecoverProcessing bool
	Now               time.Time
	ExpiresAt         time.Time
}

type Store interface {
	Claim(context.Context, ClaimRequest) (Claim, error)
	CommitSideEffect(context.Context, Key, string, string, Response, []byte, time.Time) (Response, error)
	MarkAudited(context.Context, Key, string, string, time.Time) error
	Complete(context.Context, Key, string, string, Response, time.Time) (Response, error)
	Abort(context.Context, Key, string, string) error
}

type incompleteSideEffectStore interface {
	RepairIncompleteSideEffect(context.Context, Key, string, string, Response, []byte, time.Time) (Response, error)
}

type Service struct {
	store    Store
	now      func() time.Time
	ttl      time.Duration
	newOwner func() (string, error)
}

func NewService(store Store) *Service {
	return &Service{store: store, now: time.Now, ttl: DefaultTTL, newOwner: newOwnerToken}
}

func (service *Service) Begin(ctx context.Context, key Key, fingerprint string, reconcile ReconcileFunc) (Claim, error) {
	return service.begin(ctx, key, fingerprint, nil, reconcile, nil, false)
}

// BeginRecoverable persists the original reconciliation payload with the
// claim. An exact retry may repair a processing row only through recover;
// legacy/unknown processing rows without that payload remain fenced.
func (service *Service) BeginRecoverable(ctx context.Context, key Key, fingerprint string, reconciliation []byte, reconcile ReconcileFunc, recover RecoverProcessingFunc) (Claim, error) {
	if validateReconciliation(reconciliation) != nil || recover == nil {
		return Claim{}, ErrInvalid
	}
	return service.begin(ctx, key, fingerprint, reconciliation, reconcile, recover, false)
}

// BeginUnreturnedRecoverable is for one-time secret responses that are never
// persisted. If a prior handler could not finish its public marker, recover
// fences and replaces the now-unreachable secret before any 201 is returned.
func (service *Service) BeginUnreturnedRecoverable(ctx context.Context, key Key, fingerprint string, reconciliation []byte, reconcile ReconcileFunc, recover RecoverProcessingFunc) (Claim, error) {
	if validateReconciliation(reconciliation) != nil || recover == nil {
		return Claim{}, ErrInvalid
	}
	return service.begin(ctx, key, fingerprint, reconciliation, reconcile, recover, true)
}

func (service *Service) begin(ctx context.Context, key Key, fingerprint string, reconciliation []byte, reconcile ReconcileFunc, recover RecoverProcessingFunc, recoverIncomplete bool) (Claim, error) {
	if service == nil || service.store == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) || reconcile == nil {
		return Claim{}, ErrInvalid
	}
	now := service.currentTime()
	ttl := service.ttl
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	ownerFactory := service.newOwner
	if ownerFactory == nil {
		ownerFactory = newOwnerToken
	}
	owner, err := ownerFactory()
	if err != nil || !ownerPattern.MatchString(owner) {
		return Claim{}, ErrInvalid
	}
	claim, err := service.store.Claim(ctx, ClaimRequest{
		Key: key, Fingerprint: fingerprint, OwnerToken: owner,
		Reconciliation: append([]byte(nil), reconciliation...), RecoverProcessing: recover != nil,
		Now: now, ExpiresAt: now.Add(ttl),
	})
	if err != nil {
		return Claim{}, err
	}
	if claim.Claimed {
		if claim.OwnerToken != owner || claim.State != StateProcessing || claim.Response != nil || claim.CreatedAt.IsZero() || claim.CreatedAt.Before(now.Add(-time.Second)) || claim.CreatedAt.After(now.Add(time.Second)) || !bytesEqual(claim.Reconciliation, reconciliation) {
			return Claim{}, ErrInvalid
		}
		claim.Reconciliation = append([]byte(nil), claim.Reconciliation...)
		return claim, nil
	}
	if claim.State == StateProcessing {
		storedReconciliation := append([]byte(nil), claim.Reconciliation...)
		if recover == nil {
			return Claim{}, ErrInProgress
		}
		if !ownerPattern.MatchString(claim.OwnerToken) || claim.CreatedAt.IsZero() || validateReconciliation(storedReconciliation) != nil {
			return Claim{}, ErrInProgress
		}
		response, recoverErr := recover(ctx, ProcessingClaim{OwnerToken: claim.OwnerToken, CreatedAt: claim.CreatedAt.UTC(), Reconciliation: storedReconciliation})
		if recoverErr != nil {
			return Claim{}, recoverErr
		}
		completed, completeErr := service.Complete(ctx, key, fingerprint, claim.OwnerToken, response, storedReconciliation, reconcile)
		if completeErr != nil {
			return Claim{}, completeErr
		}
		return Claim{State: StateCompleted, CreatedAt: claim.CreatedAt.UTC(), Response: &completed}, nil
	}
	if claim.Response == nil {
		return Claim{}, ErrInvalid
	}
	response := cloneResponse(*claim.Response)
	if validateResponse(response) != nil {
		return Claim{}, ErrInvalid
	}
	claim.Response = &response
	phaseReconciliation := append([]byte(nil), claim.Reconciliation...)
	if recoverIncomplete && (claim.State == StateSideEffectCommitted || claim.State == StateAudited) {
		repairStore, ok := service.store.(incompleteSideEffectStore)
		if !ok || !ownerPattern.MatchString(claim.OwnerToken) || validateReconciliation(phaseReconciliation) != nil {
			return Claim{}, ErrInvalid
		}
		previous := cloneResponse(response)
		repaired, recoverErr := recover(ctx, ProcessingClaim{
			OwnerToken: claim.OwnerToken, CreatedAt: claim.CreatedAt.UTC(), Reconciliation: append([]byte(nil), phaseReconciliation...), Response: &previous,
		})
		if recoverErr != nil {
			return Claim{}, recoverErr
		}
		if validateResponse(repaired) != nil {
			return Claim{}, ErrInvalid
		}
		response, err = repairStore.RepairIncompleteSideEffect(ctx, key, fingerprint, claim.OwnerToken, repaired, phaseReconciliation, service.currentTime())
		if err != nil {
			return Claim{}, err
		}
		if validateResponse(response) != nil {
			return Claim{}, ErrInvalid
		}
		claim.State = StateSideEffectCommitted
	}
	switch claim.State {
	case StateCompleted:
		if claim.OwnerToken != "" || claim.Reconciliation != nil {
			return Claim{}, ErrInvalid
		}
		return claim, nil
	case StateSideEffectCommitted:
		if !ownerPattern.MatchString(claim.OwnerToken) || validateReconciliation(phaseReconciliation) != nil {
			return Claim{}, ErrInvalid
		}
		if err := reconcile(ctx, cloneResponse(response), append([]byte(nil), phaseReconciliation...)); err != nil {
			return Claim{}, err
		}
		if err := service.store.MarkAudited(ctx, key, fingerprint, claim.OwnerToken, service.currentTime()); err != nil {
			return Claim{}, err
		}
	case StateAudited:
		if !ownerPattern.MatchString(claim.OwnerToken) || validateReconciliation(phaseReconciliation) != nil {
			return Claim{}, ErrInvalid
		}
	default:
		return Claim{}, ErrInvalid
	}
	completed, err := service.store.Complete(ctx, key, fingerprint, claim.OwnerToken, response, service.currentTime())
	if err != nil {
		return Claim{}, err
	}
	if validateResponse(completed) != nil {
		return Claim{}, ErrInvalid
	}
	completed = cloneResponse(completed)
	return Claim{State: StateCompleted, Response: &completed}, nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (service *Service) Complete(ctx context.Context, key Key, fingerprint, owner string, response Response, reconciliation []byte, reconcile ReconcileFunc) (Response, error) {
	if service == nil || service.store == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) || !ownerPattern.MatchString(owner) || validateResponse(response) != nil || validateReconciliation(reconciliation) != nil || reconcile == nil {
		return Response{}, ErrInvalid
	}
	reconciliation = append([]byte(nil), reconciliation...)
	committed, err := service.store.CommitSideEffect(ctx, key, fingerprint, owner, cloneResponse(response), reconciliation, service.currentTime())
	if err != nil {
		return Response{}, err
	}
	if validateResponse(committed) != nil {
		return Response{}, ErrInvalid
	}
	if err := reconcile(ctx, cloneResponse(committed), append([]byte(nil), reconciliation...)); err != nil {
		return Response{}, err
	}
	if err := service.store.MarkAudited(ctx, key, fingerprint, owner, service.currentTime()); err != nil {
		return Response{}, err
	}
	completed, err := service.store.Complete(ctx, key, fingerprint, owner, committed, service.currentTime())
	if err != nil {
		return Response{}, err
	}
	if validateResponse(completed) != nil {
		return Response{}, ErrInvalid
	}
	return cloneResponse(completed), nil
}

func validateReconciliation(value []byte) error {
	if len(value) == 0 || len(value) > maximumReconciliationBytes || !json.Valid(value) {
		return ErrInvalid
	}
	return nil
}

func (service *Service) Abort(ctx context.Context, key Key, fingerprint, owner string) error {
	if service == nil || service.store == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) || !ownerPattern.MatchString(owner) {
		return ErrInvalid
	}
	return service.store.Abort(ctx, key, fingerprint, owner)
}

func (service *Service) currentTime() time.Time {
	if service.now == nil {
		return time.Now().UTC()
	}
	return service.now().UTC()
}

func validateKey(key Key) error {
	if key.Scope.Validate() != nil || !canonicalKeyPart(key.Actor) || !canonicalKeyPart(key.OperationID) || !canonicalKeyPart(key.IdempotencyKey) {
		return ErrInvalid
	}
	return nil
}

func canonicalKeyPart(value string) bool {
	return value != "" && len(value) <= 256 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\r\n\t")
}

func validateResponse(response Response) error {
	if response.Status < 100 || response.Status > 599 || !json.Valid(response.Body) {
		return ErrInvalid
	}
	for name, values := range response.Header {
		if name == "" || strings.ContainsAny(name, "\r\n") {
			return ErrInvalid
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return ErrInvalid
			}
		}
	}
	return nil
}

func cloneResponse(response Response) Response {
	response.Header = response.Header.Clone()
	response.Body = append([]byte(nil), response.Body...)
	return response
}

func newOwnerToken() (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return "owner-" + hex.EncodeToString(random), nil
}
