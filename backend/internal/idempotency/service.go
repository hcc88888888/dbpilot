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
	Claimed    bool
	OwnerToken string
	State      State
	Response   *Response
}

type ReconcileFunc func(context.Context, Response) error

type Store interface {
	Claim(context.Context, Key, string, string, time.Time, time.Time) (Claim, error)
	CommitSideEffect(context.Context, Key, string, string, Response, time.Time) (Response, error)
	MarkAudited(context.Context, Key, string, string, time.Time) error
	Complete(context.Context, Key, string, string, Response, time.Time) (Response, error)
	Abort(context.Context, Key, string, string) error
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
	claim, err := service.store.Claim(ctx, key, fingerprint, owner, now, now.Add(ttl))
	if err != nil {
		return Claim{}, err
	}
	if claim.Claimed {
		if claim.OwnerToken != owner || claim.State != StateProcessing || claim.Response != nil {
			return Claim{}, ErrInvalid
		}
		return claim, nil
	}
	if claim.Response == nil {
		return Claim{}, ErrInvalid
	}
	response := cloneResponse(*claim.Response)
	if validateResponse(response) != nil {
		return Claim{}, ErrInvalid
	}
	claim.Response = &response
	switch claim.State {
	case StateCompleted:
		if claim.OwnerToken != "" {
			return Claim{}, ErrInvalid
		}
		return claim, nil
	case StateSideEffectCommitted:
		if !ownerPattern.MatchString(claim.OwnerToken) {
			return Claim{}, ErrInvalid
		}
		if err := reconcile(ctx, cloneResponse(response)); err != nil {
			return Claim{}, err
		}
		if err := service.store.MarkAudited(ctx, key, fingerprint, claim.OwnerToken, service.currentTime()); err != nil {
			return Claim{}, err
		}
	case StateAudited:
		if !ownerPattern.MatchString(claim.OwnerToken) {
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

func (service *Service) Complete(ctx context.Context, key Key, fingerprint, owner string, response Response, reconcile ReconcileFunc) (Response, error) {
	if service == nil || service.store == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) || !ownerPattern.MatchString(owner) || validateResponse(response) != nil || reconcile == nil {
		return Response{}, ErrInvalid
	}
	committed, err := service.store.CommitSideEffect(ctx, key, fingerprint, owner, cloneResponse(response), service.currentTime())
	if err != nil {
		return Response{}, err
	}
	if validateResponse(committed) != nil {
		return Response{}, ErrInvalid
	}
	if err := reconcile(ctx, cloneResponse(committed)); err != nil {
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
