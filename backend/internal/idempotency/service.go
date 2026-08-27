// Package idempotency provides the durable claim/complete boundary for scoped
// HTTP write operations.
package idempotency

import (
	"context"
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
	ErrInvalid     = errors.New("invalid idempotency request")
	ErrKeyConflict = errors.New("idempotency key reused with a different request")
	ErrInProgress  = errors.New("idempotent request is already processing")
	ErrNotClaimed  = errors.New("idempotency claim is unavailable")
)

var fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type State string

const (
	StateProcessing State = "processing"
	StateCompleted  State = "completed"
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
	Claimed  bool
	Response *Response
}

type Store interface {
	Claim(context.Context, Key, string, time.Time, time.Time) (Claim, error)
	Complete(context.Context, Key, string, Response, time.Time) (Response, error)
	Abort(context.Context, Key, string) error
}

type Service struct {
	store Store
	now   func() time.Time
	ttl   time.Duration
}

func NewService(store Store) *Service {
	return &Service{store: store, now: time.Now, ttl: DefaultTTL}
}

func (service *Service) Begin(ctx context.Context, key Key, fingerprint string) (Claim, error) {
	if service == nil || service.store == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) {
		return Claim{}, ErrInvalid
	}
	now := service.currentTime()
	ttl := service.ttl
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	claim, err := service.store.Claim(ctx, key, fingerprint, now, now.Add(ttl))
	if err != nil {
		return Claim{}, err
	}
	if claim.Claimed == (claim.Response != nil) {
		return Claim{}, ErrInvalid
	}
	if claim.Response != nil {
		response := cloneResponse(*claim.Response)
		if validateResponse(response) != nil {
			return Claim{}, ErrInvalid
		}
		claim.Response = &response
	}
	return claim, nil
}

func (service *Service) Complete(ctx context.Context, key Key, fingerprint string, response Response) (Response, error) {
	if service == nil || service.store == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) || validateResponse(response) != nil {
		return Response{}, ErrInvalid
	}
	completed, err := service.store.Complete(ctx, key, fingerprint, cloneResponse(response), service.currentTime())
	if err != nil {
		return Response{}, err
	}
	if validateResponse(completed) != nil {
		return Response{}, ErrInvalid
	}
	return cloneResponse(completed), nil
}

func (service *Service) Abort(ctx context.Context, key Key, fingerprint string) error {
	if service == nil || service.store == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) {
		return ErrInvalid
	}
	return service.store.Abort(ctx, key, fingerprint)
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
