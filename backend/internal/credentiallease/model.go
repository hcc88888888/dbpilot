// Package credentiallease issues short-lived, memory-only database credentials
// to authenticated Agents over the live AgentControl stream.
package credentiallease

import (
	"context"
	"errors"
	"regexp"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

const (
	RequestNonceBytes    = 32
	MaximumUsernameBytes = 256
	MaximumSecretBytes   = 64 << 10
	DefaultLeaseTTL      = time.Minute
	MinimumLeaseTTL      = 5 * time.Second
	MaximumLeaseTTL      = 5 * time.Minute
	DefaultMaximumLive   = 4096
)

var (
	ErrLeaseRejected = errors.New("credential lease failed")
	identifier       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	familyIdentifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

type AuthenticatedAgent struct {
	AgentID   string
	SessionID string
}

type LeaseRequest struct {
	Nonce                 []byte
	InstanceID            string
	AssignmentID          string
	DatabaseFamily        string
	ConfigurationRevision uint64
	OperationRevision     uint64
}

type Authorization struct {
	Scope                 platformscope.Scope
	HostID                string
	AgentID               string
	AssignmentID          string
	DatabaseFamily        string
	ConfigurationRevision uint64
	OperationRevision     uint64
	InstanceID            string
	InstanceRevision      uint64
	CredentialRef         string
	TLSRef                string
	ManagementStatus      string
	AuthorizedAt          time.Time
}

type Credential struct {
	Username    string
	SecretBytes []byte
	Revision    uint64
}

func (value Credential) Clone() Credential {
	value.SecretBytes = append([]byte(nil), value.SecretBytes...)
	return value
}

func (value *Credential) Release() {
	if value == nil {
		return
	}
	zero(value.SecretBytes)
	value.SecretBytes = nil
	value.Username = ""
	value.Revision = 0
}

type Lease struct {
	ID                    string
	InstanceID            string
	AssignmentID          string
	DatabaseFamily        string
	ConfigurationRevision uint64
	OperationRevision     uint64
	CredentialRevision    uint64
	ExpiresAt             time.Time
	Username              string
	SecretBytes           []byte
}

func (value Lease) Clone() Lease {
	value.SecretBytes = append([]byte(nil), value.SecretBytes...)
	return value
}

func (value *Lease) Release() {
	if value == nil {
		return
	}
	zero(value.SecretBytes)
	value.SecretBytes = nil
	value.Username = ""
}

type SecretProvider interface {
	Resolve(context.Context, string) (Credential, error)
}

type Authorizer interface {
	Authorize(context.Context, AuthenticatedAgent, LeaseRequest) (Authorization, error)
}

type RenewalAuthorizer interface {
	AuthorizeRenewal(context.Context, AuthenticatedAgent, LeaseRequest) (Authorization, error)
}

type DatabaseClock interface {
	Now(context.Context) (time.Time, error)
}

type Service interface {
	Lease(context.Context, AuthenticatedAgent, LeaseRequest) (Lease, error)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
