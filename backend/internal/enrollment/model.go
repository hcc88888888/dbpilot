// Package enrollment owns scoped one-time Agent enrollment.
package enrollment

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/platformscope"
)

const (
	EnrollmentTokenBytes     = 32
	MaximumCSRPEMBytes       = 64 << 10
	MaximumCSRPublicKeyBytes = 4 << 10
	DefaultTokenTTL          = 10 * time.Minute
	MaximumTokenTTL          = time.Hour
)

var (
	ErrEnrollmentRequestInvalid     = errors.New("invalid Agent enrollment request")
	ErrEnrollmentTokenInvalid       = errors.New("Agent enrollment token is invalid")
	ErrEnrollmentConflict           = errors.New("Agent enrollment conflicts with existing state")
	ErrEnrollmentNotFound           = errors.New("Agent enrollment token claim was not found")
	ErrEnrollmentGenerationConflict = errors.New("Agent enrollment generation conflict")
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var labelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type EnrollmentToken struct {
	TokenHash          [sha256.Size]byte
	Scope              platformscope.Scope
	HostID             string
	AgentID            string
	DisplayName        string
	Labels             map[string]string
	ExpiresAt          time.Time
	CreatedAt          time.Time
	EnrollmentRevision uint64
	IssuedBy           string
	IdempotencyKey     string
	RequestFingerprint string
	Generation         uint64
	Audit              EnrollmentAudit
}

type EnrollmentAudit struct {
	Actor          string
	RequestID      string
	TraceID        string
	OperationID    string
	IdempotencyKey string
}

func (value EnrollmentAudit) Validate() error {
	if !bounded(value.Actor, 256, true) || !bounded(value.RequestID, 256, true) || !bounded(value.TraceID, 256, false) ||
		!bounded(value.OperationID, 256, true) || !bounded(value.IdempotencyKey, 128, true) {
		return ErrEnrollmentRequestInvalid
	}
	return nil
}

func (token EnrollmentToken) Validate() error {
	if token.TokenHash == ([sha256.Size]byte{}) || token.Scope.Validate() != nil ||
		!identifierPattern.MatchString(token.HostID) || !identifierPattern.MatchString(token.AgentID) ||
		!bounded(token.DisplayName, 120, true) || !validLabels(token.Labels) ||
		!validUTC(token.CreatedAt) || !validUTC(token.ExpiresAt) || !token.ExpiresAt.After(token.CreatedAt) ||
		token.EnrollmentRevision == 0 || !bounded(token.IssuedBy, 256, true) || !bounded(token.IdempotencyKey, 128, true) ||
		!fingerprintPattern.MatchString(token.RequestFingerprint) || token.Generation == 0 || token.Audit.Validate() != nil {
		return ErrEnrollmentRequestInvalid
	}
	return nil
}

func (token EnrollmentToken) Grant() EnrollmentGrant {
	return EnrollmentGrant{
		Scope: token.Scope, HostID: token.HostID, AgentID: token.AgentID, DisplayName: token.DisplayName,
		Labels: cloneLabels(token.Labels), EnrollmentRevision: token.EnrollmentRevision,
	}
}

// String intentionally excludes the token hash and all certificate material.
func (token EnrollmentToken) String() string {
	return fmt.Sprintf("enrollment host=%q agent=%q scope=%q revision=%d", token.HostID, token.AgentID, token.Scope.Key(), token.EnrollmentRevision)
}

type EnrollmentGrant struct {
	Scope              platformscope.Scope
	HostID             string
	AgentID            string
	DisplayName        string
	Labels             map[string]string
	EnrollmentRevision uint64
}

func (grant EnrollmentGrant) Validate() error {
	if grant.Scope.Validate() != nil || !identifierPattern.MatchString(grant.HostID) || !identifierPattern.MatchString(grant.AgentID) ||
		!bounded(grant.DisplayName, 120, true) || !validLabels(grant.Labels) || grant.EnrollmentRevision == 0 {
		return ErrEnrollmentRequestInvalid
	}
	return nil
}

type CreateRequest struct {
	HostID             string
	AgentID            string
	DisplayName        string
	Labels             map[string]string
	ExpiresIn          time.Duration
	IssuedBy           string
	IdempotencyKey     string
	RequestFingerprint string
	Audit              EnrollmentAudit
}

type CreatedEnrollment struct {
	HostID             string
	AgentID            string
	Token              []byte
	ExpiresAt          time.Time
	EnrollmentRevision uint64
	Generation         uint64
	Replaced           bool
}

type EnrollRequest struct {
	Token        []byte
	AgentID      string
	CSRPEM       []byte
	CSRPublicKey []byte
	CSRProof     []byte
	Observation  hostinventory.Observation
}

type EnrollResult struct {
	HostID              string
	AgentID             string
	CertificatePEM      []byte
	CertificateChainPEM []byte
	ExpiresAt           time.Time
	EnrollmentRevision  uint64
}

type EnrollmentAttemptKey struct {
	TokenHash [sha256.Size]byte
	CSRDigest [sha256.Size]byte
	AgentID   string
	HostID    string
}

func (key EnrollmentAttemptKey) Validate() error {
	if key.TokenHash == ([sha256.Size]byte{}) || key.CSRDigest == ([sha256.Size]byte{}) ||
		!identifierPattern.MatchString(key.AgentID) || (key.HostID != "" && !identifierPattern.MatchString(key.HostID)) {
		return ErrEnrollmentRequestInvalid
	}
	return nil
}

type EnrollmentResolution struct {
	Grant    EnrollmentGrant
	Response *EnrollResult
}

type EnrollmentCompletion struct {
	Key         EnrollmentAttemptKey
	Grant       EnrollmentGrant
	Observation hostinventory.Observation
	Result      EnrollResult
	CompletedAt time.Time
}

type EnrollmentStore interface {
	Create(context.Context, EnrollmentToken) (EnrollmentTokenCreation, error)
	Replace(context.Context, EnrollmentToken, uint64) (EnrollmentTokenCreation, error)
	Resolve(context.Context, EnrollmentAttemptKey) (EnrollmentResolution, error)
	Complete(context.Context, EnrollmentCompletion) (EnrollResult, error)
}

type EnrollmentTokenCreation struct {
	Generation uint64
	Replaced   bool
}

type CertificateIssuer interface {
	SignAgentCSR(context.Context, EnrollmentGrant, []byte) (certificatePEM, chainPEM []byte, expiresAt time.Time, err error)
}

func HashToken(token []byte) [sha256.Size]byte { return sha256.Sum256(token) }

func validUTC(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }

func bounded(value string, maximum int, required bool) bool {
	if value == "" {
		return !required
	}
	return value == strings.TrimSpace(value) && utf8.ValidString(value) && utf8.RuneCountInString(value) <= maximum && !strings.ContainsAny(value, "\r\n\t")
}

func validLabels(values map[string]string) bool {
	if len(values) > 32 {
		return false
	}
	for key, value := range values {
		if !labelPattern.MatchString(key) || !bounded(value, 128, false) {
			return false
		}
	}
	return true
}

func cloneLabels(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
