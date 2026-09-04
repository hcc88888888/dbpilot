package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestCreateEnrollmentStoresOnlyTokenHashAndTrustedScope(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	raw := bytes.Repeat([]byte{0x42}, EnrollmentTokenBytes)
	store := &memoryTokenStore{}
	service := ApplicationService{Tokens: store, Random: bytes.NewReader(raw), Now: func() time.Time { return now }}
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}

	created, err := service.Create(context.Background(), scope, CreateRequest{
		HostID: "host-1", AgentID: "agent-1", DisplayName: "Primary database host",
		Labels: map[string]string{"role": "database"}, ExpiresIn: 10 * time.Minute,
		IssuedBy: "operator-1", IdempotencyKey: "enroll-1", RequestFingerprint: "sha256:" + strings.Repeat("1", 64),
		Audit: EnrollmentAudit{Actor: "operator-1", RequestID: "request-1", OperationID: "createHostEnrollment", IdempotencyKey: "enroll-1"},
	})

	require.NoError(t, err)
	require.Equal(t, raw, created.Token)
	require.Equal(t, now.Add(10*time.Minute), created.ExpiresAt)
	require.NotEqual(t, raw, store.created.TokenHash[:])
	require.Equal(t, HashToken(raw), store.created.TokenHash)
	require.Equal(t, scope, store.created.Scope)
	require.Equal(t, "agent-1", store.created.AgentID)
	require.Equal(t, uint64(1), store.created.EnrollmentRevision)
	require.NotContains(t, store.created.String(), string(raw))
}

func TestEnrollmentRetryReturnsStoredCertificateAndCertificateUsesCanonicalSPIFFE(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	raw := bytes.Repeat([]byte{0x31}, EnrollmentTokenBytes)
	caCertificate, caKey := testCertificateAuthority(t, now)
	issuer, err := NewAgentCertificateIssuer(caCertificate, caKey, time.Hour, func() time.Time { return now }, rand.Reader)
	require.NoError(t, err)
	store := newAttemptMemoryStore(validEnrollmentToken(HashToken(raw), now).Grant())
	service := ApplicationService{Tokens: store, Certificates: issuer, Now: func() time.Time { return now }}
	request := signedEnrollRequest(t, raw, "agent-1", now)

	first, err := service.Enroll(context.Background(), request)

	require.NoError(t, err)
	require.NotEmpty(t, first.CertificatePEM)
	require.Equal(t, "host-1", first.HostID)
	certificate := parseLeafCertificate(t, first.CertificatePEM)
	require.Len(t, certificate.URIs, 1)
	require.Equal(t, "spiffe://dbpilot.local/agent/agent-1", certificate.URIs[0].String())
	require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, certificate.ExtKeyUsage)

	replayed, err := service.Enroll(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, first, replayed)
}

func TestEnrollRejectsExpiryScopeMismatchAndInvalidEd25519Proof(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	raw := bytes.Repeat([]byte{0x52}, EnrollmentTokenBytes)
	valid := validEnrollmentToken(HashToken(raw), now)

	t.Run("expired", func(t *testing.T) {
		expired := valid
		expired.ExpiresAt = now
		store := newAttemptMemoryStore(expired.Grant())
		store.resolveErr = ErrEnrollmentTokenInvalid
		service := ApplicationService{Tokens: store, Certificates: rejectingIssuer{}, Now: func() time.Time { return now }}
		_, err := service.Enroll(context.Background(), signedEnrollRequest(t, raw, valid.AgentID, now))
		require.ErrorIs(t, err, ErrEnrollmentTokenInvalid)
	})

	t.Run("scope binding", func(t *testing.T) {
		store := newAttemptMemoryStore(valid.Grant())
		service := ApplicationService{Tokens: store, Certificates: rejectingIssuer{}, Now: func() time.Time { return now }}
		_, err := service.Enroll(context.Background(), signedEnrollRequest(t, raw, "agent-other", now))
		require.ErrorIs(t, err, ErrEnrollmentTokenInvalid)
	})

	t.Run("proof checked before consumption", func(t *testing.T) {
		store := newAttemptMemoryStore(valid.Grant())
		service := ApplicationService{Tokens: store, Certificates: rejectingIssuer{}, Now: func() time.Time { return now }}
		request := signedEnrollRequest(t, raw, valid.AgentID, now)
		request.CSRProof[0] ^= 0xff
		_, err := service.Enroll(context.Background(), request)
		require.ErrorIs(t, err, ErrEnrollmentRequestInvalid)
		require.Zero(t, store.completeCalls)
	})
}

func TestEnrollmentErrorsNeverContainTokenOrPrivateMaterial(t *testing.T) {
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	raw := bytes.Repeat([]byte("private-enrollment-token"), 2)[:EnrollmentTokenBytes]
	request := signedEnrollRequest(t, raw, "agent-1", now)
	privateMarker := "PRIVATE-KEY-MARKER"
	store := newAttemptMemoryStore(validEnrollmentToken(HashToken(raw), now).Grant())
	store.resolveErr = errors.New("storage unavailable")
	service := ApplicationService{Tokens: store, Certificates: rejectingIssuer{}, Now: func() time.Time { return now }}

	_, err := service.Enroll(context.Background(), request)

	require.Error(t, err)
	require.NotContains(t, err.Error(), string(raw))
	require.NotContains(t, err.Error(), privateMarker)
}

func signedEnrollRequest(t *testing.T, token []byte, agentID string, at time.Time) EnrollRequest {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	require.NoError(t, err)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	message, err := CSRProofMessage(agentID, csrPEM, publicDER)
	require.NoError(t, err)
	return EnrollRequest{
		Token: append([]byte(nil), token...), AgentID: agentID, CSRPEM: csrPEM, CSRPublicKey: publicDER,
		CSRProof: ed25519.Sign(privateKey, message),
		Observation: hostinventory.Observation{
			AgentID: agentID, Revision: 1, AgentVersion: "1.0.0", Hostname: "db-1.example",
			OS: "kylin", OSVersion: "V10 SP1", Kernel: "5.10", Architecture: "amd64",
			LogicalCPUCount: 4, MemoryCapacityBytes: 8 << 30, NetworkAddresses: []string{"10.0.0.10"},
			Capabilities: []string{"host.inventory.v1"}, ObservedAt: at,
		},
	}
}

func validEnrollmentToken(hash [32]byte, now time.Time) EnrollmentToken {
	return EnrollmentToken{
		TokenHash: hash, Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		HostID: "host-1", AgentID: "agent-1", DisplayName: "Primary database host",
		Labels: map[string]string{"role": "database"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		EnrollmentRevision: 1, IssuedBy: "operator-1", IdempotencyKey: "enroll-1",
		RequestFingerprint: "sha256:" + strings.Repeat("1", 64), Generation: 1,
		Audit: EnrollmentAudit{Actor: "operator-1", RequestID: "request-1", OperationID: "createHostEnrollment", IdempotencyKey: "enroll-1"},
	}
}

func testCertificateAuthority(t *testing.T, now time.Time) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DBPilot Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func parseLeafCertificate(t *testing.T, certificatePEM []byte) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode(certificatePEM)
	require.NotNil(t, block)
	require.Empty(t, strings.TrimSpace(string(rest)))
	certificate, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return certificate
}

type memoryTokenStore struct {
	created      EnrollmentToken
	tokens       map[[32]byte]EnrollmentToken
	consumeCalls int
	consumeErr   error
}

func (store *memoryTokenStore) Create(_ context.Context, token EnrollmentToken) (EnrollmentTokenCreation, error) {
	store.created = token
	if store.tokens == nil {
		store.tokens = make(map[[32]byte]EnrollmentToken)
	}
	if _, exists := store.tokens[token.TokenHash]; exists {
		return EnrollmentTokenCreation{}, ErrEnrollmentConflict
	}
	store.tokens[token.TokenHash] = token
	return EnrollmentTokenCreation{Generation: 1}, nil
}

func (store *memoryTokenStore) Consume(_ context.Context, hash [32]byte, now time.Time) (EnrollmentGrant, error) {
	store.consumeCalls++
	if store.consumeErr != nil {
		return EnrollmentGrant{}, store.consumeErr
	}
	token, exists := store.tokens[hash]
	if !exists || !now.Before(token.ExpiresAt) {
		return EnrollmentGrant{}, ErrEnrollmentTokenInvalid
	}
	delete(store.tokens, hash)
	return token.Grant(), nil
}

func (store *memoryTokenStore) Resolve(context.Context, EnrollmentAttemptKey) (EnrollmentResolution, error) {
	return EnrollmentResolution{}, ErrEnrollmentTokenInvalid
}

func (store *memoryTokenStore) Complete(context.Context, EnrollmentCompletion) (EnrollmentCompletionResult, error) {
	return EnrollmentCompletionResult{}, ErrEnrollmentTokenInvalid
}

func (store *memoryTokenStore) Replace(context.Context, EnrollmentToken, uint64) (EnrollmentTokenCreation, error) {
	return EnrollmentTokenCreation{}, ErrEnrollmentConflict
}

func (store *memoryTokenStore) ResolveReplacement(context.Context, platformscope.Scope, ReplacementLookup) (ReplacementState, error) {
	return ReplacementState{}, ErrEnrollmentNotFound
}

type rejectingIssuer struct{}

func (rejectingIssuer) SignAgentCSR(context.Context, EnrollmentGrant, []byte) ([]byte, []byte, time.Time, error) {
	return nil, nil, time.Time{}, errors.New("issuer unavailable")
}
