package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

const csrProofDomain = "dbpilot-agent-enrollment-csr-proof-v1"

type ApplicationService struct {
	Tokens       TokenStore
	Certificates CertificateIssuer
	Hosts        HostObservationRecorder
	Random       io.Reader
	Now          func() time.Time
}

func (service ApplicationService) Create(ctx context.Context, scope platformscope.Scope, request CreateRequest) (CreatedEnrollment, error) {
	if ctx == nil || service.Tokens == nil || scope.Validate() != nil {
		return CreatedEnrollment{}, ErrEnrollmentRequestInvalid
	}
	now := service.now()
	ttl := request.ExpiresIn
	if ttl == 0 {
		ttl = DefaultTokenTTL
	}
	if !validUTC(now) || ttl < time.Minute || ttl > MaximumTokenTTL {
		return CreatedEnrollment{}, ErrEnrollmentRequestInvalid
	}
	random := service.Random
	if random == nil {
		random = rand.Reader
	}
	raw := make([]byte, EnrollmentTokenBytes)
	if _, err := io.ReadFull(random, raw); err != nil {
		return CreatedEnrollment{}, errors.New("generate Agent enrollment token")
	}
	token := EnrollmentToken{
		TokenHash: HashToken(raw), Scope: scope, HostID: request.HostID, AgentID: request.AgentID,
		DisplayName: request.DisplayName, Labels: cloneLabels(request.Labels), CreatedAt: now, ExpiresAt: now.Add(ttl),
		EnrollmentRevision: 1, IssuedBy: request.IssuedBy, IdempotencyKey: request.IdempotencyKey,
	}
	if token.Validate() != nil {
		zero(raw)
		return CreatedEnrollment{}, ErrEnrollmentRequestInvalid
	}
	if err := service.Tokens.Create(ctx, token); err != nil {
		zero(raw)
		return CreatedEnrollment{}, err
	}
	return CreatedEnrollment{HostID: token.HostID, AgentID: token.AgentID, Token: raw, ExpiresAt: token.ExpiresAt, EnrollmentRevision: token.EnrollmentRevision}, nil
}

func (service ApplicationService) Enroll(ctx context.Context, request EnrollRequest) (EnrollResult, error) {
	if ctx == nil || service.Tokens == nil || service.Certificates == nil || service.Hosts == nil ||
		len(request.Token) != EnrollmentTokenBytes || !identifierPattern.MatchString(request.AgentID) ||
		request.Observation.AgentID != request.AgentID || len(request.CSRProof) != ed25519.SignatureSize {
		return EnrollResult{}, ErrEnrollmentRequestInvalid
	}
	observationProbe := request.Observation
	if observationProbe.HostID == "" {
		observationProbe.HostID = "enrollment-host"
	}
	if observationProbe.Validate() != nil {
		return EnrollResult{}, ErrEnrollmentRequestInvalid
	}
	proofMessage, publicKey, err := verifiedCSRProofInputs(request.AgentID, request.CSRPEM, request.CSRPublicKey)
	if err != nil || !ed25519.Verify(publicKey, proofMessage, request.CSRProof) {
		return EnrollResult{}, ErrEnrollmentRequestInvalid
	}
	now := service.now()
	if !validUTC(now) {
		return EnrollResult{}, ErrEnrollmentRequestInvalid
	}
	grant, err := service.Tokens.Consume(ctx, HashToken(request.Token), now)
	if err != nil {
		if errors.Is(err, ErrEnrollmentTokenInvalid) {
			return EnrollResult{}, ErrEnrollmentTokenInvalid
		}
		return EnrollResult{}, errors.New("consume Agent enrollment token")
	}
	if grant.Validate() != nil || grant.AgentID != request.AgentID || (request.Observation.HostID != "" && request.Observation.HostID != grant.HostID) {
		return EnrollResult{}, ErrEnrollmentTokenInvalid
	}
	certificatePEM, chainPEM, expiresAt, err := service.Certificates.SignAgentCSR(ctx, grant, request.CSRPEM)
	if err != nil || len(certificatePEM) == 0 || len(chainPEM) == 0 || !validUTC(expiresAt) || !expiresAt.After(now) {
		return EnrollResult{}, errors.New("issue Agent enrollment certificate")
	}
	observation := request.Observation
	observation.HostID = grant.HostID
	if err := service.Hosts.RecordEnrollment(ctx, grant, observation, now); err != nil {
		return EnrollResult{}, errors.New("record enrolled Agent host observation")
	}
	return EnrollResult{
		HostID: grant.HostID, AgentID: grant.AgentID, CertificatePEM: append([]byte(nil), certificatePEM...),
		CertificateChainPEM: append([]byte(nil), chainPEM...), ExpiresAt: expiresAt,
		EnrollmentRevision: grant.EnrollmentRevision,
	}, nil
}

func (service ApplicationService) now() time.Time {
	now := time.Now().UTC()
	if service.Now != nil {
		now = service.Now()
	}
	return now
}

// CSRProofMessage returns the canonical byte string the Agent proves with the
// private key corresponding to its CSR. It contains no token or private key.
func CSRProofMessage(agentID string, csrPEM, publicKeyDER []byte) ([]byte, error) {
	message, _, err := verifiedCSRProofInputs(agentID, csrPEM, publicKeyDER)
	return message, err
}

func verifiedCSRProofInputs(agentID string, csrPEM, publicKeyDER []byte) ([]byte, ed25519.PublicKey, error) {
	if !identifierPattern.MatchString(agentID) {
		return nil, nil, ErrEnrollmentRequestInvalid
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, ErrEnrollmentRequestInvalid
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.String() != "" || len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, nil, ErrEnrollmentRequestInvalid
	}
	publicKey, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, ErrEnrollmentRequestInvalid
	}
	parsedPublic, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return nil, nil, ErrEnrollmentRequestInvalid
	}
	provided, ok := parsedPublic.(ed25519.PublicKey)
	if !ok || !bytes.Equal(publicKey, provided) {
		return nil, nil, ErrEnrollmentRequestInvalid
	}
	csrDigest := sha256.Sum256(csr.Raw)
	keyDigest := sha256.Sum256(publicKeyDER)
	message := make([]byte, 0, len(csrProofDomain)+4+len(agentID)+sha256.Size*2)
	message = append(message, csrProofDomain...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(agentID)))
	message = append(message, length[:]...)
	message = append(message, agentID...)
	message = append(message, csrDigest[:]...)
	message = append(message, keyDigest[:]...)
	return message, append(ed25519.PublicKey(nil), publicKey...), nil
}

type AgentCertificateIssuer struct {
	ca       *x509.Certificate
	key      ed25519.PrivateKey
	lifetime time.Duration
	now      func() time.Time
	random   io.Reader
}

func NewAgentCertificateIssuer(certificatePEM, privateKeyPEM []byte, lifetime time.Duration, now func() time.Time, random io.Reader) (*AgentCertificateIssuer, error) {
	certificateBlock, certificateRest := pem.Decode(certificatePEM)
	keyBlock, keyRest := pem.Decode(privateKeyPEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(certificateRest)) != 0 ||
		keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(keyRest)) != 0 || lifetime <= 0 || lifetime > 365*24*time.Hour {
		return nil, ErrEnrollmentRequestInvalid
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ErrEnrollmentRequestInvalid
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, ErrEnrollmentRequestInvalid
	}
	privateKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok || !bytes.Equal(certificate.RawSubjectPublicKeyInfo, mustMarshalPublicKey(privateKey.Public())) {
		return nil, ErrEnrollmentRequestInvalid
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if random == nil {
		random = rand.Reader
	}
	return &AgentCertificateIssuer{ca: certificate, key: append(ed25519.PrivateKey(nil), privateKey...), lifetime: lifetime, now: now, random: random}, nil
}

func (issuer *AgentCertificateIssuer) SignAgentCSR(_ context.Context, grant EnrollmentGrant, csrPEM []byte) ([]byte, []byte, time.Time, error) {
	if issuer == nil || issuer.ca == nil || len(issuer.key) != ed25519.PrivateKeySize || grant.Validate() != nil {
		return nil, nil, time.Time{}, ErrEnrollmentRequestInvalid
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, time.Time{}, ErrEnrollmentRequestInvalid
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, nil, time.Time{}, ErrEnrollmentRequestInvalid
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, nil, time.Time{}, ErrEnrollmentRequestInvalid
	}
	now := issuer.now()
	if !validUTC(now) {
		return nil, nil, time.Time{}, ErrEnrollmentRequestInvalid
	}
	expiresAt := now.Add(issuer.lifetime)
	if expiresAt.After(issuer.ca.NotAfter) {
		expiresAt = issuer.ca.NotAfter.UTC()
	}
	if !expiresAt.After(now) {
		return nil, nil, time.Time{}, errors.New("Agent enrollment CA is expired")
	}
	serialBytes := make([]byte, 16)
	if _, err := io.ReadFull(issuer.random, serialBytes); err != nil {
		return nil, nil, time.Time{}, errors.New("generate Agent certificate serial")
	}
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	identity := &url.URL{Scheme: "spiffe", Host: "dbpilot.local", Path: "/agent/" + grant.AgentID}
	template := &x509.Certificate{
		SerialNumber: serial, NotBefore: now.Add(-time.Minute), NotAfter: expiresAt,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, URIs: []*url.URL{identity},
	}
	certificateDER, err := x509.CreateCertificate(issuer.random, template, issuer.ca, csr.PublicKey, issuer.key)
	if err != nil {
		return nil, nil, time.Time{}, errors.New("sign Agent certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.ca.Raw}), expiresAt, nil
}

func mustMarshalPublicKey(key any) []byte {
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil
	}
	return encoded
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ CertificateIssuer = (*AgentCertificateIssuer)(nil)
