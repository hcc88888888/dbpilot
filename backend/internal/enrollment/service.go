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
	"fmt"
	"io"
	"math/big"
	"net/url"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

const csrProofDomain = "dbpilot-agent-enrollment-csr-proof-v1"

type ApplicationService struct {
	Tokens       EnrollmentStore
	Certificates CertificateIssuer
	Random       io.Reader
	Now          func() time.Time
}

func (service ApplicationService) Create(ctx context.Context, scope platformscope.Scope, request CreateRequest) (CreatedEnrollment, error) {
	return service.createToken(ctx, scope, request, 0, false)
}

func (service ApplicationService) Replace(ctx context.Context, scope platformscope.Scope, request CreateRequest, expectedGeneration uint64) (CreatedEnrollment, error) {
	if expectedGeneration == 0 {
		return CreatedEnrollment{}, ErrEnrollmentRequestInvalid
	}
	return service.createToken(ctx, scope, request, expectedGeneration, true)
}

func (service ApplicationService) createToken(ctx context.Context, scope platformscope.Scope, request CreateRequest, expectedGeneration uint64, replacing bool) (CreatedEnrollment, error) {
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
		RequestFingerprint: request.RequestFingerprint, Generation: 1, Audit: request.Audit,
	}
	if token.Validate() != nil {
		zero(raw)
		return CreatedEnrollment{}, ErrEnrollmentRequestInvalid
	}
	var creation EnrollmentTokenCreation
	var err error
	if replacing {
		creation, err = service.Tokens.Replace(ctx, token, expectedGeneration)
	} else {
		creation, err = service.Tokens.Create(ctx, token)
	}
	if err != nil {
		zero(raw)
		return CreatedEnrollment{}, err
	}
	if creation.Generation == 0 || creation.Replaced != replacing {
		zero(raw)
		return CreatedEnrollment{}, ErrEnrollmentRequestInvalid
	}
	return CreatedEnrollment{
		HostID: token.HostID, AgentID: token.AgentID, Token: raw, ExpiresAt: token.ExpiresAt,
		EnrollmentRevision: token.EnrollmentRevision, Generation: creation.Generation, Replaced: creation.Replaced,
	}, nil
}

func (service ApplicationService) Enroll(ctx context.Context, request EnrollRequest) (EnrollResult, error) {
	if ctx == nil || service.Tokens == nil || service.Certificates == nil ||
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
	proofMessage, publicKey, csrDigest, err := verifiedCSRProofInputs(request.AgentID, request.CSRPEM, request.CSRPublicKey)
	if err != nil || !ed25519.Verify(publicKey, proofMessage, request.CSRProof) {
		return EnrollResult{}, ErrEnrollmentRequestInvalid
	}
	now := service.now()
	if !validUTC(now) {
		return EnrollResult{}, ErrEnrollmentRequestInvalid
	}
	key := EnrollmentAttemptKey{TokenHash: HashToken(request.Token), CSRDigest: csrDigest, AgentID: request.AgentID, HostID: request.Observation.HostID}
	resolution, err := service.Tokens.Resolve(ctx, key)
	if err != nil {
		if errors.Is(err, ErrEnrollmentTokenInvalid) {
			return EnrollResult{}, ErrEnrollmentTokenInvalid
		}
		return EnrollResult{}, errors.New("resolve Agent enrollment token")
	}
	grant := resolution.Grant
	if grant.Validate() != nil || grant.AgentID != request.AgentID || (request.Observation.HostID != "" && request.Observation.HostID != grant.HostID) {
		return EnrollResult{}, ErrEnrollmentTokenInvalid
	}
	key.HostID = grant.HostID
	if resolution.Response != nil {
		if err := validateEnrollmentResult(*resolution.Response, grant); err != nil {
			return EnrollResult{}, errors.New("stored Agent enrollment response is invalid")
		}
		return cloneEnrollmentResult(*resolution.Response), nil
	}
	certificatePEM, chainPEM, expiresAt, err := service.Certificates.SignAgentCSR(ctx, grant, request.CSRPEM)
	if err != nil || len(certificatePEM) == 0 || len(chainPEM) == 0 || !validUTC(expiresAt) || !expiresAt.After(now) {
		return EnrollResult{}, errors.New("issue Agent enrollment certificate")
	}
	result := EnrollResult{
		HostID: grant.HostID, AgentID: grant.AgentID, CertificatePEM: append([]byte(nil), certificatePEM...),
		CertificateChainPEM: append([]byte(nil), chainPEM...), ExpiresAt: expiresAt,
		EnrollmentRevision: grant.EnrollmentRevision,
	}
	observation := request.Observation
	observation.HostID = grant.HostID
	completed, err := service.Tokens.Complete(ctx, EnrollmentCompletion{Key: key, Grant: grant, Observation: observation, Result: result, CompletedAt: now})
	if err == nil {
		if validateEnrollmentResult(completed, grant) != nil {
			return EnrollResult{}, errors.New("completed Agent enrollment response is invalid")
		}
		return cloneEnrollmentResult(completed), nil
	}
	// A connection loss can make COMMIT outcome unknown. Resolve by the exact
	// token/CSR/Agent/Host key before reporting failure or asking for a new token.
	recovered, resolveErr := service.Tokens.Resolve(ctx, key)
	if resolveErr == nil && recovered.Response != nil && validateEnrollmentResult(*recovered.Response, grant) == nil {
		return cloneEnrollmentResult(*recovered.Response), nil
	}
	return EnrollResult{}, errors.New("complete Agent enrollment attempt")
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
	message, _, _, err := verifiedCSRProofInputs(agentID, csrPEM, publicKeyDER)
	return message, err
}

func verifiedCSRProofInputs(agentID string, csrPEM, publicKeyDER []byte) ([]byte, ed25519.PublicKey, [sha256.Size]byte, error) {
	if !identifierPattern.MatchString(agentID) || len(csrPEM) == 0 || len(csrPEM) > MaximumCSRPEMBytes || len(publicKeyDER) == 0 || len(publicKeyDER) > MaximumCSRPublicKeyBytes {
		return nil, nil, [sha256.Size]byte{}, ErrEnrollmentRequestInvalid
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, [sha256.Size]byte{}, ErrEnrollmentRequestInvalid
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.SignatureAlgorithm != x509.PureEd25519 || csr.Subject.String() != "" || !bytes.Equal(csr.RawSubject, []byte{0x30, 0x00}) ||
		len(csr.Attributes) != 0 || len(csr.Extensions) != 0 || len(csr.ExtraExtensions) != 0 || len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, nil, [sha256.Size]byte{}, ErrEnrollmentRequestInvalid
	}
	publicKey, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, [sha256.Size]byte{}, ErrEnrollmentRequestInvalid
	}
	parsedPublic, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return nil, nil, [sha256.Size]byte{}, ErrEnrollmentRequestInvalid
	}
	provided, ok := parsedPublic.(ed25519.PublicKey)
	canonicalPublic, canonicalErr := x509.MarshalPKIXPublicKey(publicKey)
	if !ok || canonicalErr != nil || !bytes.Equal(publicKey, provided) || !bytes.Equal(canonicalPublic, publicKeyDER) {
		return nil, nil, [sha256.Size]byte{}, ErrEnrollmentRequestInvalid
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
	return message, append(ed25519.PublicKey(nil), publicKey...), csrDigest, nil
}

func validateEnrollmentResult(result EnrollResult, grant EnrollmentGrant) error {
	if result.HostID != grant.HostID || result.AgentID != grant.AgentID || len(result.CertificatePEM) == 0 || len(result.CertificateChainPEM) == 0 ||
		!validUTC(result.ExpiresAt) || result.EnrollmentRevision != grant.EnrollmentRevision {
		return ErrEnrollmentRequestInvalid
	}
	return nil
}

func cloneEnrollmentResult(result EnrollResult) EnrollResult {
	result.CertificatePEM = append([]byte(nil), result.CertificatePEM...)
	result.CertificateChainPEM = append([]byte(nil), result.CertificateChainPEM...)
	return result
}

type AgentCertificateIssuer struct {
	ca       *x509.Certificate
	chain    []*x509.Certificate
	chainPEM []byte
	key      ed25519.PrivateKey
	lifetime time.Duration
	now      func() time.Time
	random   io.Reader
}

func NewAgentCertificateIssuer(certificatePEM, privateKeyPEM []byte, lifetime time.Duration, now func() time.Time, random io.Reader) (*AgentCertificateIssuer, error) {
	certificates, err := parseCertificateChain(certificatePEM)
	keyBlock, keyRest := pem.Decode(privateKeyPEM)
	if err != nil || keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(keyBlock.Headers) != 0 || len(bytes.TrimSpace(keyRest)) != 0 || lifetime <= 0 || lifetime > 365*24*time.Hour {
		return nil, ErrEnrollmentRequestInvalid
	}
	certificate := certificates[0]
	if !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
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
	current := now()
	if !validUTC(current) || current.Before(certificate.NotBefore) || !current.Before(certificate.NotAfter) {
		return nil, ErrEnrollmentRequestInvalid
	}
	return &AgentCertificateIssuer{
		ca: certificate, chain: certificates, chainPEM: append([]byte(nil), certificatePEM...),
		key: append(ed25519.PrivateKey(nil), privateKey...), lifetime: lifetime, now: now, random: random,
	}, nil
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), append([]byte(nil), issuer.chainPEM...), expiresAt, nil
}

func (issuer *AgentCertificateIssuer) ValidateAgentControlTrust(roots *x509.CertPool) error {
	if issuer == nil || roots == nil {
		return ErrEnrollmentRequestInvalid
	}
	publicKey, privateKey, err := ed25519.GenerateKey(issuer.random)
	if err != nil {
		return errors.New("generate enrollment trust probe key")
	}
	csrDER, err := x509.CreateCertificateRequest(issuer.random, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		return errors.New("generate enrollment trust probe CSR")
	}
	_ = publicKey
	certificatePEM, _, _, err := issuer.SignAgentCSR(context.Background(), EnrollmentGrant{
		Scope: platformscope.Scope{TenantID: "trust-probe", ProjectID: "trust-probe"}, HostID: "trust-probe", AgentID: "trust-probe",
		DisplayName: "trust-probe", Labels: map[string]string{}, EnrollmentRevision: 1,
	}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	if err != nil {
		return err
	}
	leafBlock, rest := pem.Decode(certificatePEM)
	if leafBlock == nil || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("decode enrollment trust probe certificate")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range issuer.chain {
		if certificate.CheckSignatureFrom(certificate) != nil {
			intermediates.AddCert(certificate)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: issuer.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("enrollment issuing chain is not trusted by AgentControl: %w", err)
	}
	return nil
}

func parseCertificateChain(contents []byte) ([]*x509.Certificate, error) {
	remaining := bytes.TrimSpace(contents)
	var certificates []*x509.Certificate
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrEnrollmentRequestInvalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrEnrollmentRequestInvalid
		}
		certificates = append(certificates, certificate)
		remaining = bytes.TrimSpace(rest)
	}
	if len(certificates) == 0 {
		return nil, ErrEnrollmentRequestInvalid
	}
	return certificates, nil
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
