package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAgentCertificateIssuerRejectsNotYetValidOrExpiredCA(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	for name, validity := range map[string][2]time.Time{
		"not yet valid": {now.Add(time.Hour), now.Add(2 * time.Hour)},
		"expired":       {now.Add(-2 * time.Hour), now.Add(-time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			certificate, key := reviewCA(t, "invalid", validity[0], validity[1], nil, nil)
			_, err := NewAgentCertificateIssuer(certificate, key, time.Hour, func() time.Time { return now }, rand.Reader)
			require.ErrorIs(t, err, ErrEnrollmentRequestInvalid)
		})
	}
}

func TestAgentCertificateIssuerProvesExactLeafThroughAgentControlRootsIncludingIntermediate(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	rootPEM, rootKeyPEM := reviewCA(t, "root", now.Add(-time.Hour), now.Add(24*time.Hour), nil, nil)
	rootBlock, _ := pem.Decode(rootPEM)
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	require.NoError(t, err)
	rootKeyBlock, _ := pem.Decode(rootKeyPEM)
	parsedRootKey, err := x509.ParsePKCS8PrivateKey(rootKeyBlock.Bytes)
	require.NoError(t, err)
	intermediatePEM, intermediateKey := reviewCA(t, "intermediate", now.Add(-time.Hour), now.Add(12*time.Hour), root, parsedRootKey.(ed25519.PrivateKey))
	intermediateBlock, _ := pem.Decode(intermediatePEM)
	intermediate, err := x509.ParseCertificate(intermediateBlock.Bytes)
	require.NoError(t, err)
	require.NoError(t, intermediate.CheckSignatureFrom(root))
	chain := append(append([]byte(nil), intermediatePEM...), rootPEM...)
	issuer, err := NewAgentCertificateIssuer(chain, intermediateKey, time.Hour, func() time.Time { return now }, rand.Reader)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(rootPEM))

	require.NoError(t, issuer.ValidateAgentControlTrust(roots))
	otherRoot, _ := reviewCA(t, "other", now.Add(-time.Hour), now.Add(24*time.Hour), nil, nil)
	wrongRoots := x509.NewCertPool()
	require.True(t, wrongRoots.AppendCertsFromPEM(otherRoot))
	require.Error(t, issuer.ValidateAgentControlTrust(wrongRoots))
}

func reviewCA(t *testing.T, commonName string, notBefore, notAfter time.Time, parent *x509.Certificate, parentKey ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(notBefore.UnixNano()), Subject: pkix.Name{CommonName: commonName},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	if parent == nil {
		parent, parentKey = template, privateKey
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
	require.NoError(t, err)
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}
