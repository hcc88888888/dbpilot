package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCSRProofRejectsAllIdentityAttributesAndExtensions(t *testing.T) {
	unknownOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}
	tests := map[string]*x509.CertificateRequest{
		"subject RDN":                {Subject: pkix.Name{CommonName: "agent-1"}},
		"basic constraints":          {ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x00}}}},
		"key usage":                  {ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{0x03, 0x02, 0x07, 0x80}}}},
		"unknown critical extension": {ExtraExtensions: []pkix.Extension{{Id: unknownOID, Critical: true, Value: []byte{0x05, 0x00}}}},
		"attribute":                  {Attributes: []pkix.AttributeTypeAndValueSET{{Type: unknownOID, Value: [][]pkix.AttributeTypeAndValue{{{Type: unknownOID, Value: "value"}}}}}},
	}
	for name, template := range tests {
		t.Run(name, func(t *testing.T) {
			csrPEM, publicDER := createReviewCSR(t, template)
			_, err := CSRProofMessage("agent-1", csrPEM, publicDER)
			require.ErrorIs(t, err, ErrEnrollmentRequestInvalid)
		})
	}
}

func TestCSRProofRejectsDuplicatePEMAndOversizedInputs(t *testing.T) {
	csrPEM, publicDER := createReviewCSR(t, &x509.CertificateRequest{})
	_, err := CSRProofMessage("agent-1", append(append([]byte(nil), csrPEM...), csrPEM...), publicDER)
	require.ErrorIs(t, err, ErrEnrollmentRequestInvalid)
	_, err = CSRProofMessage("agent-1", bytes.Repeat([]byte{'A'}, MaximumCSRPEMBytes+1), publicDER)
	require.ErrorIs(t, err, ErrEnrollmentRequestInvalid)
	_, err = CSRProofMessage("agent-1", csrPEM, bytes.Repeat([]byte{0x42}, MaximumCSRPublicKeyBytes+1))
	require.ErrorIs(t, err, ErrEnrollmentRequestInvalid)
}

func createReviewCSR(t *testing.T, template *x509.CertificateRequest) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	require.NoError(t, err)
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), publicDER
}
