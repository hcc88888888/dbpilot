package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/controlplane"
	"dbpilot.local/platform/internal/platformscope"
	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
)

func TestNewOIDCServerServesDiscoveryJWKSAndProductionVerifiableToken(t *testing.T) {
	fixture := startOIDCFixture(t)

	discoveryResponse, err := fixture.client.Get(fixture.issuer + "/.well-known/openid-configuration")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, discoveryResponse.StatusCode)
	var discovery map[string]any
	require.NoError(t, json.NewDecoder(discoveryResponse.Body).Decode(&discovery))
	require.NoError(t, discoveryResponse.Body.Close())
	require.Equal(t, fixture.issuer, discovery["issuer"])
	require.Equal(t, fixture.issuer+"/jwks", discovery["jwks_uri"])
	require.Equal(t, fixture.issuer+"/token", discovery["token_endpoint"])
	require.Equal(t, []any{"RS256"}, discovery["id_token_signing_alg_values_supported"])

	jwksResponse, err := fixture.client.Get(fixture.issuer + "/jwks")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, jwksResponse.StatusCode)
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(jwksResponse.Body).Decode(&jwks))
	require.NoError(t, jwksResponse.Body.Close())
	require.Len(t, jwks.Keys, 1)
	require.Equal(t, "RSA", jwks.Keys[0]["kty"])
	require.Equal(t, "RS256", jwks.Keys[0]["alg"])
	require.NotEmpty(t, jwks.Keys[0]["kid"])

	token := fixture.token(t, "valid", fixture.credential)
	ctx := coreosoidc.ClientContext(context.Background(), fixture.client)
	verifier, err := controlplane.NewOIDCTokenVerifier(ctx, fixture.issuer, "dbpilot-control-plane")
	require.NoError(t, err)
	rawClaims, err := verifier.Verify(ctx, token.AccessToken)
	require.NoError(t, err)
	var claims struct {
		Subject  string                   `json:"sub"`
		Issuer   string                   `json:"iss"`
		Audience string                   `json:"aud"`
		IssuedAt int64                    `json:"iat"`
		Expires  int64                    `json:"exp"`
		Projects []platformscope.Scope    `json:"dbpilot_projects"`
		Grants   []controlplane.OIDCGrant `json:"dbpilot_grants"`
	}
	require.NoError(t, json.Unmarshal(rawClaims, &claims))
	require.Equal(t, "acceptance-admin", claims.Subject)
	require.Equal(t, fixture.issuer, claims.Issuer)
	require.Equal(t, "dbpilot-control-plane", claims.Audience)
	require.LessOrEqual(t, time.Unix(claims.Expires, 0).Sub(time.Unix(claims.IssuedAt, 0)), 15*time.Minute)
	require.Equal(t, []platformscope.Scope{{TenantID: "tenant-acceptance", ProjectID: "project-acceptance"}}, claims.Projects)
	require.Equal(t, []controlplane.OIDCGrant{{
		TenantID: "tenant-acceptance", ProjectID: "project-acceptance",
		Permissions: []string{"inspection:view", "inspection:manage", "inspection:execute", "platform.jobs.read", "platform.jobs.cancel", "platform.artifacts.read", "platform.artifacts.download", "platform.audit.read", "platform.capabilities.read"},
	}}, claims.Grants)
}

func TestNewOIDCServerIssuesClosedNegativeVariants(t *testing.T) {
	fixture := startOIDCFixture(t)
	ctx := coreosoidc.ClientContext(context.Background(), fixture.client)
	verifier, err := controlplane.NewOIDCTokenVerifier(ctx, fixture.issuer, "dbpilot-control-plane")
	require.NoError(t, err)

	for _, variant := range []string{"wrong_audience", "expired"} {
		t.Run(variant, func(t *testing.T) {
			token := fixture.token(t, variant, fixture.credential)
			_, err := verifier.Verify(ctx, token.AccessToken)
			require.Error(t, err)
		})
	}

	missingPermission := fixture.token(t, "missing_permission", fixture.credential)
	rawClaims, err := verifier.Verify(ctx, missingPermission.AccessToken)
	require.NoError(t, err)
	var claims controlplane.OIDCClaims
	require.NoError(t, json.Unmarshal(rawClaims, &claims))
	require.Len(t, claims.Grants, 1)
	require.NotContains(t, claims.Grants[0].Permissions, "inspection:execute")

	requestBody := strings.NewReader(`{"credential":"` + fixture.credential + `","variant":"unknown"}`)
	response, err := fixture.client.Post(fixture.issuer+"/token", "application/json", requestBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	require.NoError(t, response.Body.Close())
}

func TestNewOIDCServerRejectsCredentialsBoundsAndUnexpectedRoutesWithoutLoggingSecrets(t *testing.T) {
	fixture := startOIDCFixture(t)

	badCredentialBody := `{"credential":"credential-that-must-not-be-logged","variant":"valid"}`
	response, err := fixture.client.Post(fixture.issuer+"/token", "application/json", strings.NewReader(badCredentialBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	require.NoError(t, response.Body.Close())

	oversizedBody := `{"credential":"` + strings.Repeat("x", 5000) + `","variant":"valid"}`
	response, err = fixture.client.Post(fixture.issuer+"/token", "application/json", strings.NewReader(oversizedBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusRequestEntityTooLarge, response.StatusCode)
	require.NoError(t, response.Body.Close())

	for _, requestCase := range []struct{ method, path string }{
		{http.MethodPost, "/jwks"},
		{http.MethodGet, "/token"},
		{http.MethodGet, "/debug"},
	} {
		method, path := requestCase.method, requestCase.path
		request, requestErr := http.NewRequest(method, fixture.issuer+path, nil)
		require.NoError(t, requestErr)
		response, requestErr = fixture.client.Do(request)
		require.NoError(t, requestErr)
		if path == "/debug" {
			require.Equal(t, http.StatusNotFound, response.StatusCode)
		} else {
			require.Equal(t, http.StatusMethodNotAllowed, response.StatusCode)
		}
		require.NoError(t, response.Body.Close())
	}

	require.NotContains(t, fixture.logs.String(), fixture.credential)
	require.NotContains(t, fixture.logs.String(), "credential-that-must-not-be-logged")
	require.NotContains(t, fixture.logs.String(), "eyJ")
	require.Equal(t, 16<<10, fixture.server.MaxHeaderBytes)
	require.Positive(t, fixture.server.ReadHeaderTimeout)
	require.Positive(t, fixture.server.ReadTimeout)
	require.Positive(t, fixture.server.WriteTimeout)
}

func TestNewOIDCServerTLSListenerRejectsPlainHTTPAndUsesTLS12Minimum(t *testing.T) {
	fixture := startOIDCFixture(t)
	require.Equal(t, uint16(tls.VersionTLS12), fixture.server.TLSConfig.MinVersion)
	require.NotEmpty(t, fixture.server.TLSConfig.Certificates)

	connection, err := net.DialTimeout("tcp", fixture.listenerAddress, time.Second)
	require.NoError(t, err)
	_, err = io.WriteString(connection, "GET /healthz HTTP/1.1\r\nHost: oidc\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	require.NoError(t, connection.SetReadDeadline(time.Now().Add(time.Second)))
	response := make([]byte, 256)
	count, _ := connection.Read(response)
	require.NotContains(t, string(response[:count]), "200 OK")
	require.NoError(t, connection.Close())
}

func TestOIDCTLSFixtureVerifiesChainAtDeterministicAcceptanceTime(t *testing.T) {
	fixture := startOIDCFixture(t)
	transport := fixture.client.Transport.(*http.Transport)
	require.NotNil(t, transport.TLSClientConfig.Time)
	verificationTime := transport.TLSClientConfig.Time()
	require.Equal(t, time.Date(2026, 8, 29, 3, 3, 4, 0, time.UTC), verificationTime)
	chains, err := fixture.certificate.Verify(x509.VerifyOptions{
		DNSName: "oidc", Roots: fixture.roots, CurrentTime: verificationTime,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err)
	require.NotEmpty(t, chains)
}

type runningOIDCFixture struct {
	issuer          string
	credential      string
	client          *http.Client
	server          *http.Server
	logs            *bytes.Buffer
	listenerAddress string
	certificate     *x509.Certificate
	roots           *x509.CertPool
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (fixture runningOIDCFixture) token(t *testing.T, variant, credential string) tokenResponse {
	t.Helper()
	body, err := json.Marshal(map[string]string{"credential": credential, "variant": variant})
	require.NoError(t, err)
	response, err := fixture.client.Post(fixture.issuer+"/token", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	var token tokenResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&token))
	require.NoError(t, response.Body.Close())
	require.Equal(t, "Bearer", token.TokenType)
	require.NotEmpty(t, token.AccessToken)
	require.LessOrEqual(t, token.ExpiresIn, int64((15*time.Minute)/time.Second))
	return token
}

func startOIDCFixture(t *testing.T) runningOIDCFixture {
	t.Helper()
	manifest := generateBootstrapForTest(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	issuer := "https://oidc:" + port
	logs := &bytes.Buffer{}
	configuration := OIDCConfig{
		Address: "0.0.0.0:9444", Issuer: issuer, Audience: "dbpilot-control-plane",
		TenantID: "tenant-acceptance", ProjectID: "project-acceptance", TokenTTL: 15 * time.Minute,
		CredentialFile: manifest.Files["token_credential"], SigningKeyFile: manifest.Files["oidc_signing_key"], JWKSFile: manifest.Files["jwks"],
		TLSCertificateFile: manifest.Files["oidc_cert"], TLSKeyFile: manifest.Files["oidc_key"],
		Now: func() time.Time { return time.Now().UTC() }, Logger: log.New(logs, "", 0),
	}
	server, err := NewOIDCServer(configuration)
	require.NoError(t, err)
	tlsListener := tls.NewListener(listener, server.TLSConfig.Clone())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(tlsListener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		<-serveDone
	})

	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(mustRead(t, manifest.Files["ca_cert"])))
	dialer := &net.Dialer{Timeout: time.Second}
	verificationTime := time.Date(2026, 8, 29, 3, 3, 4, 0, time.UTC)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12, Time: func() time.Time { return verificationTime }},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			parsed, parseErr := url.Parse("https://" + address)
			if parseErr != nil || parsed.Hostname() != "oidc" {
				return nil, parseErr
			}
			return dialer.DialContext(ctx, network, listener.Addr().String())
		},
	}
	credential := strings.TrimSpace(string(mustRead(t, manifest.Files["token_credential"])))
	return runningOIDCFixture{
		issuer: issuer, credential: credential, client: &http.Client{Transport: transport, Timeout: 3 * time.Second},
		server: server, logs: logs, listenerAddress: listener.Addr().String(), certificate: mustCertificate(t, manifest.Files["oidc_cert"]), roots: caPool,
	}
}
