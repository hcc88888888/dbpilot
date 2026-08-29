package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"dbpilot.local/platform/internal/controlplane"
	"dbpilot.local/platform/internal/platformscope"
)

const maximumOIDCRequestBodyBytes = 4 << 10

type OIDCConfig struct {
	Address            string           `json:"address"`
	Issuer             string           `json:"issuer"`
	Audience           string           `json:"audience"`
	TenantID           string           `json:"tenant_id"`
	ProjectID          string           `json:"project_id"`
	TokenTTL           time.Duration    `json:"token_ttl"`
	CredentialFile     string           `json:"credential_file"`
	SigningKeyFile     string           `json:"signing_key_file"`
	JWKSFile           string           `json:"jwks_file"`
	TLSCertificateFile string           `json:"tls_certificate_file"`
	TLSKeyFile         string           `json:"tls_key_file"`
	Now                func() time.Time `json:"-"`
	Logger             *log.Logger      `json:"-"`
}

type oidcHandler struct {
	config     OIDCConfig
	signingKey *rsa.PrivateKey
	jwks       []byte
}

type oidcTokenRequest struct {
	Credential string `json:"credential"`
	Variant    string `json:"variant"`
}

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func NewOIDCServer(config OIDCConfig) (*http.Server, error) {
	if err := validateOIDCConfig(config); err != nil {
		return nil, err
	}
	signingKey, err := loadRSAPrivateKey(config.SigningKeyFile)
	if err != nil {
		return nil, err
	}
	jwks, err := readBoundedRegularFile(config.JWKSFile, 64<<10, false)
	if err != nil {
		return nil, fmt.Errorf("read OIDC JWKS: %w", err)
	}
	if err := validateJWKS(jwks, &signingKey.PublicKey); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCertificateFile, config.TLSKeyFile)
	if err != nil {
		return nil, errors.New("load OIDC TLS certificate")
	}

	handler := &oidcHandler{config: config, signingKey: signingKey, jwks: append([]byte(nil), jwks...)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", handler.discovery)
	mux.HandleFunc("GET /jwks", handler.serveJWKS)
	mux.HandleFunc("GET /healthz", handler.health)
	mux.HandleFunc("POST /token", handler.token)

	errorLog := log.New(io.Discard, "", 0)
	if config.Logger != nil {
		errorLog = log.New(fixedOIDCLogWriter{destination: config.Logger.Writer()}, "", 0)
	}
	return &http.Server{
		Addr: config.Address, Handler: mux,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: errorLog,
	}, nil
}

func validateOIDCConfig(config OIDCConfig) error {
	if config.Address != "0.0.0.0:9444" {
		return errors.New("OIDC address must be 0.0.0.0:9444")
	}
	issuer, err := url.Parse(config.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || strings.TrimSuffix(config.Issuer, "/") != config.Issuer {
		return errors.New("OIDC issuer must be a canonical HTTPS URL")
	}
	for name, value := range map[string]string{"audience": config.Audience, "tenant ID": config.TenantID, "project ID": config.ProjectID} {
		if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\t") {
			return fmt.Errorf("OIDC %s is invalid", name)
		}
	}
	if config.TokenTTL <= 0 || config.TokenTTL > maximumOIDCTokenTTL {
		return errors.New("OIDC token TTL must be between zero and 15 minutes")
	}
	for _, path := range []string{config.CredentialFile, config.SigningKeyFile, config.JWKSFile, config.TLSCertificateFile, config.TLSKeyFile} {
		if !filepath.IsAbs(path) {
			return errors.New("OIDC material paths must be absolute")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("OIDC material is unavailable")
		}
	}
	for _, path := range []string{config.CredentialFile, config.SigningKeyFile, config.TLSKeyFile} {
		info, err := os.Stat(path)
		if err != nil {
			return errors.New("OIDC secret material is unavailable")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return errors.New("OIDC secret material must be mode 0600")
		}
	}
	return nil
}

func (handler *oidcHandler) discovery(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"issuer": handler.config.Issuer, "jwks_uri": handler.config.Issuer + "/jwks", "token_endpoint": handler.config.Issuer + "/token",
		"response_types_supported": []string{"id_token"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (handler *oidcHandler) serveJWKS(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(handler.jwks)
}

func (handler *oidcHandler) health(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func (handler *oidcHandler) token(response http.ResponseWriter, request *http.Request) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeOIDCError(response, http.StatusUnsupportedMediaType, "invalid_request")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumOIDCRequestBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var input oidcTokenRequest
	if err := decoder.Decode(&input); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			writeOIDCError(response, http.StatusRequestEntityTooLarge, "request_too_large")
		} else {
			writeOIDCError(response, http.StatusBadRequest, "invalid_request")
		}
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		writeOIDCError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if !validOIDCVariant(input.Variant) {
		writeOIDCError(response, http.StatusBadRequest, "invalid_variant")
		return
	}
	credential, err := readBoundedRegularFile(handler.config.CredentialFile, 1024, true)
	if err != nil {
		writeOIDCError(response, http.StatusServiceUnavailable, "credential_unavailable")
		return
	}
	provided := []byte(input.Credential)
	validCredential := len(provided) == len(credential) && subtle.ConstantTimeCompare(provided, credential) == 1
	for index := range credential {
		credential[index] = 0
	}
	if !validCredential {
		writeOIDCError(response, http.StatusUnauthorized, "invalid_credential")
		return
	}
	token, expiresIn, err := handler.issueToken(input.Variant)
	if err != nil {
		writeOIDCError(response, http.StatusInternalServerError, "token_unavailable")
		return
	}
	writeJSON(response, http.StatusOK, oidcTokenResponse{AccessToken: token, TokenType: "Bearer", ExpiresIn: expiresIn})
}

func (handler *oidcHandler) issueToken(variant string) (string, int64, error) {
	now := time.Now().UTC()
	if handler.config.Now != nil {
		now = handler.config.Now().UTC()
	}
	issuedAt, expiresAt := now, now.Add(handler.config.TokenTTL)
	audience := handler.config.Audience
	permissions := []string{"inspection:view", "inspection:manage", "inspection:execute", "platform.jobs.read", "platform.jobs.cancel", "platform.artifacts.read", "platform.artifacts.download", "platform.audit.read", "platform.capabilities.read"}
	switch variant {
	case "wrong_audience":
		audience += "-wrong"
	case "expired":
		issuedAt, expiresAt = now.Add(-30*time.Minute), now.Add(-15*time.Minute)
	case "missing_permission":
		permissions = withoutString(permissions, "inspection:execute")
	}
	claims := map[string]any{
		"sub": "acceptance-admin", "iss": handler.config.Issuer, "aud": audience,
		"iat": issuedAt.Unix(), "exp": expiresAt.Unix(),
		"dbpilot_platform_admin": false,
		"dbpilot_projects":       []platformscope.Scope{{TenantID: handler.config.TenantID, ProjectID: handler.config.ProjectID}},
		"dbpilot_grants":         []controlplane.OIDCGrant{{TenantID: handler.config.TenantID, ProjectID: handler.config.ProjectID, Permissions: permissions}},
	}
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": oidcKeyID(&handler.signingKey.PublicKey)}
	headerBody, err := json.Marshal(header)
	if err != nil {
		return "", 0, err
	}
	claimsBody, err := json.Marshal(claims)
	if err != nil {
		return "", 0, err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerBody) + "." + base64.RawURLEncoding.EncodeToString(claimsBody)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(nil, handler.signingKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", 0, err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), maxInt64(0, int64(expiresAt.Sub(issuedAt)/time.Second)), nil
}

func validOIDCVariant(value string) bool {
	switch value {
	case "valid", "wrong_audience", "expired", "missing_permission":
		return true
	default:
		return false
	}
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	body, err := readBoundedRegularFile(path, 64<<10, false)
	if err != nil {
		return nil, errors.New("read OIDC signing key")
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("parse OIDC signing key")
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse OIDC signing key")
	}
	privateKey, ok := value.(*rsa.PrivateKey)
	if !ok || privateKey.N.BitLen() != 2048 || privateKey.Validate() != nil {
		return nil, errors.New("OIDC signing key must be RSA-2048")
	}
	return privateKey, nil
}

func validateJWKS(body []byte, publicKey *rsa.PublicKey) error {
	var value struct {
		Keys []struct {
			KeyType   string `json:"kty"`
			Use       string `json:"use"`
			Algorithm string `json:"alg"`
			KeyID     string `json:"kid"`
			Modulus   string `json:"n"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &value); err != nil || len(value.Keys) != 1 {
		return errors.New("OIDC JWKS is invalid")
	}
	key := value.Keys[0]
	if key.KeyType != "RSA" || key.Use != "sig" || key.Algorithm != "RS256" || key.KeyID != oidcKeyID(publicKey) || key.Modulus != base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()) {
		return errors.New("OIDC JWKS does not match signing key")
	}
	return nil
}

func readBoundedRegularFile(path string, limit int64, trimSpace bool) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("file is unavailable or exceeds limit")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("file is unavailable or exceeds limit")
	}
	if trimSpace {
		body = []byte(strings.TrimSpace(string(body)))
	}
	return body, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("request must contain one JSON value")
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeOIDCError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]string{"error": code})
}

func withoutString(values []string, omitted string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != omitted {
			result = append(result, value)
		}
	}
	return result
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

type fixedOIDCLogWriter struct{ destination io.Writer }

func (writer fixedOIDCLogWriter) Write(message []byte) (int, error) {
	if writer.destination != nil {
		_, _ = io.WriteString(writer.destination, "OIDC server transport error [redacted]\n")
	}
	return len(message), nil
}
