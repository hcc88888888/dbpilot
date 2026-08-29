package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"dbpilot.local/platform/internal/policy"
	"gopkg.in/yaml.v3"
)

const maximumOIDCTokenTTL = 15 * time.Minute

type BootstrapOptions struct {
	Root           string
	Issuer         string
	Audience       string
	TenantID       string
	ProjectID      string
	OnlineAgentID  string
	OfflineAgentID string
	Now            time.Time
	Random         io.Reader
}

type BootstrapManifest struct {
	Issuer         string            `json:"issuer"`
	Audience       string            `json:"audience"`
	TenantID       string            `json:"tenant_id"`
	ProjectID      string            `json:"project_id"`
	OnlineAgentID  string            `json:"online_agent_id"`
	OfflineAgentID string            `json:"offline_agent_id"`
	Files          map[string]string `json:"files"`
}

type generatedAuthority struct {
	certificate    *x509.Certificate
	privateKey     ed25519.PrivateKey
	certificatePEM []byte
}

type generatedCertificate struct {
	certificatePEM []byte
	privateKeyPEM  []byte
}

func GenerateBootstrap(ctx context.Context, options BootstrapOptions) (BootstrapManifest, error) {
	if ctx == nil {
		return BootstrapManifest{}, errors.New("bootstrap context is required")
	}
	if err := ctx.Err(); err != nil {
		return BootstrapManifest{}, err
	}
	root, err := validateBootstrapOptions(options)
	if err != nil {
		return BootstrapManifest{}, err
	}
	if err := prepareBootstrapRoot(root); err != nil {
		return BootstrapManifest{}, err
	}

	randomSource := options.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	now := options.Now.UTC()
	writer := &bootstrapWriter{root: root, random: randomSource, files: make(map[string]string)}
	for _, directory := range []string{"config", "secrets", "state", "state/agent-online", "state/agent-mismatch", "state/agent-untrusted", "state/artifacts"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			return BootstrapManifest{}, fmt.Errorf("create bootstrap directory: %w", err)
		}
		if err := os.Chmod(filepath.Join(root, directory), 0o700); err != nil {
			return BootstrapManifest{}, fmt.Errorf("harden bootstrap directory: %w", err)
		}
	}

	ca, err := newAuthority(randomSource, "DBPilot acceptance CA", now)
	if err != nil {
		return BootstrapManifest{}, err
	}
	untrustedCA, err := newAuthority(randomSource, "DBPilot untrusted acceptance CA", now)
	if err != nil {
		return BootstrapManifest{}, err
	}
	if err := writer.write("ca_cert", "config/ca.pem", ca.certificatePEM, 0o644); err != nil {
		return BootstrapManifest{}, err
	}
	if err := writer.write("frontend_ca_bundle", "config/ca-certificates.crt", ca.certificatePEM, 0o644); err != nil {
		return BootstrapManifest{}, err
	}
	if err := writer.write("untrusted_ca_cert", "config/untrusted-ca.pem", untrustedCA.certificatePEM, 0o644); err != nil {
		return BootstrapManifest{}, err
	}

	certificates := []struct {
		certName   string
		keyName    string
		baseName   string
		commonName string
		dnsNames   []string
		uri        string
		client     bool
		authority  generatedAuthority
		rsaKey     bool
	}{
		{"controlplane_http_cert", "controlplane_http_key", "controlplane-http", "controlplane HTTP", []string{"controlplane"}, "", false, ca, false},
		{"controlplane_grpc_cert", "controlplane_grpc_key", "controlplane-grpc", "controlplane gRPC", []string{"controlplane"}, "", false, ca, false},
		{"frontend_cert", "frontend_key", "frontend", "frontend HTTPS", []string{"frontend"}, "", false, ca, true},
		{"oidc_cert", "oidc_key", "oidc", "OIDC", []string{"oidc"}, "", false, ca, false},
		{"agent_online_cert", "agent_online_key", "agent-online", options.OnlineAgentID, nil, "spiffe://dbpilot.local/agent/" + options.OnlineAgentID, true, ca, false},
		{"agent_mismatch_cert", "agent_mismatch_key", "agent-mismatch", "agent-certificate-id", nil, "spiffe://dbpilot.local/agent/agent-certificate-id", true, ca, false},
		{"agent_untrusted_cert", "agent_untrusted_key", "agent-untrusted", "agent-untrusted", nil, "spiffe://dbpilot.local/agent/agent-untrusted", true, untrustedCA, false},
	}
	for _, item := range certificates {
		if err := ctx.Err(); err != nil {
			return BootstrapManifest{}, err
		}
		certificate, certificateErr := newSignedCertificate(randomSource, item.authority, item.commonName, item.dnsNames, item.uri, item.client, item.rsaKey, now)
		if certificateErr != nil {
			return BootstrapManifest{}, certificateErr
		}
		if err := writer.write(item.certName, "config/"+item.baseName+".pem", certificate.certificatePEM, 0o644); err != nil {
			return BootstrapManifest{}, err
		}
		if err := writer.write(item.keyName, "secrets/"+item.baseName+"-key.pem", certificate.privateKeyPEM, 0o600); err != nil {
			return BootstrapManifest{}, err
		}
	}

	commandPublic, commandPrivate, err := ed25519.GenerateKey(randomSource)
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("generate command key: %w", err)
	}
	if err := writer.writePrivateKey("command_private_key", "secrets/command-signing-key.pem", commandPrivate); err != nil {
		return BootstrapManifest{}, err
	}
	if err := writer.writePublicKey("command_public_key", "config/command-signing-public.pem", commandPublic); err != nil {
		return BootstrapManifest{}, err
	}
	policyPublic, policyPrivate, err := ed25519.GenerateKey(randomSource)
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("generate policy key: %w", err)
	}
	if err := writer.writePrivateKey("policy_private_key", "secrets/policy-signing-key.pem", policyPrivate); err != nil {
		return BootstrapManifest{}, err
	}
	if err := writer.writePublicKey("policy_public_key", "config/policy-signing-public.pem", policyPublic); err != nil {
		return BootstrapManifest{}, err
	}

	executionKey, err := randomPrintableSecret(randomSource, 32)
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("generate execution key: %w", err)
	}
	artifactKey, err := randomPrintableSecret(randomSource, 48)
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("generate artifact key: %w", err)
	}
	postgresPassword, err := randomPrintableSecret(randomSource, 32)
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("generate PostgreSQL password: %w", err)
	}
	credential, err := randomPrintableSecret(randomSource, 32)
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("generate OIDC credential: %w", err)
	}
	for _, secret := range []struct {
		name string
		path string
		body []byte
	}{
		{"execution_key", "secrets/execution-token-key", executionKey},
		{"artifact_key", "secrets/artifact-signing-key", artifactKey},
		{"postgres_password", "secrets/postgres-password", postgresPassword},
		{"token_credential", "secrets/oidc-token-credential", credential},
	} {
		if err := writer.write(secret.name, secret.path, secret.body, 0o600); err != nil {
			return BootstrapManifest{}, err
		}
	}

	oidcPrivate, err := rsa.GenerateKey(randomSource, 2048)
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("generate OIDC signing key: %w", err)
	}
	if err := oidcPrivate.Validate(); err != nil {
		return BootstrapManifest{}, fmt.Errorf("validate OIDC signing key: %w", err)
	}
	if err := writer.writePrivateKey("oidc_signing_key", "secrets/oidc-signing-key.pem", oidcPrivate); err != nil {
		return BootstrapManifest{}, err
	}
	jwks, err := marshalJWKS(&oidcPrivate.PublicKey)
	if err != nil {
		return BootstrapManifest{}, err
	}
	if err := writer.write("jwks", "config/jwks.json", jwks, 0o644); err != nil {
		return BootstrapManifest{}, err
	}

	for _, configured := range []struct{ name, path, agentID string }{
		{"policy", "config/policy-envelope.json", options.OnlineAgentID},
		{"agent_mismatch_policy", "config/policy-mismatch-envelope.json", "agent-claimed-id"},
		{"agent_untrusted_policy", "config/policy-untrusted-envelope.json", "agent-untrusted"},
	} {
		policyEnvelope, signErr := policy.Sign(policyPrivate, policy.Policy{
			AgentID: configured.agentID, Version: 1, IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour),
			Sources: []policy.Source{
				{ID: "acceptance-host", Kind: policy.SourceHostMetrics, Interval: 10 * time.Second, Labels: map[string]string{"environment": "acceptance"}},
				{ID: "acceptance-filelog", Kind: policy.SourceFileLog, Path: "/var/log/dbpilot/acceptance.log", Interval: 5 * time.Second, Labels: map[string]string{"environment": "acceptance"}, Params: map[string]string{"start_at": "beginning"}},
			},
			Limits: policy.Limits{MaxSpoolBytes: 64 << 20, MaxBatchBytes: 1 << 20, MaxEventsPerSec: 100},
		})
		if signErr != nil {
			return BootstrapManifest{}, fmt.Errorf("sign Agent policy: %w", signErr)
		}
		policyBody, marshalErr := json.MarshalIndent(policyEnvelope, "", "  ")
		if marshalErr != nil {
			return BootstrapManifest{}, fmt.Errorf("marshal Agent policy: %w", marshalErr)
		}
		if err := writer.write(configured.name, configured.path, append(policyBody, '\n'), 0o644); err != nil {
			return BootstrapManifest{}, err
		}
	}

	containerPath := func(relative string) string {
		return filepath.ToSlash(filepath.Join(root, filepath.FromSlash(relative)))
	}
	controlplaneConfig, err := yaml.Marshal(map[string]any{
		"database_url":      "postgres://dbpilot:" + url.QueryEscape(string(postgresPassword)) + "@postgres/dbpilot?sslmode=disable",
		"http":              map[string]any{"address": "0.0.0.0:8443", "tls": map[string]any{"cert_file": containerPath("config/controlplane-http.pem"), "key_file": containerPath("secrets/controlplane-http-key.pem")}},
		"identity":          map[string]any{"mode": "oidc", "issuer": options.Issuer, "audience": options.Audience},
		"grpc":              map[string]any{"address": "0.0.0.0:9443", "tls": map[string]any{"cert_file": containerPath("config/controlplane-grpc.pem"), "key_file": containerPath("secrets/controlplane-grpc-key.pem"), "client_ca_file": containerPath("config/ca.pem")}},
		"webhook_allowlist": []string{"hooks.example.invalid"}, "event_url_base": "https://frontend:8443",
		"evaluation_every": "5s", "retry_every": "5s",
		"command":           map[string]any{"signing_private_key_ref": "env://DBPILOT_COMMAND_SIGNING_PRIVATE_KEY", "execution_token_key_ref": "env://DBPILOT_COMMAND_EXECUTION_TOKEN_KEY"},
		"artifact":          map[string]any{"storage_root": containerPath("state/artifacts"), "signing_key_ref": "secret://controlplane/artifact-download"},
		"monitoring":        map[string]any{"maximum_instances": 200, "maximum_metrics": 50, "maximum_labels": 32, "maximum_samples": 10000, "maximum_response_bytes": 1048576},
		"evaluation_scopes": []any{map[string]any{"tenant_id": options.TenantID, "project_id": options.ProjectID}},
		"agents": map[string]any{
			options.OnlineAgentID:  agentAssignment(options, "Acceptance online agent", "agent-online", "online"),
			options.OfflineAgentID: agentAssignment(options, "Acceptance offline agent", "agent-offline", "offline"),
			"agent-untrusted":      rogueAgentAssignment(options, "Untrusted certificate Agent", "agent-untrusted"),
			"agent-claimed-id":     rogueAgentAssignment(options, "Mismatched claimed Agent", "agent-claimed-id"),
			"agent-certificate-id": rogueAgentAssignment(options, "Mismatched certificate Agent", "agent-certificate-id"),
		},
	})
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("marshal control-plane config: %w", err)
	}
	if err := writer.write("controlplane_config", "secrets/controlplane.yaml", controlplaneConfig, 0o600); err != nil {
		return BootstrapManifest{}, err
	}

	agentConfigs := []struct {
		name       string
		path       string
		agentID    string
		certPath   string
		keyPath    string
		policyPath string
		dataSuffix string
	}{
		{"agent_config", "config/agent.yaml", options.OnlineAgentID, "config/agent-online.pem", "secrets/agent-online-key.pem", "config/policy-envelope.json", "agent-online"},
		{"agent_mismatch_config", "config/agent-mismatch.yaml", "agent-claimed-id", "config/agent-mismatch.pem", "secrets/agent-mismatch-key.pem", "config/policy-mismatch-envelope.json", "agent-mismatch"},
		{"agent_untrusted_config", "config/agent-untrusted.yaml", "agent-untrusted", "config/agent-untrusted.pem", "secrets/agent-untrusted-key.pem", "config/policy-untrusted-envelope.json", "agent-untrusted"},
	}
	for _, configured := range agentConfigs {
		body, marshalErr := yaml.Marshal(map[string]any{
			"agent_id": configured.agentID, "server_address": "controlplane:9443",
			"ca_file": containerPath("config/ca.pem"), "cert_file": containerPath(configured.certPath), "key_file": containerPath(configured.keyPath),
			"policy_public_key_file": containerPath("config/policy-signing-public.pem"), "policy_file": containerPath(configured.policyPath),
			"data_directory": containerPath("state/" + configured.dataSuffix), "allowed_log_roots": []string{"/var/log/dbpilot"}, "file_collection_enabled": true,
			"database_process_names": []string{"dbpilot-agent"},
			"control":                map[string]any{"public_key_file": containerPath("config/command-signing-public.pem"), "journal_path": containerPath("state/" + configured.dataSuffix + "/command-journal.db"), "heartbeat_interval": "5s", "reconnect_backoff": "1s"},
		})
		if marshalErr != nil {
			return BootstrapManifest{}, fmt.Errorf("marshal Agent config: %w", marshalErr)
		}
		if err := writer.write(configured.name, configured.path, body, 0o644); err != nil {
			return BootstrapManifest{}, err
		}
	}

	oidcConfig, err := json.MarshalIndent(OIDCConfig{
		Address: "0.0.0.0:9444", Issuer: options.Issuer, Audience: options.Audience,
		TenantID: options.TenantID, ProjectID: options.ProjectID, TokenTTL: maximumOIDCTokenTTL,
		CredentialFile: containerPath("secrets/oidc-token-credential"), SigningKeyFile: containerPath("secrets/oidc-signing-key.pem"),
		JWKSFile: containerPath("config/jwks.json"), TLSCertificateFile: containerPath("config/oidc.pem"), TLSKeyFile: containerPath("secrets/oidc-key.pem"),
	}, "", "  ")
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("marshal OIDC config: %w", err)
	}
	if err := writer.write("oidc_config", "config/oidc.json", append(oidcConfig, '\n'), 0o644); err != nil {
		return BootstrapManifest{}, err
	}

	manifest := BootstrapManifest{
		Issuer: options.Issuer, Audience: options.Audience, TenantID: options.TenantID, ProjectID: options.ProjectID,
		OnlineAgentID: options.OnlineAgentID, OfflineAgentID: options.OfflineAgentID, Files: writer.files,
	}
	manifest.Files["manifest"] = filepath.Join(root, "manifest.json")
	manifestBody, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return BootstrapManifest{}, fmt.Errorf("marshal bootstrap manifest: %w", err)
	}
	if err := writer.writeAt(manifest.Files["manifest"], append(manifestBody, '\n'), 0o644); err != nil {
		return BootstrapManifest{}, err
	}
	return manifest, nil
}

func validateBootstrapOptions(options BootstrapOptions) (string, error) {
	if strings.TrimSpace(options.Root) == "" || !filepath.IsAbs(options.Root) {
		return "", errors.New("bootstrap root must be an absolute path")
	}
	root := filepath.Clean(options.Root)
	volumeRoot := filepath.Clean(filepath.VolumeName(root) + string(filepath.Separator))
	if root == volumeRoot {
		return "", errors.New("bootstrap root must not be a filesystem root")
	}
	issuer, err := url.Parse(options.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || strings.TrimSuffix(options.Issuer, "/") != options.Issuer {
		return "", errors.New("bootstrap issuer must be a canonical HTTPS URL")
	}
	for name, value := range map[string]string{"audience": options.Audience, "tenant ID": options.TenantID, "project ID": options.ProjectID, "online Agent ID": options.OnlineAgentID, "offline Agent ID": options.OfflineAgentID} {
		if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "/\\\r\n\t") {
			return "", fmt.Errorf("bootstrap %s is invalid", name)
		}
	}
	if options.OnlineAgentID == options.OfflineAgentID || options.Now.IsZero() {
		return "", errors.New("bootstrap Agent IDs and timestamp are invalid")
	}
	return root, nil
}

func prepareBootstrapRoot(root string) error {
	if info, err := os.Lstat(root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("bootstrap root must be a non-symlink directory")
		}
		entries, readErr := os.ReadDir(root)
		if readErr != nil {
			return fmt.Errorf("inspect bootstrap root: %w", readErr)
		}
		if len(entries) != 0 {
			return errors.New("bootstrap root must not contain existing files")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect bootstrap root: %w", err)
	} else if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create bootstrap root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return fmt.Errorf("harden bootstrap root: %w", err)
	}
	return nil
}

func newAuthority(randomSource io.Reader, commonName string, now time.Time) (generatedAuthority, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(randomSource)
	if err != nil {
		return generatedAuthority{}, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial(randomSource)
	if err != nil {
		return generatedAuthority{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(randomSource, template, template, publicKey, privateKey)
	if err != nil {
		return generatedAuthority{}, fmt.Errorf("create CA certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return generatedAuthority{}, fmt.Errorf("parse CA certificate: %w", err)
	}
	return generatedAuthority{certificate: certificate, privateKey: privateKey, certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

func newSignedCertificate(randomSource io.Reader, authority generatedAuthority, commonName string, dnsNames []string, rawURI string, client, rsaKey bool, now time.Time) (generatedCertificate, error) {
	var publicKey, privateKey any
	if rsaKey {
		key, err := rsa.GenerateKey(randomSource, 2048)
		if err != nil {
			return generatedCertificate{}, fmt.Errorf("generate RSA TLS key: %w", err)
		}
		publicKey, privateKey = &key.PublicKey, key
	} else {
		keyPublic, keyPrivate, err := ed25519.GenerateKey(randomSource)
		if err != nil {
			return generatedCertificate{}, fmt.Errorf("generate TLS key: %w", err)
		}
		publicKey, privateKey = keyPublic, keyPrivate
	}
	serial, err := randomSerial(randomSource)
	if err != nil {
		return generatedCertificate{}, err
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if client {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	keyUsage := x509.KeyUsageDigitalSignature
	if rsaKey {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: keyUsage, ExtKeyUsage: usage, BasicConstraintsValid: true, DNSNames: append([]string(nil), dnsNames...),
	}
	if rawURI != "" {
		identity, parseErr := url.Parse(rawURI)
		if parseErr != nil || !identity.IsAbs() || identity.Host == "" {
			return generatedCertificate{}, errors.New("parse certificate identity URI")
		}
		template.URIs = []*url.URL{identity}
	}
	der, err := x509.CreateCertificate(randomSource, template, authority.certificate, publicKey, authority.privateKey)
	if err != nil {
		return generatedCertificate{}, fmt.Errorf("create TLS certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return generatedCertificate{}, fmt.Errorf("marshal TLS key: %w", err)
	}
	return generatedCertificate{
		certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		privateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	}, nil
}

func randomSerial(randomSource io.Reader) (*big.Int, error) {
	contents := make([]byte, 16)
	if _, err := io.ReadFull(randomSource, contents); err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	contents[0] &= 0x7f
	if allZero(contents) {
		contents[len(contents)-1] = 1
	}
	return new(big.Int).SetBytes(contents), nil
}

func randomPrintableSecret(randomSource io.Reader, length int) ([]byte, error) {
	contents := make([]byte, length)
	if _, err := io.ReadFull(randomSource, contents); err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(contents)
	return []byte(encoded[:length]), nil
}

func marshalJWKS(publicKey *rsa.PublicKey) ([]byte, error) {
	if publicKey == nil || publicKey.N == nil || publicKey.E <= 0 {
		return nil, errors.New("OIDC public key is invalid")
	}
	exponent := make([]byte, 4)
	binary.BigEndian.PutUint32(exponent, uint32(publicKey.E))
	exponent = bytesTrimLeadingZero(exponent)
	value := map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": oidcKeyID(publicKey),
		"n": base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(exponent),
	}}}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal JWKS: %w", err)
	}
	return append(body, '\n'), nil
}

func oidcKeyID(publicKey *rsa.PublicKey) string {
	digest := sha256.Sum256(publicKey.N.Bytes())
	return "acceptance-" + hex.EncodeToString(digest[:8])
}

func bytesTrimLeadingZero(value []byte) []byte {
	for len(value) > 1 && value[0] == 0 {
		value = value[1:]
	}
	return value
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func agentAssignment(options BootstrapOptions, displayName, host, state string) map[string]any {
	return map[string]any{
		"tenant_id": options.TenantID, "project_id": options.ProjectID, "display_name": displayName, "host": host,
		"labels": map[string]string{"environment": "acceptance", "connectivity_fixture": state},
	}
}

func rogueAgentAssignment(options BootstrapOptions, displayName, host string) map[string]any {
	return map[string]any{
		"tenant_id": options.TenantID, "project_id": options.ProjectID, "display_name": displayName, "host": host,
		"labels": map[string]string{"environment": "rogue", "acceptance_role": "negative-identity"},
	}
}

type bootstrapWriter struct {
	root   string
	random io.Reader
	files  map[string]string
}

func (writer *bootstrapWriter) write(name, relative string, contents []byte, mode os.FileMode) error {
	if name == "" || relative == "" {
		return errors.New("bootstrap output name and path are required")
	}
	path := filepath.Join(writer.root, filepath.FromSlash(relative))
	rootRelative, err := filepath.Rel(writer.root, path)
	if err != nil || rootRelative == ".." || strings.HasPrefix(rootRelative, ".."+string(filepath.Separator)) {
		return errors.New("bootstrap output escapes root")
	}
	if err := writer.writeAt(path, contents, mode); err != nil {
		return err
	}
	writer.files[name] = path
	return nil
}

func (writer *bootstrapWriter) writePrivateKey(name, relative string, privateKey any) error {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", name, err)
	}
	return writer.write(name, relative, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func (writer *bootstrapWriter) writePublicKey(name, relative string, publicKey any) error {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", name, err)
	}
	return writer.write(name, relative, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
}

func (writer *bootstrapWriter) writeAt(path string, contents []byte, mode os.FileMode) error {
	if _, err := os.Lstat(path); err == nil {
		return errors.New("bootstrap output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect bootstrap output: %w", err)
	}
	randomSuffix := make([]byte, 8)
	if _, err := io.ReadFull(writer.random, randomSuffix); err != nil {
		return fmt.Errorf("generate bootstrap temporary name: %w", err)
	}
	temporary := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(randomSuffix))
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create bootstrap temporary file: %w", err)
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(contents); err != nil {
		return fmt.Errorf("write bootstrap temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync bootstrap temporary file: %w", err)
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("harden bootstrap temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close bootstrap temporary file: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("install bootstrap output: %w", err)
	}
	removeTemporary = false
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(path))
		if err != nil {
			return fmt.Errorf("open bootstrap output directory: %w", err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return fmt.Errorf("sync bootstrap output directory: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close bootstrap output directory: %w", closeErr)
		}
	}
	return nil
}
