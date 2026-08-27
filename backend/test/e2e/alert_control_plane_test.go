package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	telemetryv1 "dbpilot.local/platform/gen/telemetry/v1"
	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/spool"
	"dbpilot.local/platform/internal/telemetry"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/yaml.v3"
)

var scopeT1P1 = alert.Scope{TenantID: "t1", ProjectID: "p1"}

// A no-op gRPC listener, package-private service call, missing notification
// channel, or missing scope check makes this test fail. All lifecycle state is
// observed through the production HTTPS and mTLS gRPC listeners.
func TestAlertControlPlaneLifecycle(t *testing.T) {
	requireEnv(t, "DBPILOT_ALERT_E2E")
	api := newE2EClient(t)

	template := api.CreateTemplate(scopeT1P1, map[string]any{
		"name": "fixture", "subject": "DBPilot {{event.state}}", "body": "event={{event.id}} aggregate={{evidence.aggregate}}",
	})
	policies := []alert.NotificationPolicy{
		api.CreatePolicy(scopeT1P1, policyBody("in-app", "in_app", "fixture-operator", "", template.ID)),
		api.CreatePolicy(scopeT1P1, policyBody("smtp", "smtp", "dba@example.test", "env://ALERT_SMTP_PASSWORD", template.ID)),
		api.CreatePolicy(scopeT1P1, policyBody("webhook", "webhook", "https://webhook-sink:8443/hook/retry", "env://ALERT_WEBHOOK_SECRET", template.ID)),
	}
	policyIDs := make([]string, 0, len(policies))
	for _, configured := range policies {
		policyIDs = append(policyIDs, configured.ID)
	}
	rule := api.CreateRule(scopeT1P1, thresholdRule("db.connections", 80, policyIDs))
	agent := newMTLSAgent(t, "agent-t1-p1")
	agent.PushMetric(metricEnvelope("db.connections", 91))
	t.Log("EVIDENCE agent-mtls metric_envelope=accepted")
	event := api.EventEventually(scopeT1P1, rule.ID, alert.EventFiring, 30*time.Second)
	t.Logf("EVIDENCE firing event=%s fingerprint=%s", event.ID, event.Fingerprint)

	retryScheduled := api.DeliveryEventually(scopeT1P1, event.ID, policies[2].ID, alert.DeliveryRetryScheduled, alert.EventPending, 1, 10*time.Second)
	require.NotEmpty(t, retryScheduled.FailureClass)
	deliveries := api.DeliveriesEventually(scopeT1P1, event.ID, alert.EventFiring, policies, 90*time.Second)
	deliveryForPolicy(t, deliveries, policies[2].ID, alert.DeliveryDelivered, alert.EventFiring)
	retriedWebhook := api.DeliveryEventually(scopeT1P1, event.ID, policies[2].ID, alert.DeliveryDelivered, alert.EventPending, 2, 90*time.Second)
	fixtureAfterRetry := api.FixtureStatus()
	require.GreaterOrEqual(t, fixtureAfterRetry.WebhookAttempts, 3, "one failed pending delivery, one firing delivery, and the scheduled retry must reach the sink")
	t.Logf("EVIDENCE notifications in_app=delivered smtp=delivered webhook=delivered failure=%s retry_attempts=%d sink_attempts=%d", retryScheduled.FailureClass, retriedWebhook.Attempts, fixtureAfterRetry.WebhookAttempts)

	silencedRule := api.CreateRule(scopeT1P1, thresholdRule("db.silenced.connections", 80, policyIDs))
	silencedFingerprint := alert.EventFingerprint(scopeT1P1, silencedRule.ID, map[string]string{"agent_id": "agent-t1-p1", "resource": "fixture-db", "role": "primary"})
	api.CreateSilence(scopeT1P1, fingerprintSilence(silencedFingerprint))
	agent.PushMetric(metricEnvelope("db.silenced.connections", 92))
	silencedEvent := api.EventEventually(scopeT1P1, silencedRule.ID, alert.EventFiring, 30*time.Second)
	require.Equal(t, silencedFingerprint, silencedEvent.Fingerprint)
	api.DeliveryEventually(scopeT1P1, silencedEvent.ID, policies[0].ID, alert.DeliverySuppressed, alert.EventFiring, 1, 30*time.Second)
	t.Logf("EVIDENCE silence fingerprint=%s firing_delivery=suppressed", silencedFingerprint)

	agent.PushMetric(metricEnvelope("db.silenced.connections", 1))
	resolved := api.EventEventually(scopeT1P1, silencedRule.ID, alert.EventResolved, 30*time.Second)
	t.Logf("EVIDENCE recovery event=%s state=%s", resolved.ID, resolved.State)

	status := api.GetAs(memberClient(t), eventPath("t1", "p1", event.ID))
	defer status.Body.Close()
	require.Equal(t, http.StatusForbidden, status.StatusCode)
	t.Log("EVIDENCE authorization cross_project_status=403")

	fixture := api.FixtureStatus()
	require.GreaterOrEqual(t, fixture.WebhookAttempts, 2)
	require.GreaterOrEqual(t, fixture.SMTPMessages, 1)
	require.NotEmpty(t, fixture.WebhookBodyHashes)
	require.NotEmpty(t, fixture.SMTPBodyHashes)
}

// TestPrepareAlertControlPlaneFixture is an explicit verifier-only helper. It
// creates short-lived test identities and signed policy files without printing
// private keys, passwords, notification bodies, or evidence.
func TestPrepareAlertControlPlaneFixture(t *testing.T) {
	directory := os.Getenv("DBPILOT_ALERT_PREPARE_DIR")
	if directory == "" {
		t.Skip("DBPILOT_ALERT_PREPARE_DIR required")
	}
	password := os.Getenv("DBPILOT_ALERT_POSTGRES_PASSWORD")
	require.NotEmpty(t, password)
	require.NoError(t, os.MkdirAll(filepath.Join(directory, "spool"), 0o700))

	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DBPilot alert e2e CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(4 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	server := signedFixtureCertificate(t, 2, "controlplane", []string{"controlplane", "webhook-sink", "smtp-sink"}, "", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ca, caPrivate)
	agent := signedFixtureCertificate(t, 3, "agent-t1-p1", nil, "spiffe://dbpilot/agent/agent-t1-p1", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ca, caPrivate)
	admin := signedFixtureCertificate(t, 4, "fixture-admin", nil, "spiffe://dbpilot.example/operators/admin", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ca, caPrivate)
	member := signedFixtureCertificate(t, 5, "fixture-member-p2", nil, "spiffe://dbpilot.example/operators/member-p2", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ca, caPrivate)

	writeFixtureFile(t, directory, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	writeTLSKeyPair(t, directory, "server", server)
	writeTLSKeyPair(t, directory, "agent", agent)
	writeTLSKeyPair(t, directory, "admin", admin)
	writeTLSKeyPair(t, directory, "member", member)

	policyPublic, policyPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	policyDER, err := x509.MarshalPKIXPublicKey(policyPublic)
	require.NoError(t, err)
	envelope, err := policy.Sign(policyPrivate, policy.Policy{
		AgentID: "agent-t1-p1", Version: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(3 * time.Hour),
		Sources: []policy.Source{{ID: "host", Kind: policy.SourceHostMetrics, Interval: 5 * time.Second}},
		Limits:  policy.Limits{MaxSpoolBytes: 32 << 20, MaxBatchBytes: 1 << 20, MaxEventsPerSec: 1000},
	})
	require.NoError(t, err)
	policyJSON, err := json.Marshal(envelope)
	require.NoError(t, err)
	var roundTrip policy.SignatureEnvelope
	require.NoError(t, json.Unmarshal(policyJSON, &roundTrip))
	verified, err := policy.VerifyAndValidate(policyPublic, roundTrip, now, policy.ValidationEnvironment{})
	require.NoError(t, err)
	require.Equal(t, "agent-t1-p1", verified.AgentID)
	writeFixtureFile(t, directory, "policy-public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: policyDER}))
	writeFixtureFile(t, directory, "policy.json", policyJSON)

	agentConfig := map[string]any{
		"agent_id": "agent-t1-p1", "server_address": "controlplane:9443", "ca_file": "/runtime/ca.pem", "cert_file": "/runtime/agent.pem", "key_file": "/runtime/agent-key.pem",
		"policy_public_key_file": "/runtime/policy-public.pem", "policy_file": "/runtime/policy.json", "data_directory": "/runtime/spool", "file_collection_enabled": false,
	}
	writeYAML(t, directory, "agent.yaml", agentConfig)

	databaseURL := (&url.URL{Scheme: "postgres", User: url.UserPassword("dbpilot", password), Host: "postgres:5432", Path: "/dbpilot", RawQuery: "sslmode=disable"}).String()
	controlplaneConfig := map[string]any{
		"database_url": databaseURL,
		"http":         map[string]any{"address": "0.0.0.0:8443", "tls": map[string]any{"cert_file": "/runtime/server.pem", "key_file": "/runtime/server-key.pem", "client_ca_file": "/runtime/ca.pem"}},
		"grpc":         map[string]any{"address": "0.0.0.0:9443", "tls": map[string]any{"cert_file": "/runtime/server.pem", "key_file": "/runtime/server-key.pem", "client_ca_file": "/runtime/ca.pem"}},
		"identity": map[string]any{"mode": "mtls", "principals": map[string]any{
			"spiffe://dbpilot.example/operators/admin":     map[string]any{"subject": "fixture-admin", "platform_admin": true},
			"spiffe://dbpilot.example/operators/member-p2": map[string]any{"subject": "fixture-member-p2", "projects": []any{map[string]any{"tenant_id": "t1", "project_id": "p2"}}},
		}},
		"agents":            map[string]any{"agent-t1-p1": map[string]any{"tenant_id": "t1", "project_id": "p1"}},
		"evaluation_scopes": []any{map[string]any{"tenant_id": "t1", "project_id": "p1"}},
		"webhook_allowlist": []string{"webhook-sink"}, "event_url_base": "https://controlplane:8443", "evaluation_every": "1s", "retry_every": "1s",
		"smtp": map[string]any{"address": "smtp-sink:2465", "server_name": "smtp-sink", "username": "fixture", "from": "dbpilot@example.test", "implicit_tls": true},
	}
	writeYAML(t, directory, "controlplane.yaml", controlplaneConfig)
}

// TestKylinAgentPolicyApply preserves the production Engine error boundary in
// verifier output instead of collapsing candidate failures into Agent startup.
func TestKylinAgentPolicyApply(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_KYLIN_POLICY_CHECK") != "1" {
		t.Skip("DBPILOT_ALERT_KYLIN_POLICY_CHECK=1 required")
	}
	workingDirectory, err := os.Getwd()
	require.NoError(t, err)
	require.Equal(t, "/runtime", workingDirectory)
	require.Equal(t, 65532, os.Geteuid())
	storageDirectory := filepath.Join("dbpilot-spool", fmt.Sprintf("%x", sha256.Sum256([]byte("agent-t1-p1"))))
	storageInfo, err := os.Stat(storageDirectory)
	require.NoError(t, err, "the non-root service layout must pre-create the private file-storage directory")
	require.True(t, storageInfo.IsDir())
	require.Zero(t, storageInfo.Mode().Perm()&0o022)
	publicPEM, err := os.ReadFile("/runtime/policy-public.pem")
	require.NoError(t, err)
	block, _ := pem.Decode(publicPEM)
	require.NotNil(t, block)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	public, ok := parsed.(ed25519.PublicKey)
	require.True(t, ok)
	body, err := os.ReadFile("/runtime/policy.json")
	require.NoError(t, err)
	var envelope policy.SignatureEnvelope
	require.NoError(t, json.Unmarshal(body, &envelope))
	verified, err := policy.VerifyAndValidate(public, envelope, time.Now(), policy.ValidationEnvironment{})
	require.NoError(t, err)
	store, err := spool.Open("/runtime/diagnostic-spool", spool.Limits{MaxBytes: 32 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	engine := telemetry.NewEngine(telemetry.NewEmbeddedBuilder(store))
	result, err := engine.Apply(context.Background(), verified)
	require.NoError(t, err, "engine apply result=%+v", result)
	require.Equal(t, telemetry.ApplyActive, result.State)
	require.NoError(t, engine.Stop(context.Background()))
	require.NoError(t, store.Close())
	t.Log("EVIDENCE kylin-policy engine=active uid=65532 storage=private")
}

type e2eClient struct {
	t           *testing.T
	base        string
	fixtureBase string
	http        *http.Client
}

func newE2EClient(t *testing.T) *e2eClient {
	t.Helper()
	return &e2eClient{t: t, base: requiredSetting(t, "DBPILOT_ALERT_HTTP_BASE"), fixtureBase: requiredSetting(t, "DBPILOT_ALERT_FIXTURE_BASE"), http: mtlsHTTPClient(t, requiredSetting(t, "DBPILOT_ALERT_ADMIN_CERT"), requiredSetting(t, "DBPILOT_ALERT_ADMIN_KEY"))}
}

func memberClient(t *testing.T) *http.Client {
	t.Helper()
	return mtlsHTTPClient(t, requiredSetting(t, "DBPILOT_ALERT_MEMBER_CERT"), requiredSetting(t, "DBPILOT_ALERT_MEMBER_KEY"))
}

func mtlsHTTPClient(t *testing.T, certPath, keyPath string) *http.Client {
	t.Helper()
	caPEM, err := os.ReadFile(requiredSetting(t, "DBPILOT_ALERT_CA"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}}}, Timeout: 10 * time.Second}
}

func (api *e2eClient) CreateRule(scope alert.Scope, body map[string]any) alert.AlertRule {
	var result alert.AlertRule
	api.JSON(http.MethodPost, scopePath(scope)+"/rules", body, http.StatusCreated, &result)
	return result
}

func (api *e2eClient) CreateTemplate(scope alert.Scope, body map[string]any) alert.NotificationTemplate {
	var result alert.NotificationTemplate
	api.JSON(http.MethodPost, scopePath(scope)+"/templates", body, http.StatusCreated, &result)
	return result
}

func (api *e2eClient) CreatePolicy(scope alert.Scope, body map[string]any) alert.NotificationPolicy {
	var result alert.NotificationPolicy
	api.JSON(http.MethodPost, scopePath(scope)+"/policies", body, http.StatusCreated, &result)
	return result
}

func (api *e2eClient) CreateSilence(scope alert.Scope, body map[string]any) alert.Silence {
	var result alert.Silence
	api.JSON(http.MethodPost, scopePath(scope)+"/silences", body, http.StatusCreated, &result)
	return result
}

func (api *e2eClient) EventEventually(scope alert.Scope, ruleID string, state alert.EventState, timeout time.Duration) alert.AlertEvent {
	api.t.Helper()
	var found alert.AlertEvent
	require.Eventually(api.t, func() bool {
		var events []alert.AlertEvent
		if !api.TryJSON(http.MethodGet, scopePath(scope)+"/alerts?limit=500", nil, http.StatusOK, &events) {
			return false
		}
		for _, event := range events {
			if event.RuleID == ruleID && event.State == state {
				found = event
				return true
			}
		}
		return false
	}, timeout, time.Second)
	return found
}

func (api *e2eClient) DeliveriesEventually(scope alert.Scope, eventID string, eventState alert.EventState, policies []alert.NotificationPolicy, timeout time.Duration) []alert.NotificationDelivery {
	api.t.Helper()
	var found []alert.NotificationDelivery
	require.Eventually(api.t, func() bool {
		var deliveries []alert.NotificationDelivery
		if !api.TryJSON(http.MethodGet, eventPath(scope.TenantID, scope.ProjectID, eventID)+"/deliveries", nil, http.StatusOK, &deliveries) {
			return false
		}
		for _, configured := range policies {
			matched := false
			for _, delivery := range deliveries {
				if delivery.PolicyID == configured.ID && delivery.Status == alert.DeliveryDelivered && delivery.EventState == eventState {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		found = deliveries
		return true
	}, timeout, time.Second)
	return found
}

func (api *e2eClient) DeliveryEventually(scope alert.Scope, eventID, policyID string, status alert.DeliveryStatus, eventState alert.EventState, minimumAttempts int, timeout time.Duration) alert.NotificationDelivery {
	api.t.Helper()
	var found alert.NotificationDelivery
	require.Eventually(api.t, func() bool {
		var deliveries []alert.NotificationDelivery
		if !api.TryJSON(http.MethodGet, eventPath(scope.TenantID, scope.ProjectID, eventID)+"/deliveries", nil, http.StatusOK, &deliveries) {
			return false
		}
		for _, delivery := range deliveries {
			if delivery.PolicyID == policyID && delivery.Status == status && delivery.EventState == eventState && delivery.Attempts >= minimumAttempts {
				found = delivery
				return true
			}
		}
		return false
	}, timeout, time.Second)
	return found
}

type fixtureStatus struct {
	WebhookAttempts   int      `json:"webhook_attempts"`
	SMTPMessages      int      `json:"smtp_messages"`
	WebhookBodyHashes []string `json:"webhook_body_hashes"`
	SMTPBodyHashes    []string `json:"smtp_body_hashes"`
}

func (api *e2eClient) FixtureStatus() fixtureStatus {
	api.t.Helper()
	request, err := http.NewRequest(http.MethodGet, strings.TrimRight(api.fixtureBase, "/")+"/status", nil)
	require.NoError(api.t, err)
	response, err := api.http.Do(request)
	require.NoError(api.t, err)
	defer response.Body.Close()
	require.Equal(api.t, http.StatusOK, response.StatusCode)
	var status fixtureStatus
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	require.NoError(api.t, decoder.Decode(&status), "fixture status must expose only hashes and counters")
	return status
}

func (api *e2eClient) GetAs(client *http.Client, path string) *http.Response {
	api.t.Helper()
	request, err := http.NewRequest(http.MethodGet, strings.TrimRight(api.base, "/")+path, nil)
	require.NoError(api.t, err)
	response, err := client.Do(request)
	require.NoError(api.t, err)
	return response
}

func (api *e2eClient) JSON(method, path string, body any, want int, target any) {
	api.t.Helper()
	request := api.request(method, path, body)
	response, err := api.http.Do(request)
	require.NoError(api.t, err)
	defer response.Body.Close()
	require.Equal(api.t, want, response.StatusCode, "unexpected API status for %s %s", method, path)
	if target != nil {
		require.NoError(api.t, json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target))
	}
}

func (api *e2eClient) TryJSON(method, path string, body any, want int, target any) bool {
	request := api.request(method, path, body)
	response, err := api.http.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == want && json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target) == nil
}

func (api *e2eClient) request(method, path string, body any) *http.Request {
	api.t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(api.t, err)
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, strings.TrimRight(api.base, "/")+path, reader)
	require.NoError(api.t, err)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

type mtlsAgent struct {
	t      *testing.T
	id     string
	client telemetryv1.TelemetryIngestClient
	close  func()
}

func newMTLSAgent(t *testing.T, id string) *mtlsAgent {
	t.Helper()
	caPEM, err := os.ReadFile(requiredSetting(t, "DBPILOT_ALERT_CA"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))
	certificate, err := tls.LoadX509KeyPair(requiredSetting(t, "DBPILOT_ALERT_AGENT_CERT"), requiredSetting(t, "DBPILOT_ALERT_AGENT_KEY"))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	connection, err := grpc.DialContext(ctx, requiredSetting(t, "DBPILOT_ALERT_GRPC_ADDRESS"), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}})), grpc.WithBlock())
	cancel()
	require.NoError(t, err)
	agent := &mtlsAgent{t: t, id: id, client: telemetryv1.NewTelemetryIngestClient(connection), close: func() { _ = connection.Close() }}
	t.Cleanup(agent.close)
	return agent
}

type metricInput struct {
	Name   string
	Value  float64
	Labels map[string]string
}

func metricEnvelope(name string, value float64) metricInput {
	return metricInput{Name: name, Value: value, Labels: map[string]string{"resource": "fixture-db", "role": "primary"}}
}

func (agent *mtlsAgent) PushMetric(metric metricInput) {
	agent.t.Helper()
	now := time.Now().UTC()
	payload, err := json.Marshal(map[string]any{"samples": []any{map[string]any{"name": metric.Name, "value": metric.Value, "sampled_at": now.Format(time.RFC3339), "labels": metric.Labels}}})
	require.NoError(agent.t, err)
	checksum := sha256.Sum256(payload)
	batchID := fmt.Sprintf("e2e-%d", now.UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ack, err := agent.client.PushMetricBatch(ctx, &telemetryv1.MetricBatch{BatchId: batchID, AgentId: agent.id, SourceId: "e2e", Payload: payload, Checksum: checksum[:], CreatedAtUnix: now.Unix()})
	require.NoError(agent.t, err)
	require.True(agent.t, ack.Accepted)
	require.Equal(agent.t, batchID, ack.BatchId)
}

func thresholdRule(metric string, threshold float64, policies []string) map[string]any {
	return map[string]any{"name": "e2e " + metric, "metric": metric, "aggregation": "avg", "operator": ">", "threshold": threshold, "evaluation_every": "2m", "for": "1s", "missing_data": "resolve", "severity": "critical", "notification_policy_ids": policies, "labels": map[string]string{}, "enabled": true}
}

func policyBody(name, channel, target, secretRef, templateID string) map[string]any {
	return map[string]any{"name": name, "channel": channel, "target": target, "secret_ref": secretRef, "template_id": templateID, "severities": []string{"critical"}, "enabled": true}
}

func fingerprintSilence(fingerprint string) map[string]any {
	now := time.Now().UTC()
	return map[string]any{"matchers": map[string]string{"fingerprint": fingerprint}, "starts_at": now.Add(-time.Minute), "ends_at": now.Add(5 * time.Minute), "reason": "e2e maintenance"}
}

func deliveryForPolicy(t *testing.T, deliveries []alert.NotificationDelivery, policyID string, state alert.DeliveryStatus, eventState alert.EventState) alert.NotificationDelivery {
	t.Helper()
	for _, delivery := range deliveries {
		if delivery.PolicyID == policyID && delivery.Status == state && delivery.EventState == eventState {
			return delivery
		}
	}
	require.FailNow(t, "delivery not found", "policy=%s status=%s event_state=%s", policyID, state, eventState)
	return alert.NotificationDelivery{}
}

func scopePath(scope alert.Scope) string {
	return "/api/v1/tenants/" + url.PathEscape(scope.TenantID) + "/projects/" + url.PathEscape(scope.ProjectID)
}

func eventPath(tenant, project, eventID string) string {
	return "/api/v1/tenants/" + url.PathEscape(tenant) + "/projects/" + url.PathEscape(project) + "/alerts/" + url.PathEscape(eventID)
}

func requiredSetting(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	require.NotEmpty(t, value, "%s is required", name)
	return value
}

func requireEnv(t *testing.T, name string) {
	t.Helper()
	if os.Getenv(name) != "1" {
		t.Skip(name + "=1 required")
	}
}

type fixtureCertificate struct {
	certificateDER []byte
	privateKeyDER  []byte
}

func signedFixtureCertificate(t *testing.T, serial int64, commonName string, dnsNames []string, uriValue string, usages []x509.ExtKeyUsage, ca *x509.Certificate, caKey ed25519.PrivateKey) fixtureCertificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(4 * time.Hour), DNSNames: dnsNames, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
	if uriValue != "" {
		identity, err := url.Parse(uriValue)
		require.NoError(t, err)
		template.URIs = []*url.URL{identity}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	require.NoError(t, err)
	return fixtureCertificate{certificateDER: der, privateKeyDER: keyDER}
}

func writeTLSKeyPair(t *testing.T, directory, name string, certificate fixtureCertificate) {
	t.Helper()
	writeFixtureFile(t, directory, name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.certificateDER}))
	writeFixtureFile(t, directory, name+"-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: certificate.privateKeyDER}))
}

func writeYAML(t *testing.T, directory, name string, value any) {
	t.Helper()
	body, err := yaml.Marshal(value)
	require.NoError(t, err)
	writeFixtureFile(t, directory, name, body)
}

func writeFixtureFile(t *testing.T, directory, name string, body []byte) {
	t.Helper()
	require.False(t, strings.ContainsAny(name, `/\\`))
	err := os.WriteFile(filepath.Join(directory, name), body, 0o600)
	require.False(t, errors.Is(err, os.ErrPermission))
	require.NoError(t, err)
}
