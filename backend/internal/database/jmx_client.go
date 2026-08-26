package database

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultJMXTimeout  = 30 * time.Second
	maximumJMXBody     = 4 << 20
	maximumJMXAttempts = 3
	jmxRetryBaseDelay  = 10 * time.Millisecond
)

var errJMXRedirect = errors.New("JMX redirects are not permitted")

type jmxClient struct {
	resolver SecretResolver
	config   JMXClientConfig
}

// NewJMXClient creates a client that resolves credentials and TLS material at
// request time. It never stores resolved values beyond the request lifetime.
func NewJMXClient(resolver SecretResolver, config JMXClientConfig) JMXClient {
	return &jmxClient{resolver: resolver, config: config}
}

func (client *jmxClient) Fetch(ctx context.Context, endpoint Endpoint, allowlist BeanAllowlist) ([]JMXBean, error) {
	if ctx == nil {
		return nil, errors.New("JMX fetch context is required")
	}
	if isNilInterface(client.resolver) {
		return nil, errors.New("JMX runtime secret resolver is required")
	}
	target, err := validatedJMXURL(endpoint.URL)
	if err != nil {
		return nil, err
	}
	if err := validateJMXTLSURL(target, client.config.TLS); err != nil {
		return nil, err
	}
	timeout := client.config.Timeout
	if timeout == 0 {
		timeout = defaultJMXTimeout
	}
	if timeout < 0 || timeout > maximumOperationTimeout {
		return nil, errors.New("JMX timeout must be greater than zero and at most one minute")
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tlsConfig, err := resolveJMXTLS(requestContext, client.resolver, client.config.TLS, target.Hostname())
	if err != nil {
		return nil, err
	}
	credential, err := resolveJMXCredential(requestContext, client.resolver, client.config.SecretRef)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       tlsConfig,
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errJMXRedirect
		},
	}
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, errors.New("create JMX request")
	}
	request.Header.Set("Accept", "application/json")
	if len(credential) != 0 {
		request.Header.Set("Authorization", "Bearer "+string(credential))
	}
	for attempt := 0; attempt < maximumJMXAttempts; attempt++ {
		response, requestErr := httpClient.Do(request)
		if requestErr != nil {
			if response != nil {
				response.Body.Close()
			}
			if errors.Is(requestErr, errJMXRedirect) {
				return nil, errJMXRedirect
			}
			if requestContext.Err() != nil {
				return nil, requestContext.Err()
			}
			if attempt+1 < maximumJMXAttempts && waitForJMXRetry(requestContext, attempt) == nil {
				continue
			}
			if requestContext.Err() != nil {
				return nil, requestContext.Err()
			}
			return nil, errors.New("JMX request failed")
		}
		if isTransientJMXStatus(response.StatusCode) && attempt+1 < maximumJMXAttempts {
			response.Body.Close()
			if err := waitForJMXRetry(requestContext, attempt); err != nil {
				return nil, err
			}
			continue
		}
		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			response.Body.Close()
			return nil, fmt.Errorf("JMX request returned HTTP status %d", response.StatusCode)
		}

		var payload struct {
			Beans []map[string]JSONValue `json:"beans"`
		}
		decoder := json.NewDecoder(io.LimitReader(response.Body, maximumJMXBody))
		err := decoder.Decode(&payload)
		response.Body.Close()
		if err != nil {
			return nil, errors.New("decode JMX response")
		}
		return filterJMXBeans(payload.Beans, allowlist), nil
	}
	return nil, errors.New("JMX request failed")
}

// FetchZooKeeperMonitor performs the sole non-JMX compatibility read. Its URL
// and parsed fields remain fixed in the ZooKeeper adapter.
func (client *jmxClient) FetchZooKeeperMonitor(ctx context.Context, endpoint Endpoint) (map[string]JSONValue, error) {
	target, err := validatedZooKeeperMonitorURL(endpoint.URL)
	if err != nil {
		return nil, err
	}
	if ctx == nil || isNilInterface(client.resolver) {
		return nil, errors.New("ZooKeeper monitor runtime client is required")
	}
	timeout := client.config.Timeout
	if timeout == 0 {
		timeout = defaultJMXTimeout
	}
	if timeout < 0 || timeout > maximumOperationTimeout {
		return nil, errors.New("ZooKeeper monitor timeout must be greater than zero and at most one minute")
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tlsConfig, err := resolveJMXTLS(requestContext, client.resolver, client.config.TLS, target.Hostname())
	if err != nil {
		return nil, err
	}
	credential, err := resolveJMXCredential(requestContext, client.resolver, client.config.SecretRef)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: timeout}).DialContext, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errJMXRedirect }}
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, errors.New("create ZooKeeper monitor request")
	}
	request.Header.Set("Accept", "application/json, text/plain")
	if len(credential) != 0 {
		request.Header.Set("Authorization", "Bearer "+string(credential))
	}
	response, err := httpClient.Do(request)
	if err != nil {
		if requestContext.Err() != nil {
			return nil, requestContext.Err()
		}
		return nil, errors.New("ZooKeeper monitor request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("ZooKeeper monitor returned HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumJMXBody))
	if err != nil {
		return nil, errors.New("read ZooKeeper monitor response")
	}
	return parseZooKeeperMonitor(body)
}

func validatedZooKeeperMonitorURL(raw string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Scheme == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != zooKeeperCompatibilityPath {
		return nil, errors.New("ZooKeeper monitor endpoint must use the read-only monitor path")
	}
	return parsed, nil
}

func validatedJMXURL(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) != raw || raw == "" {
		return nil, errors.New("JMX endpoint is required")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/jmx" {
		return nil, errors.New("JMX endpoint must be an HTTP(S) URL with read-only /jmx path")
	}
	return parsed, nil
}

func validateJMXTLSURL(target *url.URL, config TLSConfig) error {
	if err := validateTLSConfig(config); err != nil {
		return errors.New("JMX TLS configuration is invalid")
	}
	if config.Enabled && target.Scheme != "https" {
		return errors.New("JMX TLS requires an HTTPS endpoint")
	}
	return nil
}

func isTransientJMXStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func waitForJMXRetry(ctx context.Context, attempt int) error {
	delay := jmxRetryBaseDelay << attempt
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func resolveJMXCredential(ctx context.Context, resolver SecretResolver, reference string) ([]byte, error) {
	if reference == "" {
		return nil, nil
	}
	if err := validateSecretRef(reference); err != nil {
		return nil, errors.New("JMX credential secret reference is invalid")
	}
	credential, err := resolver.ResolveSecret(ctx, reference)
	if err != nil || len(credential) == 0 {
		return nil, errors.New("resolve JMX credential secret")
	}
	return credential, nil
}

func resolveJMXTLS(ctx context.Context, resolver SecretResolver, config TLSConfig, endpointHost string) (*tls.Config, error) {
	if err := validateTLSConfig(config); err != nil {
		return nil, errors.New("JMX TLS configuration is invalid")
	}
	if !config.Enabled {
		if config.ServerName != "" || config.CASecretRef != "" || config.CertificateSecretRef != "" || config.KeySecretRef != "" {
			return nil, errors.New("JMX TLS settings require TLS to be enabled")
		}
		return nil, nil
	}
	serverName := config.ServerName
	if serverName == "" {
		serverName = endpointHost
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if config.CASecretRef != "" {
		certificateAuthority, err := resolveRuntimeSecret(ctx, resolver, config.CASecretRef, "CA")
		if err != nil {
			return nil, errors.New("resolve JMX TLS CA secret")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(certificateAuthority) {
			return nil, errors.New("JMX TLS CA certificate is invalid")
		}
		tlsConfig.RootCAs = pool
	}
	if config.CertificateSecretRef != "" {
		certificatePEM, err := resolveRuntimeSecret(ctx, resolver, config.CertificateSecretRef, "client certificate")
		if err != nil {
			return nil, errors.New("resolve JMX TLS client certificate secret")
		}
		keyPEM, err := resolveRuntimeSecret(ctx, resolver, config.KeySecretRef, "client key")
		if err != nil {
			return nil, errors.New("resolve JMX TLS client key secret")
		}
		certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
		if err != nil {
			return nil, errors.New("JMX TLS client certificate is invalid")
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return tlsConfig, nil
}

func filterJMXBeans(rawBeans []map[string]JSONValue, allowlist BeanAllowlist) []JMXBean {
	beans := make([]JMXBean, 0, len(rawBeans))
	for _, rawBean := range rawBeans {
		name := stringJSONValue(rawBean["name"])
		properties, allowed := allowlistedJMXProperties(allowlist, name)
		if !allowed {
			beans = append(beans, JMXBean{Name: name, Attributes: map[string]JSONValue{}})
			continue
		}
		attributes := make(map[string]JSONValue, len(properties))
		for property := range properties {
			if value, found := rawBean[property]; found {
				attributes[property] = append(JSONValue(nil), value...)
			}
		}
		beans = append(beans, JMXBean{Name: name, Attributes: attributes})
	}
	return beans
}

func stringJSONValue(value JSONValue) string {
	var text string
	if json.Unmarshal(value, &text) != nil {
		return ""
	}
	return text
}

// NormalizeJMXBeans converts only fixed allowlisted JMX values to DBPilot's
// common metric representation. Unknown beans and malformed fields are
// reported as statuses instead of being guessed or remapped.
func NormalizeJMXBeans(beans []JMXBean, allowlist BeanAllowlist, labels JMXMetricLabels) ([]MetricSample, []ParseIssue, error) {
	if err := validateJMXAllowlist(allowlist); err != nil {
		return nil, nil, err
	}
	timestamp := labels.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	samples := make([]MetricSample, 0)
	issues := make([]ParseIssue, 0)
	for _, bean := range beans {
		properties, allowed := allowlistedJMXProperties(allowlist, bean.Name)
		if !allowed {
			issues = append(issues, ParseIssue{Bean: bean.Name, Status: JMXParseUnknownBean})
			continue
		}
		for property, definition := range properties {
			raw, found := bean.Attributes[property]
			if !found {
				issues = append(issues, ParseIssue{Bean: bean.Name, Property: property, Status: JMXParseMissingAttribute})
				continue
			}
			value, ok := numericJMXValue(raw)
			if !ok {
				issues = append(issues, ParseIssue{Bean: bean.Name, Property: property, Status: JMXParseInvalidAttribute})
				continue
			}
			multiplier := definition.Multiplier
			if multiplier == 0 {
				multiplier = 1
			}
			samples = append(samples, MetricSample{Cluster: labels.Cluster, Component: labels.Component, Role: labels.Role, Host: labels.Host, Instance: labels.Instance, MetricName: definition.MetricName, Value: value * multiplier, Unit: definition.Unit, Timestamp: timestamp})
		}
	}
	return samples, issues, nil
}

func validateJMXAllowlist(allowlist BeanAllowlist) error {
	for bean, properties := range allowlist {
		if strings.TrimSpace(bean) != bean || bean == "" || (strings.Contains(bean, "*") && (!strings.HasSuffix(bean, "*") || strings.Count(bean, "*") != 1 || len(strings.TrimSuffix(bean, "*")) == 0)) {
			return errors.New("JMX bean allowlist contains an invalid name")
		}
		for property, definition := range properties {
			if strings.TrimSpace(property) != property || property == "" || strings.TrimSpace(definition.MetricName) != definition.MetricName || definition.MetricName == "" || math.IsNaN(definition.Multiplier) || math.IsInf(definition.Multiplier, 0) {
				return errors.New("JMX property allowlist contains an invalid mapping")
			}
		}
	}
	return nil
}

// allowlistedJMXProperties admits exact bean names and a single terminal
// wildcard. Wildcards are fixed adapter-owned bean prefixes, not caller input;
// Hadoop and ZooKeeper include a runtime port or server id in some bean names.
func allowlistedJMXProperties(allowlist BeanAllowlist, bean string) (BeanProperties, bool) {
	if properties, ok := allowlist[bean]; ok {
		return properties, true
	}
	for template, properties := range allowlist {
		if strings.HasSuffix(template, "*") && strings.HasPrefix(bean, strings.TrimSuffix(template, "*")) {
			return properties, true
		}
	}
	return nil, false
}

func numericJMXValue(raw JSONValue) (float64, bool) {
	var number float64
	if err := json.Unmarshal(raw, &number); err == nil && !math.IsNaN(number) && !math.IsInf(number, 0) {
		return number, true
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, false
	}
	number, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, false
	}
	return number, true
}
