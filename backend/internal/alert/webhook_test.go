package alert

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWebhookRejectsHTTPPrivateIPAndUnlistedHost(t *testing.T) {
	resolver := staticIPResolver{"allowed.example": {net.ParseIP("203.0.113.10")}}
	allowlist := exactAllowlist{"allowed.example": true}
	for _, rawURL := range []string{"http://allowed.example/hook", "https://127.0.0.1/hook", "https://[::1]/hook", "https://blocked.example/hook"} {
		require.Error(t, ValidateWebhookURL(rawURL, allowlist, resolver), rawURL)
	}
}

func TestWebhookDialRevalidatesAndPinsPublicAddress(t *testing.T) {
	allowlist := exactAllowlist{"allowed.example": true}
	address, err := validatedWebhookDialAddress(context.Background(), "allowed.example:443", allowlist, staticIPResolver{"allowed.example": {net.ParseIP("203.0.113.10")}})
	require.NoError(t, err)
	require.Equal(t, "203.0.113.10:443", address)

	_, err = validatedWebhookDialAddress(context.Background(), "allowed.example:443", allowlist, staticIPResolver{"allowed.example": {net.ParseIP("10.0.0.1")}})
	require.Error(t, err)
}

func TestWebhookRejectsRedirectAndUsesTenSecondTimeout(t *testing.T) {
	resolver := staticIPResolver{"allowed.example": {net.ParseIP("203.0.113.10")}}
	transport := &recordingRoundTripper{response: &http.Response{StatusCode: http.StatusFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("redirect body"))}}
	channel := NewWebhookChannel(exactAllowlist{"allowed.example": true}, resolver, staticSecretResolver{value: []byte("secret")}, transport)

	err := channel.Deliver(context.Background(), DeliveryRequest{Target: "https://allowed.example/hook", SecretRef: "vault://hook", Body: `{"event":"event-1"}`})
	require.Error(t, err)
	require.False(t, IsRetryableDeliveryError(err))
	require.Equal(t, 10*time.Second, channel.client.Timeout)
	require.NotNil(t, channel.client.CheckRedirect)
}

func TestWebhookSignsCanonicalBodyWithReferencedSecret(t *testing.T) {
	resolver := staticIPResolver{"allowed.example": {net.ParseIP("203.0.113.10")}}
	transport := &recordingRoundTripper{response: &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}}
	channel := NewWebhookChannel(exactAllowlist{"allowed.example": true}, resolver, staticSecretResolver{value: []byte("secret")}, transport)
	channel.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	body := `{"event":"event-1","state":"firing"}`

	require.NoError(t, channel.Deliver(context.Background(), DeliveryRequest{Target: "https://allowed.example/hook", SecretRef: "vault://hook", Body: body}))
	require.Equal(t, "1800000000", transport.request.Header.Get("X-DBPilot-Timestamp"))
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte(body))
	require.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), transport.request.Header.Get("X-DBPilot-Signature"))
	require.Equal(t, body, transport.body)
}

func TestWebhookOnlyRetries408429And5xx(t *testing.T) {
	for _, test := range []struct {
		status    int
		retryable bool
	}{{400, false}, {408, true}, {429, true}, {500, true}, {502, true}} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			resolver := staticIPResolver{"allowed.example": {net.ParseIP("203.0.113.10")}}
			transport := &recordingRoundTripper{response: &http.Response{StatusCode: test.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("sensitive response body"))}}
			channel := NewWebhookChannel(exactAllowlist{"allowed.example": true}, resolver, staticSecretResolver{value: []byte("secret")}, transport)
			err := channel.Deliver(context.Background(), DeliveryRequest{Target: "https://allowed.example/hook", SecretRef: "secret-ref", Body: "{}"})
			require.Error(t, err)
			require.Equal(t, test.retryable, IsRetryableDeliveryError(err))
			require.NotContains(t, err.Error(), "sensitive response body")
		})
	}
}

func TestSMTPChannelRequiresTLSAndResolvesPasswordReference(t *testing.T) {
	sender := &recordingSMTPSender{}
	channel := NewSMTPChannel(SMTPConfig{Address: "smtp.example:587", ServerName: "smtp.example", Username: "dbpilot", From: "alerts@example"}, staticSecretResolver{value: []byte("password")}, sender)

	require.NoError(t, channel.Deliver(context.Background(), DeliveryRequest{Target: "dba@example", SecretRef: "vault://smtp", Subject: "alert", Body: "firing"}))
	require.True(t, sender.message.RequireTLS)
	require.Equal(t, "password", string(sender.message.Password))
	require.Equal(t, "vault://smtp", sender.resolvedRef)
}

type exactAllowlist map[string]bool

func (allowlist exactAllowlist) Allows(host string) bool { return allowlist[host] }

type staticIPResolver map[string][]net.IP

func (resolver staticIPResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	return resolver[host], nil
}

type staticSecretResolver struct {
	value []byte
	ref   string
}

func (resolver staticSecretResolver) Resolve(_ context.Context, ref string) ([]byte, error) {
	return append([]byte(nil), resolver.value...), nil
}

type recordingRoundTripper struct {
	request  *http.Request
	body     string
	response *http.Response
}

func (transport *recordingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.request = request
	body, _ := io.ReadAll(request.Body)
	transport.body = string(body)
	return transport.response, nil
}

type recordingSMTPSender struct {
	message     SMTPMessage
	resolvedRef string
}

func (sender *recordingSMTPSender) Send(_ context.Context, message SMTPMessage) error {
	sender.message = message
	sender.message.Password = append([]byte(nil), message.Password...)
	sender.resolvedRef = message.SecretRef
	return nil
}
