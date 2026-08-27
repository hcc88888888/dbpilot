package alert

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWebhookRejectsHTTPPrivateIPAndUnlistedHost(t *testing.T) {
	resolver := staticIPResolver{"allowed.example": {net.ParseIP("93.184.216.34")}}
	allowlist := exactAllowlist{"allowed.example": true}
	for _, rawURL := range []string{"http://allowed.example/hook", "https://127.0.0.1/hook", "https://[::1]/hook", "https://blocked.example/hook"} {
		require.Error(t, ValidateWebhookURL(rawURL, allowlist, resolver), rawURL)
	}
}

func TestWebhookDialRevalidatesAndPinsPublicAddress(t *testing.T) {
	allowlist := exactAllowlist{"allowed.example": true}
	address, err := validatedWebhookDialAddress(context.Background(), "allowed.example:443", allowlist, staticIPResolver{"allowed.example": {net.ParseIP("93.184.216.34")}})
	require.NoError(t, err)
	require.Equal(t, "93.184.216.34:443", address)

	_, err = validatedWebhookDialAddress(context.Background(), "allowed.example:443", allowlist, staticIPResolver{"allowed.example": {net.ParseIP("10.0.0.1")}})
	require.Error(t, err)
}

func TestWebhookRejectsEverySpecialUseAddressAndMixedDNSAnswer(t *testing.T) {
	for _, raw := range []string{
		"0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.0.0.1", "192.0.2.1", "192.168.0.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "240.0.0.1",
		"::", "::1", "::ffff:127.0.0.1", "64:ff9b::1", "100::1", "100:0:0:1::1", "2001:db8::1", "3fff::1", "5f00::1", "4000::1", "6000::1", "fc00::1", "fec0::1", "fe80::1", "ff00::1",
	} {
		t.Run(raw, func(t *testing.T) { require.False(t, publicWebhookIP(net.ParseIP(raw))) })
	}
	require.True(t, publicWebhookIP(net.ParseIP("93.184.216.34")))
	require.True(t, publicWebhookIP(net.ParseIP("2606:4700:4700::1111")))
	resolver := staticIPResolver{"allowed.example": {net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.1")}}
	require.Error(t, ValidateWebhookURL("https://allowed.example/hook", exactAllowlist{"allowed.example": true}, resolver))
	resolver = staticIPResolver{"allowed.example": {net.ParseIP("2606:4700:4700::1111"), net.ParseIP("3fff::1")}}
	require.Error(t, ValidateWebhookURL("https://allowed.example/hook", exactAllowlist{"allowed.example": true}, resolver))
}

func TestWebhookRejectsRedirectAndUsesTenSecondTimeout(t *testing.T) {
	resolver := staticIPResolver{"allowed.example": {net.ParseIP("93.184.216.34")}}
	redirectHeader := make(http.Header)
	redirectHeader.Set("Location", "https://allowed.example/redirected")
	transport := &recordingRoundTripper{response: &http.Response{StatusCode: http.StatusFound, Header: redirectHeader, Body: io.NopCloser(strings.NewReader("redirect body"))}}
	channel := newWebhookChannelForTest(exactAllowlist{"allowed.example": true}, resolver, staticSecretResolver{value: []byte("secret")}, transport)

	err := channel.Deliver(context.Background(), DeliveryRequest{Target: "https://allowed.example/hook", SecretRef: "vault://hook", Body: `{"event":"event-1"}`})
	require.Error(t, err)
	require.False(t, IsRetryableDeliveryError(err))
	require.Equal(t, 10*time.Second, channel.client.Timeout)
	require.NotNil(t, channel.client.CheckRedirect)
}

func TestWebhookSignsCanonicalBodyWithReferencedSecret(t *testing.T) {
	resolver := staticIPResolver{"allowed.example": {net.ParseIP("93.184.216.34")}}
	transport := &recordingRoundTripper{response: &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}}
	channel := newWebhookChannelForTest(exactAllowlist{"allowed.example": true}, resolver, staticSecretResolver{value: []byte("secret")}, transport)
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
			resolver := staticIPResolver{"allowed.example": {net.ParseIP("93.184.216.34")}}
			transport := &recordingRoundTripper{response: &http.Response{StatusCode: test.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("sensitive response body"))}}
			channel := newWebhookChannelForTest(exactAllowlist{"allowed.example": true}, resolver, staticSecretResolver{value: []byte("secret")}, transport)
			err := channel.Deliver(context.Background(), DeliveryRequest{Target: "https://allowed.example/hook", SecretRef: "secret-ref", Body: "{}"})
			require.Error(t, err)
			require.Equal(t, test.retryable, IsRetryableDeliveryError(err))
			require.NotContains(t, err.Error(), "sensitive response body")
		})
	}
}

func TestWebhookTimeoutCoversDNSAndSecretResolution(t *testing.T) {
	channel := NewWebhookChannel(exactAllowlist{"allowed.example": true}, blockingIPResolver{}, staticSecretResolver{value: []byte("secret")})
	channel.timeout = 20 * time.Millisecond
	started := time.Now()
	err := channel.Deliver(context.Background(), DeliveryRequest{Target: "https://allowed.example/hook", SecretRef: "secret-ref", Body: "{}"})
	require.Error(t, err)
	require.Less(t, time.Since(started), time.Second)

	channel = NewWebhookChannel(exactAllowlist{"allowed.example": true}, staticIPResolver{"allowed.example": {net.ParseIP("93.184.216.34")}}, blockingSecretResolver{})
	channel.timeout = 20 * time.Millisecond
	started = time.Now()
	err = channel.Deliver(context.Background(), DeliveryRequest{Target: "https://allowed.example/hook", SecretRef: "secret-ref", Body: "{}"})
	require.Error(t, err)
	require.Less(t, time.Since(started), time.Second)
}

func TestSMTPChannelRequiresTLSAndResolvesPasswordReference(t *testing.T) {
	sender := &recordingSMTPSender{}
	channel := NewSMTPChannel(SMTPConfig{Address: "smtp.example:587", ServerName: "smtp.example", Username: "dbpilot", From: "alerts@example"}, staticSecretResolver{value: []byte("password")}, sender)

	require.NoError(t, channel.Deliver(context.Background(), DeliveryRequest{Target: "dba@example", SecretRef: "vault://smtp", Subject: "alert", Body: "firing"}))
	require.True(t, sender.message.RequireTLS)
	require.Equal(t, "password", string(sender.message.Password))
	require.Equal(t, "vault://smtp", sender.resolvedRef)
}

func TestSMTPClassifiesConfigurationAuthAnd5xxPermanentBut4xxRetryable(t *testing.T) {
	require.False(t, IsRetryableDeliveryError(classifySMTPError("auth", &textproto.Error{Code: 454, Msg: "temporary auth"})))
	require.False(t, IsRetryableDeliveryError(classifySMTPError("rcpt", &textproto.Error{Code: 550, Msg: "mailbox unavailable"})))
	require.True(t, IsRetryableDeliveryError(classifySMTPError("rcpt", &textproto.Error{Code: 450, Msg: "mailbox busy"})))
	require.False(t, IsRetryableDeliveryError(classifySMTPError("tls", context.DeadlineExceeded)))

	config := SMTPConfig{Address: "smtp.example:587", ServerName: "smtp.example", From: "alerts@example"}
	permanent := NewSMTPChannel(config, staticSecretResolver{value: []byte("password")}, &recordingSMTPSender{err: classifySMTPError("rcpt", &textproto.Error{Code: 550, Msg: "unavailable"})})
	err := permanent.Deliver(context.Background(), DeliveryRequest{Target: "dba@example", SecretRef: "vault://smtp", Subject: "alert"})
	require.Error(t, err)
	require.False(t, IsRetryableDeliveryError(err))
	temporary := NewSMTPChannel(config, staticSecretResolver{value: []byte("password")}, &recordingSMTPSender{err: classifySMTPError("rcpt", &textproto.Error{Code: 450, Msg: "busy"})})
	err = temporary.Deliver(context.Background(), DeliveryRequest{Target: "dba@example", SecretRef: "vault://smtp", Subject: "alert"})
	require.Error(t, err)
	require.True(t, IsRetryableDeliveryError(err))
}

func TestSMTPTimeoutCoversSecretResolutionAndSenderProtocol(t *testing.T) {
	channel := NewSMTPChannel(SMTPConfig{Address: "smtp.example:587", ServerName: "smtp.example", From: "alerts@example"}, blockingSecretResolver{}, &recordingSMTPSender{})
	channel.timeout = 20 * time.Millisecond
	started := time.Now()
	err := channel.Deliver(context.Background(), DeliveryRequest{Target: "dba@example", SecretRef: "vault://smtp", Subject: "alert", Body: "firing"})
	require.Error(t, err)
	require.Less(t, time.Since(started), time.Second)

	channel = NewSMTPChannel(SMTPConfig{Address: "smtp.example:587", ServerName: "smtp.example", From: "alerts@example"}, staticSecretResolver{value: []byte("password")}, blockingSMTPSender{})
	channel.timeout = 20 * time.Millisecond
	started = time.Now()
	err = channel.Deliver(context.Background(), DeliveryRequest{Target: "dba@example", SecretRef: "vault://smtp", Subject: "alert", Body: "firing"})
	require.Error(t, err)
	require.Less(t, time.Since(started), time.Second)
}

type exactAllowlist map[string]bool

func (allowlist exactAllowlist) Allows(host string) bool { return allowlist[host] }

type staticIPResolver map[string][]net.IP

func (resolver staticIPResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	return resolver[host], nil
}

type blockingIPResolver struct{}

func (blockingIPResolver) LookupIP(ctx context.Context, _ string) ([]net.IP, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type staticSecretResolver struct {
	value []byte
	ref   string
}

type blockingSecretResolver struct{}

func (blockingSecretResolver) Resolve(ctx context.Context, _ string) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
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
	err         error
}

type blockingSMTPSender struct{}

func (blockingSMTPSender) Send(ctx context.Context, _ SMTPMessage) error {
	<-ctx.Done()
	return ctx.Err()
}

func (sender *recordingSMTPSender) Send(_ context.Context, message SMTPMessage) error {
	sender.message = message
	sender.message.Password = append([]byte(nil), message.Password...)
	sender.resolvedRef = message.SecretRef
	return sender.err
}
