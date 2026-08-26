package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

var ErrWebhookRedirect = errors.New("webhook redirects are disabled")

type WebhookAllowlist interface {
	Allows(host string) bool
}

type WebhookIPResolver interface {
	LookupIP(context.Context, string) ([]net.IP, error)
}

type systemIPResolver struct{}

func (systemIPResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	result := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.IP)
	}
	return result, nil
}

func ValidateWebhookURL(rawURL string, allowlist WebhookAllowlist, resolver WebhookIPResolver) error {
	return validateWebhookURL(context.Background(), rawURL, allowlist, resolver)
}

func validateWebhookURL(ctx context.Context, rawURL string, allowlist WebhookAllowlist, resolver WebhookIPResolver) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return PermanentDeliveryError("webhook_url_validation", err)
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if allowlist == nil || !allowlist.Allows(host) {
		return PermanentDeliveryError("webhook_host_not_allowed", nil)
	}
	var addresses []net.IP
	if literal := net.ParseIP(host); literal != nil {
		addresses = []net.IP{literal}
	} else {
		if resolver == nil {
			resolver = systemIPResolver{}
		}
		addresses, err = resolver.LookupIP(ctx, host)
		if err != nil || len(addresses) == 0 {
			return PermanentDeliveryError("webhook_dns_validation", err)
		}
	}
	for _, address := range addresses {
		if !publicWebhookIP(address) {
			return PermanentDeliveryError("webhook_private_address", nil)
		}
	}
	return nil
}

func publicWebhookIP(address net.IP) bool {
	return address != nil && !address.IsUnspecified() && !address.IsLoopback() && !address.IsPrivate() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast() && !address.IsMulticast()
}

type WebhookChannel struct {
	allowlist WebhookAllowlist
	resolver  WebhookIPResolver
	secrets   SecretResolver
	client    *http.Client
	now       func() time.Time
}

func NewWebhookChannel(allowlist WebhookAllowlist, resolver WebhookIPResolver, secrets SecretResolver, transport http.RoundTripper) *WebhookChannel {
	if transport == nil {
		base := http.DefaultTransport.(*http.Transport).Clone()
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			validated, err := validatedWebhookDialAddress(ctx, address, allowlist, resolver)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, validated)
		}
		transport = base
	}
	return &WebhookChannel{
		allowlist: allowlist, resolver: resolver, secrets: secrets,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return ErrWebhookRedirect
			},
		},
		now: time.Now,
	}
}

func validatedWebhookDialAddress(ctx context.Context, address string, allowlist WebhookAllowlist, resolver WebhookIPResolver) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", PermanentDeliveryError("webhook_dial_validation", err)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if allowlist == nil || !allowlist.Allows(host) {
		return "", PermanentDeliveryError("webhook_host_not_allowed", nil)
	}
	var addresses []net.IP
	if literal := net.ParseIP(host); literal != nil {
		addresses = []net.IP{literal}
	} else {
		if resolver == nil {
			resolver = systemIPResolver{}
		}
		addresses, err = resolver.LookupIP(ctx, host)
		if err != nil || len(addresses) == 0 {
			return "", PermanentDeliveryError("webhook_dns_validation", err)
		}
	}
	for _, resolved := range addresses {
		if !publicWebhookIP(resolved) {
			return "", PermanentDeliveryError("webhook_private_address", nil)
		}
	}
	return net.JoinHostPort(addresses[0].String(), port), nil
}

func (channel *WebhookChannel) Name() string { return "webhook" }

func (channel *WebhookChannel) Deliver(ctx context.Context, delivery DeliveryRequest) error {
	if channel == nil || channel.client == nil {
		return PermanentDeliveryError("webhook_configuration", nil)
	}
	if err := validateWebhookURL(ctx, delivery.Target, channel.allowlist, channel.resolver); err != nil {
		return err
	}
	if channel.secrets == nil || strings.TrimSpace(delivery.SecretRef) == "" {
		return PermanentDeliveryError("webhook_secret_reference", nil)
	}
	secret, err := channel.secrets.Resolve(ctx, delivery.SecretRef)
	if err != nil || len(secret) == 0 {
		return PermanentDeliveryError("webhook_secret_resolution", err)
	}
	defer clear(secret)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, delivery.Target, bytes.NewBufferString(delivery.Body))
	if err != nil {
		return PermanentDeliveryError("webhook_request_validation", err)
	}
	timestamp := strconvFormatUnix(channel.now().UTC())
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(delivery.Body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DBPilot-Timestamp", timestamp)
	request.Header.Set("X-DBPilot-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))

	response, err := channel.client.Do(request)
	if err != nil {
		if errors.Is(err, ErrWebhookRedirect) {
			return PermanentDeliveryError("webhook_redirect", err)
		}
		return RetryableDeliveryError("webhook_transport", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	if response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return RetryableDeliveryError(fmt.Sprintf("webhook_http_%d", response.StatusCode), nil)
	}
	return PermanentDeliveryError(fmt.Sprintf("webhook_http_%d", response.StatusCode), nil)
}

func strconvFormatUnix(at time.Time) string { return fmt.Sprintf("%d", at.Unix()) }

type InAppNotificationWriter interface {
	PersistInAppNotification(context.Context, DeliveryRequest) error
}

type InAppChannel struct{ Writer InAppNotificationWriter }

func (InAppChannel) Name() string { return "in_app" }

func (channel InAppChannel) Deliver(ctx context.Context, request DeliveryRequest) error {
	if channel.Writer == nil {
		return PermanentDeliveryError("in_app_configuration", nil)
	}
	if err := channel.Writer.PersistInAppNotification(ctx, request); err != nil {
		return RetryableDeliveryError("in_app_persistence", err)
	}
	return nil
}

type SMTPConfig struct {
	Address     string
	ServerName  string
	Username    string
	From        string
	ImplicitTLS bool
}

type SMTPMessage struct {
	SMTPConfig
	To         string
	Subject    string
	Body       string
	Password   []byte `json:"-"`
	SecretRef  string `json:"-"`
	RequireTLS bool
}

type SMTPSender interface {
	Send(context.Context, SMTPMessage) error
}

type SMTPChannel struct {
	config  SMTPConfig
	secrets SecretResolver
	sender  SMTPSender
}

func NewSMTPChannel(config SMTPConfig, secrets SecretResolver, sender SMTPSender) *SMTPChannel {
	if sender == nil {
		sender = NetworkSMTPSender{}
	}
	return &SMTPChannel{config: config, secrets: secrets, sender: sender}
}

func (*SMTPChannel) Name() string { return "smtp" }

func (channel *SMTPChannel) Deliver(ctx context.Context, request DeliveryRequest) error {
	if channel == nil || channel.secrets == nil || channel.sender == nil || strings.TrimSpace(request.SecretRef) == "" {
		return PermanentDeliveryError("smtp_configuration", nil)
	}
	if !validMailbox(request.Target) || !validMailbox(channel.config.From) || strings.ContainsAny(request.Subject, "\r\n") {
		return PermanentDeliveryError("smtp_message_validation", nil)
	}
	password, err := channel.secrets.Resolve(ctx, request.SecretRef)
	if err != nil || len(password) == 0 {
		return PermanentDeliveryError("smtp_secret_resolution", err)
	}
	defer clear(password)
	message := SMTPMessage{SMTPConfig: channel.config, To: request.Target, Subject: request.Subject, Body: request.Body, Password: password, SecretRef: request.SecretRef, RequireTLS: true}
	if err := channel.sender.Send(ctx, message); err != nil {
		return RetryableDeliveryError("smtp_transport", err)
	}
	return nil
}

func validMailbox(raw string) bool {
	parsed, err := mail.ParseAddress(raw)
	return err == nil && parsed.Address == raw
}

type NetworkSMTPSender struct{}

func (NetworkSMTPSender) Send(ctx context.Context, message SMTPMessage) error {
	if !message.RequireTLS || message.Address == "" || message.ServerName == "" {
		return errors.New("SMTP TLS configuration is required")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var connection net.Conn
	var err error
	if message.ImplicitTLS {
		connection, err = tls.DialWithDialer(dialer, "tcp", message.Address, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: message.ServerName})
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", message.Address)
	}
	if err != nil {
		return err
	}
	defer connection.Close()
	client, err := smtp.NewClient(connection, message.ServerName)
	if err != nil {
		return err
	}
	defer client.Close()
	if !message.ImplicitTLS {
		if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: message.ServerName}); err != nil {
			return err
		}
	}
	if message.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", message.Username, string(message.Password), message.ServerName)); err != nil {
			return err
		}
	}
	if err := client.Mail(message.From); err != nil {
		return err
	}
	if err := client.Rcpt(message.To); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	payload := "From: " + message.From + "\r\nTo: " + message.To + "\r\nSubject: " + message.Subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + message.Body
	if _, err := io.WriteString(writer, payload); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}
