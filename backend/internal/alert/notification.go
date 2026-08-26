package alert

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidNotification       = errors.New("invalid alert notification")
	ErrInvalidTemplate           = errors.New("invalid notification template")
	ErrNotificationScopeMismatch = errors.New("notification scope mismatch")
)

type DeliveryStatus string

const (
	DeliveryAttempting     DeliveryStatus = "attempting"
	DeliveryDelivered      DeliveryStatus = "delivered"
	DeliverySuppressed     DeliveryStatus = "suppressed"
	DeliveryRetryScheduled DeliveryStatus = "retry_scheduled"
	DeliveryAbandoned      DeliveryStatus = "abandoned"
)

var retryDelays = [...]time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute}

// NotificationRoute couples a Task 1 policy with a versioned template and
// declarative routing constraints. An empty constraint matches every value.
type NotificationRoute struct {
	Policy         NotificationPolicy
	Template       NotificationTemplate
	Severities     []string
	MatchLabels    map[string]string
	WindowStartUTC string
	WindowEndUTC   string
}

// Version is stable for the persisted template revision and deliberately does
// not contain rendered content.
func (template NotificationTemplate) Version() string {
	if !template.UpdatedAt.IsZero() {
		return template.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	if !template.CreatedAt.IsZero() {
		return template.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	return template.ID
}

// MarshalJSON exposes only whether authentication is configured. The secret
// reference itself is an internal persistence concern.
func (policy NotificationPolicy) MarshalJSON() ([]byte, error) {
	type safePolicy NotificationPolicy
	return json.Marshal(struct {
		safePolicy
		HasSecret bool `json:"has_secret"`
	}{safePolicy: safePolicy(policy), HasSecret: strings.TrimSpace(policy.SecretRef) != ""})
}

type DeliveryRequest struct {
	Scope           Scope             `json:"scope"`
	EventID         string            `json:"event_id"`
	State           EventState        `json:"state"`
	Severity        string            `json:"severity"`
	Channel         string            `json:"channel"`
	PolicyID        string            `json:"policy_id"`
	TemplateID      string            `json:"template_id"`
	TemplateVersion string            `json:"template_version"`
	Target          string            `json:"target"`
	SecretRef       string            `json:"-"`
	Subject         string            `json:"subject"`
	Body            string            `json:"body"`
	Labels          map[string]string `json:"labels,omitempty"`
}

type NotificationDelivery struct {
	ID             string          `json:"id"`
	Scope          Scope           `json:"scope"`
	EventID        string          `json:"event_id"`
	PolicyID       string          `json:"policy_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	Status         DeliveryStatus  `json:"status"`
	Attempts       int             `json:"attempts"`
	AttemptedAt    time.Time       `json:"attempted_at"`
	NextAttemptAt  time.Time       `json:"next_attempt_at,omitempty"`
	DeliveredAt    time.Time       `json:"delivered_at,omitempty"`
	FailureClass   string          `json:"failure_class,omitempty"`
	Request        DeliveryRequest `json:"-"`
}

type DeliveryChannel interface {
	Name() string
	Deliver(context.Context, DeliveryRequest) error
}

type SecretResolver interface {
	Resolve(context.Context, string) ([]byte, error)
}

type Dispatcher struct {
	repository NotificationRepository
	channels   map[string]DeliveryChannel
	now        func() time.Time
	eventURL   func(AlertEvent) string
}

func NewDispatcher(repository NotificationRepository, channels []DeliveryChannel, now func() time.Time, eventURL func(AlertEvent) string) *Dispatcher {
	byName := make(map[string]DeliveryChannel, len(channels))
	for _, channel := range channels {
		if channel != nil && strings.TrimSpace(channel.Name()) != "" {
			byName[channel.Name()] = channel
		}
	}
	if now == nil {
		now = time.Now
	}
	if eventURL == nil {
		eventURL = func(AlertEvent) string { return "" }
	}
	return &Dispatcher{repository: repository, channels: byName, now: now, eventURL: eventURL}
}

func (dispatcher *Dispatcher) Dispatch(ctx context.Context, event AlertEvent, state EventState) error {
	if dispatcher == nil || dispatcher.repository == nil || event.Validate() != nil || state != event.State {
		return ErrInvalidNotification
	}
	rule, err := dispatcher.repository.GetRule(ctx, event.Scope, event.RuleID)
	if err != nil {
		return err
	}
	if rule.Scope != event.Scope {
		return ErrNotificationScopeMismatch
	}
	routes, err := dispatcher.repository.ListNotificationRoutes(ctx, event.Scope, event.RuleID)
	if err != nil {
		return err
	}
	now := dispatcher.now().UTC()
	silences, err := dispatcher.repository.ListActiveSilences(ctx, event.Scope, now)
	if err != nil {
		return err
	}

	for _, route := range routes {
		if route.Policy.Scope != event.Scope || route.Template.Scope != event.Scope {
			return ErrNotificationScopeMismatch
		}
		if !routeMatches(route, rule, event, now) {
			continue
		}
		channel := dispatcher.channels[route.Policy.Channel]
		if channel == nil {
			if err := dispatcher.recordConfigurationFailure(ctx, route, event, state, now, "channel_validation"); err != nil {
				return err
			}
			continue
		}
		request, renderErr := dispatcher.deliveryRequest(route, rule, event, state)
		if renderErr != nil {
			if err := dispatcher.recordConfigurationFailure(ctx, route, event, state, now, "template_validation"); err != nil {
				return err
			}
			continue
		}
		delivery := newNotificationDelivery(request, event, now)
		if matchingSilence(silences, event, now) {
			delivery.Status = DeliverySuppressed
			audit := notificationAudit(delivery, "delivery.suppressed", now)
			if _, err := dispatcher.repository.ReserveNotificationDelivery(ctx, delivery, &audit); err != nil {
				return err
			}
			continue
		}
		reserved, err := dispatcher.repository.ReserveNotificationDelivery(ctx, delivery, nil)
		if err != nil {
			return err
		}
		if !reserved {
			continue
		}
		if err := dispatcher.finishAttempt(ctx, channel, &delivery, now); err != nil {
			return err
		}
	}
	return nil
}

func (dispatcher *Dispatcher) RetryDue(ctx context.Context, at time.Time) error {
	if dispatcher == nil || dispatcher.repository == nil || at.IsZero() {
		return ErrInvalidNotification
	}
	due, err := dispatcher.repository.ListDueNotificationDeliveries(ctx, at.UTC())
	if err != nil {
		return err
	}
	for index := range due {
		delivery := due[index]
		if delivery.Scope != delivery.Request.Scope || delivery.Status != DeliveryRetryScheduled || delivery.NextAttemptAt.After(at) {
			return ErrInvalidNotification
		}
		channel := dispatcher.channels[delivery.Request.Channel]
		if channel == nil {
			delivery.Status = DeliveryAbandoned
			delivery.FailureClass = "channel_validation"
			delivery.NextAttemptAt = time.Time{}
			if err := dispatcher.repository.UpdateNotificationDelivery(ctx, delivery, notificationAudit(delivery, "delivery.abandoned", at)); err != nil {
				return err
			}
			continue
		}
		delivery.Status = DeliveryAttempting
		delivery.Attempts++
		delivery.AttemptedAt = at.UTC()
		delivery.NextAttemptAt = time.Time{}
		if err := dispatcher.repository.UpdateNotificationDelivery(ctx, delivery, notificationAudit(delivery, "delivery.retrying", at)); err != nil {
			return err
		}
		if err := dispatcher.finishAttempt(ctx, channel, &delivery, at.UTC()); err != nil {
			return err
		}
	}
	return nil
}

func (dispatcher *Dispatcher) finishAttempt(ctx context.Context, channel DeliveryChannel, delivery *NotificationDelivery, at time.Time) error {
	deliveryErr := channel.Deliver(ctx, delivery.Request)
	if deliveryErr == nil {
		delivery.Status = DeliveryDelivered
		delivery.DeliveredAt = at
		delivery.NextAttemptAt = time.Time{}
		delivery.FailureClass = ""
		return dispatcher.repository.UpdateNotificationDelivery(ctx, *delivery, notificationAudit(*delivery, "delivery.delivered", at))
	}

	delivery.DeliveredAt = time.Time{}
	delivery.FailureClass = deliveryErrorClass(deliveryErr)
	if IsRetryableDeliveryError(deliveryErr) && delivery.Attempts <= len(retryDelays) {
		delivery.Status = DeliveryRetryScheduled
		delivery.NextAttemptAt = at.Add(retryDelays[delivery.Attempts-1])
		return dispatcher.repository.UpdateNotificationDelivery(ctx, *delivery, notificationAudit(*delivery, "delivery.retry_scheduled", at))
	}
	delivery.Status = DeliveryAbandoned
	delivery.NextAttemptAt = time.Time{}
	return dispatcher.repository.UpdateNotificationDelivery(ctx, *delivery, notificationAudit(*delivery, "delivery.abandoned", at))
}

func (dispatcher *Dispatcher) recordConfigurationFailure(ctx context.Context, route NotificationRoute, event AlertEvent, state EventState, at time.Time, failureClass string) error {
	request := DeliveryRequest{Scope: event.Scope, EventID: event.ID, State: state, Severity: "unknown", Channel: route.Policy.Channel, PolicyID: route.Policy.ID, TemplateID: route.Template.ID, TemplateVersion: route.Template.Version(), Target: route.Policy.Target}
	delivery := newNotificationDelivery(request, event, at)
	reserved, err := dispatcher.repository.ReserveNotificationDelivery(ctx, delivery, nil)
	if err != nil || !reserved {
		return err
	}
	delivery.Status = DeliveryAbandoned
	delivery.FailureClass = failureClass
	return dispatcher.repository.UpdateNotificationDelivery(ctx, delivery, notificationAudit(delivery, "delivery.abandoned", at))
}

func (dispatcher *Dispatcher) deliveryRequest(route NotificationRoute, rule AlertRule, event AlertEvent, state EventState) (DeliveryRequest, error) {
	values := templateValues(rule, event, state, dispatcher.eventURL(event))
	subject, err := renderNotificationText(route.Template.Subject, values, event.Labels)
	if err != nil {
		return DeliveryRequest{}, err
	}
	body, err := renderNotificationText(route.Template.Body, values, event.Labels)
	if err != nil {
		return DeliveryRequest{}, err
	}
	return DeliveryRequest{
		Scope: event.Scope, EventID: event.ID, State: state, Severity: rule.Severity,
		Channel: route.Policy.Channel, PolicyID: route.Policy.ID,
		TemplateID: route.Template.ID, TemplateVersion: route.Template.Version(),
		Target: route.Policy.Target, SecretRef: route.Policy.SecretRef,
		Subject: subject, Body: body, Labels: cloneMap(event.Labels),
	}, nil
}

func newNotificationDelivery(request DeliveryRequest, event AlertEvent, at time.Time) NotificationDelivery {
	key := deliveryIdempotencyKey(event.ID, request.State, request.Channel, request.TemplateVersion)
	return NotificationDelivery{ID: key, Scope: event.Scope, EventID: event.ID, PolicyID: request.PolicyID, IdempotencyKey: key, Status: DeliveryAttempting, Attempts: 1, AttemptedAt: at, Request: request}
}

func deliveryIdempotencyKey(eventID string, state EventState, channel, templateVersion string) string {
	digest := sha256.Sum256([]byte(eventID + string(state) + channel + templateVersion))
	return hex.EncodeToString(digest[:])
}

func routeMatches(route NotificationRoute, rule AlertRule, event AlertEvent, at time.Time) bool {
	if !route.Policy.Enabled || !containsString(rule.NotificationPolicyIDs, route.Policy.ID) {
		return false
	}
	if len(route.Severities) > 0 && !containsString(route.Severities, rule.Severity) {
		return false
	}
	for key, value := range route.MatchLabels {
		if event.Labels[key] != value {
			return false
		}
	}
	return inUTCWindow(at, route.WindowStartUTC, route.WindowEndUTC)
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func inUTCWindow(at time.Time, startRaw, endRaw string) bool {
	if startRaw == "" && endRaw == "" {
		return true
	}
	start, startErr := time.Parse("15:04", startRaw)
	end, endErr := time.Parse("15:04", endRaw)
	if startErr != nil || endErr != nil {
		return false
	}
	nowMinute := at.UTC().Hour()*60 + at.UTC().Minute()
	startMinute := start.Hour()*60 + start.Minute()
	endMinute := end.Hour()*60 + end.Minute()
	if startMinute == endMinute {
		return true
	}
	if startMinute < endMinute {
		return nowMinute >= startMinute && nowMinute < endMinute
	}
	return nowMinute >= startMinute || nowMinute < endMinute
}

func matchingSilence(silences []Silence, event AlertEvent, at time.Time) bool {
	for _, silence := range silences {
		if silence.Scope != event.Scope || at.Before(silence.StartsAt) || !at.Before(silence.EndsAt) {
			continue
		}
		matched := true
		for key, value := range silence.Matchers {
			switch {
			case key == "fingerprint":
				matched = event.Fingerprint == value
			case key == "tenant_id":
				matched = event.Scope.TenantID == value
			case key == "project_id":
				matched = event.Scope.ProjectID == value
			case key == "scope":
				matched = event.Scope.Key() == value
			case key == "resource":
				matched = event.Labels["resource"] == value || event.Labels["resource_id"] == value
			case strings.HasPrefix(key, "resource."):
				matched = event.Labels[strings.TrimPrefix(key, "resource.")] == value
			case strings.HasPrefix(key, "label."):
				matched = event.Labels[strings.TrimPrefix(key, "label.")] == value
			default:
				matched = event.Labels[key] == value
			}
			if !matched {
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

var placeholderPattern = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}`)

func templateValues(rule AlertRule, event AlertEvent, state EventState, eventURL string) map[string]string {
	return map[string]string{
		"event.id":           event.ID,
		"event.state":        string(state),
		"event.severity":     rule.Severity,
		"evidence.aggregate": event.Evidence["aggregate"],
		"event.url":          eventURL,
	}
}

func renderNotificationText(source string, values, labels map[string]string) (string, error) {
	invalid := false
	rendered := placeholderPattern.ReplaceAllStringFunc(source, func(token string) string {
		parts := placeholderPattern.FindStringSubmatch(token)
		name := parts[1]
		if value, ok := values[name]; ok {
			return value
		}
		if strings.HasPrefix(name, "resource.") && len(name) > len("resource.") {
			return labels[strings.TrimPrefix(name, "resource.")]
		}
		invalid = true
		return ""
	})
	if invalid || strings.Contains(rendered, "{{") || strings.Contains(rendered, "}}") {
		return "", ErrInvalidTemplate
	}
	return rendered, nil
}

func notificationAudit(delivery NotificationDelivery, action string, at time.Time) AuditRecord {
	details := map[string]string{
		"status":  string(delivery.Status),
		"channel": delivery.Request.Channel,
		"attempt": strconv.Itoa(delivery.Attempts),
	}
	if delivery.FailureClass != "" {
		details["failure_class"] = sanitizeFailureClass(delivery.FailureClass)
	}
	return AuditRecord{ID: notificationAuditID(delivery, action), Scope: delivery.Scope, Actor: "dbpilot-notification-dispatcher", Action: action, TargetID: delivery.ID, OccurredAt: at.UTC(), Details: details}
}

func notificationAuditID(delivery NotificationDelivery, action string) string {
	digest := sha256.Sum256([]byte(delivery.ID + action + strconv.Itoa(delivery.Attempts)))
	return "audit-" + hex.EncodeToString(digest[:12])
}

func validateNotificationAudit(record AuditRecord) error {
	if record.Scope.Validate() != nil || record.ID == "" || record.Actor == "" || record.TargetID == "" || record.OccurredAt.IsZero() {
		return ErrInvalidAuditRecord
	}
	switch record.Action {
	case "delivery.suppressed", "delivery.delivered", "delivery.retrying", "delivery.retry_scheduled", "delivery.abandoned":
	default:
		return ErrInvalidAuditRecord
	}
	for key, value := range record.Details {
		if sensitiveField(key) || containsSecretMaterial(value) {
			return ErrInvalidAuditRecord
		}
	}
	return nil
}

type deliveryError struct {
	class     string
	retryable bool
	cause     error
}

func (failure *deliveryError) Error() string { return sanitizeFailureClass(failure.class) }
func (failure *deliveryError) Unwrap() error { return failure.cause }

func RetryableDeliveryError(class string, cause error) error {
	return &deliveryError{class: sanitizeFailureClass(class), retryable: true, cause: cause}
}

func PermanentDeliveryError(class string, cause error) error {
	return &deliveryError{class: sanitizeFailureClass(class), retryable: false, cause: cause}
}

func IsRetryableDeliveryError(err error) bool {
	var failure *deliveryError
	return errors.As(err, &failure) && failure.retryable
}

func deliveryErrorClass(err error) string {
	var failure *deliveryError
	if errors.As(err, &failure) {
		return sanitizeFailureClass(failure.class)
	}
	return "channel_error"
}

func sanitizeFailureClass(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var sanitized strings.Builder
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			sanitized.WriteRune(character)
		}
		if sanitized.Len() >= 64 {
			break
		}
	}
	if sanitized.Len() == 0 {
		return "delivery_error"
	}
	return sanitized.String()
}
