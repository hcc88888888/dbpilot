// Package databaseinstance owns the lifecycle of managed database instances.
package databaseinstance

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/platformscope"
)

const DefaultListLimit = 50

var (
	ErrInvalid           = errors.New("invalid database instance value")
	ErrNotFound          = errors.New("database instance not found")
	ErrConflict          = errors.New("database instance conflict")
	ErrPrecondition      = errors.New("database instance precondition failed")
	ErrPluginMissing     = errors.New("database plugin is not installed")
	ErrPluginUnavailable = errors.New("database plugin is unavailable")
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var familyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var variantPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
var labelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var requestFingerprintPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var cursorPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)

type ManagementStatus string

const (
	StatusAccepted             ManagementStatus = "accepted"
	StatusProvisioning         ManagementStatus = "provisioning"
	StatusConnectionTesting    ManagementStatus = "connection_testing"
	StatusManaged              ManagementStatus = "managed"
	StatusMonitoring           ManagementStatus = "monitoring"
	StatusPluginFailed         ManagementStatus = "plugin_failed"
	StatusAuthenticationFailed ManagementStatus = "authentication_failed"
	StatusTLSFailed            ManagementStatus = "tls_failed"
	StatusUnreachable          ManagementStatus = "unreachable"
	StatusUnsupportedVersion   ManagementStatus = "unsupported_version"
	StatusDegraded             ManagementStatus = "degraded"
	StatusOffline              ManagementStatus = "offline"
	StatusRetired              ManagementStatus = "retired"
)

type ConnectionTestStatus string

const (
	ConnectionNotTested            ConnectionTestStatus = "not_tested"
	ConnectionQueued               ConnectionTestStatus = "queued"
	ConnectionRunning              ConnectionTestStatus = "running"
	ConnectionSucceeded            ConnectionTestStatus = "succeeded"
	ConnectionAuthenticationFailed ConnectionTestStatus = "authentication_failed"
	ConnectionTLSFailed            ConnectionTestStatus = "tls_failed"
	ConnectionUnreachable          ConnectionTestStatus = "unreachable"
	ConnectionUnsupportedVersion   ConnectionTestStatus = "unsupported_version"
	ConnectionPluginFailed         ConnectionTestStatus = "plugin_failed"
)

type CapabilityState string

const (
	CapabilityPluginNotInstalled CapabilityState = "plugin_not_installed"
	CapabilityPluginAvailable    CapabilityState = "plugin_available"
	CapabilityPluginUnavailable  CapabilityState = "plugin_unavailable"
	CapabilityPluginFailed       CapabilityState = "plugin_failed"
	CapabilityDegraded           CapabilityState = "degraded"
)

type ConnectionTestErrorCode string

const (
	ConnectionErrorAuthentication     ConnectionTestErrorCode = "instance_authentication_failed"
	ConnectionErrorTLS                ConnectionTestErrorCode = "instance_tls_failed"
	ConnectionErrorUnreachable        ConnectionTestErrorCode = "instance_unreachable"
	ConnectionErrorUnsupportedVersion ConnectionTestErrorCode = "database_version_unsupported"
	ConnectionErrorPlugin             ConnectionTestErrorCode = "plugin_failed"
)

type MutationAudit struct {
	Actor              string
	OperationID        string
	IdempotencyKey     string
	RequestFingerprint string
	RequestID          string
	TraceID            string
}

func (value MutationAudit) Validate() error {
	if !bounded(value.Actor, 256, true) || !bounded(value.OperationID, 128, true) || !bounded(value.IdempotencyKey, 128, true) || !requestFingerprintPattern.MatchString(value.RequestFingerprint) || !bounded(value.RequestID, 256, true) || !bounded(value.TraceID, 256, false) {
		return ErrInvalid
	}
	return nil
}

type AcceptCandidateRequest struct {
	DisplayName               string
	DatabaseFamily            string
	DatabaseVariant           string
	Endpoint                  string
	UnixSocket                string
	CredentialRef             string
	TLSRef                    string
	Labels                    map[string]string
	ExpectedCandidateRevision uint64
	CandidateFingerprint      string
	Audit                     MutationAudit
}

func (request AcceptCandidateRequest) Validate() error {
	if !bounded(request.DisplayName, 120, true) || !familyPattern.MatchString(request.DatabaseFamily) || !variantPattern.MatchString(request.DatabaseVariant) || !validConnection(request.Endpoint, request.UnixSocket) || !validSecretReference(request.CredentialRef, true) || !validSecretReference(request.TLSRef, false) || !validLabels(request.Labels) || request.ExpectedCandidateRevision == 0 || !fingerprintPattern.MatchString(request.CandidateFingerprint) || request.Audit.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

type Instance struct {
	ID                       string
	Scope                    platformscope.Scope
	HostID                   string
	AgentID                  string
	CandidateID              string
	DiscoverySource          discovery.Source
	SourceFingerprint        string
	SourceIdentity           string
	DatabaseFamily           string
	DatabaseVariant          string
	DisplayName              string
	Endpoint                 string
	UnixSocket               string
	Version                  string
	Edition                  string
	Role                     string
	Topology                 string
	CredentialRef            string
	TLSRef                   string
	PluginID                 string
	DesiredPluginVersion     string
	TemplateProfileID        string
	Labels                   map[string]string
	Capabilities             []string
	CapabilityState          CapabilityState
	ConnectionTestStatus     ConnectionTestStatus
	ConnectionTestErrorCode  ConnectionTestErrorCode
	ConnectionTestAt         *time.Time
	PluginAssignmentRevision uint64
	ManagementStatus         ManagementStatus
	Revision                 uint64
	CreatedAt                time.Time
	UpdatedAt                time.Time
	RetiredAt                *time.Time
}

func (value Instance) Validate() error {
	if !identifierPattern.MatchString(value.ID) || value.Scope.Validate() != nil || !identifierPattern.MatchString(value.HostID) || !identifierPattern.MatchString(value.AgentID) || !identifierPattern.MatchString(value.CandidateID) || (value.DiscoverySource != discovery.SourceNative && value.DiscoverySource != discovery.SourceDocker) || !fingerprintPattern.MatchString(value.SourceFingerprint) || !bounded(value.SourceIdentity, 512, true) || !familyPattern.MatchString(value.DatabaseFamily) || !variantPattern.MatchString(value.DatabaseVariant) || !bounded(value.DisplayName, 120, true) || !validConnection(value.Endpoint, value.UnixSocket) || !validSecretReference(value.CredentialRef, true) || !validSecretReference(value.TLSRef, false) || !validLabels(value.Labels) || len(value.Capabilities) > 64 || !validCapabilityState(value.CapabilityState) || !validConnectionTestState(value.ConnectionTestStatus, value.ConnectionTestErrorCode, value.ConnectionTestAt) || !validManagementStatus(value.ManagementStatus) || value.Revision == 0 || !validUTC(value.CreatedAt) || !validUTC(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) {
		return ErrInvalid
	}
	for _, capability := range value.Capabilities {
		if !bounded(capability, 128, true) {
			return ErrInvalid
		}
	}
	if value.ConnectionTestAt != nil && !validUTC(*value.ConnectionTestAt) || (value.ManagementStatus == StatusRetired) != (value.RetiredAt != nil) || value.RetiredAt != nil && !validUTC(*value.RetiredAt) {
		return ErrInvalid
	}
	return nil
}

func validCapabilityState(value CapabilityState) bool {
	switch value {
	case CapabilityPluginNotInstalled, CapabilityPluginAvailable, CapabilityPluginUnavailable, CapabilityPluginFailed, CapabilityDegraded:
		return true
	default:
		return false
	}
}

func validConnectionTestState(status ConnectionTestStatus, code ConnectionTestErrorCode, at *time.Time) bool {
	if status == ConnectionNotTested {
		return code == "" && at == nil
	}
	if at == nil || !validUTC(*at) {
		return false
	}
	switch status {
	case ConnectionQueued, ConnectionRunning, ConnectionSucceeded:
		return code == ""
	case ConnectionAuthenticationFailed:
		return code == ConnectionErrorAuthentication
	case ConnectionTLSFailed:
		return code == ConnectionErrorTLS
	case ConnectionUnreachable:
		return code == ConnectionErrorUnreachable
	case ConnectionUnsupportedVersion:
		return code == ConnectionErrorUnsupportedVersion
	case ConnectionPluginFailed:
		return code == ConnectionErrorPlugin
	default:
		return false
	}
}

func (value Instance) FutureAssignmentKey() string {
	return value.AgentID + "\x00" + value.DatabaseFamily
}

type Filter struct {
	HostID         string
	DatabaseFamily string
	Status         ManagementStatus
	Cursor         string
	Limit          int
}

func (value Filter) Validate() error {
	if value.HostID != "" && !identifierPattern.MatchString(value.HostID) || value.DatabaseFamily != "" && !familyPattern.MatchString(value.DatabaseFamily) || value.Status != "" && !validManagementStatus(value.Status) || value.Cursor != "" && !cursorPattern.MatchString(value.Cursor) || value.Limit < 0 || value.Limit > 100 {
		return ErrInvalid
	}
	return nil
}

type Page struct {
	Items      []Instance
	NextCursor string
}

type Update struct {
	DisplayName          *string
	CredentialRef        *string
	TLSRef               *string
	DesiredPluginVersion *string
	TemplateProfileID    *string
	Labels               *map[string]string
	Audit                MutationAudit
}

func (value Update) Validate() error {
	if value.DisplayName == nil && value.CredentialRef == nil && value.TLSRef == nil && value.DesiredPluginVersion == nil && value.TemplateProfileID == nil && value.Labels == nil {
		return ErrInvalid
	}
	if value.DisplayName != nil && !bounded(*value.DisplayName, 120, true) || value.CredentialRef != nil && !validSecretReference(*value.CredentialRef, true) || value.TLSRef != nil && !validSecretReference(*value.TLSRef, true) || value.DesiredPluginVersion != nil && !bounded(*value.DesiredPluginVersion, 64, false) || value.TemplateProfileID != nil && !bounded(*value.TemplateProfileID, 128, false) || value.Labels != nil && !validLabels(*value.Labels) {
		return ErrInvalid
	}
	if value.Audit != (MutationAudit{}) && value.Audit.Validate() != nil {
		return ErrInvalid
	}
	return nil
}

func validSecretReference(value string, required bool) bool {
	if value == "" {
		return !required
	}
	if !bounded(value, 512, true) || strings.Contains(value, "\\") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "secret" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Path == "" || parsed.Path == "/" {
		return false
	}
	if strings.Contains(parsed.Host, ":") || path.Clean(parsed.Path) != parsed.Path || strings.Contains(parsed.Path, "..") {
		return false
	}
	return true
}

func validConnection(endpoint, socket string) bool {
	if (endpoint == "") == (socket == "") {
		return false
	}
	if endpoint != "" {
		if !bounded(endpoint, 512, true) || strings.ContainsAny(endpoint, "/?#@") {
			return false
		}
		normalized, err := discovery.NormalizeEndpoint(endpoint)
		return err == nil && normalized == endpoint
	}
	return bounded(socket, 512, true) && strings.HasPrefix(socket, "/") && path.Clean(socket) == socket && !strings.Contains(socket, "..")
}

func validLabels(values map[string]string) bool {
	if len(values) > 32 {
		return false
	}
	for key, value := range values {
		if !labelPattern.MatchString(key) || !bounded(value, 128, false) {
			return false
		}
	}
	return true
}

func validManagementStatus(value ManagementStatus) bool {
	switch value {
	case StatusAccepted, StatusProvisioning, StatusConnectionTesting, StatusManaged, StatusMonitoring, StatusPluginFailed, StatusAuthenticationFailed, StatusTLSFailed, StatusUnreachable, StatusUnsupportedVersion, StatusDegraded, StatusOffline, StatusRetired:
		return true
	default:
		return false
	}
}

func bounded(value string, maximum int, required bool) bool {
	if value == "" {
		return !required
	}
	return value == strings.TrimSpace(value) && utf8.ValidString(value) && utf8.RuneCountInString(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n\t")
}

func validUTC(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }

func cloneLabels(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
