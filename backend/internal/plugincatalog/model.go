package plugincatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

var (
	ErrInvalid             = errors.New("invalid plugin catalog request")
	ErrNotFound            = errors.New("plugin version not found")
	ErrConflict            = errors.New("plugin version conflicts with existing state")
	ErrRevisionConflict    = errors.New("plugin version revision conflict")
	ErrManifestRejected    = errors.New("plugin manifest rejected")
	ErrSignatureRejected   = errors.New("plugin signature rejected")
	ErrUnknownPublisher    = errors.New("plugin publisher is not approved")
	ErrPlatformMismatch    = errors.New("plugin platform mismatch")
	ErrPackageTooLarge     = errors.New("plugin package exceeds limits")
	ErrArtifactUnavailable = errors.New("plugin artifact unavailable")
	ErrBeforeSideEffect    = errors.New("plugin operation failed before a durable side effect")
	ErrOperationPending    = errors.New("plugin catalog operation is pending")
)

type Manifest struct {
	PluginID                    string           `json:"plugin_id"`
	DatabaseFamily              string           `json:"database_family"`
	Version                     string           `json:"version"`
	ProtocolVersion             string           `json:"protocol_version"`
	PublisherID                 string           `json:"publisher_id"`
	SigningKeyID                string           `json:"signing_key_id"`
	MinimumAgentProtocolVersion string           `json:"minimum_agent_protocol_version"`
	MaximumAgentProtocolVersion string           `json:"maximum_agent_protocol_version"`
	SupportedVariants           []string         `json:"supported_variants"`
	DatabaseVersionRange        string           `json:"database_version_range"`
	Capabilities                []string         `json:"capabilities"`
	MetricTemplateSchemaVersion int              `json:"metric_template_schema_version"`
	Binaries                    []ManifestBinary `json:"binaries"`
	Files                       []ManifestFile   `json:"files"`
}

type ManifestBinary struct {
	OperatingSystem string `json:"operating_system"`
	Architecture    string `json:"architecture"`
	Path            string `json:"path"`
	SHA256          string `json:"sha256"`
	SizeBytes       int64  `json:"size_bytes"`
}

type ManifestFile struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type Status string

const (
	StatusUploaded   Status = "uploaded"
	StatusVerified   Status = "verified"
	StatusApproved   Status = "approved"
	StatusAvailable  Status = "available"
	StatusDeprecated Status = "deprecated"
	StatusRevoked    Status = "revoked"
	StatusRejected   Status = "rejected"
)

func (status Status) Valid() bool {
	switch status {
	case StatusUploaded, StatusVerified, StatusApproved, StatusAvailable, StatusDeprecated, StatusRevoked, StatusRejected:
		return true
	default:
		return false
	}
}

type Platform struct {
	OperatingSystem string `json:"operating_system"`
	Architecture    string `json:"architecture"`
	SHA256          string `json:"sha256"`
	SizeBytes       int64  `json:"size_bytes"`
}

type PluginVersion struct {
	ID                          string
	Scope                       platformscope.Scope
	PluginID                    string
	Version                     string
	Status                      Status
	ArtifactID                  string
	PackageSHA256               string
	ManifestDigest              string
	PublisherID                 string
	SigningKeyID                string
	ProtocolVersion             string
	MinimumAgentProtocolVersion string
	MaximumAgentProtocolVersion string
	SupportedVariants           []string
	DatabaseVersionRange        string
	Capabilities                []string
	MetricTemplateSchemaVersion int
	Platforms                   []Platform
	Revision                    uint64
	CreatedAt                   time.Time
	ApprovedAt                  *time.Time
}

func (value PluginVersion) Validate() error {
	if !catalogIDPattern.MatchString(value.ID) || value.Scope.Validate() != nil || !identifierPattern.MatchString(value.PluginID) || !canonicalText(value.Version, 64) || !value.Status.Valid() || !catalogIDPattern.MatchString(value.ArtifactID) || !digestPattern.MatchString(value.PackageSHA256) || !digestPattern.MatchString(value.ManifestDigest) || !identifierPattern.MatchString(value.PublisherID) || !identifierPattern.MatchString(value.SigningKeyID) || !canonicalText(value.ProtocolVersion, 32) || !canonicalText(value.MinimumAgentProtocolVersion, 32) || !canonicalText(value.MaximumAgentProtocolVersion, 32) || !uniqueCanonicalIdentifiers(value.SupportedVariants, 16) || !canonicalText(value.DatabaseVersionRange, 128) || !uniqueCanonicalIdentifiers(value.Capabilities, 64) || value.MetricTemplateSchemaVersion < 1 || value.MetricTemplateSchemaVersion > 65535 || len(value.Platforms) == 0 || len(value.Platforms) > 16 || value.Revision == 0 || value.CreatedAt.IsZero() {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(value.Platforms))
	for _, platform := range value.Platforms {
		key := platform.OperatingSystem + "-" + platform.Architecture
		if platform.OperatingSystem != "linux" || platform.Architecture != "amd64" && platform.Architecture != "arm64" || !digestPattern.MatchString(platform.SHA256) || platform.SizeBytes <= 0 {
			return ErrInvalid
		}
		if _, duplicate := seen[key]; duplicate {
			return ErrInvalid
		}
		seen[key] = struct{}{}
	}
	if value.ApprovedAt != nil && value.ApprovedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

func (value PluginVersion) ETag() string {
	if value.Revision == 0 {
		return ""
	}
	return `"` + strconv.FormatUint(value.Revision, 10) + `"`
}

type PluginDefinition struct {
	Scope                  platformscope.Scope
	PluginID               string
	Name                   string
	DatabaseFamily         string
	ProtocolVersion        string
	SupportedVariants      []string
	Capabilities           []string
	LatestAvailableVersion string
}

func (value PluginDefinition) Validate() error {
	if value.Scope.Validate() != nil || !identifierPattern.MatchString(value.PluginID) || !canonicalText(value.Name, 120) || !identifierPattern.MatchString(value.DatabaseFamily) || !canonicalText(value.ProtocolVersion, 32) || !uniqueCanonicalIdentifiers(value.SupportedVariants, 16) || !uniqueCanonicalIdentifiers(value.Capabilities, 64) || value.LatestAvailableVersion != "" && !canonicalText(value.LatestAvailableVersion, 64) {
		return ErrInvalid
	}
	return nil
}

type UploadMetadata struct {
	Actor         string
	ContentLength int64
}

type VersionFilter struct {
	VersionID string
	PluginID  string
	Status    Status
	Cursor    string
	Limit     int
}

func (filter VersionFilter) Validate() error {
	if filter.VersionID != "" && !catalogIDPattern.MatchString(filter.VersionID) || filter.PluginID != "" && !identifierPattern.MatchString(filter.PluginID) || filter.Status != "" && !filter.Status.Valid() || filter.Cursor != "" && (!canonicalText(filter.Cursor, 512) || strings.HasPrefix(filter.Cursor, " ")) || filter.Limit < 0 || filter.Limit > 100 {
		return ErrInvalid
	}
	return nil
}

type DefinitionFilter struct {
	DatabaseFamily string
	Cursor         string
	Limit          int
}

func (filter DefinitionFilter) Validate() error {
	if filter.DatabaseFamily != "" && !identifierPattern.MatchString(filter.DatabaseFamily) || filter.Cursor != "" && !canonicalText(filter.Cursor, 512) || filter.Limit < 0 || filter.Limit > 100 {
		return ErrInvalid
	}
	return nil
}

type VersionPage struct {
	Items      []PluginVersion
	More       bool
	NextCursor string
}

type DefinitionPage struct {
	Items      []PluginDefinition
	More       bool
	NextCursor string
}

type Service interface {
	Upload(context.Context, platformscope.Scope, UploadMetadata, io.Reader) (PluginVersion, error)
	Approve(context.Context, platformscope.Scope, string, uint64) (PluginVersion, error)
	Revoke(context.Context, platformscope.Scope, string, uint64, string) (PluginVersion, error)
	ListVersions(context.Context, platformscope.Scope, VersionFilter) (VersionPage, error)
}

type PublicationService interface {
	Publish(context.Context, platformscope.Scope, string, uint64) (PluginVersion, error)
}

type DefinitionService interface {
	ListDefinitions(context.Context, platformscope.Scope, DefinitionFilter) (DefinitionPage, error)
}

type CatalogService interface {
	Service
	PublicationService
	DefinitionService
	UploadOperation(context.Context, platformscope.Scope, UploadMetadata, OperationKey, []byte, OperationResponseBuilder, io.Reader) (OperationSnapshot, error)
	ApproveOperation(context.Context, platformscope.Scope, string, uint64, OperationKey, []byte, OperationResponseBuilder) (OperationSnapshot, error)
	PublishOperation(context.Context, platformscope.Scope, string, uint64, OperationKey, []byte, OperationResponseBuilder) (OperationSnapshot, error)
	RevokeOperation(context.Context, platformscope.Scope, string, uint64, string, OperationKey, []byte, OperationResponseBuilder) (OperationSnapshot, error)
	RecoverOperation(context.Context, OperationKey) (OperationSnapshot, error)
}

type OperationState string

const (
	OperationPending   OperationState = "pending"
	OperationCommitted OperationState = "committed"
	OperationAbandoned OperationState = "abandoned"
)

const DefaultOperationLease = 10 * time.Minute

type OperationKey struct {
	Scope          platformscope.Scope
	Actor          string
	OperationID    string
	IdempotencyKey string
	Fingerprint    string
	OwnerToken     string
}

func (key OperationKey) Validate() error {
	if key.Scope.Validate() != nil || !canonicalText(key.Actor, 256) || !canonicalText(key.OperationID, 128) || !canonicalText(key.IdempotencyKey, 128) || len(key.Fingerprint) != len("sha256:")+64 || !strings.HasPrefix(key.Fingerprint, "sha256:") || len(key.OwnerToken) != len("owner-")+64 || !strings.HasPrefix(key.OwnerToken, "owner-") {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(key.Fingerprint, "sha256:")); err != nil {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(key.OwnerToken, "owner-")); err != nil {
		return ErrInvalid
	}
	return nil
}

func (key OperationKey) Identity() string {
	return key.Scope.Key() + "\x00" + key.Actor + "\x00" + key.OperationID + "\x00" + key.IdempotencyKey
}

func (key OperationKey) RecordID() string {
	digest := sha256.Sum256([]byte(key.Identity()))
	return "plugin-operation-" + hex.EncodeToString(digest[:16])
}

type OperationResponse struct {
	Status int
	ETag   string
	Body   []byte
}

func (response OperationResponse) Validate() error {
	if response.Status < 100 || response.Status > 599 || response.ETag == "" || !json.Valid(response.Body) {
		return ErrInvalid
	}
	return nil
}

type OperationResponseBuilder func(PluginVersion) (OperationResponse, error)

type OperationSnapshot struct {
	Key            OperationKey
	State          OperationState
	Kind           string
	Definition     PluginDefinition
	Version        PluginVersion
	ArtifactID     string
	ArtifactSHA256 string
	ArtifactBytes  int64
	LeaseExpiresAt time.Time
	AbandonedAt    *time.Time
	Response       OperationResponse
	AuditEventJSON []byte
}

func (snapshot OperationSnapshot) Validate() error {
	if snapshot.Key.Validate() != nil || snapshot.State != OperationPending && snapshot.State != OperationCommitted && snapshot.State != OperationAbandoned || !json.Valid(snapshot.AuditEventJSON) || snapshot.LeaseExpiresAt.IsZero() {
		return ErrInvalid
	}
	if snapshot.Version.Validate() != nil || snapshot.Response.Validate() != nil || snapshot.State == OperationAbandoned && snapshot.AbandonedAt == nil {
		return ErrInvalid
	}
	return nil
}

type UploadOperationRequest struct {
	Key            OperationKey
	Definition     PluginDefinition
	Version        PluginVersion
	ArtifactID     string
	ArtifactSHA256 string
	ArtifactBytes  int64
	CreatedBy      string
	CreatedAt      time.Time
	LeaseExpiresAt time.Time
	Response       OperationResponse
	AuditEventJSON []byte
}

type TransitionOperationRequest struct {
	Key            OperationKey
	Transition     TransitionRequest
	AuditEventJSON []byte
}

type OperationRepository interface {
	GetOperation(context.Context, OperationKey) (OperationSnapshot, error)
	BeginUploadOperation(context.Context, UploadOperationRequest) (OperationSnapshot, error)
	FinalizeUploadOperation(context.Context, OperationKey, OperationResponseBuilder) (OperationSnapshot, error)
	TransitionOperation(context.Context, TransitionOperationRequest, OperationResponseBuilder) (OperationSnapshot, error)
	ReconcileExpiredUploadOperations(context.Context, time.Time, int) (OperationReconcileResult, error)
}

type OperationReconcileResult struct {
	Finalized int
	Abandoned int
}

type TransitionRequest struct {
	Scope            platformscope.Scope
	VersionID        string
	ExpectedRevision uint64
	AllowedFrom      []Status
	To               Status
	Reason           string
}

type Repository interface {
	Create(context.Context, PluginDefinition, PluginVersion) (PluginVersion, error)
	Transition(context.Context, TransitionRequest) (PluginVersion, error)
	ListVersions(context.Context, platformscope.Scope, VersionFilter) (VersionPage, error)
	ListDefinitions(context.Context, platformscope.Scope, DefinitionFilter) (DefinitionPage, error)
}

var catalogIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
var reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type VerifiedPackage struct {
	Manifest       Manifest
	PackageSHA256  string
	ManifestDigest string
	ContentDigest  string
	SizeBytes      int64

	lifecycle *verifiedPackageLifecycle
}

type verifiedPackageLifecycle struct {
	mu       sync.Mutex
	file     *os.File
	size     int64
	path     string
	close    func(*os.File) error
	remove   func(string) error
	observe  func(error)
	closeErr error
}

func (value *VerifiedPackage) Open() (io.ReadCloser, error) {
	if value == nil || value.lifecycle == nil {
		return nil, ErrInvalid
	}
	value.lifecycle.mu.Lock()
	defer value.lifecycle.mu.Unlock()
	if value.lifecycle.file == nil {
		return nil, ErrInvalid
	}
	return io.NopCloser(io.NewSectionReader(value.lifecycle.file, 0, value.lifecycle.size)), nil
}

func (value *VerifiedPackage) Close() error {
	if value == nil {
		return nil
	}
	if value.lifecycle == nil {
		return nil
	}
	value.lifecycle.mu.Lock()
	defer value.lifecycle.mu.Unlock()
	if value.lifecycle.file == nil && value.lifecycle.path == "" {
		return value.lifecycle.closeErr
	}
	var closeErr, removeErr error
	if value.lifecycle.file != nil {
		closeErr = value.lifecycle.close(value.lifecycle.file)
		value.lifecycle.file = nil
	}
	if value.lifecycle.path != "" {
		removeErr = value.lifecycle.remove(value.lifecycle.path)
		value.lifecycle.path = ""
	}
	value.lifecycle.closeErr = errors.Join(closeErr, removeErr)
	if value.lifecycle.closeErr != nil && value.lifecycle.observe != nil {
		value.lifecycle.observe(value.lifecycle.closeErr)
	}
	return value.lifecycle.closeErr
}
