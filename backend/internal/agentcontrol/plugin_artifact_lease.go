package agentcontrol

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/artifact"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	pluginArtifactLeaseHeader = "X-DBPilot-Artifact-Lease"
	pluginArtifactPathPrefix  = "/api/v1/agent/plugin-artifacts/"
	maximumPluginArtifactSize = 256 << 20
)

var ErrPluginArtifactLeaseRejected = errors.New("plugin artifact lease rejected")

type PluginArtifactGrant struct {
	AgentID           string
	AssignmentID      string
	ArtifactID        string
	OperationRevision uint64
	Artifact          artifact.Artifact
}

type PluginArtifactAuthorizer interface {
	AuthorizePluginArtifact(context.Context, string, string, string, uint64) (PluginArtifactGrant, error)
}

type PluginArtifactArtifactBlobStore interface {
	Open(context.Context, artifact.Artifact) (artifact.ReadSeekCloser, error)
}

type PluginArtifactLeaseIssuerConfig struct {
	Origin        string
	HMACKey       []byte
	TTL           time.Duration
	MaximumLeases int
	Authorizer    PluginArtifactAuthorizer
	Now           func() time.Time
}

type pluginArtifactLeaseRecord struct {
	requestNonce      [sha256.Size]byte
	agentID           string
	assignmentID      string
	artifactID        string
	operationRevision uint64
	issuedAt          time.Time
	expiresAt         time.Time
	leaseID           string
	artifact          artifact.Artifact
}

type PluginArtifactLeaseIssuer struct {
	mu            sync.Mutex
	origin        *url.URL
	hmacKey       []byte
	ttl           time.Duration
	maximumLeases int
	authorizer    PluginArtifactAuthorizer
	now           func() time.Time
	byNonce       map[string]pluginArtifactLeaseRecord
	byLease       map[string]pluginArtifactLeaseRecord
}

func NewPluginArtifactLeaseIssuer(config PluginArtifactLeaseIssuerConfig) (*PluginArtifactLeaseIssuer, error) {
	origin, err := url.Parse(config.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || strings.TrimRight(origin.Path, "/") != "" || len(config.HMACKey) < 32 || config.TTL <= 0 || config.TTL > artifact.MaximumDownloadTTL || config.MaximumLeases < 1 || config.MaximumLeases > 65536 || config.Authorizer == nil {
		return nil, ErrPluginArtifactLeaseRejected
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &PluginArtifactLeaseIssuer{origin: origin, hmacKey: append([]byte(nil), config.HMACKey...), ttl: config.TTL, maximumLeases: config.MaximumLeases, authorizer: config.Authorizer, now: config.Now, byNonce: map[string]pluginArtifactLeaseRecord{}, byLease: map[string]pluginArtifactLeaseRecord{}}, nil
}

func (issuer *PluginArtifactLeaseIssuer) Issue(ctx context.Context, agentID string, request *agentv1.PluginArtifactLeaseRequest) (*agentv1.PluginArtifactLeaseResponse, error) {
	if issuer == nil || ctx == nil || ctx.Err() != nil || !validAgentResource(agentID) || request == nil || len(request.GetRequestNonce()) != sha256.Size || !validAgentResource(request.GetAssignmentId()) || !validAgentResource(request.GetArtifactId()) || request.GetOperationRevision() == 0 {
		return nil, ErrPluginArtifactLeaseRejected
	}
	grant, err := issuer.authorizer.AuthorizePluginArtifact(ctx, agentID, request.GetAssignmentId(), request.GetArtifactId(), request.GetOperationRevision())
	if err != nil || !validPluginArtifactGrant(grant, agentID, request.GetAssignmentId(), request.GetArtifactId(), request.GetOperationRevision()) {
		return nil, ErrPluginArtifactLeaseRejected
	}
	var nonce [sha256.Size]byte
	copy(nonce[:], request.GetRequestNonce())
	nonceKey := agentID + "\x00" + hex.EncodeToString(nonce[:])
	now := issuer.now().UTC()
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	issuer.pruneLocked(now)
	if existing, ok := issuer.byNonce[nonceKey]; ok {
		if existing.assignmentID != request.GetAssignmentId() || existing.artifactID != request.GetArtifactId() || existing.operationRevision != request.GetOperationRevision() || !sameArtifact(existing.artifact, grant.Artifact) {
			return nil, ErrPluginArtifactLeaseRejected
		}
		return issuer.response(existing), nil
	}
	if len(issuer.byLease) >= issuer.maximumLeases {
		return nil, ErrPluginArtifactLeaseRejected
	}
	expiresAt := now.Add(issuer.ttl).UTC()
	identity := sha256.Sum256([]byte(agentID + "\x00" + request.GetAssignmentId() + "\x00" + request.GetArtifactId() + "\x00" + strconv.FormatUint(request.GetOperationRevision(), 10) + "\x00" + hex.EncodeToString(nonce[:]) + "\x00" + expiresAt.Format(time.RFC3339Nano)))
	record := pluginArtifactLeaseRecord{requestNonce: nonce, agentID: agentID, assignmentID: request.GetAssignmentId(), artifactID: request.GetArtifactId(), operationRevision: request.GetOperationRevision(), issuedAt: now, expiresAt: expiresAt, leaseID: "lease-" + hex.EncodeToString(identity[:16]), artifact: grant.Artifact}
	issuer.byNonce[nonceKey], issuer.byLease[record.leaseID] = record, record
	return issuer.response(record), nil
}

func (issuer *PluginArtifactLeaseIssuer) response(record pluginArtifactLeaseRecord) *agentv1.PluginArtifactLeaseResponse {
	return &agentv1.PluginArtifactLeaseResponse{RequestNonce: append([]byte(nil), record.requestNonce[:]...), LeaseId: record.leaseID, AssignmentId: record.assignmentID, ArtifactId: record.artifactID, OperationRevision: record.operationRevision, ExpiresAt: timestamppb.New(record.expiresAt), DownloadUrl: strings.TrimRight(issuer.origin.String(), "/") + pluginArtifactPathPrefix + url.PathEscape(record.leaseID), RequestHeaders: map[string]string{pluginArtifactLeaseHeader: issuer.token(record)}}
}

func (issuer *PluginArtifactLeaseIssuer) token(record pluginArtifactLeaseRecord) string {
	hash := hmac.New(sha256.New, issuer.hmacKey)
	_, _ = io.WriteString(hash, "dbpilot-plugin-artifact-lease-v1\n")
	for _, value := range []string{record.leaseID, record.agentID, record.assignmentID, record.artifactID, strconv.FormatUint(record.operationRevision, 10), hex.EncodeToString(record.requestNonce[:]), record.expiresAt.Format(time.RFC3339Nano)} {
		_, _ = io.WriteString(hash, strconv.Itoa(len(value))+":"+value)
	}
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func (issuer *PluginArtifactLeaseIssuer) authorizeDownload(ctx context.Context, agentID, leaseID, token string) (PluginArtifactGrant, error) {
	if issuer == nil || ctx == nil || ctx.Err() != nil || !validAgentResource(agentID) || !validAgentResource(leaseID) || token == "" || len(token) > 128 {
		return PluginArtifactGrant{}, ErrPluginArtifactLeaseRejected
	}
	now := issuer.now().UTC()
	issuer.mu.Lock()
	issuer.pruneLocked(now)
	record, ok := issuer.byLease[leaseID]
	issuer.mu.Unlock()
	if !ok || record.agentID != agentID || !record.expiresAt.After(now) {
		return PluginArtifactGrant{}, ErrPluginArtifactLeaseRejected
	}
	expected := issuer.token(record)
	if len(expected) != len(token) || subtle.ConstantTimeCompare([]byte(expected), []byte(token)) != 1 {
		return PluginArtifactGrant{}, ErrPluginArtifactLeaseRejected
	}
	grant, err := issuer.authorizer.AuthorizePluginArtifact(ctx, agentID, record.assignmentID, record.artifactID, record.operationRevision)
	if err != nil || !validPluginArtifactGrant(grant, agentID, record.assignmentID, record.artifactID, record.operationRevision) || !sameArtifact(record.artifact, grant.Artifact) {
		return PluginArtifactGrant{}, ErrPluginArtifactLeaseRejected
	}
	return grant, nil
}

func (issuer *PluginArtifactLeaseIssuer) pruneLocked(now time.Time) {
	for leaseID, record := range issuer.byLease {
		if !record.expiresAt.After(now) {
			delete(issuer.byLease, leaseID)
			delete(issuer.byNonce, record.agentID+"\x00"+hex.EncodeToString(record.requestNonce[:]))
		}
	}
}

type PluginArtifactLeaseHTTPHandler struct {
	issuer *PluginArtifactLeaseIssuer
	blobs  PluginArtifactArtifactBlobStore
}

func NewPluginArtifactLeaseHTTPHandler(issuer *PluginArtifactLeaseIssuer, blobs PluginArtifactArtifactBlobStore) (*PluginArtifactLeaseHTTPHandler, error) {
	if issuer == nil || blobs == nil {
		return nil, ErrPluginArtifactLeaseRejected
	}
	return &PluginArtifactLeaseHTTPHandler{issuer: issuer, blobs: blobs}, nil
}

func (handler *PluginArtifactLeaseHTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || request == nil || request.Method != http.MethodGet || request.URL.RawQuery != "" || request.Header.Get("Range") != "" {
		writePluginArtifactError(writer, http.StatusMethodNotAllowed)
		return
	}
	if request.TLS == nil {
		writePluginArtifactError(writer, http.StatusForbidden)
		return
	}
	agentID, err := spiffeAgentFromTLS(*request.TLS)
	if err != nil {
		writePluginArtifactError(writer, http.StatusForbidden)
		return
	}
	leaseID := request.PathValue("leaseID")
	if leaseID == "" && strings.HasPrefix(request.URL.Path, pluginArtifactPathPrefix) {
		leaseID = strings.TrimPrefix(request.URL.Path, pluginArtifactPathPrefix)
	}
	if strings.Contains(leaseID, "/") {
		writePluginArtifactError(writer, http.StatusForbidden)
		return
	}
	grant, err := handler.issuer.authorizeDownload(request.Context(), agentID, leaseID, request.Header.Get(pluginArtifactLeaseHeader))
	if err != nil {
		writePluginArtifactError(writer, http.StatusForbidden)
		return
	}
	reader, err := handler.blobs.Open(request.Context(), grant.Artifact)
	if err != nil {
		writePluginArtifactError(writer, http.StatusNotFound)
		return
	}
	defer reader.Close()
	if err := verifyPluginArtifactReader(request.Context(), reader, grant.Artifact); err != nil {
		writePluginArtifactError(writer, http.StatusConflict)
		return
	}
	writer.Header().Set("Content-Type", "application/gzip")
	writer.Header().Set("Content-Length", strconv.FormatInt(grant.Artifact.SizeBytes, 10))
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(writer, reader, grant.Artifact.SizeBytes)
}

func verifyPluginArtifactReader(ctx context.Context, reader artifact.ReadSeekCloser, value artifact.Artifact) error {
	if ctx == nil || value.SizeBytes <= 0 || value.SizeBytes > maximumPluginArtifactSize || !strings.HasPrefix(value.Checksum, "sha256:") {
		return ErrPluginArtifactLeaseRejected
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(value.Checksum, "sha256:"))
	if err != nil || len(expected) != sha256.Size {
		return ErrPluginArtifactLeaseRejected
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	var total int64
	for total <= value.SizeBytes {
		if err := ctx.Err(); err != nil {
			return err
		}
		read, readErr := reader.Read(buffer)
		if read > 0 {
			total += int64(read)
			if total > value.SizeBytes {
				return ErrPluginArtifactLeaseRejected
			}
			_, _ = hash.Write(buffer[:read])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil || read == 0 {
			return ErrPluginArtifactLeaseRejected
		}
	}
	if total != value.SizeBytes || subtle.ConstantTimeCompare(hash.Sum(nil), expected) != 1 {
		return ErrPluginArtifactLeaseRejected
	}
	_, err = reader.Seek(0, io.SeekStart)
	return err
}

func validPluginArtifactGrant(grant PluginArtifactGrant, agentID, assignmentID, artifactID string, operationRevision uint64) bool {
	value := grant.Artifact
	return grant.AgentID == agentID && grant.AssignmentID == assignmentID && grant.ArtifactID == artifactID && grant.OperationRevision == operationRevision && value.ID == artifactID && value.Scope.Validate() == nil && value.Kind == "plugin-package" && value.ContentType == "application/gzip" && value.SizeBytes > 0 && value.SizeBytes <= maximumPluginArtifactSize && len(value.Checksum) == len("sha256:")+64 && strings.HasPrefix(value.Checksum, "sha256:") && value.SourceResource.ResourceType == "plugin_catalog_operation" && validAgentResource(value.SourceResource.ResourceID) && value.StorageReference != ""
}

func sameArtifact(left, right artifact.Artifact) bool {
	return left.ID == right.ID && left.Scope == right.Scope && left.Kind == right.Kind && left.ContentType == right.ContentType && left.SizeBytes == right.SizeBytes && left.Checksum == right.Checksum && left.SourceResource == right.SourceResource && left.StorageReference == right.StorageReference
}

func validAgentResource(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if index == 0 && !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9') || index > 0 && !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '.' || character == ':' || character == '-') {
			return false
		}
	}
	return true
}

func writePluginArtifactError(writer http.ResponseWriter, status int) {
	writer.Header().Set("Cache-Control", "no-store")
	http.Error(writer, "plugin artifact is unavailable", status)
}

var _ http.Handler = (*PluginArtifactLeaseHTTPHandler)(nil)
