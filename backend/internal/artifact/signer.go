package artifact

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/platformscope"
)

type HMACDownloadSigner struct {
	baseURL  *url.URL
	keyRef   string
	resolver database.SecretResolver
	now      func() time.Time
}

func NewHMACDownloadSigner(baseURL, keyRef string, resolver database.SecretResolver) (*HMACDownloadSigner, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.TrimSpace(parsed.Path) == "" || strings.TrimSpace(keyRef) == "" || resolver == nil {
		return nil, ErrInvalid
	}
	copyURL := *parsed
	copyURL.Path = strings.TrimSuffix(copyURL.Path, "/")
	return &HMACDownloadSigner{baseURL: &copyURL, keyRef: keyRef, resolver: resolver, now: time.Now}, nil
}

func (signer *HMACDownloadSigner) Sign(ctx context.Context, value Artifact, expires time.Time) (string, error) {
	if signer == nil || signer.resolver == nil || ctx == nil || value.Scope.Validate() != nil || !validArtifactID(value.ID) || expires.IsZero() {
		return "", ErrInvalid
	}
	expires = expires.UTC().Truncate(time.Second)
	key, err := signer.key(ctx)
	if err != nil {
		return "", err
	}
	signature := signatureFor(key, value.ID, value.Scope, expires)
	result := *signer.baseURL
	encodedID := base64.RawURLEncoding.EncodeToString([]byte(value.ID))
	result.Path = strings.TrimSuffix(result.Path, "/") + "/" + encodedID
	query := url.Values{}
	query.Set("tenant_id", value.Scope.TenantID)
	query.Set("project_id", value.Scope.ProjectID)
	query.Set("expires", strconv.FormatInt(expires.Unix(), 10))
	query.Set("signature", base64.RawURLEncoding.EncodeToString(signature))
	result.RawQuery = query.Encode()
	return result.String(), nil
}

func (signer *HMACDownloadSigner) Verify(ctx context.Context, rawURL string) (DownloadClaims, error) {
	if signer == nil || signer.resolver == nil || ctx == nil {
		return DownloadClaims{}, ErrInvalidSignature
	}
	value, err := url.Parse(rawURL)
	if err != nil || value.User != nil || value.Scheme != signer.baseURL.Scheme || value.Host != signer.baseURL.Host {
		return DownloadClaims{}, ErrInvalidSignature
	}
	prefix := strings.TrimSuffix(signer.baseURL.Path, "/") + "/"
	if !strings.HasPrefix(value.EscapedPath(), prefix) {
		return DownloadClaims{}, ErrInvalidSignature
	}
	escapedID := strings.TrimPrefix(value.EscapedPath(), prefix)
	if escapedID == "" || strings.Contains(escapedID, "/") {
		return DownloadClaims{}, ErrInvalidSignature
	}
	decodedID, err := base64.RawURLEncoding.DecodeString(escapedID)
	id := string(decodedID)
	if err != nil || base64.RawURLEncoding.EncodeToString(decodedID) != escapedID || !validArtifactID(id) {
		return DownloadClaims{}, ErrInvalidSignature
	}
	query := value.Query()
	if len(query) != 4 || len(query["tenant_id"]) != 1 || len(query["project_id"]) != 1 || len(query["expires"]) != 1 || len(query["signature"]) != 1 {
		return DownloadClaims{}, ErrInvalidSignature
	}
	scope := platformscope.Scope{TenantID: query.Get("tenant_id"), ProjectID: query.Get("project_id")}
	unixExpiry, err := strconv.ParseInt(query.Get("expires"), 10, 64)
	if err != nil || scope.Validate() != nil {
		return DownloadClaims{}, ErrInvalidSignature
	}
	expires := time.Unix(unixExpiry, 0).UTC()
	provided, err := base64.RawURLEncoding.DecodeString(query.Get("signature"))
	if err != nil {
		return DownloadClaims{}, ErrInvalidSignature
	}
	key, err := signer.key(ctx)
	if err != nil {
		return DownloadClaims{}, err
	}
	expected := signatureFor(key, id, scope, expires)
	if len(provided) != len(expected) || subtle.ConstantTimeCompare(provided, expected) != 1 {
		return DownloadClaims{}, ErrInvalidSignature
	}
	if !expires.After(signer.currentTime()) {
		return DownloadClaims{}, ErrExpired
	}
	if expires.After(signer.currentTime().Add(MaximumDownloadTTL)) {
		return DownloadClaims{}, ErrInvalidSignature
	}
	return DownloadClaims{ArtifactID: id, Scope: scope, ExpiresAt: expires}, nil
}

func (signer *HMACDownloadSigner) Ready(ctx context.Context) error {
	if signer == nil || ctx == nil {
		return ErrInvalid
	}
	_, err := signer.key(ctx)
	return err
}

func (signer *HMACDownloadSigner) VerifyRequest(ctx context.Context, request *http.Request) (DownloadClaims, error) {
	if signer == nil || request == nil || request.URL == nil || request.Host != signer.baseURL.Host {
		return DownloadClaims{}, ErrInvalidSignature
	}
	value := *signer.baseURL
	value.Path = request.URL.Path
	value.RawPath = request.URL.RawPath
	value.RawQuery = request.URL.RawQuery
	return signer.Verify(ctx, value.String())
}

func (signer *HMACDownloadSigner) key(ctx context.Context) ([]byte, error) {
	key, err := signer.resolver.ResolveSecret(ctx, signer.keyRef)
	if err != nil || len(key) < sha256.Size {
		return nil, errors.New("resolve artifact signing key")
	}
	return key, nil
}

func (signer *HMACDownloadSigner) currentTime() time.Time {
	if signer.now == nil {
		return time.Now().UTC()
	}
	return signer.now().UTC()
}

func signatureFor(key []byte, id string, scope platformscope.Scope, expires time.Time) []byte {
	mac := hmac.New(sha256.New, key)
	for _, value := range []string{id, scope.TenantID, scope.ProjectID, strconv.FormatInt(expires.Unix(), 10)} {
		_, _ = mac.Write([]byte(strconv.Itoa(len(value))))
		_, _ = mac.Write([]byte{':'})
		_, _ = mac.Write([]byte(value))
	}
	return mac.Sum(nil)
}
