package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/coreos/go-oidc/v3/oidc"
)

type OIDCGrant struct {
	TenantID    string   `json:"tenant_id"`
	ProjectID   string   `json:"project_id"`
	Permissions []string `json:"permissions"`
}

type OIDCClaims struct {
	Subject       string      `json:"sub"`
	PlatformAdmin bool        `json:"dbpilot_platform_admin"`
	Grants        []OIDCGrant `json:"dbpilot_grants"`
}

type TokenVerifier interface {
	Verify(context.Context, string) (json.RawMessage, error)
}

type BearerPrincipalResolver struct {
	Verifier TokenVerifier
}

func (resolver BearerPrincipalResolver) ResolvePrincipal(request *http.Request) (Principal, error) {
	if request == nil || resolver.Verifier == nil {
		return Principal{}, ErrUnauthenticated
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return Principal{}, ErrUnauthenticated
	}
	value := values[0]
	if !strings.HasPrefix(value, "Bearer ") {
		return Principal{}, ErrUnauthenticated
	}
	token := strings.TrimPrefix(value, "Bearer ")
	if token == "" || value != "Bearer "+token || strings.ContainsAny(token, " ,\t\r\n") {
		return Principal{}, ErrUnauthenticated
	}
	rawClaims, err := resolver.Verifier.Verify(request.Context(), token)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	if err := rejectDuplicateJSONMembers(rawClaims); err != nil {
		return Principal{}, ErrUnauthenticated
	}
	var claims OIDCClaims
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return Principal{}, ErrUnauthenticated
	}
	return principalFromClaims(claims)
}

func principalFromClaims(claims OIDCClaims) (Principal, error) {
	if claims.Subject == "" || claims.Subject != strings.TrimSpace(claims.Subject) || len(claims.Subject) > 256 || strings.ContainsAny(claims.Subject, "\r\n\t") {
		return Principal{}, ErrUnauthenticated
	}
	principal := Principal{
		Subject:       claims.Subject,
		PlatformAdmin: claims.PlatformAdmin,
		Projects:      make(map[string]struct{}, len(claims.Grants)),
		Grants:        make(map[string]map[string]struct{}, len(claims.Grants)),
	}
	for _, claim := range claims.Grants {
		scope := platformscope.Scope{TenantID: claim.TenantID, ProjectID: claim.ProjectID}
		if scope.Validate() != nil || !headerIdentifier.MatchString(scope.TenantID) || !headerIdentifier.MatchString(scope.ProjectID) {
			return Principal{}, ErrUnauthenticated
		}
		key := scope.Key()
		if _, duplicate := principal.Grants[key]; duplicate {
			return Principal{}, ErrUnauthenticated
		}
		permissions := make(map[string]struct{}, len(claim.Permissions))
		for _, permission := range claim.Permissions {
			if permission == "" || permission != strings.TrimSpace(permission) || strings.ContainsAny(permission, "\r\n\t") {
				return Principal{}, ErrUnauthenticated
			}
			if _, duplicate := permissions[permission]; duplicate {
				return Principal{}, ErrUnauthenticated
			}
			permissions[permission] = struct{}{}
		}
		principal.Projects[key] = struct{}{}
		principal.Grants[key] = permissions
	}
	return principal, nil
}

type coreosTokenVerifier struct {
	verifier *oidc.IDTokenVerifier
}

func (verifier coreosTokenVerifier) Verify(ctx context.Context, raw string) (json.RawMessage, error) {
	if verifier.verifier == nil || ctx == nil || raw == "" {
		return nil, ErrUnauthenticated
	}
	token, err := verifier.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var claims json.RawMessage
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func rejectDuplicateJSONMembers(raw json.RawMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate JSON object member")
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

// NewOIDCTokenVerifier performs discovery once and returns a verifier whose
// provider-managed key set is reused across requests.
func NewOIDCTokenVerifier(ctx context.Context, issuer, audience string) (TokenVerifier, error) {
	if ctx == nil || strings.TrimSpace(issuer) == "" || issuer != strings.TrimSpace(issuer) || strings.TrimSpace(audience) == "" || audience != strings.TrimSpace(audience) {
		return nil, errors.New("OIDC issuer and audience are required")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return coreosTokenVerifier{verifier: provider.Verifier(&oidc.Config{ClientID: audience})}, nil
}
