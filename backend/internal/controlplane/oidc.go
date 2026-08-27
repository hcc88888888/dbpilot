package controlplane

import (
	"context"
	"errors"
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
	Verify(context.Context, string) (OIDCClaims, error)
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
	claims, err := resolver.Verifier.Verify(request.Context(), token)
	if err != nil {
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

func (verifier coreosTokenVerifier) Verify(ctx context.Context, raw string) (OIDCClaims, error) {
	if verifier.verifier == nil || ctx == nil || raw == "" {
		return OIDCClaims{}, ErrUnauthenticated
	}
	token, err := verifier.verifier.Verify(ctx, raw)
	if err != nil {
		return OIDCClaims{}, err
	}
	var claims OIDCClaims
	if err := token.Claims(&claims); err != nil {
		return OIDCClaims{}, err
	}
	return claims, nil
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
