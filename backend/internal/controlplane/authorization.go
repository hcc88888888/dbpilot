package controlplane

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/platformscope"
)

var ErrForbidden = errors.New("permission is not granted for project")

// Principal is the authenticated control-plane identity. Projects records
// scope membership while Grants records exact permissions per project scope.
type Principal struct {
	Subject       string
	PlatformAdmin bool
	Projects      map[string]struct{}
	Grants        map[string]map[string]struct{}
}

func (principal Principal) AllowsScope(scope platformscope.Scope) bool {
	if scope.Validate() != nil {
		return false
	}
	if principal.PlatformAdmin {
		return true
	}
	key := scope.Key()
	if _, ok := principal.Projects[key]; ok {
		return true
	}
	_, ok := principal.Grants[key]
	return ok
}

func (principal Principal) Allows(scope platformscope.Scope, permission string) bool {
	if scope.Validate() != nil || permission == "" {
		return false
	}
	if principal.PlatformAdmin {
		return true
	}
	_, ok := principal.Grants[scope.Key()][permission]
	return ok
}

// AlertPrincipal adapts the common identity to the legacy alert/monitoring
// authorization boundary without exposing action grants to those handlers.
func (principal Principal) AlertPrincipal() alert.Principal {
	projects := make(map[string]struct{}, len(principal.Projects))
	for key := range principal.Projects {
		projects[key] = struct{}{}
	}
	return alert.Principal{
		Subject:       principal.Subject,
		PlatformAdmin: principal.PlatformAdmin,
		Projects:      projects,
	}
}

type Authorizer struct{}

func (Authorizer) Require(principal Principal, scope platformscope.Scope, permission string) error {
	if !principal.Allows(scope, permission) {
		return ErrForbidden
	}
	return nil
}

func permissionForStrictOperation(operationID string) (string, bool) {
	if operationID == "" {
		return "", false
	}
	generatedID := strings.ToLower(operationID[:1]) + operationID[1:]
	permission, ok := openapi.OperationPermissions[generatedID]
	return permission, ok
}

func generatedAuthorizationMiddleware(authorizer Authorizer) openapi.StrictMiddlewareFunc {
	return func(next openapi.StrictHandlerFunc, operationID string) openapi.StrictHandlerFunc {
		return func(ctx context.Context, writer http.ResponseWriter, request *http.Request, input any) (any, error) {
			permission, ok := permissionForStrictOperation(operationID)
			if !ok {
				return nil, errors.New("generated operation has no permission mapping")
			}
			principal, principalOK := ctx.Value(principalContextKey{}).(Principal)
			scope, scopeOK := ctx.Value(platformScopeContextKey{}).(platformscope.Scope)
			if !principalOK || !scopeOK {
				return nil, ErrUnauthenticated
			}
			if err := authorizer.Require(principal, scope, permission); err != nil {
				return nil, err
			}
			return next(ctx, writer, request, input)
		}
	}
}
