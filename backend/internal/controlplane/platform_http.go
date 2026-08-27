package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
)

const platformRouteBase = "/api/v1/tenants/{tenantID}/projects/{projectID}"

func mountPlatformRoutes(mux *http.ServeMux, services Services, resolver PrincipalResolver) {
	validator := newPlatformResponseValidator()
	registrar := platformRouteRegistrar{mux: mux, resolver: resolver, validator: validator}
	strict := openapi.NewStrictHandlerWithOptions(
		platformAPI{services: services},
		[]openapi.StrictMiddlewareFunc{generatedAuthorizationMiddleware(Authorizer{})},
		openapi.StrictHTTPServerOptions{
			RequestErrorHandlerFunc: func(writer http.ResponseWriter, request *http.Request, _ error) {
				writePlatformProblem(writer, request, ErrInvalidRequest)
			},
			ResponseErrorHandlerFunc: func(writer http.ResponseWriter, request *http.Request, err error) {
				writePlatformProblem(writer, request, err)
			},
		},
	)
	_ = openapi.HandlerWithOptions(strict, openapi.StdHTTPServerOptions{
		BaseURL:    platformRouteBase,
		BaseRouter: registrar,
		ErrorHandlerFunc: func(writer http.ResponseWriter, request *http.Request, _ error) {
			writePlatformProblem(writer, request, ErrInvalidRequest)
		},
	})
}

type platformRouteRegistrar struct {
	mux       *http.ServeMux
	resolver  PrincipalResolver
	validator platformResponseValidator
}

func (registrar platformRouteRegistrar) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	secured := authenticatePlatform(registrar.resolver, requirePlatformScope(http.HandlerFunc(handler)))
	registrar.mux.Handle(pattern, withRequestID(registrar.validator.middleware(secured)))
}

func (registrar platformRouteRegistrar) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	registrar.mux.ServeHTTP(writer, request)
}

func authenticatePlatform(resolver PrincipalResolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if resolver == nil {
			writePlatformProblem(writer, request, ErrUnauthenticated)
			return
		}
		principal, err := resolver.ResolvePrincipal(request)
		if err != nil || strings.TrimSpace(principal.Subject) == "" {
			writePlatformProblem(writer, request, ErrUnauthenticated)
			return
		}
		ctx := context.WithValue(request.Context(), principalContextKey{}, principal)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func requirePlatformScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := request.Context().Value(principalContextKey{}).(Principal)
		if !ok || strings.TrimSpace(principal.Subject) == "" {
			writePlatformProblem(writer, request, ErrUnauthenticated)
			return
		}
		scope := platformscope.Scope{TenantID: request.PathValue("tenantID"), ProjectID: request.PathValue("projectID")}
		if scope.Validate() != nil || !headerIdentifier.MatchString(scope.TenantID) || !headerIdentifier.MatchString(scope.ProjectID) {
			writePlatformProblem(writer, request, ErrInvalidRequest)
			return
		}
		if !principal.AllowsScope(scope) {
			writePlatformProblem(writer, request, ErrForbidden)
			return
		}
		ctx := context.WithValue(request.Context(), platformScopeContextKey{}, scope)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

type platformResponseValidator struct {
	spec   *openapi3.T
	router routers.Router
	err    error
}

func newPlatformResponseValidator() platformResponseValidator {
	spec, err := openapi.GetSpec()
	if err != nil {
		return platformResponseValidator{err: err}
	}
	router, err := legacy.NewRouter(spec)
	return platformResponseValidator{spec: spec, router: router, err: err}
}

func (validator platformResponseValidator) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if validator.err != nil || validator.spec == nil || validator.router == nil {
			writePlatformProblem(writer, request, validator.err)
			return
		}
		buffered := &bufferedResponse{header: make(http.Header)}
		next.ServeHTTP(buffered, request)
		status := buffered.status
		if status == 0 {
			status = http.StatusOK
		}
		if err := validator.validate(request, status, buffered.header, buffered.body.Bytes()); err != nil {
			writePlatformProblem(writer, request, err)
			return
		}
		copyBufferedResponse(writer, buffered)
	})
}

func (validator platformResponseValidator) validate(request *http.Request, status int, header http.Header, body []byte) error {
	route, pathParameters, err := validator.router.FindRoute(request)
	if err != nil {
		return err
	}
	requestInput := &openapi3filter.RequestValidationInput{Request: request, PathParams: pathParameters, Route: route}
	responseInput := (&openapi3filter.ResponseValidationInput{RequestValidationInput: requestInput, Status: status, Header: header}).SetBodyBytes(body)
	if err := openapi3filter.ValidateResponse(request.Context(), responseInput); err == nil {
		return nil
	} else if status < 500 || !strings.HasPrefix(header.Get("Content-Type"), "application/problem+json") {
		return err
	}
	var problem any
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decodeErr := decoder.Decode(&problem); decodeErr != nil {
		return err
	}
	if schemaErr := validator.spec.Components.Schemas["Problem"].Value.VisitJSON(problem); schemaErr != nil {
		return err
	}
	return nil
}
