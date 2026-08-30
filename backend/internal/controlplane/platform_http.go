package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

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
	registrar := &platformRouteRegistrar{mux: mux, resolver: resolver, validator: validator, allowed: make(map[string]map[string]struct{})}
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
	mu        sync.RWMutex
	allowed   map[string]map[string]struct{}
}

func (registrar *platformRouteRegistrar) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok || method == "" || !strings.HasPrefix(path, "/") {
		panic("invalid generated platform route pattern")
	}
	registrar.mu.Lock()
	methods := registrar.allowed[path]
	firstPathRegistration := methods == nil
	if firstPathRegistration {
		methods = make(map[string]struct{})
		registrar.allowed[path] = methods
	}
	methods[method] = struct{}{}
	registrar.mu.Unlock()

	validated := capturePlatformRequestMetadata(registrar.validator.requestMiddleware(http.HandlerFunc(handler)))
	secured := authenticatePlatform(registrar.resolver, requirePlatformScope(validated))
	registrar.mux.Handle(pattern, withRequestID(withTraceContext(registrar.validator.middleware(exactPlatformMethod(method, secured)))))
	if firstPathRegistration {
		registrar.mux.Handle(path, withRequestID(withTraceContext(registrar.validator.middleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writePlatformMethodNotAllowed(writer, request, registrar.allowedMethods(path))
		})))))
	}
}

type platformRequestMetadata struct {
	Method        string
	Path          string
	RawQuery      string
	IfMatch       string
	Body          []byte
	BodyDigest    string
	ContentLength int64
}

type platformRequestMetadataContextKey struct{}

func capturePlatformRequestMetadata(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.EqualFold(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]), "application/gzip") {
			captureBinaryPlatformRequest(next, writer, request)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, maxJSONBodyBytes+1))
		if err != nil || int64(len(body)) > maxJSONBodyBytes {
			writePlatformProblem(writer, request, ErrInvalidRequest)
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
		metadata := platformRequestMetadata{
			Method: request.Method, Path: request.URL.EscapedPath(), RawQuery: request.URL.RawQuery,
			IfMatch: request.Header.Get("If-Match"), Body: append([]byte(nil), body...), ContentLength: int64(len(body)),
		}
		ctx := context.WithValue(request.Context(), platformRequestMetadataContextKey{}, metadata)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func captureBinaryPlatformRequest(next http.Handler, writer http.ResponseWriter, request *http.Request) {
	const maximumBinaryRequestBytes int64 = 256 << 20
	if request.ContentLength <= 0 || request.ContentLength > maximumBinaryRequestBytes {
		writePlatformProblem(writer, request, ErrInvalidRequest)
		return
	}
	temporary, err := os.CreateTemp("", ".dbpilot-platform-upload-*")
	if err != nil {
		writePlatformProblem(writer, request, ErrServiceUnavailable)
		return
	}
	path := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(path)
	}
	defer cleanup()
	hash := sha256.New()
	written, err := io.CopyBuffer(io.MultiWriter(temporary, hash), io.LimitReader(request.Body, request.ContentLength+1), make([]byte, 32<<10))
	if err != nil || written != request.ContentLength {
		writePlatformProblem(writer, request, ErrInvalidRequest)
		return
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		writePlatformProblem(writer, request, ErrServiceUnavailable)
		return
	}
	request.Body = temporary
	// net/http parses Content-Length into Request.ContentLength and normally
	// removes it from Header. The generated Task 1 binder models the required
	// contract header, so restore the canonical value for that binder only.
	request.Header.Set("Content-Length", strconv.FormatInt(written, 10))
	metadata := platformRequestMetadata{
		Method: request.Method, Path: request.URL.EscapedPath(), RawQuery: request.URL.RawQuery,
		IfMatch: request.Header.Get("If-Match"), BodyDigest: "sha256:" + hex.EncodeToString(hash.Sum(nil)), ContentLength: written,
	}
	ctx := context.WithValue(request.Context(), platformRequestMetadataContextKey{}, metadata)
	next.ServeHTTP(writer, request.WithContext(ctx))
}

func (registrar *platformRouteRegistrar) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	registrar.mux.ServeHTTP(writer, request)
}

func (registrar *platformRouteRegistrar) allowedMethods(path string) string {
	registrar.mu.RLock()
	defer registrar.mu.RUnlock()
	methods := make([]string, 0, len(registrar.allowed[path]))
	for method := range registrar.allowed[path] {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	return strings.Join(methods, ", ")
}

func exactPlatformMethod(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != method {
			writePlatformMethodNotAllowed(writer, request, method)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func writePlatformMethodNotAllowed(writer http.ResponseWriter, request *http.Request, allow string) {
	writer.Header().Set("Allow", allow)
	writePlatformProblem(writer, request, ErrMethodNotAllowed)
}

func authenticatePlatform(resolver PrincipalResolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if resolver == nil {
			setBearerChallenge(writer, resolver)
			writePlatformProblem(writer, request, ErrUnauthenticated)
			return
		}
		principal, err := resolver.ResolvePrincipal(request)
		if err != nil || strings.TrimSpace(principal.Subject) == "" {
			setBearerChallenge(writer, resolver)
			writePlatformProblem(writer, request, ErrUnauthenticated)
			return
		}
		ctx := context.WithValue(request.Context(), principalContextKey{}, principal)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func setBearerChallenge(writer http.ResponseWriter, resolver PrincipalResolver) {
	switch resolver.(type) {
	case BearerPrincipalResolver, *BearerPrincipalResolver:
		writer.Header().Set("WWW-Authenticate", "Bearer")
	}
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

func (validator platformResponseValidator) requestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if validator.err != nil || validator.router == nil {
			writePlatformProblem(writer, request, validator.err)
			return
		}
		route, pathParameters, err := validator.router.FindRoute(request)
		if err != nil {
			writePlatformProblem(writer, request, ErrInvalidRequest)
			return
		}
		input := &openapi3filter.RequestValidationInput{
			Request: request, PathParams: pathParameters, Route: route,
			Options: &openapi3filter.Options{
				AuthenticationFunc:                openapi3filter.NoopAuthenticationFunc,
				RejectWhenRequestBodyNotSpecified: false,
			},
		}
		// kin-openapi v0.142 rejects every non-empty body when
		// RejectWhenRequestBodyNotSpecified is enabled, including operations
		// that declare a request body. Enforce the intended condition here.
		if route.Operation.RequestBody == nil && request.ContentLength > 0 {
			writePlatformProblem(writer, request, ErrInvalidRequest)
			return
		}
		if route.Operation.OperationID == "uploadPluginVersionPackage" && strings.EqualFold(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]), "application/gzip") {
			next.ServeHTTP(writer, request)
			return
		}
		if err := openapi3filter.ValidateRequest(request.Context(), input); err != nil {
			writePlatformProblem(writer, request, ErrInvalidRequest)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (validator platformResponseValidator) validate(request *http.Request, status int, header http.Header, body []byte) error {
	validationRequest := request
	if status == http.StatusMethodNotAllowed {
		allowed := strings.Split(header.Get("Allow"), ", ")
		if len(allowed) == 0 || allowed[0] == "" {
			return ErrMethodNotAllowed
		}
		validationRequest = request.Clone(request.Context())
		validationRequest.Method = allowed[0]
	}
	route, pathParameters, err := validator.router.FindRoute(validationRequest)
	if err != nil {
		return err
	}
	requestInput := &openapi3filter.RequestValidationInput{Request: validationRequest, PathParams: pathParameters, Route: route}
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
