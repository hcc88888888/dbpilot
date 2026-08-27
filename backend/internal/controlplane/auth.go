package controlplane

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"dbpilot.local/platform/internal/platformscope"
)

const (
	HeaderSubject       = "X-DBPilot-Subject"
	HeaderPlatformAdmin = "X-DBPilot-Platform-Admin"
	HeaderProjects      = "X-DBPilot-Projects"
)

var (
	ErrUnauthenticated = errors.New("authenticated principal is required")
	headerIdentifier   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

// PrincipalResolver is the replaceable enterprise identity boundary. The
// header implementation below exists only for local deployments and tests.
type PrincipalResolver interface {
	ResolvePrincipal(*http.Request) (Principal, error)
}

type HeaderPrincipalResolver struct{}

func (HeaderPrincipalResolver) ResolvePrincipal(request *http.Request) (Principal, error) {
	if request == nil {
		return Principal{}, ErrUnauthenticated
	}
	subject, ok := singleHeader(request.Header, HeaderSubject, true)
	if !ok || len(subject) > 256 || strings.ContainsAny(subject, ",\r\n\t") {
		return Principal{}, ErrUnauthenticated
	}
	adminValue, ok := singleHeader(request.Header, HeaderPlatformAdmin, false)
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	admin := false
	if adminValue != "" {
		switch adminValue {
		case "false":
		default:
			return Principal{}, ErrUnauthenticated
		}
	}

	projectsValue, ok := singleHeader(request.Header, HeaderProjects, false)
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	projects := make(map[string]struct{})
	if projectsValue != "" {
		for _, assignment := range strings.Split(projectsValue, ",") {
			if assignment == "" || assignment != strings.TrimSpace(assignment) {
				return Principal{}, ErrUnauthenticated
			}
			parts := strings.Split(assignment, "/")
			if len(parts) != 2 || !headerIdentifier.MatchString(parts[0]) || !headerIdentifier.MatchString(parts[1]) {
				return Principal{}, ErrUnauthenticated
			}
			projects[(platformscope.Scope{TenantID: parts[0], ProjectID: parts[1]}).Key()] = struct{}{}
		}
	}
	if !admin && len(projects) == 0 {
		return Principal{}, ErrUnauthenticated
	}
	return Principal{Subject: subject, PlatformAdmin: admin, Projects: projects}, nil
}

// CertificatePrincipalResolver maps a verified client-certificate URI to a
// principal provisioned by the enterprise identity inventory.
type CertificatePrincipalResolver struct {
	Principals map[string]Principal
}

func (resolver CertificatePrincipalResolver) ResolvePrincipal(request *http.Request) (Principal, error) {
	if request == nil || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return Principal{}, ErrUnauthenticated
	}
	leaf := request.TLS.VerifiedChains[0][0]
	if len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return Principal{}, ErrUnauthenticated
	}
	principal, ok := resolver.Principals[leaf.URIs[0].String()]
	if !ok || strings.TrimSpace(principal.Subject) == "" {
		return Principal{}, ErrUnauthenticated
	}
	return principal, nil
}

func singleHeader(header http.Header, name string, required bool) (string, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", !required
	}
	if len(values) != 1 || values[0] == "" || values[0] != strings.TrimSpace(values[0]) {
		return "", false
	}
	return values[0], true
}
