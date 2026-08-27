package controlplane

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"dbpilot.local/platform/internal/alert"
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
	ResolvePrincipal(*http.Request) (alert.Principal, error)
}

type HeaderPrincipalResolver struct{}

func (HeaderPrincipalResolver) ResolvePrincipal(request *http.Request) (alert.Principal, error) {
	if request == nil {
		return alert.Principal{}, ErrUnauthenticated
	}
	subject, ok := singleHeader(request.Header, HeaderSubject, true)
	if !ok || len(subject) > 256 || strings.ContainsAny(subject, ",\r\n\t") {
		return alert.Principal{}, ErrUnauthenticated
	}
	adminValue, ok := singleHeader(request.Header, HeaderPlatformAdmin, false)
	if !ok {
		return alert.Principal{}, ErrUnauthenticated
	}
	admin := false
	if adminValue != "" {
		switch adminValue {
		case "false":
		default:
			return alert.Principal{}, ErrUnauthenticated
		}
	}

	projectsValue, ok := singleHeader(request.Header, HeaderProjects, false)
	if !ok {
		return alert.Principal{}, ErrUnauthenticated
	}
	projects := make(map[string]struct{})
	if projectsValue != "" {
		for _, assignment := range strings.Split(projectsValue, ",") {
			if assignment == "" || assignment != strings.TrimSpace(assignment) {
				return alert.Principal{}, ErrUnauthenticated
			}
			parts := strings.Split(assignment, "/")
			if len(parts) != 2 || !headerIdentifier.MatchString(parts[0]) || !headerIdentifier.MatchString(parts[1]) {
				return alert.Principal{}, ErrUnauthenticated
			}
			projects[(alert.Scope{TenantID: parts[0], ProjectID: parts[1]}).Key()] = struct{}{}
		}
	}
	if !admin && len(projects) == 0 {
		return alert.Principal{}, ErrUnauthenticated
	}
	return alert.Principal{Subject: subject, PlatformAdmin: admin, Projects: projects}, nil
}

// CertificatePrincipalResolver maps a verified client-certificate URI to a
// principal provisioned by the enterprise identity inventory.
type CertificatePrincipalResolver struct {
	Principals map[string]alert.Principal
}

func (resolver CertificatePrincipalResolver) ResolvePrincipal(request *http.Request) (alert.Principal, error) {
	if request == nil || request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return alert.Principal{}, ErrUnauthenticated
	}
	leaf := request.TLS.VerifiedChains[0][0]
	if len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return alert.Principal{}, ErrUnauthenticated
	}
	principal, ok := resolver.Principals[leaf.URIs[0].String()]
	if !ok || strings.TrimSpace(principal.Subject) == "" {
		return alert.Principal{}, ErrUnauthenticated
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
