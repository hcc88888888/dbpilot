// Package platformscope defines the common tenant and project boundary shared
// by platform services. It intentionally has no dependency on feature modules.
package platformscope

import (
	"errors"
	"strconv"
	"strings"
)

var ErrInvalid = errors.New("platform scope requires canonical tenant and project identifiers")

type Scope struct {
	TenantID  string `json:"tenant_id"`
	ProjectID string `json:"project_id"`
}

func (s Scope) Validate() error {
	if s.TenantID == "" || s.ProjectID == "" || s.TenantID != strings.TrimSpace(s.TenantID) || s.ProjectID != strings.TrimSpace(s.ProjectID) {
		return ErrInvalid
	}
	return nil
}

// Key returns an unambiguous, length-prefixed identity suitable for maps.
func (s Scope) Key() string {
	return strconv.Itoa(len(s.TenantID)) + ":" + s.TenantID + strconv.Itoa(len(s.ProjectID)) + ":" + s.ProjectID
}
