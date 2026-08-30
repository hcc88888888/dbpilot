package discovery

import (
	"errors"
	"regexp"
	"sort"
	"strings"
)

const maximumProcHelperNames = 64

var procHelperProcessNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$`)

// NormalizeProcHelperProcessNames validates the root-owned local database
// executable allowlist. This list is an independent upper bound; signed rules
// still decide which matching processes become candidates.
func NormalizeProcHelperProcessNames(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" || !procHelperProcessNamePattern.MatchString(value) {
			return nil, errors.New("invalid proc helper process allowlist")
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		if len(result) > maximumProcHelperNames {
			return nil, errors.New("proc helper process allowlist exceeds bound")
		}
	}
	if len(result) == 0 {
		return nil, errors.New("proc helper process allowlist is empty")
	}
	sort.Strings(result)
	return result, nil
}
