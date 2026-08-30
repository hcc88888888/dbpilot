package dockerdiscovery

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const maximumCommandSummaryBytes = 512

var credentialKey = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|credential|authorization|api[_-]?key)`)

// RedactCommand constructs the only command representation permitted to leave
// the helper. It is intentionally lossy and bounded.
func RedactCommand(arguments []string) string {
	redacted := make([]string, 0, len(arguments))
	redactNext := false
	for _, argument := range arguments {
		if len(redacted) == 32 {
			break
		}
		value := strings.TrimSpace(argument)
		if value == "" || strings.ContainsAny(value, "\x00\r\n") {
			continue
		}
		if redactNext {
			redacted = append(redacted, "[REDACTED]")
			redactNext = false
			continue
		}
		key, _, hasValue := strings.Cut(value, "=")
		if credentialKey.MatchString(strings.TrimLeft(key, "-")) {
			if hasValue {
				redacted = append(redacted, key+"=[REDACTED]")
			} else {
				redacted = append(redacted, value)
				redactNext = true
			}
			continue
		}
		if strings.HasPrefix(value, "-p") && len(value) > 2 {
			redacted = append(redacted, "-p[REDACTED]")
			continue
		}
		if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" && parsed.User != nil {
			parsed.User = url.User("[REDACTED]")
			value = parsed.String()
		}
		redacted = append(redacted, value)
	}
	summary := strings.Join(redacted, " ")
	if len(summary) > maximumCommandSummaryBytes {
		summary = summary[:maximumCommandSummaryBytes]
	}
	return summary
}

func FilterLabels(labels map[string]string, allowed []string) map[string]string {
	result := make(map[string]string)
	keys := append([]string(nil), allowed...)
	sort.Strings(keys)
	for _, key := range keys {
		value, ok := labels[key]
		if !ok || len(key) > 128 || len(value) > 256 || strings.ContainsAny(key+value, "\x00\r\n") {
			continue
		}
		if credentialKey.MatchString(key) || credentialKey.MatchString(value) {
			value = "[REDACTED]"
		}
		result[key] = value
	}
	return result
}
