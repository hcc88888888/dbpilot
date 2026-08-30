package dockerdiscovery

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const maximumCommandSummaryBytes = 512

var credentialKey = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|credential|authorization|api[_-]?key)`)
var sensitiveValueFlags = map[string]struct{}{
	"-p": {}, "--password": {}, "--passwd": {}, "--pwd": {}, "--token": {}, "--secret": {}, "--credential": {}, "--authorization": {}, "--header": {}, "--database-url": {}, "--database_url": {}, "--dsn": {}, "--uri": {}, "--url": {}, "--connection": {}, "--connection-string": {}, "--connection_string": {},
}

// RedactCommand constructs the only command representation permitted to leave
// the helper. It is intentionally lossy and bounded.
func RedactCommand(arguments []string) string {
	redacted := make([]string, 0, len(arguments))
	redactNext := false
	for _, argument := range arguments {
		if len(redacted) == 32 {
			break
		}
		value := strings.TrimSpace(strings.ToValidUTF8(argument, "[REDACTED]"))
		if value == "" || strings.ContainsAny(value, "\x00\r\n") {
			continue
		}
		if redactNext {
			redacted = append(redacted, "[REDACTED]")
			redactNext = false
			continue
		}
		lower := strings.ToLower(value)
		_, sensitive := sensitiveValueFlags[lower]
		if sensitive || value == "-H" {
			redacted = append(redacted, value)
			redactNext = true
			continue
		}
		if strings.HasPrefix(value, "-p") && len(value) > 2 {
			redacted = append(redacted, "-p[REDACTED]")
			continue
		}
		if strings.HasPrefix(value, "-H") && len(value) > 2 {
			redacted = append(redacted, "-H[REDACTED]")
			continue
		}
		key, _, hasValue := strings.Cut(value, "=")
		lowerKey := strings.ToLower(key)
		_, sensitiveFlag := sensitiveValueFlags[lowerKey]
		sensitiveFlag = sensitiveFlag || key == "-H"
		if sensitiveFlag || credentialKey.MatchString(strings.TrimLeft(key, "-")) {
			if hasValue {
				redacted = append(redacted, key+"=[REDACTED]")
			} else {
				redacted = append(redacted, value)
				redactNext = true
			}
			continue
		}
		if hasValue {
			_, rawValue, _ := strings.Cut(value, "=")
			value = key + "=" + redactEmbeddedValue(rawValue)
		} else {
			value = redactEmbeddedValue(value)
		}
		redacted = append(redacted, value)
	}
	summary := strings.Join(redacted, " ")
	return truncateUTF8(summary, maximumCommandSummaryBytes)
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
		if credentialKey.MatchString(key) {
			value = "[REDACTED]"
		} else {
			value = redactEmbeddedValue(strings.ToValidUTF8(value, "[REDACTED]"))
		}
		result[key] = value
	}
	return result
}

func redactEmbeddedValue(value string) string {
	if value == "" {
		return value
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.Scheme != "" {
		if parsed.User != nil {
			parsed.User = url.User("[REDACTED]")
		}
		query := parsed.Query()
		for key := range query {
			if credentialKey.MatchString(key) {
				query.Set(key, "[REDACTED]")
			}
		}
		parsed.RawQuery = query.Encode()
		result := parsed.String()
		result = strings.ReplaceAll(result, "%5BREDACTED%5D", "[REDACTED]")
		result = strings.ReplaceAll(result, "%5bREDACTED%5d", "[REDACTED]")
		return result
	}
	if strings.Contains(value, "://") && (strings.Contains(value, "@") || credentialKey.MatchString(value)) {
		return "[REDACTED]"
	}
	if credentialKey.MatchString(value) {
		return "[REDACTED]"
	}
	return value
}

func truncateUTF8(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	end := maximum
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end]
}
