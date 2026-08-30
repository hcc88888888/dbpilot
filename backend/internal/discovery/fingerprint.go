package discovery

import (
	"crypto/sha256"
	"encoding/json"
	"net"
	"path"
	"strconv"
	"strings"
)

func Fingerprint(hostID string, observation CandidateObservation) ([32]byte, error) {
	if !identifierPattern.MatchString(hostID) || (observation.Source != SourceNative && observation.Source != SourceDocker) || !familyPattern.MatchString(observation.DatabaseFamily) || !variantPattern.MatchString(observation.DatabaseVariant) {
		return [32]byte{}, ErrInvalid
	}
	endpoint, err := NormalizeEndpoint(observation.NormalizedEndpoint)
	if err != nil {
		return [32]byte{}, err
	}
	socket := normalizeSocket(observation.UnixSocket)
	if endpoint == "" && socket == "" {
		return [32]byte{}, ErrInvalid
	}
	identity := strings.TrimSpace(observation.ServiceName)
	if observation.Source == SourceDocker {
		identity = strings.TrimSpace(observation.ContainerIdentity)
	}
	if identity == "" {
		identity = strings.TrimSpace(observation.ProcessIdentity)
	}
	if identity == "" {
		return [32]byte{}, ErrInvalid
	}
	payload := struct {
		HostID   string `json:"host_id"`
		Family   string `json:"family"`
		Endpoint string `json:"endpoint,omitempty"`
		Socket   string `json:"socket,omitempty"`
		Identity string `json:"identity"`
	}{hostID, observation.DatabaseFamily, endpoint, socket, identity}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return [32]byte{}, ErrInvalid
	}
	return sha256.Sum256(encoded), nil
}

func NormalizeEndpoint(raw string) (string, error) {
	if strings.TrimSpace(raw) != raw {
		return "", ErrInvalid
	}
	if raw == "" {
		return "", nil
	}
	host, portRaw, err := net.SplitHostPort(raw)
	if err != nil {
		return "", ErrInvalid
	}
	port, err := strconv.ParseUint(portRaw, 10, 16)
	if err != nil || port == 0 {
		return "", ErrInvalid
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if ipv4 := canonicalIPv4(host); ipv4 != "" {
		host = ipv4
	} else if parsed := net.ParseIP(host); parsed != nil {
		host = parsed.String()
	} else if host == "" || strings.ContainsAny(host, " /\\@") {
		return "", ErrInvalid
	}
	return net.JoinHostPort(host, strconv.FormatUint(port, 10)), nil
}

func canonicalIPv4(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return ""
	}
	result := make([]string, 4)
	for index, part := range parts {
		value, err := strconv.ParseUint(part, 10, 8)
		if err != nil || part == "" {
			return ""
		}
		result[index] = strconv.FormatUint(value, 10)
	}
	return strings.Join(result, ".")
}

func normalizeSocket(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "\x00\r\n") {
		return ""
	}
	return path.Clean(raw)
}
