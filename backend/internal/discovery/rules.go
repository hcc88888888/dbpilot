package discovery

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	MinimumScanInterval      = time.Minute
	MaximumScanInterval      = time.Hour
	MaximumRules             = 128
	RuleAttestationVersion   = 1
	RuleAttestationAlgorithm = "ed25519-sha256"
)

type Rule struct {
	ID                     string   `json:"rule_id"`
	Version                uint64   `json:"version"`
	DatabaseFamily         string   `json:"database_family"`
	DatabaseVariant        string   `json:"database_variant"`
	ProcessNames           []string `json:"process_names,omitempty"`
	ExecutablePathPatterns []string `json:"executable_path_patterns,omitempty"`
	SystemdUnits           []string `json:"systemd_units,omitempty"`
	DefaultPorts           []uint16 `json:"default_ports,omitempty"`
	UnixSocketPatterns     []string `json:"unix_socket_patterns,omitempty"`
	DockerImagePatterns    []string `json:"docker_image_patterns,omitempty"`
	DockerLabelSelectors   []string `json:"docker_label_selectors,omitempty"`
}

func (rule Rule) Validate() error {
	native := len(rule.ProcessNames)+len(rule.ExecutablePathPatterns)+len(rule.SystemdUnits) > 0
	docker := len(rule.DockerImagePatterns) > 0 && len(rule.DockerLabelSelectors) > 0
	if !identifierPattern.MatchString(rule.ID) || rule.Version == 0 || !familyPattern.MatchString(rule.DatabaseFamily) || !variantPattern.MatchString(rule.DatabaseVariant) || len(rule.ProcessNames) > 32 || len(rule.ExecutablePathPatterns) > 32 || len(rule.SystemdUnits) > 32 || len(rule.DefaultPorts) > 32 || len(rule.UnixSocketPatterns) > 32 || len(rule.DockerImagePatterns) > 32 || len(rule.DockerLabelSelectors) > 32 || (!native && !docker) || (len(rule.DockerImagePatterns) > 0) != (len(rule.DockerLabelSelectors) > 0) {
		return ErrInvalidRule
	}
	for _, value := range append(append([]string{}, rule.ProcessNames...), rule.SystemdUnits...) {
		if !safeRuleLiteral(value) {
			return ErrInvalidRule
		}
	}
	patterns := append(append(append([]string{}, rule.ExecutablePathPatterns...), rule.UnixSocketPatterns...), rule.DockerImagePatterns...)
	for _, pattern := range patterns {
		if pattern == "" || len(pattern) > 512 || strings.ContainsAny(pattern, "\x00\r\n") {
			return ErrInvalidRule
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return ErrInvalidRule
		}
	}
	seenSelectors := make(map[string]struct{}, len(rule.DockerLabelSelectors))
	for _, selector := range rule.DockerLabelSelectors {
		key, value, ok := strings.Cut(selector, "=")
		if !ok || !safeDockerLabel(key) || !safeDockerLabel(value) {
			return ErrInvalidRule
		}
		if _, duplicate := seenSelectors[selector]; duplicate {
			return ErrInvalidRule
		}
		seenSelectors[selector] = struct{}{}
	}
	seenPorts := make(map[uint16]struct{}, len(rule.DefaultPorts))
	for _, port := range rule.DefaultPorts {
		if port == 0 {
			return ErrInvalidRule
		}
		if _, duplicate := seenPorts[port]; duplicate {
			return ErrInvalidRule
		}
		seenPorts[port] = struct{}{}
	}
	return nil
}

type RuleSet struct {
	Revision           uint64        `json:"revision"`
	IssuedAt           time.Time     `json:"issued_at"`
	ExpiresAt          time.Time     `json:"expires_at"`
	ScanInterval       time.Duration `json:"scan_interval"`
	DisappearanceGrace time.Duration `json:"disappearance_grace"`
	Rules              []Rule        `json:"rules"`
}

func (rules RuleSet) Validate() error {
	if rules.Revision == 0 || !validUTC(rules.IssuedAt) || !validUTC(rules.ExpiresAt) || !rules.ExpiresAt.After(rules.IssuedAt) || rules.ScanInterval < MinimumScanInterval || rules.ScanInterval > MaximumScanInterval || rules.DisappearanceGrace < rules.ScanInterval || rules.DisappearanceGrace > 24*time.Hour || len(rules.Rules) == 0 || len(rules.Rules) > MaximumRules {
		return ErrInvalidRuleSet
	}
	seen := make(map[string]struct{}, len(rules.Rules))
	for _, rule := range rules.Rules {
		if rule.Validate() != nil {
			return ErrInvalidRuleSet
		}
		if _, duplicate := seen[rule.ID]; duplicate {
			return ErrInvalidRuleSet
		}
		seen[rule.ID] = struct{}{}
	}
	return nil
}

type SignedRuleSet struct {
	RuleSet   RuleSet `json:"rule_set"`
	KeyID     string  `json:"key_id"`
	Signature []byte  `json:"signature"`
}

type RuleAttestation struct {
	Version            uint32            `json:"version"`
	Algorithm          string            `json:"algorithm"`
	KeyID              string            `json:"key_id"`
	Revision           uint64            `json:"revision"`
	Digest             [sha256.Size]byte `json:"digest"`
	IssuedAt           time.Time         `json:"issued_at"`
	ExpiresAt          time.Time         `json:"expires_at"`
	DisappearanceGrace time.Duration     `json:"disappearance_grace"`
	Signature          []byte            `json:"-"`
}

func SignRuleSet(privateKey ed25519.PrivateKey, rules RuleSet) (SignedRuleSet, error) {
	return SignRuleSetWithKey(privateKey, "default", rules)
}

func SignRuleSetWithKey(privateKey ed25519.PrivateKey, keyID string, rules RuleSet) (SignedRuleSet, error) {
	if len(privateKey) != ed25519.PrivateKeySize || rules.Validate() != nil {
		return SignedRuleSet{}, ErrInvalidRuleSet
	}
	digest, err := CanonicalRuleSetDigest(rules)
	if err != nil {
		return SignedRuleSet{}, ErrInvalidRuleSet
	}
	attestation := RuleAttestation{Version: RuleAttestationVersion, Algorithm: RuleAttestationAlgorithm, KeyID: keyID, Revision: rules.Revision, Digest: digest, IssuedAt: rules.IssuedAt, ExpiresAt: rules.ExpiresAt, DisappearanceGrace: rules.DisappearanceGrace}
	encoded, err := canonicalAttestation(attestation)
	if err != nil {
		return SignedRuleSet{}, ErrInvalidRuleSet
	}
	return SignedRuleSet{RuleSet: rules, KeyID: keyID, Signature: ed25519.Sign(privateKey, encoded)}, nil
}

func VerifyRuleSet(publicKey ed25519.PublicKey, envelope SignedRuleSet, now time.Time, previousRevision uint64) (RuleSet, error) {
	if len(publicKey) != ed25519.PublicKeySize || !validUTC(now) || envelope.RuleSet.Validate() != nil {
		return RuleSet{}, ErrInvalidRuleSet
	}
	digest, err := CanonicalRuleSetDigest(envelope.RuleSet)
	if err != nil {
		return RuleSet{}, ErrInvalidRuleSet
	}
	attestation := RuleAttestation{Version: RuleAttestationVersion, Algorithm: RuleAttestationAlgorithm, KeyID: envelope.KeyID, Revision: envelope.RuleSet.Revision, Digest: digest, IssuedAt: envelope.RuleSet.IssuedAt, ExpiresAt: envelope.RuleSet.ExpiresAt, DisappearanceGrace: envelope.RuleSet.DisappearanceGrace}
	encoded, err := canonicalAttestation(attestation)
	if err != nil || len(envelope.Signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, encoded, envelope.Signature) {
		return RuleSet{}, ErrInvalidSignature
	}
	if now.Before(envelope.RuleSet.IssuedAt) || !envelope.RuleSet.ExpiresAt.After(now) {
		return RuleSet{}, ErrInvalidRuleSet
	}
	if previousRevision != 0 && envelope.RuleSet.Revision <= previousRevision {
		return RuleSet{}, ErrRuleRevisionRollback
	}
	return envelope.RuleSet, nil
}

func AttestationFor(envelope SignedRuleSet) (RuleAttestation, error) {
	digest, err := CanonicalRuleSetDigest(envelope.RuleSet)
	if err != nil {
		return RuleAttestation{}, err
	}
	return RuleAttestation{Version: RuleAttestationVersion, Algorithm: RuleAttestationAlgorithm, KeyID: envelope.KeyID, Revision: envelope.RuleSet.Revision, Digest: digest, IssuedAt: envelope.RuleSet.IssuedAt, ExpiresAt: envelope.RuleSet.ExpiresAt, DisappearanceGrace: envelope.RuleSet.DisappearanceGrace, Signature: append([]byte(nil), envelope.Signature...)}, nil
}

func VerifyRuleAttestation(publicKey ed25519.PublicKey, attestation RuleAttestation, now time.Time) error {
	if VerifyRuleAttestationSignature(publicKey, attestation) != nil || now.Before(attestation.IssuedAt) || !attestation.ExpiresAt.After(now) {
		return ErrInvalidRuleSet
	}
	return nil
}

func VerifyRuleAttestationSignature(publicKey ed25519.PublicKey, attestation RuleAttestation) error {
	if len(publicKey) != ed25519.PublicKeySize || len(attestation.Signature) != ed25519.SignatureSize || attestation.Version != RuleAttestationVersion || attestation.Algorithm != RuleAttestationAlgorithm || !safeRuleLiteral(attestation.KeyID) || attestation.Revision == 0 || !validUTC(attestation.IssuedAt) || !validUTC(attestation.ExpiresAt) || !attestation.ExpiresAt.After(attestation.IssuedAt) || attestation.DisappearanceGrace < MinimumScanInterval || attestation.DisappearanceGrace > 24*time.Hour {
		return ErrInvalidRuleSet
	}
	encoded, err := canonicalAttestation(attestation)
	if err != nil || !ed25519.Verify(publicKey, encoded, attestation.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

func (rules RuleSet) Active(now time.Time) error {
	if rules.Validate() != nil || !validUTC(now) || now.Before(rules.IssuedAt) || !rules.ExpiresAt.After(now) {
		return ErrInvalidRuleSet
	}
	return nil
}

func CanonicalRuleSetDigest(rules RuleSet) ([sha256.Size]byte, error) {
	encoded, err := canonicalRuleSet(rules)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func canonicalAttestation(attestation RuleAttestation) ([]byte, error) {
	if attestation.Version != RuleAttestationVersion || attestation.Algorithm != RuleAttestationAlgorithm || !safeRuleLiteral(attestation.KeyID) {
		return nil, ErrInvalidRuleSet
	}
	copy := attestation
	copy.Signature = nil
	return json.Marshal(copy)
}

func canonicalRuleSet(rules RuleSet) ([]byte, error) {
	clone := rules
	clone.Rules = append([]Rule(nil), rules.Rules...)
	for index := range clone.Rules {
		clone.Rules[index].ProcessNames = sortedStrings(clone.Rules[index].ProcessNames)
		clone.Rules[index].ExecutablePathPatterns = sortedStrings(clone.Rules[index].ExecutablePathPatterns)
		clone.Rules[index].SystemdUnits = sortedStrings(clone.Rules[index].SystemdUnits)
		clone.Rules[index].UnixSocketPatterns = sortedStrings(clone.Rules[index].UnixSocketPatterns)
		clone.Rules[index].DockerImagePatterns = sortedStrings(clone.Rules[index].DockerImagePatterns)
		clone.Rules[index].DockerLabelSelectors = sortedStrings(clone.Rules[index].DockerLabelSelectors)
		clone.Rules[index].DefaultPorts = append([]uint16(nil), clone.Rules[index].DefaultPorts...)
		sort.Slice(clone.Rules[index].DefaultPorts, func(left, right int) bool {
			return clone.Rules[index].DefaultPorts[left] < clone.Rules[index].DefaultPorts[right]
		})
	}
	sort.Slice(clone.Rules, func(left, right int) bool { return clone.Rules[left].ID < clone.Rules[right].ID })
	return json.Marshal(clone)
}

func safeDockerLabel(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n;|&$`<>/\\:@")
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func safeRuleLiteral(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n;|&$`<>") && !strings.Contains(value, "://")
}
