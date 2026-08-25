package policy

import (
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"time"
)

func Sign(private ed25519.PrivateKey, p Policy) (SignatureEnvelope, error) {
	bytes, err := canonicalBytes(p)
	if err != nil {
		return SignatureEnvelope{}, err
	}
	if len(private) != ed25519.PrivateKeySize {
		return SignatureEnvelope{}, ErrInvalidSignature
	}
	return SignatureEnvelope{Policy: p, Signature: ed25519.Sign(private, bytes)}, nil
}

func Verify(public ed25519.PublicKey, envelope SignatureEnvelope, now time.Time) (Policy, error) {
	if len(public) != ed25519.PublicKeySize {
		return Policy{}, ErrInvalidSignature
	}
	bytes, err := canonicalBytes(envelope.Policy)
	if err != nil || !ed25519.Verify(public, bytes, envelope.Signature) {
		return Policy{}, ErrInvalidSignature
	}
	if !envelope.Policy.ExpiresAt.After(now) {
		return Policy{}, ErrExpiredPolicy
	}
	if err := Validate(envelope.Policy, defaultValidationEnvironment()); err != nil {
		return Policy{}, err
	}
	return envelope.Policy, nil
}

func canonicalBytes(p Policy) ([]byte, error) {
	// The alias avoids recursively invoking any future JSON methods on Policy.
	type policyAlias Policy
	canonical := policyAlias(p)
	canonical.Sources = append([]Source(nil), p.Sources...)
	ids := make(map[string]struct{}, len(canonical.Sources))
	for _, source := range canonical.Sources {
		if _, exists := ids[source.ID]; exists {
			return nil, ErrDuplicateSourceID
		}
		ids[source.ID] = struct{}{}
	}
	sort.Slice(canonical.Sources, func(i, j int) bool { return canonical.Sources[i].ID < canonical.Sources[j].ID })
	return json.Marshal(canonical)
}

func defaultValidationEnvironment() ValidationEnvironment {
	return ValidationEnvironment{
		AllowedRoots:   []string{"/var/log", "/var/lib/dbpilot", "/opt/dbpilot"},
		ForbiddenRoots: []string{"/proc", "/sys", "/dev"},
		PluginIDs:      map[string]struct{}{},
	}
}
