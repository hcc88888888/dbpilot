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
	if err := verifySignatureAndExpiry(public, envelope, now); err != nil {
		return Policy{}, err
	}
	if err := ValidateStructural(envelope.Policy); err != nil {
		return Policy{}, err
	}
	return envelope.Policy, nil
}

// VerifyAndValidate verifies a signature and applies the runtime's policy
// environment, including canonical path resolution, plugin registry, and the
// last persisted policy version. Agents should persist the returned Version
// only after all policy application steps succeed.
func VerifyAndValidate(public ed25519.PublicKey, envelope SignatureEnvelope, now time.Time, env ValidationEnvironment) (Policy, error) {
	if err := verifySignatureAndExpiry(public, envelope, now); err != nil {
		return Policy{}, err
	}
	if err := Validate(envelope.Policy, env); err != nil {
		return Policy{}, err
	}
	if env.VersionStore != nil {
		if err := env.VersionStore.CheckAndRecord(envelope.Policy.AgentID, envelope.Policy.Version); err != nil {
			return Policy{}, err
		}
	}
	return envelope.Policy, nil
}

func verifySignatureAndExpiry(public ed25519.PublicKey, envelope SignatureEnvelope, now time.Time) error {
	if len(public) != ed25519.PublicKeySize {
		return ErrInvalidSignature
	}
	bytes, err := canonicalBytes(envelope.Policy)
	if err != nil || !ed25519.Verify(public, bytes, envelope.Signature) {
		return ErrInvalidSignature
	}
	if !envelope.Policy.ExpiresAt.After(now) {
		return ErrExpiredPolicy
	}
	return nil
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
