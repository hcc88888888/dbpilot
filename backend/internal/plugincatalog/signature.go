package plugincatalog

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

type PublisherKeyStore interface {
	PublicKey(context.Context, string, string) (ed25519.PublicKey, error)
}

type PublisherKey struct {
	PublisherID string
	KeyID       string
	PublicKey   ed25519.PublicKey
}

type StaticPublisherKeyStore struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

func NewStaticPublisherKeyStore(values []PublisherKey) (*StaticPublisherKeyStore, error) {
	store := &StaticPublisherKeyStore{keys: make(map[string]ed25519.PublicKey, len(values))}
	for _, value := range values {
		if !identifierPattern.MatchString(value.PublisherID) || !identifierPattern.MatchString(value.KeyID) || len(value.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		key := value.PublisherID + "\x00" + value.KeyID
		if _, duplicate := store.keys[key]; duplicate {
			return nil, ErrInvalid
		}
		store.keys[key] = append(ed25519.PublicKey(nil), value.PublicKey...)
	}
	return store, nil
}

func (store *StaticPublisherKeyStore) PublicKey(ctx context.Context, publisherID, keyID string) (ed25519.PublicKey, error) {
	if store == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrUnknownPublisher
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	value, ok := store.keys[publisherID+"\x00"+keyID]
	if !ok {
		return nil, ErrUnknownPublisher
	}
	return append(ed25519.PublicKey(nil), value...), nil
}

func signatureMessage(manifestDigest, contentDigest [sha256.Size]byte) []byte {
	return []byte("dbpilot-plugin-signature-v1\nmanifest-sha256:" + hex.EncodeToString(manifestDigest[:]) + "\ncontent-sha256:" + hex.EncodeToString(contentDigest[:]) + "\n")
}

func verifyPublisherSignature(ctx context.Context, publishers PublisherKeyStore, manifest Manifest, signature []byte, manifestDigest, contentDigest [sha256.Size]byte) error {
	if ctx == nil || publishers == nil || len(signature) != ed25519.SignatureSize {
		return ErrSignatureRejected
	}
	publicKey, err := publishers.PublicKey(ctx, manifest.PublisherID, manifest.SigningKeyID)
	if err != nil {
		if errors.Is(err, ErrUnknownPublisher) {
			return fmt.Errorf("%w: %w", ErrSignatureRejected, ErrUnknownPublisher)
		}
		return ErrSignatureRejected
	}
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, signatureMessage(manifestDigest, contentDigest), signature) {
		return ErrSignatureRejected
	}
	return nil
}
