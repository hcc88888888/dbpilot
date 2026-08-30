package plugincatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPackageVerifierRejectsUnknownPublisherAndInvalidEd25519Signature(t *testing.T) {
	// Break caught: valid package structure alone must never bypass the approved
	// publisher key boundary, and signature failures remain a fixed error.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	fixture := newSignedPackageFixture(t, "publisher-1", "key-1", private, nil)

	t.Run("unknown publisher", func(t *testing.T) {
		verifier, err := NewStreamingPackageVerifier(PackageVerifierConfig{
			Publishers: testPublisherStore{}, TemporaryDirectory: t.TempDir(), Limits: testPackageLimits(),
		})
		require.NoError(t, err)
		_, err = verifier.Verify(context.Background(), bytes.NewReader(fixture.Archive), int64(len(fixture.Archive)))
		require.ErrorIs(t, err, ErrUnknownPublisher)
		require.ErrorIs(t, err, ErrSignatureRejected)
	})

	t.Run("invalid signature", func(t *testing.T) {
		entries := cloneTarEntries(fixture.Entries)
		for index := range entries {
			if entries[index].Name == "plugin-package/SIGNATURE.ed25519" {
				entries[index].Body[0] ^= 0xff
			}
		}
		archive := writeTarGzip(t, entries)
		_, err := newTestPackageVerifier(t, public, testPackageLimits()).Verify(context.Background(), bytes.NewReader(archive), int64(len(archive)))
		require.ErrorIs(t, err, ErrSignatureRejected)
	})
}

func TestStaticPublisherKeyStoreCopiesApprovedKeysAndRejectsDuplicates(t *testing.T) {
	// Break caught: mutable caller key slices or duplicate publisher/key IDs can
	// silently replace the trust root after startup.
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	store, err := NewStaticPublisherKeyStore([]PublisherKey{{PublisherID: "publisher-1", KeyID: "key-1", PublicKey: public}})
	require.NoError(t, err)
	public[0] ^= 0xff
	stored, err := store.PublicKey(context.Background(), "publisher-1", "key-1")
	require.NoError(t, err)
	require.NotEqual(t, public, stored)
	stored[0] ^= 0xff
	again, err := store.PublicKey(context.Background(), "publisher-1", "key-1")
	require.NoError(t, err)
	require.NotEqual(t, stored, again)

	_, err = NewStaticPublisherKeyStore([]PublisherKey{
		{PublisherID: "publisher-1", KeyID: "key-1", PublicKey: again},
		{PublisherID: "publisher-1", KeyID: "key-1", PublicKey: again},
	})
	require.ErrorIs(t, err, ErrInvalid)
	_, err = store.PublicKey(context.Background(), "publisher-1", "missing")
	require.ErrorIs(t, err, ErrUnknownPublisher)
}

func TestStaticPublisherKeyStoreReadinessRequiresTrustRoot(t *testing.T) {
	empty, err := NewStaticPublisherKeyStore(nil)
	require.NoError(t, err)
	require.ErrorIs(t, empty.Ready(context.Background()), ErrUnknownPublisher)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	configured, err := NewStaticPublisherKeyStore([]PublisherKey{{PublisherID: "publisher-1", KeyID: "key-1", PublicKey: public}})
	require.NoError(t, err)
	require.NoError(t, configured.Ready(context.Background()))
}
