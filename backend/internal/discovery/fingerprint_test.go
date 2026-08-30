package discovery

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFingerprintIsPIDIndependentAndEndpointCanonical(t *testing.T) {
	left := CandidateObservation{Source: SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld"}
	right := left
	right.ObservationID = "pid-99999"
	right.NormalizedEndpoint = "127.000.000.001:3306"

	leftDigest, err := Fingerprint("host-1", left)
	require.NoError(t, err)
	rightDigest, err := Fingerprint("host-1", right)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(leftDigest[:]), hex.EncodeToString(rightDigest[:]))
}

func TestFingerprintSeparatesHostsAndRequiresStableIdentity(t *testing.T) {
	observation := CandidateObservation{Source: SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", UnixSocket: "/run/mysqld/mysqld.sock", ServiceName: "mysqld.service"}
	left, err := Fingerprint("host-1", observation)
	require.NoError(t, err)
	right, err := Fingerprint("host-2", observation)
	require.NoError(t, err)
	require.NotEqual(t, left, right)

	_, err = Fingerprint("host-1", CandidateObservation{Source: SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessIdentity: "mysqld"})
	require.ErrorIs(t, err, ErrInvalid)
}
